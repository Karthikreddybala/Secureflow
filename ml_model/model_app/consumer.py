import asyncio
import json
import logging
from channels.generic.websocket import AsyncWebsocketConsumer
from asgiref.sync import sync_to_async

from .views import process_packet_batch

logger = logging.getLogger(__name__)
PROCESSING_QUEUE_MAX = 128

class AlertConsumer(AsyncWebsocketConsumer):

    async def connect(self):

        self.group_name = "alerts"

        await self.channel_layer.group_add(
            self.group_name,
            self.channel_name
        )

        await self.accept()

    async def disconnect(self, close_code):

        await self.channel_layer.group_discard(
            self.group_name,
            self.channel_name
        )

    async def send_alert(self, event):

        await self.send(
            text_data=json.dumps(event["data"])
        )

class NetworkTrafficConsumer(AsyncWebsocketConsumer):

    async def connect(self):

        self.group_name = "network_traffic"

        await self.channel_layer.group_add(
            self.group_name,
            self.channel_name
        )

        await self.accept()

    async def disconnect(self, close_code):

        await self.channel_layer.group_discard(
            self.group_name,
            self.channel_name
        )

    async def send_traffic(self, event):

        await self.send(
            text_data=json.dumps(event["data"])
        )


class PacketConsumer(AsyncWebsocketConsumer):

    async def connect(self):
        self.packet_queue = asyncio.Queue(maxsize=PROCESSING_QUEUE_MAX)
        self.processor_task = asyncio.create_task(self._process_packet_queue())
        await self.accept()
        logger.info("Packet sensor connected")

    async def disconnect(self, close_code):
        if hasattr(self, "processor_task") and self.processor_task:
            self.processor_task.cancel()
            try:
                await self.processor_task
            except asyncio.CancelledError:
                pass
        logger.info("Packet sensor disconnected")

    async def _process_packet_queue(self):
        while True:
            packets = await self.packet_queue.get()
            try:
                # Run heavy flow/ML processing off the receive path.
                await sync_to_async(process_packet_batch, thread_sensitive=False)(packets, False)
            except Exception:
                logger.exception("Error processing packet batch")
            finally:
                self.packet_queue.task_done()

    async def receive(self, text_data):
        try:
            data = json.loads(text_data)
            packets = data.get("packets", [])
            
            if not packets:
                return

            # Send packets to dashboard via network_traffic group
            channel_layer = self.channel_layer
            await channel_layer.group_send(
                "network_traffic",
                {
                    "type": "send_traffic",
                    "data": packets
                }
            )

            # Queue ML processing so receive stays low-latency.
            try:
                self.packet_queue.put_nowait(packets)
            except asyncio.QueueFull:
                # Drop the oldest queued batch under overload to preserve freshness.
                _ = self.packet_queue.get_nowait()
                self.packet_queue.task_done()
                self.packet_queue.put_nowait(packets)
            
        except json.JSONDecodeError as error:
            logger.error("JSON decode error: %s", error)
        except Exception:
            logger.exception("Error processing packet data")


class DeviceConsumer(AsyncWebsocketConsumer):
    """
    WebSocket consumer for real-time hotspot device updates.
    ws://localhost:8000/ws/devices/

    On connect: immediately sends current device list.
    Every 2 seconds: pushes fresh device snapshot to all subscribers.
    Also receives group messages from _push_device_update().
    """
    _push_task = None

    async def connect(self):
        self.group_name = 'hotspot_devices'
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()
        logger.info('DeviceConsumer connected')

        # Send initial snapshot immediately
        await self._send_snapshot()

        # Start periodic push task (one per instance)
        self._push_task = asyncio.create_task(self._periodic_push())

    async def disconnect(self, close_code):
        if self._push_task:
            self._push_task.cancel()
            try:
                await self._push_task
            except asyncio.CancelledError:
                pass
        await self.channel_layer.group_discard(self.group_name, self.channel_name)
        logger.info('DeviceConsumer disconnected')

    async def _send_snapshot(self):
        """Fetch device list and push to this client."""
        try:
            from .views import _hotspot_tracker
            devices = await sync_to_async(_hotspot_tracker.get_all, thread_sensitive=False)()
            stats   = await sync_to_async(_hotspot_tracker.get_stats, thread_sensitive=False)()
            await self.send(text_data=json.dumps({'devices': devices, 'stats': stats}))
        except Exception as exc:
            logger.error('DeviceConsumer snapshot error: %s', exc)

    async def _periodic_push(self):
        """Push device updates to THIS client every 2 seconds."""
        while True:
            await asyncio.sleep(2)
            try:
                await self._send_snapshot()
            except Exception:
                break   # Client disconnected

    async def send_devices(self, event):
        """Handle group broadcast from _push_device_update()."""
        try:
            await self.send(text_data=json.dumps(event['data']))
        except Exception:
            pass

