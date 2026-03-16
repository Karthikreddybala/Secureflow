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
