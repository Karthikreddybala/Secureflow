import json
from channels.generic.websocket import AsyncWebsocketConsumer

from .views import flush_flows_async, process_packet

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
        await self.accept()
        print("Packet sensor connected")

    async def disconnect(self, close_code):
        print("Packet sensor disconnected")

    async def receive(self, text_data):
        try:
            data = json.loads(text_data)
            packets = data.get("packets", [])
            
            if not packets:
                print("No packets received")
                return

            print(f"Received {len(packets)} packets from sensor")

            # Send packets to dashboard via network_traffic group
            channel_layer = self.channel_layer
            await channel_layer.group_send(
                "network_traffic",
                {
                    "type": "send_traffic",
                    "data": packets
                }
            )

            # Process packets for ML analysis (sync to async)
            for pkt in packets:
                # Convert async function call to sync for compatibility
                from asgiref.sync import sync_to_async
                await sync_to_async(process_packet)(pkt)

            # Trigger flow processing
            await sync_to_async(flush_flows_async)()
            
        except json.JSONDecodeError as e:
            print(f"JSON decode error: {e}")
        except Exception as e:
            print(f"Error processing packet data: {e}")
