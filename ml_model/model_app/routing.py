from django.urls import path

from model_app.consumer import AlertConsumer, PacketConsumer, NetworkTrafficConsumer, DeviceConsumer

websocket_urlpatterns = [
    path('ws/alerts/',   AlertConsumer.as_asgi()),
    path('ws/network/',  NetworkTrafficConsumer.as_asgi()),
    path('ws/packets/',  PacketConsumer.as_asgi()),
    path('ws/devices/',  DeviceConsumer.as_asgi()),   # Hotspot device monitor
]
