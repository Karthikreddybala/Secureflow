from django.urls import path

from model_app.consumer import AlertConsumer, PacketConsumer
from model_app.consumer import NetworkTrafficConsumer

websocket_urlpatterns = [
    path('ws/alerts/', AlertConsumer.as_asgi()),
    path('ws/network/', NetworkTrafficConsumer.as_asgi()),
    path('ws/packets/', PacketConsumer.as_asgi()),
]
