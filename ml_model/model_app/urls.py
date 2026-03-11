from django.http import JsonResponse
from django.urls import path
from .views import predict_flow, get_processing_stats

urlpatterns = [
    path("predict", predict_flow, name="predict_flow"),
    path("stats", lambda request: JsonResponse(get_processing_stats()), name="processing_stats"),
] 
