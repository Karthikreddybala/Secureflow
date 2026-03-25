from django.http import JsonResponse
from django.urls import path
from .views import (
    predict_flow,
    get_processing_stats,
    get_host_scores,
    get_incidents,
    manage_blocked_ips,
    simulate_attack,
    export_alerts,
)

urlpatterns = [
    path('predict',     predict_flow,                                              name='predict_flow'),
    path('stats',       lambda r: JsonResponse(get_processing_stats()),            name='processing_stats'),
    path('hosts',       get_host_scores,                                           name='host_scores'),
    path('incidents',   get_incidents,                                             name='incidents'),
    path('block_ip',    manage_blocked_ips,                                        name='manage_blocked_ips'),
    path('simulate',    simulate_attack,                                           name='simulate_attack'),
    path('export',      export_alerts,                                             name='export_alerts'),
]
