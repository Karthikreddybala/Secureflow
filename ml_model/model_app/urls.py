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
    list_db_alerts,
    delete_db_alert,
    get_log_lines,
    # New endpoints
    capture_control,
    list_network_flows,
    download_network_flows,
    manage_blocked_ips_db,
)

urlpatterns = [
    path('predict',         predict_flow,                                              name='predict_flow'),
    path('stats',           lambda r: JsonResponse(get_processing_stats()),            name='processing_stats'),
    path('hosts',           get_host_scores,                                           name='host_scores'),
    path('incidents',       get_incidents,                                             name='incidents'),
    path('block_ip',        manage_blocked_ips,                                        name='manage_blocked_ips'),
    path('simulate',        simulate_attack,                                           name='simulate_attack'),
    path('export',          export_alerts,                                             name='export_alerts'),
    path('db_alerts',       list_db_alerts,                                            name='list_db_alerts'),
    path('db_alerts/<int:alert_id>', delete_db_alert,                                  name='delete_db_alert'),
    path('logs',            get_log_lines,                                             name='get_log_lines'),
    # ── New endpoints ──────────────────────────────────────────
    path('capture',         capture_control,                                           name='capture_control'),
    path('flows',           list_network_flows,                                        name='list_network_flows'),
    path('flows/download',  download_network_flows,                                    name='download_network_flows'),
    path('blocked_ips_db',  manage_blocked_ips_db,                                     name='manage_blocked_ips_db'),
]
