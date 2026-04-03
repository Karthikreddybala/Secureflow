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
    capture_control,
    list_network_flows,
    download_network_flows,
    manage_blocked_ips_db,
    # Hotspot device management
    get_hotspot_devices,
    get_hotspot_stats,
    manage_hotspot_device,
    scan_hotspot_now,
    hotspot_arp_check,
    # Device alert email rules
    manage_device_emails,
    manage_device_email_detail,
    test_device_email,
    # Web Push notifications
    get_vapid_public_key,
    push_subscribe,
    push_unsubscribe,
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
    # ── Capture control ────────────────────────────────────
    path('capture',         capture_control,                                           name='capture_control'),
    # ── Network flows ──────────────────────────────────────
    path('flows',           list_network_flows,                                        name='list_network_flows'),
    path('flows/download',  download_network_flows,                                    name='download_network_flows'),
    # ── Blocked IPs (DB-backed) ───────────────────────────
    path('blocked_ips_db',  manage_blocked_ips_db,                                     name='manage_blocked_ips_db'),
    # ── Hotspot device management ─────────────────────────
    path('hotspot/devices',                      get_hotspot_devices,    name='hotspot_devices'),
    path('hotspot/stats',                        get_hotspot_stats,      name='hotspot_stats'),
    path('hotspot/devices/<str:device_ip>/action', manage_hotspot_device, name='manage_hotspot_device'),
    path('hotspot/scan',                         scan_hotspot_now,       name='hotspot_scan'),
    path('hotspot/arp_check',                    hotspot_arp_check,      name='hotspot_arp_check'),
    # ── Device alert email rules ──────────────────────────
    path('device_emails',                manage_device_emails,       name='device_emails'),
    path('device_emails/test',           test_device_email,          name='test_device_email'),
    path('device_emails/<int:rule_id>',  manage_device_email_detail, name='device_email_detail'),
    # ── Web Push ──────────────────────────────────────────
    path('push/vapid_key',   get_vapid_public_key, name='vapid_public_key'),
    path('push/subscribe',   push_subscribe,       name='push_subscribe'),
    path('push/unsubscribe', push_unsubscribe,     name='push_unsubscribe'),
]
