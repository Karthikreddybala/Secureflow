@echo off
:: ─────────────────────────────────────────────────────
:: SecureFlow — Start Django via Daphne (ASGI)
:: Handles HTTP + WebSocket on port 8000
:: MUST be run as Administrator for netsh + raw sockets
:: ─────────────────────────────────────────────────────
echo [SecureFlow] Starting Daphne ASGI server on port 8000...
echo [SecureFlow] WebSocket routes: ws/alerts/  ws/network/  ws/packets/
echo.
cd /d %~dp0
daphne -b 0.0.0.0 -p 8000 ml_model.asgi:application
