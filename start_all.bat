@echo off
:: ─────────────────────────────────────────────────────────────────────────────
:: SecureFlow IDS — Start All Services
:: Run this as Administrator!
:: ─────────────────────────────────────────────────────────────────────────────
echo.
echo  ███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗███████╗██╗      ██████╗ ██╗    ██╗
echo  ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝██╔════╝██║     ██╔═══██╗██║    ██║
echo  ███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗  █████╗  ██║     ██║   ██║██║ █╗ ██║
echo  ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝  ██╔══╝  ██║     ██║   ██║██║███╗██║
echo  ███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗██║     ███████╗╚██████╔╝╚███╔███╔╝
echo  ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝     ╚══════╝ ╚═════╝  ╚══╝╚══╝
echo.
echo  Starting SecureFlow IDS — Real-Time Intrusion Detection System
echo  ─────────────────────────────────────────────────────────────
echo.

:: ── Window 1: Node.js Auth Backend (port 5000) ──────────────────────────────
echo  [1/3] Starting Node.js Auth Backend on port 5000...
start "SecureFlow Auth (Node.js)" cmd /k "cd /d %~dp0dashboard\backend && npm start"
timeout /t 2 /nobreak >nul

:: ── Window 2: Django/Daphne ML Backend (port 8000) ──────────────────────────
echo  [2/3] Starting Django+Daphne ML Backend on port 8000 (HTTP + WebSocket)...
start "SecureFlow ML (Daphne)" cmd /k "cd /d %~dp0ml_model && daphne -b 0.0.0.0 -p 8000 ml_model.asgi:application"
timeout /t 3 /nobreak >nul

:: ── Window 3: React Frontend (port 5173) ─────────────────────────────────────
echo  [3/3] Starting React Frontend on port 5173...
start "SecureFlow UI (Vite)" cmd /k "cd /d %~dp0dashboard\frontend && npm run dev"

echo.
echo  ─────────────────────────────────────────────────────────────
echo  All services started in separate windows!
echo.
echo  Frontend:   http://localhost:5173
echo  ML Backend: http://localhost:8000
echo  Auth API:   http://localhost:5000
echo  WebSockets: ws://localhost:8000/ws/alerts/   (alerts feed)
echo              ws://localhost:8000/ws/network/  (packet feed)
echo.
echo  ── Packet Capture (run manually as Administrator) ────────────
echo  cd ml_model\engine
echo  C:\Users\saket\3-2Mini\mini\Scripts\python.exe pp.py
echo.
echo  Dual-capture mode (auto-detects):
echo    [WIFI]    Wi-Fi          (your laptop traffic)
echo    [HOTSPOT] Wi-Fi 2        (hotspot client traffic)
echo.
echo  Enable Mobile Hotspot first:
echo    Settings -^> Network ^& Internet -^> Mobile Hotspot
echo  ─────────────────────────────────────────────────────────────
echo.
pause
