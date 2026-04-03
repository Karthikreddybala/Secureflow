# SecureFlow IDS

**Real-Time Intrusion Detection System** — ML-powered network packet analysis with live WebSocket alerts and a React dashboard.

---

## Architecture

| Service | Tech | Port |
|---|---|---|
| **Auth Backend** | Node.js + Express + PostgreSQL | 5000 |
| **ML Backend** | Django + Daphne + Channels (ASGI) | 8000 |
| **Frontend** | React + Vite | 5173 (dev) / static (prod) |

WebSocket feeds: `ws://host:8000/ws/alerts/` · `ws://host:8000/ws/network/`

---

## Prerequisites

- **Python** ≥ 3.10  
- **Node.js** ≥ 18  
- **PostgreSQL** ≥ 14  
- **Redis** ≥ 6 *(production only — for WebSocket channel scaling)*

---

## Local Development Setup

### 1. Clone & download ML models
```bash
git clone <repo-url>
cd secureflow

# Set the base URL where your model files are hosted, then run:
set MODEL_BASE_URL=https://your-storage.example.com/models
python download_models.py
```
> Without models the ML backend will start but predictions won't work.

### 2. ML Backend (Django / Daphne)
```bash
cd ml_model

# Copy and fill in environment variables
copy .env.example .env

pip install -r requirements.txt

python manage.py migrate
daphne -b 0.0.0.0 -p 8000 ml_model.asgi:application
```

### 3. Auth Backend (Node.js)
```bash
cd dashboard/backend

# Copy and fill in environment variables
copy .env.example .env

npm install
npm start
```

Make sure the PostgreSQL `secrets` database exists and the `users` table is set up.  
The server auto-creates the `alert_actions` table on first start.

### 4. Frontend (React + Vite)
```bash
cd dashboard/frontend
npm install
npm run dev          # dev server on http://localhost:5173
```

### 5. Start everything at once (Windows)
```bash
# Run as Administrator
start_all.bat
```

---

## Environment Variables

### ML Backend — `ml_model/.env`
| Variable | Required | Description |
|---|---|---|
| `DJANGO_SECRET_KEY` | ✅ prod | Django secret key |
| `DJANGO_DEBUG` | | `False` in production (default: `False`) |
| `DJANGO_ALLOWED_HOSTS` | ✅ prod | Comma-separated hostnames |
| `REDIS_URL` | ✅ prod | Redis URL for WebSocket scaling, e.g. `redis://localhost:6379` |
| `CORS_ALLOWED_ORIGINS` | ✅ prod | Comma-separated frontend origins |

Copy `ml_model/.env.example` → `ml_model/.env`

### Auth Backend — `dashboard/backend/.env`
| Variable | Required | Description |
|---|---|---|
| `JWT_SECRET` | ✅ | Long random string for JWT signing |
| `NODE_ENV` | ✅ prod | Set to `production` |
| `db_username` | ✅ | PostgreSQL user |
| `db_password` | ✅ | PostgreSQL password |
| `db_host` | ✅ | PostgreSQL host |
| `db_port` | ✅ | PostgreSQL port (default: 5432) |
| `db_name` | ✅ | Database name |
| `FRONTEND_URL` | ✅ prod | Frontend origin for CORS restriction |

Copy `dashboard/backend/.env.example` → `dashboard/backend/.env`

### Frontend — `dashboard/frontend/.env.production`
| Variable | Description |
|---|---|
| `VITE_API_URL` | URL of the deployed auth backend |
| `VITE_WS_BASE_URL` | WebSocket base URL of the ML backend |

Copy `dashboard/frontend/.env.example` → `dashboard/frontend/.env.production`

---

## Production Deployment

### Build the frontend
```bash
cd dashboard/frontend
# Edit .env.production with your real server URLs first
npm run build          # outputs to dist/
```
Serve `dist/` with Nginx, Caddy, or any static host.

### Django — collect static files
```bash
cd ml_model
python manage.py collectstatic --noinput
```

### Django — run with Daphne (ASGI + WebSockets)
```bash
daphne -b 0.0.0.0 -p 8000 ml_model.asgi:application
```

### Node.js Auth Server
```bash
NODE_ENV=production node src/index.js
```

### Redis (required in production)
```bash
# Docker example
docker run -d -p 6379:6379 redis:alpine
```
Set `REDIS_URL=redis://localhost:6379` in the ML backend `.env`.

---

## ML Model Files

Trained models are **excluded from git** (≈930 MB total). Before deployment:

1. Upload model files to a storage bucket (S3, GCS, etc.)
2. Set `MODEL_BASE_URL` to the bucket base URL
3. Run `python download_models.py`

Models live in: `ml_model/ai_models/models/`

---

## Security Checklist Before Go-Live

- [ ] `DJANGO_SECRET_KEY` is a fresh random key (never the insecure default)
- [ ] `DJANGO_DEBUG=False` is set
- [ ] `DJANGO_ALLOWED_HOSTS` is locked to your domain
- [ ] `JWT_SECRET` is a long random string
- [ ] `FRONTEND_URL` restricts CORS on the auth backend
- [ ] `CORS_ALLOWED_ORIGINS` restricts CORS on the ML backend
- [ ] `REDIS_URL` is set (for WebSocket channel scaling)
- [ ] PostgreSQL password is strong and not the default
- [ ] All `.env` files are excluded from git (verify with `git status`)
- [ ] HTTPS is enforced via reverse proxy (Nginx/Caddy)
