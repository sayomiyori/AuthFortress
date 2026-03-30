# AuthFortress

[![CI](https://github.com/sayomiyori/AuthFortress/actions/workflows/ci.yml/badge.svg)](https://github.com/sayomiyori/AuthFortress/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.12-blue?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Docker](https://img.shields.io/badge/docker-compose-2496ED?logo=docker&logoColor=white)](https://docs.docker.com/compose/)
[![Ruff](https://img.shields.io/badge/code%20style-ruff-orange?logo=ruff)](https://docs.astral.sh/ruff/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Production-ready authentication microservice built with **FastAPI**, **PostgreSQL**, and **Redis**.
Covers the full auth stack: JWT sessions, OAuth2 social login, TOTP 2FA, role-based access control, audit logging, rate limiting, and Prometheus metrics — all in one deployable service.

---

## Features

| Category | What's included |
|----------|----------------|
| **Auth** | Register, login, logout, `/me` |
| **JWT** | Access token (15 min) + refresh token (30 days) with rotation |
| **OAuth2** | Google, GitHub, Yandex — account linking included |
| **2FA** | TOTP (Google Authenticator) — setup, verify, backup codes |
| **RBAC** | `user` / `admin` / `superadmin` hierarchy |
| **Audit log** | 15+ auth events with IP, user-agent, JSON details |
| **Rate limiting** | 5 login/min · 3 register/min (sliding window, Redis) |
| **Admin API** | Manage users, sessions, audit log |
| **Metrics** | Prometheus endpoint at `GET /metrics` |
| **CI/CD** | GitHub Actions — Ruff · Mypy · Pytest · Docker build |

---

## Quick Start (Docker)

```bash
# 1. Clone
git clone https://github.com/sayomiyori/AuthFortress.git
cd AuthFortress

# 2. Configure (optional — OAuth keys, custom ports)
cp .env.example .env

# 3. Start
docker compose up -d

# API:      http://localhost:28080/docs
# Postgres: localhost:45432
# Redis:    localhost:26379
```

Migrations run automatically on startup. No extra steps needed.

---

## Local Development

**Requirements:** Python 3.12, PostgreSQL, Redis

```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables
export DATABASE_URL=postgresql+psycopg2://user:pass@localhost:5432/authfortress
export REDIS_URL=redis://localhost:6379/0
export JWT_SECRET_KEY=your-secret-key-at-least-32-characters

# Apply migrations
alembic upgrade head

# Run
uvicorn app.main:app --reload
```

---

## API Overview

Interactive docs available at `http://localhost:28080/docs`.

### Auth

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/auth/register` | Register a new user |
| `POST` | `/api/v1/auth/login` | Login (returns access + refresh tokens) |
| `POST` | `/api/v1/auth/refresh` | Rotate refresh token |
| `POST` | `/api/v1/auth/logout` | Revoke current session |
| `GET`  | `/api/v1/auth/me` | Current user info |

### OAuth2

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/oauth/{provider}/authorize` | Redirect to provider |
| `GET` | `/api/v1/oauth/{provider}/callback` | OAuth2 callback |

`{provider}` — `google`, `github`, or `yandex`.

### 2FA

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/auth/2fa/setup` | Generate TOTP secret + QR code |
| `POST` | `/api/v1/auth/2fa/verify` | Confirm setup, receive backup codes |
| `POST` | `/api/v1/auth/login/2fa` | Complete login when 2FA is enabled |
| `POST` | `/api/v1/auth/2fa/disable` | Disable 2FA (requires TOTP or backup code) |

### Admin

Requires `admin` role or higher. Role-change and delete require `superadmin`.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/admin/stats` | Users, sessions, audit count |
| `GET` | `/api/v1/admin/users` | Paginated user list |
| `GET` | `/api/v1/admin/users/{id}` | Single user detail |
| `PATCH` | `/api/v1/admin/users/{id}/block` | Block / unblock user |
| `PATCH` | `/api/v1/admin/users/{id}/role` | Change role (`superadmin` only) |
| `DELETE` | `/api/v1/admin/users/{id}` | Delete user (`superadmin` only) |
| `GET` | `/api/v1/admin/sessions` | Active sessions list |
| `DELETE` | `/api/v1/admin/sessions/{id}` | Revoke session |
| `GET` | `/api/v1/admin/audit` | Audit log (filterable) |

---

## OAuth2 Setup

1. Copy `.env.example` → `.env`
2. Register an OAuth app with each provider and fill in the credentials:

```dotenv
OAUTH_REDIRECT_BASE_URL=http://localhost:28080

GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...

GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...

YANDEX_CLIENT_ID=...
YANDEX_CLIENT_SECRET=...
```

**Callback URLs** to register with providers:
```
http://localhost:28080/api/v1/oauth/google/callback
http://localhost:28080/api/v1/oauth/github/callback
http://localhost:28080/api/v1/oauth/yandex/callback
```

Providers with no credentials set are silently skipped.

---

## 2FA Login Flow

```
POST /auth/login          → { temp_token }   # valid 5 min
POST /auth/login/2fa      → { access_token, refresh_token }
  body: { temp_token, code }   # code = TOTP or backup code
```

Setup flow:

```
POST /auth/2fa/setup      → { secret, qr_code_base64, provisioning_uri }
POST /auth/2fa/verify     → { backup_codes }   # scans QR first, then confirms
```

---

## Refresh Token Rotation

Each `/auth/refresh` call:
1. Validates the old refresh token against a stored SHA-256 hash
2. Issues a new access + refresh token pair
3. Invalidates the old refresh token immediately

Replaying the old token returns `401 Unauthorized`.

---

## RBAC

| Role | Rank | Can access |
|------|------|-----------|
| `user` | 0 | Own profile, 2FA, logout |
| `admin` | 1 | + User list, sessions, audit log |
| `superadmin` | 2 | + Role changes, user deletion, OAuth config |

---

## Prometheus Metrics

```
GET /metrics
```

| Metric | Type | Labels |
|--------|------|--------|
| `auth_login_total` | Counter | `method`, `status` |
| `auth_register_total` | Counter | — |
| `rate_limit_exceeded_total` | Counter | `route` |
| `active_sessions_total` | Gauge | — |
| `totp_setup_total` | Counter | `status` |

---

## Screenshots

### Swagger UI
![Swagger UI](docs/images/swagger-ui.png)

### Admin — User List
![Admin Users](docs/images/admin-users.png)

### RBAC — Forbidden Response
![RBAC Forbidden](docs/images/rbac-forbidden.png)

### Audit Log
![Audit Log](docs/images/audit-log.png)

### Prometheus Metrics
![Prometheus Metrics](docs/images/prometheus-metrics.png)

### OAuth — GitHub Redirect
![OAuth GitHub](docs/images/oauth-github-redirect.png)

### OAuth — User Created via OAuth
![OAuth User DB](docs/images/oauth-user-db.png)

### Docker Services
![Docker Services](docs/images/docker-services.png)

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | — | PostgreSQL connection string |
| `REDIS_URL` | — | Redis connection string |
| `JWT_SECRET_KEY` | — | Secret for signing JWTs (32+ chars) |
| `OAUTH_REDIRECT_BASE_URL` | `http://localhost:28080` | Base URL for OAuth callbacks |
| `OAUTH_TOKEN_ENCRYPTION_KEY` | derived from JWT key | Fernet key for encrypting OAuth tokens |
| `APP_PORT` | `28080` | Host port for the app container |
| `PG_PORT` | `45432` | Host port for PostgreSQL |
| `REDIS_PORT` | `26379` | Host port for Redis |

---

## Running Tests

```bash
# Requires running PostgreSQL and Redis (or use docker compose)
pytest -q
```

CI runs on every push and pull request via GitHub Actions:
- Ruff (linting)
- Mypy (type checking)
- Pytest with real PostgreSQL + Redis
- Docker image build

---

## License

[MIT](LICENSE) © 2025 sayomiyori
