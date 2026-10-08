# AuthFortress

[![CI](https://github.com/sayomiyori/AuthFortress/actions/workflows/ci.yml/badge.svg)](https://github.com/sayomiyori/AuthFortress/actions)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue)](#)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)](#)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?logo=postgresql&logoColor=white)](#)
[![Redis](https://img.shields.io/badge/Redis-DC382D?logo=redis&logoColor=white)](#)
[![Docker](https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=white)](#)
[![Prometheus](https://img.shields.io/badge/Prometheus-E6522C?logo=prometheus&logoColor=white)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Authentication microservice built with **FastAPI**, **PostgreSQL**, and **Redis**.
Local verification does not establish public deployment readiness; review secrets,
HTTPS, provider callbacks, backups and deployment configuration for each host.
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

# 2. Configure (required: database/Redis and a strong unique JWT secret)
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

Use Python 3.12 and the isolated verification stack. It binds only to loopback
and uses separate databases for HTTP smoke tests, pytest, and migration checks.
The pytest fixture applies Alembic migrations, rolls back each test transaction,
and routes HTTP audit writes into the same test database. Redis tests use database 15.

```powershell
uv venv --python 3.12 .venv
uv pip install --python .venv/Scripts/python.exe -r requirements.txt
docker compose -p authfortress-verification -f docker-compose.test.yml config --quiet
docker compose -p authfortress-verification -f docker-compose.test.yml up -d --build --wait
$env:TEST_DATABASE_URL = 'postgresql+psycopg2://authfortress_test:local-test-only@localhost:55432/authfortress_pytest_test'
$env:TEST_REDIS_URL = 'redis://localhost:56379/15'
$env:JWT_SECRET_KEY = 'verification-test-secret-at-least-32-bytes-long'
.venv/Scripts/python.exe -m pytest -q --tb=no
.venv/Scripts/python.exe -m ruff check app tests scripts
.venv/Scripts/python.exe -m mypy app
.venv/Scripts/python.exe scripts/verify_auth.py
$env:DATABASE_URL = 'postgresql+psycopg2://authfortress_test:local-test-only@localhost:55432/authfortress_test'
.venv/Scripts/python.exe -m scripts.verify_refresh_concurrency --database-race
.venv/Scripts/python.exe -m scripts.verify_refresh_concurrency
```

The smoke script creates disposable users and a tenant and checks login, `/me`, auth
failures, RBAC, refresh replay, logout, metrics, tenant authorization and cross-user
isolation at `http://127.0.0.1:38080`.
It does not print credentials or tokens. Only point it at disposable local data.

Migration drift can be checked separately:

```powershell
$env:DATABASE_URL = 'postgresql+psycopg2://authfortress_test:local-test-only@localhost:55432/authfortress_migration_test'
.venv/Scripts/python.exe -m alembic upgrade head
.venv/Scripts/python.exe -m alembic check
```

Downgrades remove schema/data: obtain approval before running them, even on a test database.
Do not use `down -v` or recreate database storage to clean tests.

### Tenant foundation

Authenticated users can create and access organizations through:

| Endpoint | Result |
| --- | --- |
| `POST /api/v1/tenants` with `{ "name": "Team" }` | 201 tenant with creator as owner |
| `GET /api/v1/tenants?offset=0&limit=50` | Active memberships, ordered by creation time and UUID |
| `GET /api/v1/tenants/{tenant_id}` | Active tenant and caller's membership role |
| `POST /api/v1/tenants/{tenant_id}/authorize` with `{ "permission": "tenant.read" }` | Authorized identity and tenant context |

Names are trimmed and limited to 1–128 characters. Pagination allows offset >= 0
and limit 1–100. Creation and authorization reject extra body fields.
Creation writes the tenant, owner membership and audit event in one transaction.
Timestamps are returned in UTC.

Members can authorize `tenant.read`, `bot.read` and `ai.read`. Owners additionally
authorize `tenant.manage`, `bot.manage` and `ai.configure`. Global `admin` and
`superadmin` roles provide no tenant bypass. Missing, invalid, revoked or inactive
identity returns 401; an inaccessible/inactive tenant or membership returns 404;
an active member requesting a management permission gets 403.

Deleting a tenant creator through either superadmin user deletion endpoint returns
409 (`User owns a tenant`), including when the tenant is inactive. Owner transfer
and tenant deletion must be designed before permitting this deletion.

Alembic revision `004_tenants` adds tenants and unique `(tenant_id, user_id)`
memberships. This stage provides identity context only: membership invitations,
tenant mutation and downstream tenant enforcement
are not implemented. Permission names do not establish working bot or AI endpoints.

### Internal tenant status

`GET /internal/v1/tenants/{tenant_id}/status` uses `X-Service-Key`, independently
configured with `AUTHFORTRESS_WEBHOOK_SERVICE_KEY` (random ASCII, 32 to 256 bytes,
different from `JWT_SECRET_KEY`). Leave the optional variable unset to disable
this endpoint: it returns 503 (`Service unavailable`). Invalid or missing keys
return 401 (`Invalid service key`); user JWTs cannot substitute for this key.

Active tenants return only `{ "tenant_id": "UUID", "is_active": true }`.
Missing or inactive tenants return 404 (`Tenant not found`). Every request reads
the database; no positive status cache is used. This key grants no access to user
APIs. Restrict `/internal/` at the public ingress and use private transport/TLS
between services. Bot registration and downstream enforcement remain separate work.

### Authentication security contracts

- Access tokens require an active session claim; unknown registration fields are rejected.
- Enabled TOTP must be disabled with a valid factor before setting up a replacement.
- Password and OAuth login both return a single-use Redis-backed challenge when TOTP is enabled.
- 2FA has a per-user attempt limit; a successful TOTP cannot be replayed during its acceptance window.
- OAuth callbacks require the browser's HttpOnly, SameSite=Lax state cookie; state is consumed atomically.
- OAuth login rejects inactive accounts. For TOTP accounts, callback returns a JSON challenge even in redirect mode.
- Admins cannot modify or revoke sessions of users with a higher role.
- Client IP comes from `request.client`; forwarded headers must be handled by explicitly trusted proxy configuration.
- Passwords are limited to 72 UTF-8 bytes to prevent bcrypt truncation. Existing bcrypt hashes remain supported.

Local verification on 2026-10-09 passed 192 tests, real PostgreSQL/Redis refresh
and backup-code races, Ruff, Mypy, and dependency audit. Concurrent duplicate
registration returns a conflict; audit writes run in a threadpool to keep the
event loop responsive. See `docs/ERRORS.md` for regressions.
Real OAuth provider login and public deployment still require separate gates.

CI runs on every push and pull request via GitHub Actions:
- Ruff (linting)
- Mypy (type checking)
- Pytest with real PostgreSQL + Redis
- Docker image build

---

## License

[MIT](LICENSE) © 2025 sayomiyori
