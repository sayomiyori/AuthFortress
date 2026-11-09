# Verified Defects and Regression Checks

## 2026-11-08: Logout could not revoke a session after the access token expired

- `POST /api/v1/auth/logout` required a valid access token, so a client whose
  15-minute access token had expired had no way to end its own session; the
  `UserSession` row and the Redis `session:{sid}` key survived until natural
  expiry. The revocation helper also read the session without a row lock and
  surfaced a Redis delete failure as a server error after the database row had
  already been revoked.
- The refresh-credential flow is a separate `POST /api/v1/auth/logout/refresh`
  endpoint. The original `POST /api/v1/auth/logout` keeps its exact signature
  and dependency set and remains bearer-only and body-agnostic: malformed JSON,
  non-object bodies and extra fields are still ignored, valid access-token
  logout still returns `204`, and a refresh token in the body is not
  authentication.
- `POST /api/v1/auth/logout/refresh` requires a JSON object with a required
  `refresh_token`; a missing body, non-object body, malformed JSON, or missing
  or non-string field returns `422` before any token is examined. The refresh
  JWT is accepted only when its signature, a required finite numeric `exp`,
  `type=refresh`, `sub`, `sid` and `jti` are valid. A missing or malformed `exp`
  is rejected locally in this path; the shared decoder is unchanged for login,
  refresh and access checks. It revokes the single session named by its own
  `sid`; `session.user_id` must equal `sub`, so a token for one account cannot
  revoke another account's session. It is never accepted as authentication. The
  stored hash of the current `jti` is deliberately not required, so a
  previously rotated refresh token can end its own session.
- Both logout paths select the session row `FOR UPDATE` with
  `populate_existing` before revoking, sharing the lock used by refresh
  rotation. A refresh that commits first has its new token pair invalidated by
  the revocation that follows; a refresh that waits observes `revoked_at` and
  fails. No user-row lock is taken, so the order stays session lock -> plain
  user read and cannot deadlock with the 2FA paths that lock the user first.
  Revocation is idempotent and the database row is authoritative; deleting the
  Redis key is best-effort. `logout_session` is shared with
  `DELETE /api/v1/admin/sessions/{id}`, whose `403`/`404`/`204` responses are
  unchanged; admin revocation gains the same row lock and best-effort cache
  eviction.
- Redis outage: the refresh endpoint does not perform the access-token Redis
  `exists` check, so an access-cache outage cannot block durable revocation. A
  Redis `delete` failure is swallowed after the database commit.
- Trade-off: any still-valid older refresh JWT for a session can force that
  session to log out (self-denial of service). It cannot mint tokens, cannot
  authenticate a protected endpoint, and cannot revoke a different session.
- Privacy: the refresh token is accepted only in the request body, is never
  echoed and is never written to the audit row; `logout` still records only
  `session_id` with the user UUID, and denial details stay generic. Unknown
  body fields are ignored before validation, so a token sent as an extra JSON
  *field name* is not reflected, and a malformed `refresh_token` value reports
  only the `body.refresh_token` location. Other routes keep their existing
  validation behavior.
- Regressions: expired-access plus refresh-endpoint logout (`204`, then `/me`
  and `/refresh` `401`); a rotated-away refresh token revokes its own session
  while a sibling session survives; a refresh token is rejected as a Bearer
  credential; an access token is rejected in the refresh field; expired,
  missing-exp, malformed-exp, wrong-type, unknown-`sid` and wrong-subject
  tokens are rejected without revoking anything; idempotent repeat; database
  revocation retained when the Redis delete raises; an access-cache `exists`
  outage does not block the refresh endpoint; missing, non-object and malformed
  bodies and a missing field return `422`; a malformed `refresh_token` value
  returns `422` without echoing the token; a token used as an extra field name
  is ignored and never reflected; the original logout route still accepts any
  body with a valid Bearer, still ignores a refresh body without a Bearer, and
  keeps its `204`/`401` behavior; and two deterministic PostgreSQL races where
  logout queues on `FOR UPDATE` behind an in-flight refresh, for both the
  refresh-endpoint and access-token paths. Full suite 276 passed on a fresh
  database and a fresh isolated Redis database; Ruff, Mypy (39 files) and
  `git diff --check` are clean.

## 2026-11-07: Blocking an account left its sessions alive

- `PATCH /api/v1/admin/users/{id}/block` only flipped `is_active`; it did not
  revoke the target's `UserSession` rows or Redis `session:{sid}` keys. Access
  tokens were rejected while the account stayed blocked (the per-request active
  check), but unblocking silently revived every session issued before the block.
  The endpoint also took no user-row lock, so a login, OAuth callback or 2FA
  completion committing between the block read and update could create a session
  that the block never saw.
- Blocking now locks the user row, sets the account inactive and revokes all of
  its sessions. The `User.is_active` update and every `UserSession.revoked_at`
  write commit together; Redis `session:{sid}` deletion is best-effort cache
  cleanup, and the DB row is authoritative if eviction fails. A concurrent
  issuance waits on the same row lock and either fails on the inactive account
  or has its session revoked. `PATCH /api/v1/users/{id}` with `is_active: false`
  follows the same rule.
- Unblocking and reactivation also revoke every remaining session, including for
  accounts that were already inactive before this fix or were deactivated out of
  band. Without that, the per-request active check would let a pre-existing
  session revive the moment `is_active` flipped back to true. Neither path
  recreates sessions; the user must sign in again. Active -> active calls stay a
  no-op and do not revoke anything.
- Regressions: block then unblock leaves the pre-block access token at 401 while
  a fresh login works; the equivalent `is_active` PATCH covers the second
  deactivation path. A directly seeded inactive account with a live session is
  rejected after both reactivation endpoints, and the login-vs-block race test
  proves the block request actually waits for the user-row lock.

## 2026-11-01: Authentication audit rows stored plaintext addresses

- Registration and OAuth callbacks wrote the account address into
  `audit_logs.details`, and failed password logins wrote the submitted address.
  New rows no longer carry it: register drops the key (the user UUID remains),
  OAuth keeps only the provider, and failed logins record the existing keyed,
  normalized subject (`hmac_sha256(lower(email), JWT_SECRET_KEY)`), so casing
  variants of one account correlate while no plaintext is stored.
- Scope is new writes only. Rows written before this change are not rewritten:
  scrubbing them needs a separate migration with backup and rollback, so it is
  deliberately out of scope. IP address and user agent are retained by design.
- Regressions: register and OAuth audit details contain no address and no `@`,
  failed-login subjects match for `A@Example.com` and `a@example.com`, and the
  401 response never echoes the attempted address.

## 2026-11-01: 2FA state changes left sessions alive; enrollment lacked step-up

- Enabling or disabling TOTP committed the factor change without revoking the
  user's other sessions, so a session created before the change survived it.
  Both endpoints now hold the user row lock, revalidate the caller's own session
  after acquiring it, reject a row that became inactive while waiting, revoke
  every other session in the same transaction, and keep the calling session.
- Backup-code login committed the consumed code before issuing tokens, releasing
  the user row lock early; a concurrent 2FA change could then be followed by a
  new session. The lock is now held through issuance, and the consumed code and
  the session row commit together.
- The OAuth callback read `is_active`/`totp_enabled` from a cached instance after
  linking had committed, then wrote an audit row (which commits) before issuing.
  It now re-reads the user under the row lock, evaluates policy on that instance,
  and issues before auditing.
- Enrolling 2FA required only a bearer token, so a stolen access token could add
  an authenticator and lock the owner out. Setup and verify now require
  `current_password`, checked with the existing bcrypt helper under the same user
  lock, bounded by five shared step-up attempts per account per minute before
  bcrypt and before the lock. Missing, wrong, oversized, malformed-Unicode and
  OAuth-only (no local password) input is denied generically without echoing the
  value; failures revoke nothing. An explicit OAuth re-authentication flow is
  still open, so OAuth-only accounts cannot enroll yet.
- Regressions: session revocation on enable/disable, caller retention, no
  revocation on failure, backup-code rollback, OAuth deactivation between link
  and issuance, stolen bearer without password, shared limiter with 429
  Retry-After, OAuth-only denial, escaped-surrogate password, and the fresh
  inactive guard. Full suite 231 passed; Ruff and Mypy pass. A pristine
  `116ffdb` control fails thirteen of these cases, so the tests discriminate the
  old behaviour.

## 2026-10-12: Validation diagnostics echoed authentication payloads

A registration request without username returned HTTP 422 containing the whole
request body, including its password. The default RequestValidationError handler
serialized Pydantic input/context diagnostics. Sanitize those two fields globally
while retaining the existing 422 status and detail/type/loc/msg structure.
Four regressions cover incomplete registration/login/2FA and malformed refresh
payloads; synthetic markers must never appear in the response.

## 2026-10-09: Registration race and audit responsiveness

- Concurrent registration passed the email pre-check twice, then returned 500
  on the unique constraint. Roll back and translate only a confirmed duplicate
  email to the existing conflict response; unrelated integrity errors still fail.
- Synchronous audit commits ran on the async event loop. Run the whole audit
  session lifecycle in a threadpool. A real 300 ms PostgreSQL lock delayed a
  20 ms callback by 302.6 ms before and 26.8 ms after the fix.
- `tests/test_concurrency_regressions.py`: two real PostgreSQL regressions pass;
  complete suite 192 passed, Ruff/Mypy and Alembic schema check pass.
- Current installed-environment pip-audit found no known advisories; real
  backup-code login/login, login/disable and disable/disable races passed.
  Older open-work lists below describe their dated checkpoints.

## 2026-10-03: Authentication verification

| Symptom | Root cause | Fix | Regression evidence |
| --- | --- | --- | --- |
| Missing-session JWT authenticated | Session existence check was conditional on `sid` | Reject missing session claim | `test_access_token_requires_session_claim` |
| Unexpected registration fields accepted | Default Pydantic extra-field policy | Forbid extra fields | `test_registration_cannot_assign_admin_role` |
| Tests could contact the regular database | Audit middleware used its own session factory; settings aliases were ignored | Bind audit to test transaction; use explicit aliases and real PostgreSQL/Redis | `test_http_audit_is_written_to_test_database` |
| Enabled TOTP reset through setup | Setup unconditionally cleared `totp_enabled` | Reject setup/verify while enabled | `test_enabled_twofa_cannot_be_reset_with_access_token` |
| Repeated 2FA login challenge accepted | Temp JWT lacked tracked one-use state | Redis challenge with atomic consumption | `test_twofa_login_requires_code_and_temp_token_is_single_use` |
| Unlimited 2FA attempts | No second-step limiter | Per-user 2FA limiter | `test_twofa_login_is_rate_limited` |
| TOTP replay with whitespace accepted | Validation normalized input; replay key did not | Normalize once and hash replay key | `test_totp_replay_cannot_bypass_guard_with_whitespace` |
| OAuth bypassed TOTP and issued blocked-account sessions | Callback did not enforce local account policy | Challenge TOTP users; reject inactive users | `test_oauth_respects_twofa_and_account_block` |
| OAuth callback accepted state from another browser | Global Redis state without browser binding | HttpOnly cookie plus atomic state consumption | `test_oauth_state_cannot_be_used_without_browser_cookie` |
| Forwarded headers bypassed login limiter | Directly trusted arbitrary X-Forwarded-For | Use request client address | `test_forwarded_header_cannot_bypass_login_rate_limit` |
| Admin could reset superadmin credentials or revoke its session | Only actor role checked | Reject mutations of higher-role targets | `test_admin_cannot_mutate_superadmin`, `test_admin_cannot_revoke_superadmin_session` |
| Role changes returned 500 | `role_rank` received User instead of UserRole | Pass actor.role | `test_role_change_requires_superadmin` |
| User response validation failed | UUID returned for string schema | Normalize output UUID | `test_users_api_serializes_uuid_ids` |
| ORM/migration drift | Enum length and email unique-index representation differed | Align ORM with existing schema | `alembic check` |
| Password truncation and bcrypt backend warning | passlib bcrypt adapter plus unrestricted byte length | Use existing bcrypt directly; enforce byte limit | `test_registration_rejects_password_beyond_bcrypt_byte_limit` |
| Concurrent refresh issued two token pairs | Session hash read/check/write lacked a row lock | Lock session before hash validation | `python -m scripts.verify_refresh_concurrency --database-race` reproduced two successes before the fix |

The verification stack's API now has a healthcheck; Compose `--wait` previously
returned before the HTTP process finished startup. Do not rebuild/recreate test
infrastructure while pytest is running: a previous run lost a connection during recreation.

## Open verification work

- Live Google/GitHub/Yandex flows and provider error paths; automated callback tests use a provider double.
- Backup-code concurrency across login and disable paths. Login now locks the user row; a concurrent acceptance check remains.
- Dependency audit reported advisories in six direct pinned packages. Duplicate advisory rows are not unique findings; transitive dependencies were not covered by that command.
- Public-deployment configuration, default secrets, exposed infrastructure ports and non-root image policy.
# Pause addendum — 2026-10-03

Verified additional defects and fixes:

- Disable-2FA had unlimited attempts and accepted TOTP already used for login.
  Added shared per-user limiter, normalized TOTP replay guard and row-lock reload.
  Regressions: `test_twofa_disable_is_rate_limited`,
  `test_twofa_disable_rejects_totp_used_for_login`; three real HTTP backup-code races pass.
- Split Redis limiter read/write admitted two concurrent requests with limit one.
  Atomic Lua admission fixes `test_concurrent_requests_cannot_exceed_rate_limit`.
- OAuth exchange ignored the supplied HTTP client; profile/token validation accepted
  unverified/malformed identities. Real HTTP-boundary adapter/failure tests reproduce
  and verify fixes in `tests/test_oauth_providers.py` and `tests/test_oauth_http.py`.
- Missing/weak/default JWT secret was accepted. Configuration now rejects it and
  hides validation inputs; `tests/test_config.py` passes. Explicit JWT secret required.
- Non-ASCII state and non-object/corrupt Redis state metadata caused callback 500s.
  ASCII/type validation now returns 400; six new state cases pass.
- Direct dependency warnings and transitive Starlette warnings were removed through
  targeted security version updates; installed-environment audit reports no known vulnerabilities.

Paused before full-suite rerun after final OAuth-state changes. Last complete suite
122 passed; latest Ruff has one E501 in `tests/test_oauth.py:207`; Mypy passes.
Current built image predates final OAuth-state fix. See NexusCore pause checkpoint.

## Final resume — 2026-10-04

The pause status above is historical. Final OAuth-state cases are included in
the complete run: 128 passed, one upstream warning, 220.24s. Ruff passes; Mypy
passes for 35 files. The latest image includes the state fix and runs as UID10001;
`.env/.git/.venv` exclusion assertions pass. Real auth, refresh concurrency and
three 2FA backup-code races pass. Installed-environment pip-audit reports no known
vulnerabilities. Real provider browser login, tenant modeling and public deployment
remain unverified. See NexusCore final verification report for commands.
