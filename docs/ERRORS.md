# Verified Defects and Regression Checks

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
