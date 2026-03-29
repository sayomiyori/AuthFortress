from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, generate_latest

auth_login_total = Counter(
    "auth_login_total",
    "Login attempts",
    ("method", "status"),
)

auth_register_total = Counter(
    "auth_register_total",
    "Registrations",
)

rate_limit_exceeded_total = Counter(
    "rate_limit_exceeded_total",
    "Rate limit hits",
    ("route",),
)

active_sessions_gauge = Gauge(
    "active_sessions_total",
    "Active (non-revoked) sessions in DB",
)

totp_setup_total = Counter(
    "totp_setup_total",
    "TOTP setup completions",
    ("status",),
)


def metrics_response_body() -> tuple[bytes, str]:
    return generate_latest(), CONTENT_TYPE_LATEST
