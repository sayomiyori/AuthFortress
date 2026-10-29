from app.api.v1.auth import _client_ip
from starlette.requests import Request


def test_client_ip_ignores_forwarded_headers():
    request = Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/api/v1/auth/login",
            "raw_path": b"/api/v1/auth/login",
            "query_string": b"",
            "headers": [(b"x-forwarded-for", b"198.51.100.7")],
            "client": ("127.0.0.1", 12345),
            "server": ("testserver", 80),
        }
    )
    assert _client_ip(request) == "127.0.0.1"
