"""Security Headers & Anti-Caching Middleware.

Enforces zero-trust HTTP response security headers, prevents sensitive prompt/completion
caching in intermediate proxy servers, and strips server disclosure headers.
"""

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """ASGI Middleware injecting strict security headers and anti-caching directives."""

    DEFAULT_SECURITY_HEADERS = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none';",
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0",
        "Pragma": "no-cache",
        "Expires": "0",
        "Permissions-Policy": "geolocation=(), camera=(), microphone=(), payment=()",
    }

    HEADERS_TO_REMOVE = ["server", "x-powered-by"]

    def __init__(self, app, custom_headers=None):
        super().__init__(app)
        self.headers = dict(self.DEFAULT_SECURITY_HEADERS)
        if custom_headers:
            self.headers.update(custom_headers)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)

        # Apply security headers
        for header_name, header_value in self.headers.items():
            response.headers[header_name] = header_value

        # Strip info disclosure headers
        for h in self.HEADERS_TO_REMOVE:
            if h in response.headers:
                del response.headers[h]

        return response
