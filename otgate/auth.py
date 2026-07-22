"""Bearer-token authentication for otgate's HTTP transport.

otgate runs two separate HTTP channels — one for the agent, one for the human
operator — each guarded by its own token. This is the mechanism that stops an
agent from calling ``approve`` on its own writes: the operator tools live behind
a token the agent does not hold, on a different endpoint.

:class:`BearerAuthMiddleware` is a small ASGI middleware wrapped around the
FastMCP Starlette app. It checks ``Authorization: Bearer <token>`` on every
request and returns ``401`` otherwise. Token comparison is constant-time to
avoid leaking the token via timing.

This is transport-level auth, deliberately simple. It does **not** replace
network isolation: the OPC UA server must still be reachable only by the otgate
process (see the deployment notes in the README), otherwise an attacker can skip
the gateway entirely.
"""

from __future__ import annotations

import hmac

from starlette.types import ASGIApp, Receive, Scope, Send


class BearerAuthMiddleware:
    """ASGI middleware enforcing a single Bearer token on all HTTP requests.

    Args:
        app: the wrapped ASGI application.
        token: the expected bearer token. Must be non-empty.
        realm: label used in the ``WWW-Authenticate`` header and errors.

    Raises:
        ValueError: if ``token`` is empty (refusing to run an unauthenticated
            channel by accident — fail closed at construction).
    """

    def __init__(
        self,
        app: ASGIApp,
        token: str,
        realm: str = "otgate",
        open_paths: tuple[str, ...] = ("/health",),
    ) -> None:
        if not token:
            raise ValueError(
                f"refusing to start {realm} channel with an empty token "
                "(set the corresponding OTGATE_*_TOKEN)"
            )
        self._app = app
        self._token = token
        self._realm = realm
        # Paths served without auth (liveness probes). They must expose only
        # non-sensitive status, never tag data.
        self._open_paths = open_paths

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        # Only HTTP requests carry auth; pass lifespan/other events straight
        # through so startup/shutdown still work.
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        if scope.get("path") in self._open_paths or self._authorized(scope):
            await self._app(scope, receive, send)
            return

        await self._unauthorized(send)

    def _authorized(self, scope: Scope) -> bool:
        header = _get_header(scope, b"authorization")
        if header is None:
            return False
        prefix = "Bearer "
        if not header.startswith(prefix):
            return False
        presented = header[len(prefix):].strip()
        # Constant-time comparison to avoid timing side channels.
        return hmac.compare_digest(presented, self._token)

    async def _unauthorized(self, send: Send) -> None:
        body = b'{"error": "unauthorized"}'
        await send(
            {
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"www-authenticate", f'Bearer realm="{self._realm}"'.encode()),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


def _get_header(scope: Scope, name: bytes) -> str | None:
    """Return a request header value (decoded) or None. ``name`` must be lower-case."""
    for key, value in scope.get("headers", []):
        if key == name:
            return value.decode("latin-1")
    return None
