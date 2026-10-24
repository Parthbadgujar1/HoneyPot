"""HTTP decoy: the public-facing fake web application.

Every request is logged with method, path, headers and a body preview.
Responses come from the deception policy, so the attacker sees fake login
pages, a fake .env file with honeytokens and fake API data. Nothing is
proxied and nothing on the sensor is reachable through it.
"""

from __future__ import annotations

import time

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from ..deception import DecoyPolicy
from ..events import CONNECTION, HTTP, Event
from .common import EmitFn, flow_detail

MAX_BODY_BYTES = 8192
METHODS = ["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]


async def _read_limited(request: Request) -> bytes:
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > MAX_BODY_BYTES:
            chunks.append(chunk[: MAX_BODY_BYTES - (total - len(chunk))])
            break
        chunks.append(chunk)
    return b"".join(chunks)


def build_app(config: dict, emit: EmitFn, decoys: DecoyPolicy) -> Starlette:
    http_port = int(config["decoys"]["http"]["port"])

    async def handle(request: Request) -> Response:
        started = time.time()
        client = request.client.host if request.client else "0.0.0.0"
        body = await _read_limited(request)
        body_text = body.decode("utf-8", errors="replace")

        path = request.url.path
        query = request.url.query
        decision = decoys.http_response(request.method, path, client, body_text)

        response = Response(
            content=b"" if request.method == "HEAD" else decision["body"],
            status_code=decision["status"],
            headers=decision["headers"],
            media_type=decision["content_type"],
        )

        request_line = f"{request.method} {path}"
        if query:
            request_line += f"?{query}"
        raw_headers = "\r\n".join(f"{k}: {v}" for k, v in request.headers.items())
        raw = f"{request_line} HTTP/1.1\r\n{raw_headers}\r\n\r\n{body_text}"[:4096]
        ended = time.time()

        emit(Event(
            kind=HTTP,
            src_ip=client,
            dst_port=http_port,
            service="http",
            ts=started,
            detail={
                "method": request.method,
                "path": path,
                "query": query[:512],
                "status": decision["status"],
                "user_agent": request.headers.get("user-agent", "")[:300],
                "host": request.headers.get("host", "")[:200],
                "referer": request.headers.get("referer", "")[:300],
                "body_preview": body_text[:512],
                "raw": raw,
            },
        ))

        emit(Event(
            kind=CONNECTION,
            src_ip=client,
            dst_port=http_port,
            service="http",
            ts=started,
            detail=flow_detail(
                started=started,
                ended=ended,
                chunk_sizes=[len(raw)],
                bytes_out=len(decision["body"]),
                writes_out=1,
                graceful=True,
                reset=False,
                end_reason="http_response",
                # Web requests are judged by HTTP_ENDPOINT_PROBING, not by
                # the protocol fingerprint rule, so no signature is set.
                extra={"http_requests": 1},
            ),
        ))
        return response

    routes = [
        Route("/", handle, methods=METHODS),
        Route("/{path:path}", handle, methods=METHODS),
    ]
    return Starlette(routes=routes)
