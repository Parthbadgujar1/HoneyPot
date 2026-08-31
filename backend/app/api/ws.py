"""WebSocket endpoint for live telemetry streaming."""

import asyncio

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect

from app.security.auth import decode_token
from app.websocket.bus import event_bus

router = APIRouter()


@router.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket, token: str = Query(..., alias="token")
):
    # Require a valid access token before accepting the connection.
    try:
        decode_token(token)
    except Exception:
        await websocket.close(code=4401)
        return

    await websocket.accept()
    loop = asyncio.get_event_loop()
    sub = event_bus.subscribe(loop)
    try:
        # replay recent history
        for ev in event_bus.history(limit=100):
            try:
                await websocket.send_json(ev)
            except Exception:
                break
        while True:
            try:
                event = await asyncio.wait_for(sub.queue.get(), timeout=30)
                await websocket.send_json(event)
            except asyncio.TimeoutError:
                await websocket.send_json({"kind": "ping"})
            except Exception:
                break
    except WebSocketDisconnect:
        pass
    finally:
        event_bus.unsubscribe(sub)
