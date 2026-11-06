from typing import Optional
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, status
from app.core.event_bus import event_bus
from app.core.security import decode_token
from app.core.config import settings

router = APIRouter(tags=["WebSocket Realtime"])

@router.websocket("/ws")
@router.websocket("/ws/events")
async def websocket_endpoint(websocket: WebSocket, token: Optional[str] = Query(None)):
    """
    Subscribes connected admin dashboards and security consoles to live
    real-time event broadcasts (Threat alerts, Multi-device campaigns, Blocklist updates).
    Validates authentication token to prevent unauthorized eavesdropping.
    """
    if token:
        try:
            decode_token(token)
        except Exception:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
    elif settings.ENVIRONMENT == "production":
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await event_bus.connect(websocket)
    try:
        while True:
            # Keep-alive ping/pong
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text('{"event": "pong"}')
    except WebSocketDisconnect:
        await event_bus.disconnect(websocket)
    except Exception:
        await event_bus.disconnect(websocket)

