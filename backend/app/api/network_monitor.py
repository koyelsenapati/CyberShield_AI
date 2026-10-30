"""
CyberShield AI
Network Monitor API
"""

import asyncio
import json

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect, status

from app.api.dependencies import get_current_user

from app.core.jwt import verify_access_token
from app.services.network_monitor_service import get_network_snapshot
from app.services.network_telemetry import get_network_telemetry

router = APIRouter(
    tags=["Network Monitor"]
)

@router.get("/network/statistics")
def network_statistics(current_user=Depends(get_current_user)):
    """
    Return the current real-time network monitoring snapshot.

    Requires authentication: the snapshot describes the host's live
    network activity.
    """
    return get_network_snapshot()

@router.websocket("/ws/network")
async def network_monitor(
    websocket: WebSocket,
    token: str = None,
):
    # Authenticate WebSocket connection via token query param
    if not token:
        await websocket.close(
            code=status.WS_1008_POLICY_VIOLATION,
            reason="Missing authentication token",
        )
        return

    payload = verify_access_token(token)

    if not payload or not payload.get("sub"):
        await websocket.close(
            code=status.WS_1008_POLICY_VIOLATION,
            reason="Invalid authentication token",
        )
        return

    await websocket.accept()

    try:
        while True:
            telemetry = get_network_telemetry()

            await websocket.send_text(
                json.dumps(telemetry)
            )

            await asyncio.sleep(2)

    except WebSocketDisconnect:
        print("Network WebSocket client disconnected")

    except Exception as exc:
        print(f"Network WebSocket error: {exc}")
