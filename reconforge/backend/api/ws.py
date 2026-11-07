"""WebSocket endpoint for real-time scan progress streaming."""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)
router = APIRouter()

# Global connection registry: scan_id -> set of websockets
_connections: dict[int, set[WebSocket]] = {}
_lock = asyncio.Lock()


async def register(scan_id: int, ws: WebSocket) -> None:
    async with _lock:
        _connections.setdefault(scan_id, set()).add(ws)


async def unregister(scan_id: int, ws: WebSocket) -> None:
    async with _lock:
        conns = _connections.get(scan_id)
        if conns:
            conns.discard(ws)
            if not conns:
                del _connections[scan_id]


async def broadcast(scan_id: int, data: dict[str, Any]) -> None:
    """Called by the scan engine to push progress to all listeners."""
    async with _lock:
        conns = _connections.get(scan_id, set()).copy()
    dead: list[WebSocket] = []
    payload = json.dumps(data)
    for ws in conns:
        try:
            await ws.send_text(payload)
        except Exception:
            dead.append(ws)
    for ws in dead:
        await unregister(scan_id, ws)


async def progress_callback_for(scan_id: int):
    """Return a callback the ScanEngine can await to push updates."""
    async def _cb(data: dict[str, Any]) -> None:
        await broadcast(scan_id, data)
    return _cb


@router.websocket("/ws/scan/{scan_id}")
async def scan_ws(websocket: WebSocket, scan_id: int):
    await websocket.accept()
    await register(scan_id, websocket)
    try:
        while True:
            # Keep connection alive; client can send pings or commands
            msg = await websocket.receive_text()
            if msg == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        await unregister(scan_id, websocket)
