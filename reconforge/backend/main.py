"""ReconForge FastAPI application — entry point."""
from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from backend.config import settings
from backend.database import init_db

logging.basicConfig(
    level=logging.DEBUG if settings.debug else logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s  %(message)s",
)
logger = logging.getLogger("reconforge")

app = FastAPI(
    title="ReconForge",
    description="Universal OSINT & Static Analysis Engine",
    version="1.0.0",
)

# ── CORS ─────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ──────────────────────────────────────────────────────────────
from backend.api.scans import router as scans_router      # noqa: E402
from backend.api.findings import router as findings_router  # noqa: E402
from backend.api.reports import router as reports_router    # noqa: E402
from backend.api.dashboard import router as dashboard_router  # noqa: E402
from backend.api.ws import router as ws_router              # noqa: E402
from backend.api.results import router as results_router    # noqa: E402

app.include_router(scans_router)
app.include_router(findings_router)
app.include_router(reports_router)
app.include_router(results_router)
app.include_router(dashboard_router)
app.include_router(ws_router)


# ── Health ───────────────────────────────────────────────────────────────
@app.get("/api/health")
def health():
    return {"status": "ok", "version": "1.0.0"}


# ── Startup ──────────────────────────────────────────────────────────────
@app.on_event("startup")
def on_startup():
    logger.info("Initializing database...")
    init_db()
    settings.ensure_dirs()
    logger.info("ReconForge ready on %s:%s", settings.host, settings.port)


# ── Static file serving (frontend SPA) ──────────────────────────────────
FRONTEND_DIST = Path(__file__).parent.parent / "frontend" / "dist"

if FRONTEND_DIST.exists():
    app.mount("/assets", StaticFiles(directory=str(FRONTEND_DIST / "assets")), name="static-assets")

    @app.get("/{full_path:path}")
    async def spa_fallback(request: Request, full_path: str):
        # Serve actual files if they exist
        file_path = FRONTEND_DIST / full_path
        if full_path and file_path.exists() and file_path.is_file():
            return FileResponse(str(file_path))
        # SPA fallback — return index.html for all non-API routes
        index = FRONTEND_DIST / "index.html"
        if index.exists():
            return FileResponse(str(index))
        return JSONResponse({"error": "Frontend not built. Run: cd frontend && npm run build"}, 404)


# ── Uvicorn entry ────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "backend.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        workers=1 if settings.debug else settings.workers,
        log_level="debug" if settings.debug else "info",
    )
