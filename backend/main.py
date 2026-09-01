"""
DNSentinel -- FastAPI application entry point.

Run with:
    uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

Then just open http://localhost:8000/ -- it redirects straight into the
single-page frontend (frontend/index.html), which has all views
(Analyzer, Dashboard, Alerts, Domains, Investigation) behind one URL
with client-side tab navigation. No more separate page URLs to remember.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
import os

from backend.api import (
    alert_routes, auth_routes, dashboard_routes, dns_routes, pcap_routes, threat_routes,
)
from backend.core.config import settings
from backend.database.database import init_db

app = FastAPI(
    title="DNSentinel",
    description="AI-Powered DNS Threat Intelligence & Security Gateway (SIH260003)",
    version="0.1.0",
)

# CORS: open for the hackathon demo (frontend is served separately as static files)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(dns_routes.router)
app.include_router(threat_routes.router)
app.include_router(dashboard_routes.router)
app.include_router(auth_routes.router)
app.include_router(pcap_routes.router)
app.include_router(alert_routes.router)

FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.isdir(FRONTEND_DIR):
    app.mount("/app", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")


@app.on_event("startup")
def on_startup():
    init_db()


@app.get("/")
def root():
    """Redirect straight into the single-page app -- one URL for everything."""
    return RedirectResponse(url="/app/index.html")


@app.get("/api")
def api_info():
    return {"service": settings.app_name, "status": "running", "docs": "/docs"}


@app.get("/health")
def health():
    return {"status": "ok"}
