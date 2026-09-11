"""FastAPI application: authenticated REST + SSE, compiled UI served as static files."""
from __future__ import annotations

import asyncio
import json
import logging
import pathlib
import threading
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from sih_api.auth import COOKIE, AuthStore, Session
from sih_api.live import LiveHub, consume_forever
from sih_api.queries import Queries, reader
from sih_common import env
from sih_common.chttp import ClickHouseError

log = logging.getLogger("api")

Severity = Literal["", "info", "low", "medium", "high", "critical"]
ThreatClass = Literal["", "ddos", "beaconing", "dga", "dns_tunnel", "encrypted_malware_like", "scan", "exfiltration"]
Status = Literal["", "new", "updated", "escalated", "resolved"]

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                               "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Cache-Control": "no-store",
}

DISCLAIMER = ("Offline simulation. Docker networking models one-way export semantics only; it is not a hardware diode "
              "and a compromised host could bypass it. Single-host deployment: no high availability. Detection is "
              "passive and intelligence-only; no payloads are decrypted.")


class LoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


def create_app(auth: AuthStore | None = None, queries: Queries | None = None, hub: LiveHub | None = None,
               start_consumer: bool = True, ui_dir: str | None = None) -> FastAPI:
    stop = threading.Event()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.hub.loop = asyncio.get_running_loop()
        if start_consumer:
            threading.Thread(target=consume_forever, args=(app.state.hub, env.env_str("KAFKA_BOOTSTRAP", "redpanda:9092"), stop),
                             name="live-consumer", daemon=True).start()
        yield
        stop.set()

    app = FastAPI(title="SIH SOC API", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.auth = auth or AuthStore.from_env()
    app.state.queries = queries or Queries(reader())
    app.state.hub = hub or LiveHub()
    secure_cookie = env.env_bool("API_COOKIE_SECURE", False)

    @app.middleware("http")
    async def headers(request: Request, call_next):
        resp = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            resp.headers.setdefault(k, v)
        return resp

    def session(request: Request) -> Session:
        s = app.state.auth.session(request.cookies.get(COOKIE))
        if s is None:
            raise HTTPException(401, "authentication required")
        return s

    def admin(s: Session = Depends(session)) -> Session:
        if s.role != "admin":
            raise HTTPException(403, "admin role required")
        return s

    def csrf(request: Request) -> None:
        if request.headers.get("x-requested-with") != "sih-ui":
            raise HTTPException(403, "missing X-Requested-With header")

    def history(fn):
        try:
            return fn()
        except ClickHouseError as e:
            log.warning("history unavailable: %s", e)
            return JSONResponse({"stale": True, "reason": "history store unavailable"}, status_code=503)

    @app.get("/api/health")
    def health():
        return {"status": "alive"}

    @app.get("/api/ready")
    def ready():
        hub = app.state.hub
        ch_ok = app.state.queries.ch.ping()
        status = "ready" if ch_ok and hub.consumer_ok else "degraded"
        return {"status": status, "history_store": "ok" if ch_ok else "unavailable",
                "live_stream": "ok" if hub.consumer_ok else "reconnecting"}

    @app.post("/api/login")
    def login(body: LoginBody, request: Request, response: Response, _=Depends(csrf)):
        res = app.state.auth.login(body.username, body.password, request.client.host if request.client else "?")
        if res is None:
            raise HTTPException(401, "invalid credentials")
        token, s = res
        response.set_cookie(COOKIE, token, httponly=True, samesite="strict", secure=secure_cookie, path="/")
        return {"user": s.user, "role": s.role}

    @app.post("/api/logout")
    def logout(request: Request, response: Response, _=Depends(csrf)):
        app.state.auth.logout(request.cookies.get(COOKIE))
        response.delete_cookie(COOKIE, path="/")
        return {"ok": True}

    @app.get("/api/me")
    def me(s: Session = Depends(session)):
        return {"user": s.user, "role": s.role, "disclaimer": DISCLAIMER}

    @app.get("/api/incidents")
    def incidents(s: Session = Depends(session), since_minutes: int = Query(1440, ge=1, le=129600),
                  severity: Severity = "", threat_class: ThreatClass = "", status: Status = "",
                  q: str = Query("", max_length=128), limit: int = Query(200, ge=1, le=1000)):
        return history(lambda: {"items": app.state.queries.incidents(since_minutes, severity, threat_class, status, q, limit)})

    @app.get("/api/incidents/{incident_id}")
    def incident(incident_id: str, s: Session = Depends(session)):
        if len(incident_id) != 36 or any(c not in "0123456789abcdef-" for c in incident_id):
            raise HTTPException(400, "invalid incident id")

        def load():
            d = app.state.queries.incident(incident_id)
            if d is None:
                raise HTTPException(404, "incident not found")
            return d
        return history(load)

    @app.get("/api/stats")
    def stats(s: Session = Depends(session), window_minutes: int = Query(60, ge=5, le=10080)):
        def load():
            d = app.state.queries.stats(window_minutes)
            d["api_visible_latency"] = {"definition": "API arrival minus receiver arrival of the evidence (this API process only)",
                                        **app.state.hub.latency_summary()}
            return d
        return history(load)

    @app.get("/api/quarantine")
    def quarantine(s: Session = Depends(admin), limit: int = Query(100, ge=1, le=1000)):
        app.state.auth.audit("quarantine_read", s.user, limit=limit)
        return history(lambda: {"items": app.state.queries.quarantine(limit)})

    @app.get("/api/stream")
    async def stream(request: Request, s: Session = Depends(session)):
        hub: LiveHub = app.state.hub
        last = request.headers.get("last-event-id") or request.query_params.get("last_event_id")
        backlog, resync = hub.backlog_after(last)
        q = hub.subscribe()

        async def events():
            try:
                if resync:
                    yield "event: resync\ndata: {}\n\n"
                for seq, raw in backlog:
                    yield f"id: {hub.nonce}-{seq}\nevent: alert\ndata: {raw}\n\n"
                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        item = await asyncio.wait_for(q.get(), timeout=15)
                    except asyncio.TimeoutError:
                        yield ": keepalive\n\n"
                        continue
                    if item is None:
                        yield "event: resync\ndata: {\"reason\": \"slow_client\"}\n\n"
                        break
                    seq, raw = item
                    yield f"id: {hub.nonce}-{seq}\nevent: alert\ndata: {raw}\n\n"
            finally:
                hub.unsubscribe(q)

        return StreamingResponse(events(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})

    ui = pathlib.Path(ui_dir or env.env_str("UI_DIR", "/app/ui"))
    if ui.is_dir():
        app.mount("/", StaticFiles(directory=str(ui), html=True), name="ui")
    return app


def json_dumps(obj) -> str:
    return json.dumps(obj, separators=(",", ":"))
