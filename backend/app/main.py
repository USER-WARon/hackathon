from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from app.api.approvals import router as approvals_router
from app.api.chat import router as chat_router
from app.api.events import EventHub
from app.api.integrations import router as integrations_router
from app.config import DB_PATH, FRONTEND_ORIGIN, PRODUCTION_DB_PATH
from app.database import ensure_production_demo_db, initialize_database
from app.mcp_server import github_reader, production_database, weather_api
from app.security.approvals import ApprovalManager
from app.security.audit import AuditLogger
from app.security.interceptor import ShadowGuardInterceptor
from app.security.ml_models import get_ml_models
from app.security.registry import TrustRegistry
from app.security.shadow_state import ShadowStateManager
from app.security.taint import TaintEngine


def configure_app_state(app: FastAPI):
    initialize_database(str(DB_PATH))
    ensure_production_demo_db()
    ml_models = get_ml_models()
    app.state.db_path = str(DB_PATH)
    app.state.production_db_path = str(PRODUCTION_DB_PATH)
    app.state.event_hub = EventHub()
    app.state.ml_models = ml_models
    app.state.trust_registry = TrustRegistry(str(DB_PATH), ml_models=ml_models)
    app.state.taint_engine = TaintEngine(str(DB_PATH))
    app.state.audit_logger = AuditLogger(str(DB_PATH))
    app.state.shadow_state = ShadowStateManager(str(PRODUCTION_DB_PATH))
    app.state.approval_manager = ApprovalManager(str(DB_PATH))
    app.state.raw_tools = {
        'github_reader': github_reader,
        'weather_api': weather_api,
        'production_database': lambda sql: production_database(sql, _guarded=True),
    }
    app.state.interceptor = ShadowGuardInterceptor(
        db_path=str(DB_PATH),
        trust_registry=app.state.trust_registry,
        taint_engine=app.state.taint_engine,
        shadow_state=app.state.shadow_state,
        approval_manager=app.state.approval_manager,
        audit_logger=app.state.audit_logger,
        event_hub=app.state.event_hub,
        raw_tools=app.state.raw_tools,
        ml_models=ml_models,
    )
    app.state.app_state = {
        'db_path': str(DB_PATH),
        'production_db_path': str(PRODUCTION_DB_PATH),
        'event_hub': app.state.event_hub,
        'trust_registry': app.state.trust_registry,
        'taint_engine': app.state.taint_engine,
        'approval_manager': app.state.approval_manager,
        'interceptor': app.state.interceptor,
        'raw_tools': app.state.raw_tools,
        'ml_models': ml_models,
    }


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_app_state(app)
    yield


app = FastAPI(title='ShadowGuard AI', lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_ORIGIN, 'http://localhost:5173', 'http://127.0.0.1:5173'],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)

app.include_router(chat_router)
app.include_router(integrations_router)
app.include_router(approvals_router)


@app.get('/api/health')
def health_check():
    return {'status': 'ok', 'service': 'shadowguard-ai'}


@app.get('/api/security/events')
def security_events():
    return {'events': app.state.event_hub.get_recent(50)}


@app.get('/api/trace/{request_id}')
def get_trace(request_id: str):
    """Return the full correlated audit trace for a single request_id."""
    return {'request_id': request_id, 'events': app.state.audit_logger.get_trace(request_id)}


@app.get('/api/trace')
def list_traces(session_id: str | None = None, limit: int = 20):
    """Return recent request IDs, optionally filtered by session."""
    if session_id:
        request_ids = app.state.audit_logger.get_request_ids(session_id, limit)
    else:
        request_ids = []
    return {'request_ids': request_ids, 'session_id': session_id}


@app.post('/api/demo/scenario-a')
def scenario_a():
    session_id = app.state.taint_engine.get_or_create_session(None, 'demo-user')
    app.state.interceptor.execute('github_reader', {'repo': 'demo'}, session_id, 'demo-user')
    staged = app.state.interceptor.execute('production_database', {'sql': 'DELETE FROM users WHERE id = 1'}, session_id, 'demo-user')
    return {'session_id': session_id, 'result': staged, 'state': app.state.taint_engine.current_state(session_id)}


@app.post('/api/demo/scenario-b')
def scenario_b():
    session_id = app.state.taint_engine.get_or_create_session(None, 'demo-user')
    app.state.interceptor.execute('weather_api', {'city': 'Seattle'}, session_id, 'demo-user')
    blocked = app.state.interceptor.execute('production_database', {'sql': 'DELETE FROM users WHERE id = 2'}, session_id, 'demo-user')
    return {'session_id': session_id, 'result': blocked, 'state': app.state.taint_engine.current_state(session_id)}


@app.websocket('/ws')
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    app.state.event_hub.add_connection(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        app.state.event_hub.remove_connection(websocket)


if __name__ == '__main__':
    import uvicorn

    uvicorn.run('app.main:app', host='0.0.0.0', port=8000, reload=True)
