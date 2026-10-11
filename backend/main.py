from datetime import datetime, timezone
from typing import Optional

from bson import ObjectId
from fastapi import (
    FastAPI,
    WebSocket,
    WebSocketDisconnect,
    HTTPException,
    Query,
    Depends,
    Request,
)
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from auth import (
    LoginRequest,
    authenticate_user,
    create_access_token,
    ensure_demo_admin,
    public_user,
    require_user,
    require_admin,
    token_from_string,
    CreateUserRequest,
    list_users,
    create_user,
    delete_user,
    check_login_allowed,
    record_login_failure,
    record_login_success,
    write_audit,
)

from database import check_database_connection, database
from security_events import (
    create_security_event,
    get_security_events,
    get_security_event,
    get_dashboard_stats,
    update_event_status,
)
from detection.rules import analyze_security_event
from risk.engine import calculate_risk
from ml.detector import detect_anomaly
from response.engine import determine_response
from blockchain.client import (
    record_threat_on_blockchain,
    get_threat_from_blockchain,
    get_all_threats_from_blockchain,
)

app = FastAPI(
    title="SentinelX API",
    description="AI-Powered Decentralized Cyber Threat Detection and Defense Platform",
    version="3.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


connected_clients = []
ensure_demo_admin()


@app.websocket("/ws/security")
async def security_websocket(websocket: WebSocket):
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=1008)
        return
    try:
        token_from_string(token)
    except HTTPException:
        await websocket.close(code=1008)
        return

    await websocket.accept()
    connected_clients.append(websocket)
    print(f"WebSocket client connected. Total clients: {len(connected_clients)}")

    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in connected_clients:
            connected_clients.remove(websocket)
        print(f"WebSocket client disconnected. Total clients: {len(connected_clients)}")
    except Exception:
        if websocket in connected_clients:
            connected_clients.remove(websocket)


class SecurityEvent(BaseModel):
    source_ip: str
    event_type: str
    severity: str = "LOW"
    agent_status: str = "UNKNOWN"
    description: str = ""
    packets_per_min: int = 0
    connections_per_min: int = 0
    unique_ports: int = 0
    failed_connections: int = 0
    login_failures: int = 0
    new_device: bool = False


class EventAction(BaseModel):
    action: str



@app.post("/auth/login")
def login(credentials: LoginRequest, request: Request):
    client_ip = request.client.host if request.client else "unknown"

    check_login_allowed(credentials.username, client_ip)

    user = authenticate_user(
        credentials.username,
        credentials.password,
    )

    if not user:
        record_login_failure(credentials.username, client_ip)
        write_audit(
            action="LOGIN_FAILED",
            username=credentials.username,
            details="Invalid credentials",
            client_ip=client_ip,
        )
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
        )

    record_login_success(credentials.username, client_ip)

    public = public_user(user)

    write_audit(
        action="LOGIN_SUCCESS",
        username=public["username"],
        role=public["role"],
        client_ip=client_ip,
    )

    return {
        "access_token": create_access_token(user),
        "token_type": "bearer",
        "user": public,
    }


@app.get("/auth/me")
def auth_me(current_user=Depends(require_user)):
    return {
        "authenticated": True,
        "user": current_user,
    }


@app.get("/")
def root():
    return {
        "project": "SentinelX",
        "status": "online",
        "version": "3.0.0",
        "message": "SentinelX Cyber Defense API is running",
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/system")
def system_status(current_user=Depends(require_user)):
    return {
        "system": "SentinelX",
        "security_engine": "online",
        "ml_engine": "online",
        "blockchain": "online",
        "database": "connected" if check_database_connection() else "disconnected",
    }


@app.get("/database/status")
def database_status(current_user=Depends(require_user)):
    connected = check_database_connection()
    return {
        "database": "MongoDB Atlas",
        "status": "connected" if connected else "disconnected",
    }


@app.post("/events")
async def create_event(event: SecurityEvent, current_user=Depends(require_user)):
    event_data = event.model_dump()

    print("AGENT STATUS RECEIVED:", event_data.get("agent_status"))

    threat_analysis = analyze_security_event(event_data)
    ml_analysis = detect_anomaly(event_data)
    risk_analysis = calculate_risk(event_data, threat_analysis)
    response = determine_response(risk_analysis, threat_analysis)

    blockchain_result = None

    if risk_analysis["risk_level"] in ["HIGH", "CRITICAL"]:
        detected_attack = "UNKNOWN"

        if threat_analysis["detections"]:
            detected_attack = ", ".join(
                detection["attack_type"]
                for detection in threat_analysis["detections"]
            )

        blockchain_result = record_threat_on_blockchain(
            source_ip=event_data["source_ip"],
            attack_type=detected_attack,
            risk_level=risk_analysis["risk_level"],
            risk_score=risk_analysis["risk_score"],
        )

    result = create_security_event(
        event_data=event_data,
        threat_analysis=threat_analysis,
        ml_analysis=ml_analysis,
        risk_analysis=risk_analysis,
        response=response,
        blockchain=blockchain_result,
    )

    response_data = {
        **result,
        "event": event_data,
        "threat_analysis": threat_analysis,
        "ml_analysis": ml_analysis,
        "risk_analysis": risk_analysis,
        "response": response,
        "blockchain": blockchain_result,
    }

    disconnected_clients = []

    for client in connected_clients:
        try:
            await client.send_json(response_data)
        except Exception:
            disconnected_clients.append(client)

    for client in disconnected_clients:
        if client in connected_clients:
            connected_clients.remove(client)

    return response_data


@app.get("/events")
def list_events(
    limit: int = Query(default=100, ge=1, le=500),
    skip: int = Query(default=0, ge=0),
    risk: Optional[str] = Query(default=None),
    source_ip: Optional[str] = Query(default=None),
    current_user=Depends(require_user),
):
    return get_security_events(
        limit=limit,
        skip=skip,
        risk=risk,
        source_ip=source_ip,
    )


@app.get("/events/{event_id}")
def event_details(event_id: str, current_user=Depends(require_user)):
    if not ObjectId.is_valid(event_id):
        raise HTTPException(status_code=400, detail="Invalid event ID")

    event = get_security_event(event_id)

    if not event:
        raise HTTPException(status_code=404, detail="Security event not found")

    return event


@app.get("/dashboard/stats")
def dashboard_stats(current_user=Depends(require_user)):
    return get_dashboard_stats()


@app.post("/events/{event_id}/acknowledge")
def acknowledge_event(event_id: str, current_user=Depends(require_user)):
    if not ObjectId.is_valid(event_id):
        raise HTTPException(status_code=400, detail="Invalid event ID")

    updated = update_event_status(event_id, "ACKNOWLEDGED")

    if not updated:
        raise HTTPException(status_code=404, detail="Security event not found")

    return {
        "success": True,
        "event_id": event_id,
        "status": "ACKNOWLEDGED",
    }


@app.post("/events/{event_id}/action")
def execute_simulated_action(event_id: str, action: EventAction, current_user=Depends(require_user)):
    allowed_actions = {
        "BLOCK_SIMULATED_SOURCE",
        "ISOLATE_SIMULATED_SOURCE",
        "MARK_TRUSTED",
        "MONITOR",
    }

    if action.action not in allowed_actions:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported action. Allowed: {sorted(allowed_actions)}",
        )

    if not ObjectId.is_valid(event_id):
        raise HTTPException(status_code=400, detail="Invalid event ID")

    updated = update_event_status(
        event_id,
        "ACTION_EXECUTED",
        action=action.action,
    )

    if not updated:
        raise HTTPException(status_code=404, detail="Security event not found")

    return {
        "success": True,
        "event_id": event_id,
        "action": action.action,
        "status": "SIMULATED_EXECUTED",
        "message": "No real firewall or network control was performed.",
    }


@app.get("/users")
def get_users(current_user=Depends(require_admin)):
    return {
        "users": list_users(),
        "count": len(list_users()),
    }


@app.post("/users")
def add_user(
    user: CreateUserRequest,
    current_user=Depends(require_admin),
):
    try:
        created = create_user(
            username=user.username,
            password=user.password,
            role=user.role,
        )
        write_audit(
            action="USER_CREATED",
            username=created["username"],
            role=created["role"],
            details=f"Created by {current_user.get('username', 'unknown')}",
        )
        return {
            "success": True,
            "user": created,
        }
    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        )


@app.delete("/users/{username}")
def remove_user(
    username: str,
    current_user=Depends(require_admin),
):
    try:
        deleted = delete_user(
            username=username,
            current_username=current_user.get("username", ""),
        )
    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        )

    if not deleted:
        raise HTTPException(
            status_code=404,
            detail="User not found",
        )

    write_audit(
        action="USER_DELETED",
        username=username,
        details=f"Deleted by {current_user.get('username', 'unknown')}",
    )

    return {
        "success": True,
        "username": username,
        "message": "User deleted successfully",
    }



@app.get("/audit")
def get_audit_logs(
    limit: int = Query(default=100, ge=1, le=500),
    current_user=Depends(require_admin),
):
    logs = list(
        database["security_audit"]
        .find({}, {"_id": 0})
        .sort("created_at", -1)
        .limit(limit)
    )
    return {
        "logs": logs,
        "count": len(logs),
    }

@app.get("/blockchain/threat/{threat_id}")
def get_blockchain_threat(
    threat_id: int,
    current_user=Depends(require_user),
):
    return get_threat_from_blockchain(threat_id)


@app.get("/blockchain/threats")
def get_all_blockchain_threats(current_user=Depends(require_user)):
    return get_all_threats_from_blockchain()
