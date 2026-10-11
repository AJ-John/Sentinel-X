from datetime import datetime, timezone
from bson import ObjectId

from database import database

events_collection = database["security_events"]


def _serialize_event(event: dict) -> dict:
    event["_id"] = str(event["_id"])

    if isinstance(event.get("created_at"), datetime):
        event["created_at"] = event["created_at"].isoformat()

    if isinstance(event.get("updated_at"), datetime):
        event["updated_at"] = event["updated_at"].isoformat()

    return event


def create_security_event(
    event_data: dict,
    threat_analysis: dict | None = None,
    ml_analysis: dict | None = None,
    risk_analysis: dict | None = None,
    response: dict | None = None,
    blockchain: dict | None = None,
):
    now = datetime.now(timezone.utc)

    event = {
        "source_ip": event_data["source_ip"],
        "event_type": event_data["event_type"],
        "severity": event_data.get("severity", "LOW"),
        "agent_status": event_data.get("agent_status", "UNKNOWN"),
        "description": event_data.get("description", ""),
        "packets_per_min": event_data.get("packets_per_min", 0),
        "connections_per_min": event_data.get("connections_per_min", 0),
        "unique_ports": event_data.get("unique_ports", 0),
        "failed_connections": event_data.get("failed_connections", 0),
        "login_failures": event_data.get("login_failures", 0),
        "new_device": event_data.get("new_device", False),
        "threat_analysis": threat_analysis or {},
        "ml_analysis": ml_analysis or {},
        "risk_analysis": risk_analysis or {},
        "response": response or {},
        "blockchain": blockchain,
        "status": "NEW",
        "action": None,
        "created_at": now,
        "updated_at": now,
    }

    result = events_collection.insert_one(event)

    return {
        "event_id": str(result.inserted_id),
        "message": "Security event stored successfully",
    }


def get_security_events(
    limit: int = 100,
    skip: int = 0,
    risk: str | None = None,
    source_ip: str | None = None,
):
    query = {}

    if risk and risk.upper() != "ALL":
        query["risk_analysis.risk_level"] = risk.upper()

    if source_ip:
        query["source_ip"] = source_ip

    cursor = (
        events_collection
        .find(query)
        .sort("created_at", -1)
        .skip(skip)
        .limit(limit)
    )

    events = [_serialize_event(event) for event in cursor]

    return {
        "count": len(events),
        "limit": limit,
        "skip": skip,
        "events": events,
    }


def get_security_event(event_id: str):
    event = events_collection.find_one({"_id": ObjectId(event_id)})

    if not event:
        return None

    return _serialize_event(event)


def update_event_status(
    event_id: str,
    status: str,
    action: str | None = None,
):
    update_data = {
        "status": status,
        "updated_at": datetime.now(timezone.utc),
    }

    if action:
        update_data["action"] = action

    result = events_collection.update_one(
        {"_id": ObjectId(event_id)},
        {"$set": update_data},
    )

    return result.modified_count > 0 or result.matched_count > 0


def get_dashboard_stats():
    events = list(
        events_collection.find(
            {},
            {
                "risk_analysis": 1,
                "threat_analysis": 1,
                "ml_analysis": 1,
                "response": 1,
                "blockchain": 1,
                "status": 1,
                "created_at": 1,
            },
        )
    )

    total = len(events)
    threats = 0
    critical = 0
    automated_responses = 0
    ml_anomalies = 0
    blockchain_records = 0
    risk_total = 0
    risk_count = 0

    attack_counts = {}
    risk_counts = {
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0,
    }

    for event in events:
        risk_data = event.get("risk_analysis") or {}
        threat_data = event.get("threat_analysis") or {}
        ml_data = event.get("ml_analysis") or {}
        response_data = event.get("response") or {}
        blockchain_data = event.get("blockchain")

        risk_level = risk_data.get("risk_level", "LOW")
        risk_score = risk_data.get("risk_score", 0)

        risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1

        if isinstance(risk_score, (int, float)):
            risk_total += risk_score
            risk_count += 1

        if threat_data.get("threat_detected"):
            threats += 1

        if risk_level == "CRITICAL":
            critical += 1

        if response_data.get("automatic_response"):
            automated_responses += 1

        if ml_data.get("ml_anomaly"):
            ml_anomalies += 1

        if blockchain_data and blockchain_data.get("blockchain_status") == "RECORDED":
            blockchain_records += 1

        for detection in threat_data.get("detections", []):
            attack_type = detection.get("attack_type")
            if attack_type:
                attack_counts[attack_type] = attack_counts.get(attack_type, 0) + 1

    average_risk = round(risk_total / risk_count, 2) if risk_count else 0

    return {
        "events_processed": total,
        "threats_detected": threats,
        "critical_events": critical,
        "automated_responses": automated_responses,
        "ml_anomalies": ml_anomalies,
        "blockchain_records": blockchain_records,
        "average_risk": average_risk,
        "risk_distribution": risk_counts,
        "attack_distribution": attack_counts,
    }
