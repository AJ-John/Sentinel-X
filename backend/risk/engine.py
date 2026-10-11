def calculate_risk(event: dict, threat_analysis: dict):
    score = 0
    factors = []

    # Brute-force detection
    brute_force = any(
        detection["attack_type"] == "BRUTE_FORCE"
        for detection in threat_analysis["detections"]
    )

    if brute_force:
        score += 30
        factors.append("Brute-force behavior detected")

    # Port-scan detection
    port_scan = any(
        detection["attack_type"] == "PORT_SCAN"
        for detection in threat_analysis["detections"]
    )

    if port_scan:
        score += 10
        factors.append("Port scanning behavior detected")

    # Traffic spike
    traffic_spike = any(
        detection["attack_type"] == "TRAFFIC_SPIKE"
        for detection in threat_analysis["detections"]
    )

    if traffic_spike:
        score += 20
        factors.append("Abnormally high network activity")

    # New device
    if event.get("new_device", False):
        score += 10
        factors.append("New device detected")

    # High failed connections
    if event.get("failed_connections", 0) >= 20:
        score += 20
        factors.append("High number of failed connections")

    score = min(score, 100)

    if score >= 80:
        risk_level = "CRITICAL"
    elif score >= 60:
        risk_level = "HIGH"
    elif score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "risk_factors": factors
    }