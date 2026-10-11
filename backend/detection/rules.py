def detect_brute_force(event: dict):
    login_failures = event.get("login_failures", 0)
    failed_connections = event.get("failed_connections", 0)

    if login_failures >= 20 or failed_connections >= 20:
        return {
            "detected": True,
            "attack_type": "BRUTE_FORCE",
            "severity": "HIGH",
            "reason": "High number of failed login/connection attempts"
        }

    if login_failures >= 10 or failed_connections >= 10:
        return {
            "detected": True,
            "attack_type": "BRUTE_FORCE",
            "severity": "MEDIUM",
            "reason": "Repeated failed login/connection attempts"
        }

    return {
        "detected": False,
        "attack_type": None,
        "severity": "LOW",
        "reason": None
    }


def detect_port_scan(event: dict):
    unique_ports = event.get("unique_ports", 0)

    if unique_ports >= 30:
        return {
            "detected": True,
            "attack_type": "PORT_SCAN",
            "severity": "HIGH",
            "reason": "Large number of unique ports detected"
        }

    if unique_ports >= 20:
        return {
            "detected": True,
            "attack_type": "PORT_SCAN",
            "severity": "MEDIUM",
            "reason": "Unusually high number of unique ports"
        }

    return {
        "detected": False,
        "attack_type": None,
        "severity": "LOW",
        "reason": None
    }


def detect_traffic_spike(event: dict):
    packets = event.get("packets_per_min", 0)
    connections = event.get("connections_per_min", 0)

    if packets >= 1000 or connections >= 500:
        return {
            "detected": True,
            "attack_type": "TRAFFIC_SPIKE",
            "severity": "HIGH",
            "reason": "Abnormally high network activity"
        }

    if packets >= 500 or connections >= 250:
        return {
            "detected": True,
            "attack_type": "TRAFFIC_SPIKE",
            "severity": "MEDIUM",
            "reason": "Elevated network activity"
        }

    return {
        "detected": False,
        "attack_type": None,
        "severity": "LOW",
        "reason": None
    }


def analyze_security_event(event: dict):
    detections = []

    brute_force = detect_brute_force(event)
    if brute_force["detected"]:
        detections.append(brute_force)

    port_scan = detect_port_scan(event)
    if port_scan["detected"]:
        detections.append(port_scan)

    traffic_spike = detect_traffic_spike(event)
    if traffic_spike["detected"]:
        detections.append(traffic_spike)

    if not detections:
        return {
            "threat_detected": False,
            "detections": [],
            "highest_severity": "LOW"
        }

    severity_order = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4
    }

    highest = max(
        detections,
        key=lambda item: severity_order[item["severity"]]
    )

    return {
        "threat_detected": True,
        "detections": detections,
        "highest_severity": highest["severity"]
    }