import time
import requests

LOGIN_URL = "http://127.0.0.1:8000/auth/login"
API_URL = "http://127.0.0.1:8000/events"

USERNAME = "admin"
PASSWORD = "SentinelX@123"

INTERVAL = 10


DEMO_EVENTS = [
    {
        "name": "NORMAL_ACTIVITY",
        "source_ip": "127.0.0.1",
        "event_type": "DEMO_NORMAL",
        "severity": "LOW",
        "agent_status": "NORMAL",
        "description": "Safe SentinelX normal-activity demonstration.",
        "packets_per_min": 0,
        "connections_per_min": 0,
        "unique_ports": 0,
        "failed_connections": 0,
        "login_failures": 0,
        "new_device": False,
    },
    {
        "name": "BRUTE_FORCE",
        "source_ip": "192.168.1.50",
        "event_type": "DEMO_BRUTE_FORCE",
        "severity": "MEDIUM",
        "agent_status": "SUSPICIOUS",
        "description": "Safe SentinelX brute-force demonstration.",
        "packets_per_min": 0,
        "connections_per_min": 30,
        "unique_ports": 0,
        "failed_connections": 25,
        "login_failures": 25,
        "new_device": False,
    },
    {
        "name": "PORT_SCAN",
        "source_ip": "192.168.1.60",
        "event_type": "DEMO_PORT_SCAN",
        "severity": "HIGH",
        "agent_status": "SUSPICIOUS",
        "description": "Safe SentinelX port-scan demonstration.",
        "packets_per_min": 0,
        "connections_per_min": 40,
        "unique_ports": 35,
        "failed_connections": 0,
        "login_failures": 0,
        "new_device": False,
    },
    {
        "name": "TRAFFIC_SPIKE",
        "source_ip": "192.168.1.70",
        "event_type": "DEMO_TRAFFIC_SPIKE",
        "severity": "HIGH",
        "agent_status": "SUSPICIOUS",
        "description": "Safe SentinelX traffic-spike demonstration.",
        "packets_per_min": 1500,
        "connections_per_min": 700,
        "unique_ports": 0,
        "failed_connections": 0,
        "login_failures": 0,
        "new_device": False,
    },
    {
        "name": "MULTI_THREAT",
        "source_ip": "192.168.1.99",
        "event_type": "DEMO_MULTI_THREAT",
        "severity": "CRITICAL",
        "agent_status": "HIGH_ACTIVITY",
        "description": "Safe SentinelX multi-threat demonstration.",
        "packets_per_min": 1500,
        "connections_per_min": 700,
        "unique_ports": 50,
        "failed_connections": 25,
        "login_failures": 25,
        "new_device": True,
    },
]


def login():
    print("[SentinelX Demo] Logging in...")

    try:
        response = requests.post(
            LOGIN_URL,
            json={
                "username": USERNAME,
                "password": PASSWORD
            },
            timeout=10
        )

        if not response.ok:
            print(
                f"[SentinelX Demo] Login failed: "
                f"HTTP {response.status_code}"
            )
            print(response.text)
            return None

        data = response.json()
        token = data.get("access_token")

        if not token:
            print("[SentinelX Demo] No access token received.")
            return None

        print("[SentinelX Demo] Authentication successful.")
        return token

    except requests.exceptions.RequestException as error:
        print(f"[SentinelX Demo] Login connection error: {error}")
        return None


def send_demo_event(event, token):
    headers = {
        "Authorization": f"Bearer {token}"
    }

    try:
        response = requests.post(
            API_URL,
            json=event,
            headers=headers,
            timeout=10
        )

        print(f"[SentinelX Demo] HTTP {response.status_code}")

        if response.status_code == 401:
            print("[SentinelX Demo] Token expired or invalid.")
            return "TOKEN_EXPIRED"

        if not response.ok:
            print(response.text)
            return "ERROR"

        result = response.json()

        risk = result.get("risk_analysis", {})
        ml = result.get("ml_analysis", {})
        threat = result.get("threat_analysis", {})
        blockchain = result.get("blockchain")

        print(f"Event: {event['name']}")

        print(
            f"Risk: {risk.get('risk_score', 0)}/100 "
            f"| {risk.get('risk_level', 'UNKNOWN')}"
        )

        print(
            f"ML: {ml.get('ml_status', 'UNKNOWN')}"
        )

        if threat.get("threat_detected"):
            for detection in threat.get("detections", []):
                print(
                    f"  -> {detection.get('attack_type')} "
                    f"| {detection.get('severity')}"
                )

        response_data = result.get("response", {})

        print(
            f"Response: "
            f"{response_data.get('response_action', 'UNKNOWN')}"
        )

        if blockchain:
            print(
                f"Blockchain: "
                f"{blockchain.get('blockchain_status', 'UNKNOWN')}"
            )

        return "SUCCESS"

    except requests.exceptions.RequestException as error:
        print(
            f"[SentinelX Demo] Backend connection error: {error}"
        )
        return "ERROR"


def main():

    print("=" * 65)
    print("           SENTINELX SAFE DEMO AGENT")
    print("=" * 65)

    print(f"Backend : {API_URL}")
    print()

    print("SAFE DEMO MODE")
    print("No real attack, scan, or network traffic is generated.")
    print()

    print(
        "Sequence: NORMAL -> BRUTE_FORCE -> PORT_SCAN -> "
        "TRAFFIC_SPIKE -> MULTI_THREAT"
    )

    print("Press CTRL+C to stop.")
    print()

    token = login()

    if not token:
        print()
        print("Unable to authenticate with SentinelX.")
        print("Make sure FastAPI is running.")
        return

    print()

    index = 0

    while True:

        event = DEMO_EVENTS[index % len(DEMO_EVENTS)]

        result = send_demo_event(event, token)

        if result == "TOKEN_EXPIRED":
            print("[SentinelX Demo] Getting a new token...")
            token = login()

            if not token:
                print("[SentinelX Demo] Re-authentication failed.")
                return

        print("-" * 65)

        index += 1

        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()