import requests
import time
import json
from datetime import datetime

BASE_URL = "http://localhost:8001"

def create_silence(match, duration_seconds: int):
    resp = requests.post(
        f"{BASE_URL}/silence",
        json={"match": match, "duration_seconds": duration_seconds},
    )
    print(f"Silence created: {resp.json()}")

# 模拟 5 个 Pod 同时触发 SLS 告警
def simulate_sls_burst():
    print("--- [SIMULATING SLS BURST] ---")
    ts = int(datetime.now().timestamp())
    for i in range(1, 6):
        payload = {
            "alert_id": f"sls-{ts}-{i}",
            "alert_name": "CPU_USAGE_HIGH",
            "service": "order-service",
            "pod": f"pod-{i}",
            "cluster": "prod-sh-1",
            "severity": "high",
            "value": 95.5 + i,
            "timestamp": int(datetime.now().timestamp()),
            "status": "firing",
            "labels": {"env": "prod"}
        }
        
        response = requests.post(f"{BASE_URL}/ingest/SLS", json=payload)
        print(f"Alert {i} Ingested: {response.json()}")
        time.sleep(0.5)

# 模拟 Sunfire 告警接入
def simulate_sunfire_alert():
    print("\n--- [SIMULATING SUNFIRE ALERT] ---")
    payload = {
        "id": f"sunfire-{int(datetime.now().timestamp())}",
        "appName": "order-service",
        "ruleName": "CPU_USAGE_HIGH",
        "level": "S1",
        "time": datetime.now().isoformat()
    }
    response = requests.post(f"{BASE_URL}/ingest/Sunfire", json=payload)
    print(f"Sunfire Alert Ingested: {response.json()}")

if __name__ == "__main__":
    # 模拟流程
    try:
        create_silence(
            match={"service": "order-service", "metric_name": "CPU_USAGE_HIGH"},
            duration_seconds=5,
        )

        # 1. 触发 SLS 告警风暴
        simulate_sls_burst()
        
        time.sleep(6)

        simulate_sls_burst()

        time.sleep(2)

        # 2. 触发 Sunfire 告警
        simulate_sunfire_alert()
        
    except Exception as e:
        print(f"Error during demo: {e}. Make sure the server is running on {BASE_URL}")
