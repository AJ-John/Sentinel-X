import os
import random
import pandas as pd


random.seed(42)

rows = []


# -------------------------
# NORMAL NETWORK BEHAVIOR
# -------------------------

for _ in range(200):

    rows.append({
        "packets_per_min": random.randint(15, 100),
        "connections_per_min": random.randint(5, 60),
        "unique_ports": random.randint(1, 10),
        "failed_connections": random.randint(0, 8),
        "login_failures": random.randint(0, 5),
        "new_device": random.choice([0, 0, 0, 1])
    })


# -------------------------
# MODERATE / UNUSUAL BEHAVIOR
# -------------------------

for _ in range(50):

    rows.append({
        "packets_per_min": random.randint(150, 400),
        "connections_per_min": random.randint(80, 200),
        "unique_ports": random.randint(10, 25),
        "failed_connections": random.randint(10, 50),
        "login_failures": random.randint(5, 25),
        "new_device": random.choice([0, 1])
    })


# -------------------------
# HIGHLY ABNORMAL BEHAVIOR
# -------------------------

for _ in range(100):

    rows.append({
        "packets_per_min": random.randint(500, 1500),
        "connections_per_min": random.randint(250, 800),
        "unique_ports": random.randint(25, 100),
        "failed_connections": random.randint(80, 350),
        "login_failures": random.randint(30, 150),
        "new_device": 1
    })


random.shuffle(rows)


data = pd.DataFrame(rows)


dataset_path = os.path.join(
    os.path.dirname(__file__),
    "dataset",
    "sentinelx_dataset.csv"
)


data.to_csv(dataset_path, index=False)


print("SentinelX dataset generated successfully.")
print(f"Total samples: {len(data)}")
print(f"Dataset saved to: {dataset_path}")
