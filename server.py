import socket
import hmac
import hashlib
import threading
import os
import time

SERVER_IP = "0.0.0.0"
PORT = 5000
BUFFER_SIZE = 1024

SECRET_TOKEN = "SECURE123"
SECRET_KEY = b"network_security_key"

CPU_THRESHOLD = 5
TIMEOUT = 10

node_data = {}
alert_state = {}
alert_log = []

lock = threading.Lock()

total_packets = 0
start_time = time.time()
latencies = []

server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind((SERVER_IP, PORT))

print("Monitoring Server started on port", PORT)


# 🔹 Dashboard thread
def dashboard_loop():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')

        print("========== LIVE SYSTEM MONITOR ==========\n")

        current_time = time.time()

        with lock:
            if not node_data:
                print("No data received yet...\n")
            else:
                for node, data in node_data.items():
                    time_diff = current_time - data["last_seen"]

                    if time_diff > TIMEOUT:
                        print(f"Node {node} → OFFLINE ❌")
                    else:
                        print(f"Node {node} → CPU: {data['cpu']}% | Memory: {data['memory']}%")

        print("\n---------- PERFORMANCE METRICS ----------\n")

        elapsed_time = current_time - start_time
        throughput = total_packets / elapsed_time if elapsed_time > 0 else 0
        avg_latency = sum(latencies) / len(latencies) if latencies else 0

        print(f"Total Packets: {total_packets}")
        print(f"Throughput: {throughput:.2f} packets/sec")
        print(f"Avg Latency: {avg_latency*1000:.2f} ms")

        print("\n---------- RECENT ALERTS ----------\n")

        with lock:
            if not alert_log:
                print("No alerts")
            else:
                for alert in alert_log[-5:]:
                    print(alert)

        print("\n=========================================\n")

        time.sleep(1)


# 🔹 Handle client packets
def handle_client(data, address):
    global total_packets, latencies

    receive_time = time.time()

    message = data.decode()
    parts = message.split(",")

    if len(parts) != 6:
        return

    token, node_id, cpu, memory, timestamp, received_hash = parts

    if token != SECRET_TOKEN:
        return

    base_message = f"{token},{node_id},{cpu},{memory},{timestamp}"

    computed_hash = hmac.new(
        SECRET_KEY,
        base_message.encode(),
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(received_hash, computed_hash):
        return

    cpu = float(cpu)
    memory = float(memory)
    sent_time = float(timestamp)

    latency = receive_time - sent_time

    with lock:
        node_data[node_id] = {
            "cpu": cpu,
            "memory": memory,
            "last_seen": receive_time
        }

        if node_id not in alert_state:
            alert_state[node_id] = False

        # 🔥 STATE-BASED ALERT SYSTEM
        if cpu > CPU_THRESHOLD:
            if not alert_state[node_id]:
                alert_log.append(f"🚨 Node {node_id} HIGH CPU ({cpu}%)")
                alert_state[node_id] = True
        else:
            if alert_state[node_id]:
                alert_log.append(f"✅ Node {node_id} RECOVERED ({cpu}%)")
                alert_state[node_id] = False

        total_packets += 1
        latencies.append(latency)


# 🔹 Start dashboard thread
threading.Thread(target=dashboard_loop, daemon=True).start()


# 🔹 Main receive loop
while True:
    data, address = server_socket.recvfrom(BUFFER_SIZE)

    threading.Thread(
        target=handle_client,
        args=(data, address)
    ).start()