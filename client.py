import socket
import time
import psutil
import sys
import hmac
import hashlib

SERVER_IP = "127.0.0.1"
PORT = 5000

SECRET_TOKEN = "SECURE123"
SECRET_KEY = b"network_security_key"

if len(sys.argv) != 2:
    print("Usage: python client.py <node_id>")
    exit()

node_id = sys.argv[1]

client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

print(f"Client {node_id} started sending data...")

while True:
    cpu = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory().percent

    timestamp = time.time()

    base_message = f"{SECRET_TOKEN},{node_id},{cpu},{memory},{timestamp}"

    hash_value = hmac.new(
        SECRET_KEY,
        base_message.encode(),
        hashlib.sha256
    ).hexdigest()

    final_message = f"{base_message},{hash_value}"

    client_socket.sendto(final_message.encode(), (SERVER_IP, PORT))

    print("Sent:", final_message)

    time.sleep(5)