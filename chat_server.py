import socket
import threading
import queue
import json
import argparse
import sys

# Argument parser
parser = argparse.ArgumentParser()
parser.add_argument('-sp',type=int, required=True)
args = parser.parse_args()

# Constants
SERVER_PORT = args.sp
SERVER_IP = socket.gethostbyname(socket.gethostname())
SERVER_ADDR = (SERVER_IP, SERVER_PORT)

# Create server socket
try:
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(SERVER_ADDR)
    print("Application starting at " + str(SERVER_IP) + ":" + str(SERVER_PORT) + " ...")
except:
    sys.exit("Error: Unable to open UDP socket at port " + str(SERVER_PORT))

# messages queue to store incoming UDP messages
messages = queue.Queue()
# clients list to store signed in clients
clients = []

# Add new client to the clients list
def update_clients(message_json, addr):
    # Check if username is already present
    if not is_client(message_json['username']):
        clients.append((message_json['username'], addr))
    else:
        # Send error message to user informing of duplicate username
        send_error("Username " + message_json['username'] + " already in use.", addr)

# Check if client is present in clients list
def is_client(username):
    for client in clients:
        if username == client[0]:
            return True
    return False

# Send error message
def send_error(message, addr):
    error_json = json.dumps({"type": "ERROR", "message": message})
    server.sendto(error_json.encode(), addr)

# Receive all UDP messages and add them to the messages queue
def receiver():
    while True:
        try:
            message, addr = server.recvfrom(1024)
            messages.put((message, addr))
        except:
            pass

# Process the queued messages
def processor():
    while True:
        while not messages.empty():
            message, addr = messages.get()
            message_json = json.loads(message)

            if message_json['type'] == 'SIGN-IN':
                update_clients(message_json, addr)

            elif message_json['type'] == 'LIST':
                clients_json = json.dumps({"type": "LIST", "clients": clients})
                server.sendto(clients_json.encode(), addr)

# Running the receiver() and processor() functions in different threads
# so that the operate in parallel
t1 = threading.Thread(target=receiver)
t2 = threading.Thread(target=processor)
t1.daemon = True
t1.start()
t2.start()
t2.join()