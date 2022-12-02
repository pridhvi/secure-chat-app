import socket
import threading
import queue
import json
import argparse
import sys
import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import ast
import encryption
import os
import LoggedInClient

clients_creds = {"c1": "26eedef98e80edc0614d757ae8cc3de657ac5d33bd1daf59703b73de69ff9610", "c2": "cad43162a389b24871764af247b3ddfb7a3d50d744b619464fb4f4b87eeba11c", "c3": "d44873f2e8af3b127109702d70b63f6dada15ee7d13d63a2cbde7acb366c0848"}

# clients list to store signed in clients
logged_in_clients = []

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

def rsa_decrypt(message):
    server_private_key = extract_server_private_key()
    return server_private_key.decrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def extract_server_private_key():
    try:
        with open("server_priv.key", "rb") as key_file: 
            server_private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )
    except:
        sys.exit("Error: Reading Sender Private Key failed.")
    return server_private_key

# Add new client to the clients list
def login_client(message_data, addr):
    # Check if username and password match
    if is_client(message_data['username'], message_data['password_hash']):
        N2 = str(os.urandom(10))
        #clients.append([message_data['username'], addr, message_data['shared_key'], N2])
        new_client = LoggedInClient.LoggedInClient(message_data['username'], addr, message_data['shared_key'], N2)
        global logged_in_clients
        logged_in_clients.append(new_client)
        update_client_list(new_client)
        #send_updated_client_list()
        #for i in logged_in_clients:
        #    print(i.clients_shared_keys)
        #client_list = update_client_list(message_data)
        # add client_list to data
        data = "{'N1': "+str(message_data['N1'])+", 'N2': "+N2+", 'client_list': "+str(new_client.clients_shared_keys)+"}"
        enc_data, iv = encryption.symmetrical_encrypt(data.encode(), message_data['shared_key'])

        message = "{'type': 'LOGIN', 'data': "+str(enc_data)+", 'iv': "+str(iv)+"}"
        send_message(message.encode(), addr)
    else:
        # Send error message to user informing of duplicate username
        send_error("Incorrect Credentials!", addr)

# Check if client is present in clients list
def is_client(username, password_hash):
    if clients_creds[username] == password_hash:
        return True
    return False

def update_client_list(new_client):
    global logged_in_clients
    for client in logged_in_clients:
        client.update_clients_shared_keys(new_client.username, os.urandom(10), new_client.addr)
        new_client.update_clients_shared_keys(client.username, client.clients_shared_keys[new_client.username], client.addr)    

def send_updated_client_list():
    global logged_in_clients
    for client in logged_in_clients:
        enc_logged_in_clients, iv = encryption.symmetrical_encrypt(str(client.clients_shared_keys).encode(), client.server_shared_key)
        
        message = "{'type': 'LIST', 'client_list': "++"}"
        send_message(message, client.addr)

def send_message(message, addr):
    server.sendto(message, addr)

# Send error message
def send_error(message, addr):
    error_json = json.dumps({"type": "ERROR", "message": message})
    server.sendto(error_json.encode(), addr)

# Process the queued messages
def processor():
    while True:
        message, addr = server.recvfrom(4096)
        message_data = ast.literal_eval(message.decode())
        if message_data['type'] == 'LOGIN':
            data_dec = ast.literal_eval(rsa_decrypt(message_data['data']).decode())
            login_client(data_dec, addr)

        elif message_json['type'] == 'LOGIN-3':
            finish_login(message_json, addr)

        elif message_json['type'] == 'LIST':
            clients_json = json.dumps({"type": "LIST", "clients": clients})
            server.sendto(clients_json.encode(), addr)

processor()
