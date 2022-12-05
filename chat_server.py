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
import loggedin_client

#clients_creds = {"c1": "26eedef98e80edc0614d757ae8cc3de657ac5d33bd1daf59703b73de69ff9610", "c2": "cad43162a389b24871764af247b3ddfb7a3d50d744b619464fb4f4b87eeba11c", "c3": "d44873f2e8af3b127109702d70b63f6dada15ee7d13d63a2cbde7acb366c0848"}
clients_creds = {"c1": {"salt": "7vq&9rVn9mZu", "hash": "375a3da193bcecc10d56720241b2202fa991f3c6750b27b91442bb53cdfbf210"}, "c2": {"salt": "@p5dnYP159lC", "hash": "51350c67960963d8a9b4fdbc200c5fe8a9642f5afdda30a9b6da4b597b12da02"}, "c3": {"salt": "cC83^cWpeEkv", "hash": "19d40e00d8d943511e815ee9a45320e805cb726d774fb2851472620510dd5332"}}

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
    try:
        server_private_key = extract_server_private_key()
        return server_private_key.decrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except:
        sys.exit("Error: Decryption failed")

def extract_server_private_key():
    try:
        with open("server_priv.key", "rb") as key_file: 
            server_private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )
    except:
        sys.exit("Error: Reading Private Key failed.")
    return server_private_key

# Add new client to the clients list
def login_client(message_data, addr):
    # Check if username and password match
    if is_client(message_data['username'], message_data['password_hash'], addr):
        N2 = str(os.urandom(10))
        #clients.append([message_data['username'], addr, message_data['shared_key'], N2])
        new_client = loggedin_client.LoggedInClient(message_data['username'], message_data['shared_key'], addr, N2)
        global logged_in_clients
        logged_in_clients.append(new_client)
        update_client_list(new_client)
        send_updated_client_list()
        data = "{'username': '"+str(message_data['username'])+"', 'N1': "+str(message_data['N1'])+", 'N2': "+N2+"}"
        enc_data, iv = encryption.symmetrical_encrypt(data.encode(), message_data['shared_key'])

        message = "{'type': 'LOGIN', 'data': "+str(enc_data)+", 'iv': "+str(iv)+"}"
        send_message(message.encode(), addr)
    else:
        # Send error message to user informing of duplicate username
        message = "{'type': 'ERROR', 'message': 'Incorrect Credentials!'}"
        send_message(message.encode(), addr)

# Check if client is present in clients list
def is_client(username, password_hash, addr):
    try:
        global clients_creds
        client_cred = clients_creds[username]
        salted_hash = password_hash+client_cred['salt']
        h = hashlib.sha256(salted_hash.encode())
        if client_cred['hash'] == h.hexdigest():
            return True
        return False
    except:
        message = "{'type': 'ERROR', 'message': 'Incorrect Credentials!'}"
        send_message(message.encode(), addr)

def update_client_list(new_client):
    global logged_in_clients
    for client in logged_in_clients:
        client.update_clients_shared_keys(new_client.username, os.urandom(32), new_client.addr)
        new_client.update_clients_shared_keys(client.username, client.clients_shared_keys[new_client.username], client.addr)    

def send_updated_client_list():
    global logged_in_clients     
    for client in logged_in_clients:
        enc_logged_in_clients, iv = encryption.symmetrical_encrypt(str(client.clients_shared_keys).encode(), client.server_shared_key)
        data = "{'clients_shared_keys': "+str(client.clients_shared_keys)+", 'clients_addr': "+str(client.clients_addr)+"}"
        enc_data, iv = encryption.symmetrical_encrypt(data.encode(), client.server_shared_key)
        message = "{'type': 'LIST', 'data': "+str(enc_data)+", 'iv': "+str(iv)+"}"
        send_message(message.encode(), client.addr)

def logout_client(data_dec):
    global logged_in_clients
    for client in logged_in_clients:
        if client.username == data_dec['username']:
            if client.N2 == str(data_dec['N2']):
                data = "{'N3': "+str(data_dec['N3'])+", 'username': '"+client.username+"'}"
                data_enc, iv = encryption.symmetrical_encrypt(data.encode(), client.server_shared_key)
                message = "{'type': 'LOGOUT', 'data': "+str(data_enc)+", 'iv' : "+str(iv)+"}"
                send_message(message.encode(), client.addr)
                remove_client(client)
                send_updated_client_list()
                break
    
def remove_client(client):
    global logged_in_clients
    logged_in_clients.remove(client)
    for c in logged_in_clients:
        c.clients_addr.pop(client.username)
        c.clients_shared_keys.pop(client.username)

def send_message(message, addr):
    server.sendto(message, addr)

# Process the queued messages
def processor():
    while True:
        message, addr = server.recvfrom(4096)
        message_data = ast.literal_eval(message.decode())
        if message_data['type'] == 'LOGIN':
            data_dec = ast.literal_eval(rsa_decrypt(message_data['data']).decode())
            login_client(data_dec, addr)

        elif message_data['type'] == 'LOGOUT':
            data_dec = ast.literal_eval(rsa_decrypt(message_data['data']).decode())
            logout_client(data_dec)

processor()
