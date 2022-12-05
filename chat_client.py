import socket
import threading
import json
import argparse
import random
import sys
import hashlib
import os
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import encryption
import ast
import dh_exchange
import time
import getpass

# Argument parser
parser = argparse.ArgumentParser()
#parser.add_argument('-u',type=str, required=True)
#parser.add_argument('-p',type=str, required=True)
parser.add_argument('-sip',type=str, required=True)
parser.add_argument('-sp',type=int, required=True)
args = parser.parse_args()

# Constants
# Choose a random port between 8000-9000 for the client socket
CLIENT_PORT = random.randint(8000, 9000)
#CLIENT_IP = socket.gethostbyname(socket.gethostname())
CLIENT_IP = "127.0.0.1"
CLIENT_USERNAME = input("Username: ")
CLIENT_PASSWORD = getpass.getpass("Password: ")
CLIENT_ADDR = (CLIENT_IP, CLIENT_PORT)
SERVER_ADDR = (args.sip, args.sp)
N2 = ""
N3 = ""
a = 0
b = 0
p = 0

# clients list to cache logged in clients
clients_shared_keys = {}
clients_addr = {}
clients_dh_keys = {}

# Create client socket
try:
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(CLIENT_ADDR)
except:
    sys.exit("Error: Unable to open UDP socket at port " + str(CLIENT_PORT))

def send_message(message, addr):
    client.sendto(message, addr)

def rsa_encrypt(message):
    #print(message)
    server_public_key = extract_server_public_key()
    #try:
    return server_public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    #except:
    #    sys.exit("Error: RSA encryption of the message failed.")
    
def extract_server_public_key():
    try:
        with open("server_pub.pem", "rb") as file:
            server_public_key = serialization.load_pem_public_key(file.read())
    except:
        sys.exit("Error: Reading Server Public Key failed.")
    return server_public_key

# Log-In to the server
sha256_password = hashlib.sha256(CLIENT_PASSWORD.encode())
#print(sha256_password.hexdigest())
N1 = str(os.urandom(10))
shared_key = os.urandom(32)
# Creat a json object
login_message_data = "{'username': '"+CLIENT_USERNAME+"', 'password_hash': '"+sha256_password.hexdigest()+"', 'N1': "+N1+", 'shared_key': "+str(shared_key)+"}"
login_message = "{'type': 'LOGIN', 'data': "+str(rsa_encrypt(login_message_data.encode()))+"}"
# Convert json object to json string
# Send the json string after encoding it to bytes
send_message(login_message.encode(), SERVER_ADDR)

# Send message to another client
def send_message_to_client(username, text):
    if not clients_dh_keys.get(username):
        initiate_dh_handshake(username)
        for i in range(10):
            if not clients_dh_keys.get(username):
                time.sleep(6)
    
    data = "{'receiver-username': '"+username+"', 'text': '"+text+"'}"
    # Encrypting the text symmetrically using the DH derived key
    data_enc, iv = encryption.symmetrical_encrypt(data.encode(), clients_dh_keys[username].digest())
    # Calculcate the HMAC
    h = hmac.HMAC(clients_dh_keys[username].digest(), hashes.SHA256())
    h.update(data_enc)
    signature = h.finalize()

    message = "{'type': 'MESSAGE', 'sender-username': '"+CLIENT_USERNAME+"', 'data': "+str(data_enc)+", 'iv': "+str(iv)+", 'signature': "+str(signature)+"}"

    send_message(message.encode(), clients_addr[username])


def initiate_dh_handshake(username):
    print("Generating keys for first communication...")
    global a, p
    gamodp, g, p, a = dh_exchange.send_dh_parameters()
    client_shared_key = clients_shared_keys[username]
    client_addr = clients_addr[username]

    data = "{'receiver-username': '"+username+"', 'g': "+str(g)+", 'p': "+str(p)+", 'gamodp': "+str(gamodp)+"}"
    data_enc, iv = encryption.symmetrical_encrypt(data.encode(), client_shared_key)
    message = "{'type': 'DH-HANDSHAKE-1', 'sender-username': '"+str(CLIENT_USERNAME)+"', 'data': "+str(data_enc)+", 'iv': "+str(iv)+"}"

    send_message(message.encode(), client_addr)

def receive_dh_handshake(message_data, addr):
    message_data, data = extract_dh_data(message_data)

    global b
    gbmodp, b = dh_exchange.receive_dh_parameters(data['g'], data['p'])
    calculate_dh_derived_key_receiver(data['gamodp'], data['p'], message_data['sender-username'])

    data = "{'receiver-username': '"+message_data['sender-username']+"', 'gbmodp': "+str(gbmodp)+"}"
    data_enc, iv = encryption.symmetrical_encrypt(data.encode(), clients_shared_keys[message_data['sender-username']])
    message = "{'type': 'DH-HANDSHAKE-2', 'sender-username': '"+str(CLIENT_USERNAME)+"', 'data': "+str(data_enc)+", 'iv': "+str(iv)+"}"
    send_message(message.encode(), addr)

def extract_dh_data(message_data):
    client_shared_key = clients_shared_keys[message_data['sender-username']]
    data_dec = encryption.symmetrical_decrypt(message_data['data'], client_shared_key, message_data['iv'])
    data = ast.literal_eval(data_dec.decode())

    if str(data['receiver-username']) != CLIENT_USERNAME:
        sys.exit("Error: Messaging")
    return message_data, data

def calculate_dh_derived_key_receiver(gamodp, p, username):
    global b
    derived_key = pow(gamodp, b, p)
    derived_key = hashlib.sha256(str(derived_key).encode())
    clients_dh_keys[username] = derived_key

def calculate_dh_derived_key_sender(gbmodp, p, username):
    global a
    derived_key = pow(gbmodp, a, p)
    derived_key = hashlib.sha256(str(derived_key).encode())
    clients_dh_keys[username] = derived_key

# Print the list of logged in clients received from the server
def update_clients(data):
    global clients_shared_keys, clients_addr
    clients_shared_keys = data['clients_shared_keys']
    clients_addr = data['clients_addr']

def print_clients():
    global clients_addr
    if len(clients_addr) == 1:
        print("No other logged in users.")
        return
    for username, addr in clients_addr.items():
        if not username == CLIENT_USERNAME:
            print(username + " --> " + str(addr))

# Print received message with the username of the sender
# Add functionality: Can search the clients list for the username using addr
def print_message(message_json, addr):
    print(message_json['sender'] + ": " + message_json['message'])

# Get address (IP:Port) of username from clients list
def get_client_addr(username):
    for client in clients:
        if client[0] == username:
            return str(client[1][0]), client[1][1]

def finish_login(message_data, addr):
    global shared_key, N2
    message_data_dec = ast.literal_eval(encryption.symmetrical_decrypt(message_data['data'], shared_key, message_data['iv']).decode())
    if str(message_data_dec['username']) == CLIENT_USERNAME and str(message_data_dec['N1']) == N1:
        N2 = message_data_dec['N2']
    else:
        sys.exit("Error: Server Authentication failed!")

def logout():
    global N2, N3
    N3 = os.urandom(10)
    data = "{'username': '"+CLIENT_USERNAME+"', 'N2': "+str(N2)+", 'N3': "+str(N3)+"}"
    message = "{'type': 'LOGOUT', 'data': "+str(rsa_encrypt(data.encode()))+"}"
    send_message(message.encode(), SERVER_ADDR)

def remove_data():
    global N2, N3, a, b, p, clients_shared_keys, clients_addr, clients_dh_keys
    del N2, N3, a, b, p, clients_shared_keys, clients_addr, clients_dh_keys

# Print help command output
def help():
    print("--------------------------------------------------")
    print("These are the available commands:")
    print("1. list")
    print("    -> usage: list")
    print("2. send")
    print("    -> usage: send <receiver_username> <message>")
    print("3. logout")
    print("    -> usage: logout")
    print("4. help")
    print("    -> usage: help")
    print("--------------------------------------------------")

# Get user input commands
def menu():
    while True:
        # Split space seperated input into list of strings
        command = input().split()
        if not command:
            continue
        # command[0] is the first string
        if command[0] == "list":
            print_clients()
        elif command[0] == "send":
            # Second string(command[1]) is the username
            # Passing rest of the strings in the list as the message
            #try:
            send_message_to_client(command[1], ' '.join(command[2:]))
            #except:
            #    print("Error: Failed to send message.")
        elif command[0] == "logout":
            logout()

        elif command[0] == "help":
            help()
        else:
            print("Error: Invalid Command")
            help()

# Process all incoming UDP messages
def receiver():
    while True:
        #try:
        message, addr = client.recvfrom(4096)
        message_data = ast.literal_eval(message.decode())

        if message_data['type'] == 'LOGIN':
            try:
                finish_login(message_data, addr)
            except:
                sys.exit("Error: Login failed.")

        # If type of message received is LIST
        elif message_data['type'] == 'LIST':
            try:
                data = ast.literal_eval(encryption.symmetrical_decrypt(message_data['data'], shared_key, message_data['iv']).decode())
                update_clients(data)
            except:
                pass

        #If type of message received is MESSAGE
        elif message_data['type'] == 'DH-HANDSHAKE-1':
            receive_dh_handshake(message_data, addr)

        elif message_data['type'] == 'DH-HANDSHAKE-2':
            _, data = extract_dh_data(message_data)
            global p
            calculate_dh_derived_key_sender(data['gbmodp'], p, message_data['sender-username'])
        
        elif message_data['type'] == 'MESSAGE':
            client_dh_key = clients_dh_keys[message_data['sender-username']]

            # Verify HMAC
            h = hmac.HMAC(client_dh_key.digest(), hashes.SHA256())
            h.update(message_data['data'])
            h.verify(message_data['signature'])

            data_dec = encryption.symmetrical_decrypt(message_data['data'], client_dh_key.digest(), message_data['iv'])
            data = ast.literal_eval(data_dec.decode())

            if str(data['receiver-username']) != CLIENT_USERNAME:
                sys.exit("Error: Messaging")
            
            print(str(message_data['sender-username']) + ": " + str(data['text']))
        
        elif message_data['type'] == 'LOGOUT':
            data_dec = encryption.symmetrical_decrypt(message_data['data'], shared_key, message_data['iv'])
            data = ast.literal_eval(data_dec.decode())

            if str(data['username']) != CLIENT_USERNAME:
                sys.exit("Error: Messaging")

            global N3
            if str(data['N3']) == str(N3):
                remove_data()
                print("Logged out successfully!")
                sys.exit()

        # Print error message and stop the program
        elif message_data['type'] == 'ERROR':
            print("ERROR: " + message_data['message'])
            break
        #except:
        #    print("Error: Error reading incoming message.")

# Running menu and receiver as different threads
t1 = threading.Thread(target=menu)
t2 = threading.Thread(target=receiver)
t1.daemon = True
t1.start()
t2.start()
t2.join()