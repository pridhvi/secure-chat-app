import socket
import threading
import json
import argparse
import random
import sys
import hashlib
import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import keygen
import base64
import encryption
import ast

# Argument parser
parser = argparse.ArgumentParser()
parser.add_argument('-u',type=str, required=True)
parser.add_argument('-p',type=str, required=True)
parser.add_argument('-sip',type=str, required=True)
parser.add_argument('-sp',type=int, required=True)
args = parser.parse_args()

# Constants
# Choose a random port between 8000-9000 for the client socket
CLIENT_PORT = random.randint(8000, 9000)
CLIENT_IP = socket.gethostbyname(socket.gethostname())
CLIENT_USERNAME = args.u
CLIENT_ADDR = (CLIENT_IP, CLIENT_PORT)
SERVER_ADDR = (args.sip, args.sp)

# clients list to cache logged in clients
clients = []

# Create client socket
try:
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(CLIENT_ADDR)
    print("Application starting at " + str(CLIENT_IP) + ":" + str(CLIENT_PORT) + " ...")
except:
    sys.exit("Error: Unable to open UDP socket at port " + str(CLIENT_PORT))

def send_message_server(message, addr):
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
sha256_password = hashlib.sha256(args.p.encode())
#print(sha256_password.hexdigest())
N1 = str(os.urandom(10))
shared_key = os.urandom(32)
# Creat a json object
login_message_data = "{'username': '"+CLIENT_USERNAME+"', 'password_hash': '"+sha256_password.hexdigest()+"', 'N1': "+N1+", 'shared_key': "+str(shared_key)+"}"
login_message = "{'type': 'LOGIN', 'data': "+str(rsa_encrypt(login_message_data.encode()))+"}"
# Convert json object to json string
# Send the json string after encoding it to bytes
send_message_server(login_message.encode(), SERVER_ADDR)

# Send message to another client
def send_message(username, message):
    message_json = json.dumps({"type": "MESSAGE","sender": CLIENT_USERNAME, "message": message})
    # Get the client's address (IP:Port) using username
    receiver_ip, receiver_port = get_client_addr(username) or (None, None)
    # If the user is not found in the clients list
    if receiver_ip is None:
        print("User " + username + " not found.")
        return
    client.sendto(message_json.encode(), (receiver_ip, receiver_port))

# Send list command to server
def send_list_command():
    list_json = json.dumps({"type": "LIST"})
    client.sendto(list_json.encode(), SERVER_ADDR)

# Print the list of logged in clients received from the server
def print_clients(clients_shared_keys):
    #global clients
    # Cache clients
    #clients = message_json['clients']
    #print(', '.join(str(client[0]) for client in clients))
    print(clients_shared_keys)

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
    global shared_key
    message_data_dec = ast.literal_eval(encryption.symmetrical_decrypt(message_data['data'], shared_key, message_data['iv']).decode())
    if str(message_data_dec['N1']) == N1:
        # save client list
        #print(message_data_dec)
        pass
    else:
        sys.exit("Error: Server Authentication failed!")

# Print help command output
def help():
    print("--------------------------------------------------")
    print("These are the available commands:")
    print("1. list")
    print("    -> usage: list")
    print("2. send")
    print("    -> usage: send <receiver_username> <message>")
    print("3. help")
    print("    -> usage: help")
    print("--------------------------------------------------")

# Get user input commands
#def menu():
#    while True:
#        # Split space seperated input into list of strings
#        command = input().split()
#        # command[0] is the first string
#        if command[0] == "list":
#            send_list_command()
#        elif command[0] == "send":
#            # Second string(command[1]) is the username
#            # Passing rest of the strings in the list as the message
#            send_message(command[1], ' '.join(command[2:]))
#        elif command[0] == "help":
#            help()
#        else:
#            print("Error: Invalid Command")
#            help()

# Process all incoming UDP messages
def processor():
    while True:
        #try:
        message, addr = client.recvfrom(4096)
        message_data = ast.literal_eval(message.decode())
        if message_data['type'] == 'LOGIN':
            #print(message_data)
            finish_login(message_data, addr)
        # If type of message received is LIST
        elif message_data['type'] == 'LIST':
            print_clients(ast.literal_eval(message_data['client_list']))
        # If type of message received is MESSAGE
        elif message_json['type'] == 'MESSAGE':
            print_message(message_json, addr)
        # Print error message and stop the program
        elif message_json['type'] == 'ERROR':
            print("ERROR: " + message_json['message'])
            break
        #except:
        #    print("Error: Error reading incoming message.")

processor()

# Running menu and processor as different threads
#t1 = threading.Thread(target=menu)
#t2 = threading.Thread(target=processor)
#t1.daemon = True
#t1.start()
#t2.start()
#t2.join()