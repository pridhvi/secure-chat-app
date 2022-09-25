import socket
import threading
import json
import argparse
import random
import sys

# Argument parser
parser = argparse.ArgumentParser()
parser.add_argument('-u',type=str, required=True)
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

# clients list to cache signed in clients
clients = []

# Create client socket
try:
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(CLIENT_ADDR)
    print("Application starting at " + str(CLIENT_IP) + ":" + str(CLIENT_PORT) + " ...")
except:
    sys.exit("Error: Unable to open UDP socket at port " + str(CLIENT_PORT))

# Sign-In to the server
# Creat a json object
signin_message = {"type": "SIGN-IN", "username": CLIENT_USERNAME}
# Conver json object to json string
signin_message_json = json.dumps(signin_message)
# Send the json string after encoding it to bytes
client.sendto(signin_message_json.encode(), SERVER_ADDR)

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

# Print the list of signed in clients received from the server
def print_clients(message_json):
    global clients
    # Cache clients
    clients = message_json['clients']
    print(', '.join(str(client[0]) for client in clients))

# Print received message with the username of the sender
# Add functionality: Can search the clients list for the username using addr
def print_message(message_json, addr):
    print(message_json['sender'] + ": " + message_json['message'])

# Get address (IP:Port) of username from clients list
def get_client_addr(username):
    for client in clients:
        if client[0] == username:
            return str(client[1][0]), client[1][1]

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
def menu():
    while True:
        # Split space seperated input into list of strings
        command = input().split()
        # command[0] is the first string
        if command[0] == "list":
            send_list_command()
        elif command[0] == "send":
            # Second string(command[1]) is the username
            # Passing rest of the strings in the list as the message
            send_message(command[1], ' '.join(command[2:]))
        elif command[0] == "help":
            help()
        else:
            print("Error: Invalid Command")
            help()

# Process all incoming UDP messages
def processor():
    while True:
        try:
            message, addr = client.recvfrom(1024)
            message_json = json.loads(message)
            # If type of message received is LIST
            if message_json['type'] == 'LIST':
                print_clients(message_json)
            # If type of message received is MESSAGE
            elif message_json['type'] == 'MESSAGE':
                print_message(message_json, addr)
            # Print error message and stop the program
            elif message_json['type'] == 'ERROR':
                print("ERROR: " + message_json['message'])
                break
        except:
            print("Error: Error reading incoming message.")

# Running menu and processor as different threads
t1 = threading.Thread(target=menu)
t2 = threading.Thread(target=processor)
t1.daemon = True
t1.start()
t2.start()
t2.join()