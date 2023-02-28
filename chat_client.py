import socket, threading, argparse, random, sys, hashlib, os, base64, encryption, ast, dh_exchange, time, getpass, atexit
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Argument parser
parser = argparse.ArgumentParser()
parser.add_argument('-sip',type=str, required=True)
#parser.add_argument('-sp',type=int, required=True)
args = parser.parse_args()

# Constants
# Choose a random port between 8000-9000 for the client socket
CLIENT_PORT = random.randint(8000, 9000)
#CLIENT_PORT = 4000
CLIENT_IP = socket.gethostbyname(socket.gethostname())
CLIENT_USERNAME = input("Username: ")
CLIENT_PASSWORD = getpass.getpass("Password: ")
CLIENT_ADDR = (CLIENT_IP, CLIENT_PORT)
SERVER_ADDR = (args.sip, 3000)
N2 = ""
N3 = ""
a = 0
b = 0
p = 0

# Stores shared keys with other logged in clients
clients_shared_keys = {}
# Stores IP, Port of other logged in clients
clients_addr = {}
# Stores the DH derived keys (used to send texts) of other logged in clients
clients_dh_keys = {}

# Create client socket
try:
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(CLIENT_ADDR)
except:
    sys.exit("Error: Unable to open UDP socket at port " + str(CLIENT_PORT))

# Send a message to a specific address (IP, Port)
def send_message(message, addr):
    client.sendto(message, addr)

# RSA encryption using server's public key
def rsa_encrypt(message):
    server_public_key = extract_server_public_key()
    try:
        return server_public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except:
        sys.exit("Error: RSA encryption of the message failed.")

# Reading Server's public key from file
def extract_server_public_key():
    try:
        with open("server_pub.pem", "rb") as file:
            server_public_key = serialization.load_pem_public_key(file.read())
    except:
        sys.exit("Error: Reading Server Public Key failed.")
    return server_public_key

# Log-In to the server
# Calculate SHA256 hash of the user's password
sha256_password = hashlib.sha256(CLIENT_PASSWORD.encode())
N1 = str(os.urandom(10))
# Ephemeral symmetric key between client and server
shared_key = os.urandom(32)
# Draft a login message in the format of a dictionary which is sent as a encoded string
login_message_data = "{'username': '"+CLIENT_USERNAME+"', 'password_hash': '"+sha256_password.hexdigest()+"', 'N1': "+N1+", 'shared_key': "+str(shared_key)+"}"
login_message = "{'type': 'LOGIN', 'data': "+str(rsa_encrypt(login_message_data.encode()))+"}"
send_message(login_message.encode(), SERVER_ADDR)

# Send message to another client
def send_message_to_client(username, text):
    # Check if the user is logged in before sending message
    if not clients_addr.get(username):
        print("Error: User does not exist.")
        return
    # If there is no existing DH derived key between the two clients
    if not clients_dh_keys.get(username):
        # Start the DH key echange
        initiate_dh_handshake(username)
        # Wait a total of 60 seconds for DH exhange to complete
        for i in range(10):
            # Check if DH derived is generated every 6 seconds
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
    # Send the message to the client
    send_message(message.encode(), clients_addr[username])

# Start the DH exchange
def initiate_dh_handshake(username):
    #print("Generating keys for first communication with " + username)
    global a, p
    gamodp, g, p, a = dh_exchange.send_dh_parameters()
    # Shared key between the clients received from the server
    client_shared_key = clients_shared_keys[username]
    client_addr = clients_addr[username]
    # Send gamodp, g, and p (values for DH) to the client encrypted with the shared key
    data = "{'receiver-username': '"+username+"', 'g': "+str(g)+", 'p': "+str(p)+", 'gamodp': "+str(gamodp)+"}"
    data_enc, iv = encryption.symmetrical_encrypt(data.encode(), client_shared_key)
    # Send the first message of the DH exchange to the client
    message = "{'type': 'DH-HANDSHAKE-1', 'sender-username': '"+str(CLIENT_USERNAME)+"', 'data': "+str(data_enc)+", 'iv': "+str(iv)+"}"
    send_message(message.encode(), client_addr)

# Receive DH handshake from initiator
def receive_dh_handshake(message_data, addr):
    # Decrypt the DH values from incoming message
    message_data, data = extract_dh_data(message_data)
    global b
    gbmodp, b = dh_exchange.receive_dh_parameters(data['g'], data['p'])
    # Calculate the derived key using all the DH values
    calculate_dh_derived_key_receiver(data['gamodp'], data['p'], message_data['sender-username'])
    # Send back gbmodp to the initiator client for them to calculate the derived key
    data = "{'receiver-username': '"+message_data['sender-username']+"', 'gbmodp': "+str(gbmodp)+"}"
    data_enc, iv = encryption.symmetrical_encrypt(data.encode(), clients_shared_keys[message_data['sender-username']])
    
    message = "{'type': 'DH-HANDSHAKE-2', 'sender-username': '"+str(CLIENT_USERNAME)+"', 'data': "+str(data_enc)+", 'iv': "+str(iv)+"}"
    send_message(message.encode(), addr)

def extract_dh_data(message_data):
    # Shared key between the clients received from the server
    client_shared_key = clients_shared_keys[message_data['sender-username']]
    # Decrypt the DH values using shared key
    data_dec = encryption.symmetrical_decrypt(message_data['data'], client_shared_key, message_data['iv'])
    data = ast.literal_eval(data_dec.decode())

    if str(data['receiver-username']) != CLIENT_USERNAME:
        sys.exit("Error: Messaging")
    return message_data, data

# The DH exchange receiver calculates the derived key
def calculate_dh_derived_key_receiver(gamodp, p, username):
    global b
    derived_key = pow(gamodp, b, p)
    derived_key = hashlib.sha256(str(derived_key).encode())
    # Store the derived key in the clients_dh_keys dictionary
    clients_dh_keys[username] = derived_key

# The DH exchange initiator calculates the derived key
def calculate_dh_derived_key_sender(gbmodp, p, username):
    global a
    derived_key = pow(gbmodp, a, p)
    derived_key = hashlib.sha256(str(derived_key).encode())
    # Store the derived key in the clients_dh_keys dictionary
    clients_dh_keys[username] = derived_key

# Update the client lists when server sends the updated list
def update_clients(data):
    global clients_shared_keys, clients_addr
    clients_shared_keys = data['clients_shared_keys']
    clients_addr = data['clients_addr']

# Print the list of clients and address for the list command
def print_clients():
    global clients_addr
    if len(clients_addr) == 1:
        print("No other logged in users.")
        return
    for username, addr in clients_addr.items():
        if not username == CLIENT_USERNAME:
            print(username + " --> " + str(addr))

# Print the incoming message after decrypting and verifying it
def print_message(message_data):
    client_dh_key = clients_dh_keys[message_data['sender-username']]

    # Verify HMAC of the incoming message
    h = hmac.HMAC(client_dh_key.digest(), hashes.SHA256())
    h.update(message_data['data'])
    h.verify(message_data['signature'])
    # Decrypt the message using the DH derived key common between the clients
    data_dec = encryption.symmetrical_decrypt(message_data['data'], client_dh_key.digest(), message_data['iv'])
    data = ast.literal_eval(data_dec.decode())

    if str(data['receiver-username']) != CLIENT_USERNAME:
        raise Exception
            
    print(str(message_data['sender-username']) + ": " + str(data['text']))

# Complete the login after receiving the second login message from server
def finish_login(message_data, addr):
    global shared_key, N2
    message_data_dec = ast.literal_eval(encryption.symmetrical_decrypt(message_data['data'], shared_key, message_data['iv']).decode())
    # Check if N1 is same to authenticate the server
    if str(message_data_dec['username']) == CLIENT_USERNAME and str(message_data_dec['N1']) == N1:
        N2 = message_data_dec['N2']
        help()
    else:
        sys.exit("Error: Server Authentication failed!")

# Send logout request to server
def logout():
    global N2, N3
    N3 = os.urandom(10)
    data = "{'username': '"+CLIENT_USERNAME+"', 'N2': "+str(N2)+", 'N3': "+str(N3)+"}"
    message = "{'type': 'LOGOUT', 'data': "+str(rsa_encrypt(data.encode()))+"}"
    send_message(message.encode(), SERVER_ADDR)

# Delete client data from memory to avoid future attacks
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
            try:
                send_message_to_client(command[1], ' '.join(command[2:]))
            except:
                print("Error: Failed to send message.")
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
        message, addr = client.recvfrom(4096)
        # Converts the message string into a dictionary
        message_data = ast.literal_eval(message.decode())
        # If type of message received is LOGIN
        if message_data['type'] == 'LOGIN':
            try:
                finish_login(message_data, addr)
            except:
                sys.exit("Error: Login failed.")

        # If type of message received is LIST
        elif message_data['type'] == 'LIST':
            try:
                # Derypts and converts the message_data['data'] string into a dictionary
                data = ast.literal_eval(encryption.symmetrical_decrypt(message_data['data'], shared_key, message_data['iv']).decode())
                update_clients(data)
            except:
                print("Error: Failed to retrieve list.")

        # If type of message received is DH-HANDSHAKE-1
        elif message_data['type'] == 'DH-HANDSHAKE-1':
            try:
                receive_dh_handshake(message_data, addr)
            except:
                print("Error: Incoming DH Handshake Failed.")
        # If type of message received is DH-HANDSHAKE-2
        elif message_data['type'] == 'DH-HANDSHAKE-2':
            try:
                _, data = extract_dh_data(message_data)
                global p
                calculate_dh_derived_key_sender(data['gbmodp'], p, message_data['sender-username'])
            except:
                print("Error: DH Handshake Failed.")
        # If type of message received is MESSAGE
        elif message_data['type'] == 'MESSAGE':
            try:
                print_message(message_data)
            except:
                print("Error: Failed to receive message from " + message_data['sender-username'])
        # If type of message received is LOGOUT
        elif message_data['type'] == 'LOGOUT':
            try:
                data_dec = encryption.symmetrical_decrypt(message_data['data'], shared_key, message_data['iv'])
                data = ast.literal_eval(data_dec.decode())

                if str(data['username']) != CLIENT_USERNAME:
                    raise Exception

                global N3
                if str(data['N3']) == str(N3):
                    # Removing all the saved data of client from memory
                    remove_data()
                    print("Logged out successfully!")
            except:
                print("Error: Logout failed.")
                sys.exit()
            finally:
                sys.exit()
        # Print error message and stop the program
        elif message_data['type'] == 'ERROR':
            print("ERROR: " + message_data['message'])
            break

# Initiate logout if the application exits
def exit_handler():
    try:
        N2
    except NameError:
        pass
    else:
        logout()

atexit.register(exit_handler)

# Running menu and receiver as different threads
t1 = threading.Thread(target=menu)
t2 = threading.Thread(target=receiver)
t1.daemon = True
t1.start()
t2.start()
t2.join()
