import os

# Class for all the logged in clients that the server stores
class LoggedInClient:

    def __init__(self, username, server_shared_key, addr, N2):
        self.username = username
        self.addr = addr
        self.server_shared_key = server_shared_key
        self.N2 = N2
        self.clients_shared_keys = {}
        self.clients_addr = {}
    
    def update_clients_shared_keys(self, username, key, addr):
        self.clients_shared_keys[username] = key
        self.clients_addr[username] = addr