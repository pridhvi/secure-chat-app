import os

class LoggedInClient:

    def __init__(self, username, addr, server_shared_key, N2):
        self.username = username
        self.addr = addr
        self.server_shared_key = server_shared_key
        self.N2 = N2
        self.clients_shared_keys = {}
        self.clients_addr = {}
    
    def update_clients_shared_keys(self, username, key, addr):
        self.clients_shared_keys[username] = key
        self.clients_addr[username] = addr
        #print(self.clients_shared_keys)
        #print(self.clients_addr)