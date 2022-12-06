# udp-chat-python
A console based chat application implemented with self-designed protocols.

## SERVER

Command

`python3 chat_server.py -sp <port>`

## CLIENT

Command

`python3 chat_client.py -sip <server-ip> -sp <server-port>`

## Information

Server keys (RSA) are included as the files server_priv.key and server_pub.key. Clients and server use these keys to communicate confidentially. Please generate new RSA key pair for your usage.

There are three clients in the server. Only those three clients can login (There is no registration function). The credentials for those clients are as follows:

### Client 1
Username: pridhvi

Password: @iCVqx5^142E
### Client 2
Username: animish

Password: #0v2^WZuT&33
### Client 3
Username: virat

Password: %Ja5cji4s!fQ

Type "help" to get a list of commands

The client will start running at a random port between 8000 and 9000.
