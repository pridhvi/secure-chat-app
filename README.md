# Secure Chat Application
A console based chat application implemented with self-designed authentication protocols entirely functioning using UDP.

## Run the python files
### SERVER

`python3 chat_server.py`

### CLIENT

`python3 chat_client.py -sip <server-ip>`

## Run as Docker Containers
### SERVER

`docker run --name chat-server --rm -d pridhvi/chat-server`

### CLIENT
`docker run -it --rm -e serverip=<server-ip> pridhvi/chat-client`

## Build Docker Images
### SERVER

`docker build --no-cache -t pridhvi/chat-server -f Dockerfile_Server .`

### CLIENT
`docker build --no-cache -t pridhvi/chat-client -f Dockerfile_Client .`

## Additional Information

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
