#!/usr/bin/env python3
import socket, sys, threading
import _thread as thread
import paramiko # apt install python3-paramiko
import logging
import graypy # apt install python3-graypy

# generate key with 'ssh-keygen -t rsa -f server.key'
HOST_KEY = paramiko.RSAKey(filename='/root/honeypot/server.key')
SSH_PORT = 22
GELF_UDP_HOST = 'localhost'
GELF_UDP_PORT = 12201

# =========================

my_logger = logging.getLogger('python-ssh-honeypot')
my_logger.setLevel(logging.INFO)
handler = graypy.GELFUDPHandler(GELF_UDP_HOST, GELF_UDP_PORT, debugging_fields=False)
my_logger.addHandler(handler)

class SSHServerHandler(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()
    def check_auth_password(self, username, password):
#            print("New login: " + username + ":" + password)
            return paramiko.AUTH_FAILED

def handleConnection(client):
    transport = paramiko.Transport(client)
    transport.add_server_key(HOST_KEY)
    server_handler = SSHServerHandler()
    transport.start_server(server=server_handler)
    channel = transport.accept(1)
    if not channel is None:
        channel.close()
        print('Closing connection.')

def main():
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('', SSH_PORT))
        server_socket.listen(100)
        print('SSH Honeypot Server Started.')

        while True:
            try:
                client_socket, client_addr = server_socket.accept()
                print('Connection Received From:', client_addr)
                la = logging.LoggerAdapter(logging.getLogger('python-ssh-honeypot'),{'source_ip': client_addr[0]})
                la.info("python-ssh-honeypot")
                thread.start_new_thread(handleConnection, (client_socket,))
            except Exception as e:
                print("ERROR: Client handling")
                print(e)

    except Exception as e:
        print("ERROR: Failed to create socket")
        print(e)
        sys.exit(1)

main()
