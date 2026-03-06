#!/usr/bin/env python3
import argparse
import json
import logging
import os
import signal
import socket
import sys
import threading

import paramiko  # apt install python3-paramiko
import graypy  # apt install python3-graypy

# Default configuration
DEFAULTS = {
    'key_path': '/opt/honeypot/server.key',
    'ssh_port': 22,
    'gelf_host': 'localhost',
    'gelf_port': 12201,
}

# Limits
MAX_CREDENTIAL_LENGTH = 200
TRANSPORT_TIMEOUT = 30
SSH_BANNER = 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6'

# Global flag for graceful shutdown
shutdown_event = threading.Event()


def load_config(config_path):
    """Load configuration from JSON file."""
    config = DEFAULTS.copy()
    if config_path and os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                file_config = json.load(f)
                config.update(file_config)
            print(f'Loaded configuration from {config_path}')
        except json.JSONDecodeError as e:
            print(f'ERROR: Invalid JSON in config file: {e}')
            sys.exit(1)
        except IOError as e:
            print(f'ERROR: Could not read config file: {e}')
            sys.exit(1)
    elif config_path:
        print(f'ERROR: Config file not found: {config_path}')
        sys.exit(1)
    return config


def setup_logger(gelf_host, gelf_port):
    """Configure and return the Graylog logger."""
    logger = logging.getLogger('python-ssh-honeypot')
    logger.setLevel(logging.INFO)
    handler = graypy.GELFUDPHandler(gelf_host, gelf_port, debugging_fields=False)
    logger.addHandler(handler)
    return logger


class SSHServerHandler(paramiko.ServerInterface):
    def __init__(self, client_addr, logger):
        self.client_addr = client_addr
        self.logger = logger
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        return 'password'

    def check_auth_password(self, username, password):
        # Log the credential attempt with source IP
        self.logger.info(
            'SSH login attempt',
            extra={
                'source_ip': self.client_addr[0],
                'source_port': self.client_addr[1],
                'username': username[:MAX_CREDENTIAL_LENGTH],
                'password': password[:MAX_CREDENTIAL_LENGTH],
            }
        )
        return paramiko.AUTH_FAILED


def handle_connection(client_socket, client_addr, host_key, logger):
    """Handle a single SSH connection."""
    transport = None
    try:
        transport = paramiko.Transport(client_socket)
        transport.local_version = SSH_BANNER
        transport.add_server_key(host_key)
        transport.set_keepalive(TRANSPORT_TIMEOUT)
        server_handler = SSHServerHandler(client_addr, logger)
        transport.start_server(server=server_handler)

        # Wait for a channel request with timeout
        channel = transport.accept(1)
        if channel is not None:
            channel.close()

    except paramiko.SSHException as e:
        logger.warning(
            'SSH exception during connection handling',
            extra={
                'source_ip': client_addr[0],
                'error': str(e),
            }
        )
    except Exception as e:
        logger.error(
            'Unexpected error during connection handling',
            extra={
                'source_ip': client_addr[0],
                'error': str(e),
            }
        )
    finally:
        if transport is not None:
            transport.close()


def signal_handler(signum, frame):
    """Handle shutdown signals gracefully."""
    print(f'\nReceived signal {signum}, shutting down...')
    shutdown_event.set()


def main():
    parser = argparse.ArgumentParser(description='SSH Honeypot Server')
    parser.add_argument(
        '-c', '--config',
        default='/opt/honeypot/config.json',
        help='Path to JSON config file (default: /opt/honeypot/config.json)'
    )
    parser.add_argument(
        '-k', '--key',
        help='Path to RSA host key (overrides config file)'
    )
    parser.add_argument(
        '-p', '--port',
        type=int,
        help='SSH port to listen on (overrides config file)'
    )
    parser.add_argument(
        '--gelf-host',
        help='Graylog GELF UDP host (overrides config file)'
    )
    parser.add_argument(
        '--gelf-port',
        type=int,
        help='Graylog GELF UDP port (overrides config file)'
    )
    args = parser.parse_args()

    # Load config file
    config = load_config(args.config)

    # Command-line arguments override config file
    if args.key:
        config['key_path'] = args.key
    if args.port is not None:
        config['ssh_port'] = args.port
    if args.gelf_host:
        config['gelf_host'] = args.gelf_host
    if args.gelf_port is not None:
        config['gelf_port'] = args.gelf_port

    # Setup signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Load host key
    try:
        host_key = paramiko.RSAKey(filename=config['key_path'])
    except FileNotFoundError:
        print(f"ERROR: Host key not found at {config['key_path']}")
        print("Generate one with: ssh-keygen -t rsa -f server.key")
        sys.exit(1)
    except paramiko.SSHException as e:
        print(f"ERROR: Failed to load host key: {e}")
        sys.exit(1)

    # Setup logger
    logger = setup_logger(config['gelf_host'], config['gelf_port'])
    print(f"Logging to {config['gelf_host']}:{config['gelf_port']}")

    # Create server socket
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.settimeout(1.0)  # Allow periodic check of shutdown_event
        server_socket.bind(('', config['ssh_port']))
        server_socket.listen(100)
        print(f"SSH Honeypot Server started on port {config['ssh_port']}")
    except OSError as e:
        print(f"ERROR: Failed to create socket: {e}")
        sys.exit(1)

    # Main accept loop
    try:
        while not shutdown_event.is_set():
            try:
                client_socket, client_addr = server_socket.accept()
                print(f'Connection received from: {client_addr[0]}:{client_addr[1]}')

                # Start handler thread
                thread = threading.Thread(
                    target=handle_connection,
                    args=(client_socket, client_addr, host_key, logger),
                    daemon=True
                )
                thread.start()

            except socket.timeout:
                # This is expected - allows checking shutdown_event
                continue
            except OSError as e:
                if not shutdown_event.is_set():
                    print(f"ERROR: Client handling failed: {e}")

    finally:
        server_socket.close()
        print('SSH Honeypot Server stopped.')


if __name__ == '__main__':
    main()
