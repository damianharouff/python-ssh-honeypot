# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a simple SSH honeypot that logs connection attempts and credential attempts to a Graylog server via GELF UDP. It always rejects authentication.

## Dependencies

- Python 3
- paramiko (installed via venv)
- graypy (installed via venv; `python3-graypy` was removed in Debian 12+)

## Configuration

The honeypot reads from `/opt/honeypot/config.json` by default. See `config.json.example` for format.

Command-line arguments override config file values:

| Option | Description |
|--------|-------------|
| `-c, --config` | Path to JSON config file |
| `-k, --key` | Path to RSA host key |
| `-p, --port` | SSH port to listen on |
| `--gelf-host` | Graylog GELF UDP host |
| `--gelf-port` | Graylog GELF UDP port |

## Systemd Deployment

```bash
# Create dedicated user
useradd -r -s /usr/sbin/nologin honeypot

# Setup directory
mkdir -p /opt/honeypot
cp honeypot.py /opt/honeypot/
cp config.json.example /opt/honeypot/config.json
# Edit config.json with your settings
ssh-keygen -t rsa -f /opt/honeypot/server.key -N ''

# Create venv and install dependencies
python3 -m venv /opt/honeypot/venv
/opt/honeypot/venv/bin/pip install paramiko graypy

chown -R honeypot:honeypot /opt/honeypot
chmod 600 /opt/honeypot/server.key

# Install and enable service
cp honeypotpy.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now honeypotpy
```

## Architecture

Single-file honeypot using:
- `paramiko.ServerInterface` subclass (`SSHServerHandler`) that always returns `AUTH_FAILED`
- JSON config file with command-line overrides
- `threading.Thread` for each connection
- Graceful shutdown via SIGINT/SIGTERM

## Logged Data (GELF)

Each SSH login attempt logs to Graylog with:
- `source_ip`: Attacker's IP address
- `source_port`: Attacker's source port
- `username`: Attempted username
- `password`: Attempted password
