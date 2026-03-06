# Graylog SSH Honeypot

A lightweight SSH honeypot that logs connection attempts and credentials to Graylog via GELF UDP.

## Features

- Captures SSH login attempts (username/password)
- Logs to Graylog via GELF UDP protocol
- Runs as non-root user with minimal privileges
- JSON configuration file
- Graceful shutdown handling

## Requirements

- Python 3
- paramiko
- graypy

Dependencies are installed via a Python venv (see Deployment below). The `python3-graypy` Debian package is no longer available in Debian 12+.

## Configuration

Create a `config.json` file:

```json
{
    "key_path": "/opt/honeypot/server.key",
    "ssh_port": 22,
    "gelf_host": "graylog.example.com",
    "gelf_port": 12201
}
```

Command-line options override config file values:

```
-c, --config    Path to config file (default: /opt/honeypot/config.json)
-k, --key       Path to RSA host key
-p, --port      SSH port to listen on
--gelf-host     Graylog GELF UDP host
--gelf-port     Graylog GELF UDP port
```

## Deployment

**Never run as root.** Use the systemd service which runs as a dedicated user with minimal privileges.

### 1. Create Honeypot User

Create a system user with no login shell:

```bash
sudo useradd -r -s /usr/sbin/nologin honeypot
```

### 2. Install Files

```bash
sudo mkdir -p /opt/honeypot
sudo cp honeypot.py /opt/honeypot/
sudo cp config.json.example /opt/honeypot/config.json
```

### 3. Create Venv and Install Dependencies

```bash
sudo python3 -m venv /opt/honeypot/venv
sudo /opt/honeypot/venv/bin/pip install paramiko graypy
```

### 4. Generate SSH Host Key

```bash
sudo ssh-keygen -t rsa -f /opt/honeypot/server.key -N ''
```

### 5. Configure

Edit `/opt/honeypot/config.json` with your Graylog server:

```bash
sudo nano /opt/honeypot/config.json
```

```json
{
    "key_path": "/opt/honeypot/server.key",
    "ssh_port": 22,
    "gelf_host": "your-graylog-server.example.com",
    "gelf_port": 12201
}
```

### 6. Set Permissions

```bash
sudo chown -R honeypot:honeypot /opt/honeypot
sudo chmod 600 /opt/honeypot/server.key
sudo chmod 600 /opt/honeypot/config.json
```

### 7. Install Systemd Service

```bash
sudo cp honeypotpy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable honeypotpy
sudo systemctl start honeypotpy
```

### 8. Verify

```bash
sudo systemctl status honeypotpy
sudo journalctl -u honeypotpy -f
```

### Security Notes

The systemd unit is hardened with:
- `CAP_NET_BIND_SERVICE` capability to bind port 22 without root
- `ProtectSystem=strict` - read-only filesystem
- `PrivateTmp=yes` - isolated /tmp namespace
- `NoNewPrivileges=yes` - prevents privilege escalation
- `ProtectKernelTunables=yes` - blocks kernel parameter modification

## Logged Data

Each authentication attempt sends a GELF message with:

| Field | Description |
|-------|-------------|
| `source_ip` | Attacker's IP address |
| `source_port` | Attacker's source port |
| `username` | Attempted username |
| `password` | Attempted password |

## Graylog Setup

1. Create a GELF UDP input in Graylog (System → Inputs)
2. Set the port to 12201 (or your chosen port)
3. Configure firewall to allow UDP traffic on the GELF port

## Bug Bounty

A small bug bounty is offered if you are able to authenticate or otherwise get to a shell or upload files into the user's home directory. The bug must be specifically related to this script; vulnerabilities in Python or Paramiko will not be accepted.

Reports must include the specific commit ID and instructions to replicate the vulnerability for that commit. Only vulnerabilities in the most recent commit will be accepted.

Keeping in mind this is toy software automatically built by a machine, please keep your expectations for bounty payout reasonable. Contact information for the author is easy to find; consider it part of the hunt, especially if you fashion yourself as a security researcher.
