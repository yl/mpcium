# Mpcium Deployment Guide

This directory contains deployment scripts and configurations for Mpcium MPC (Multi-Party Computation) nodes.

## Overview

Mpcium is a distributed threshold cryptographic system that requires multiple nodes to collaborate for secure operations. This deployment guide covers setting up a production-ready MPC cluster.

## Quick Start (Recommended)

For automated deployment, use the setup script:

```bash
sudo ./setup-config.sh
```

This script handles all configuration, permissions, and service setup automatically.

## Prerequisites

### Infrastructure Requirements

- **Minimum 3 nodes** (cloud-based, ARM architecture preferred)
- **Linux** distribution
- **Network connectivity** between all nodes
- **External services**: NATS message broker, Consul service discovery

### Software Dependencies

- **Go 1.25+** on all nodes
- **Git** for source code management
- **NATS server** with credentials
- **Consul** for service discovery
- **mkcert** for TLS certificate generation

### Deployment

Follow these steps for manual deployment across your cluster:

#### Step 1: Prepare Environment

```bash
# Install Mpcium binaries
sudo make install

# Create system user and directories
sudo useradd -r -s /bin/false -d /opt/mpcium -c "Mpcium MPC Node" mpcium
sudo mkdir -p /opt/mpcium /etc/mpcium
```

#### Step 2: Configure Permissions

```bash
# Application data directories (service-owned)
sudo chown -R mpcium:mpcium /opt/mpcium
sudo chmod g+s /opt/mpcium
sudo chmod 750 /opt/mpcium

# Configuration directory (root-controlled, service-readable)
sudo chown root:mpcium /etc/mpcium
sudo chmod 750 /etc/mpcium
```

#### Step 3: Generate Peer Configuration

On **one designated node** only:

```bash
cd /opt/mpcium
mpcium-cli generate-peers -n 3
```

#### Step 4: Copy Config and Update Configuration

```bash
# Copy configuration template
cp ~/mpcium/config.prod.yaml.template /etc/mpcium/config.yaml
# Set proper configuration permissions
sudo chown root:mpcium /etc/mpcium/config.yaml
sudo chmod 640 /etc/mpcium/config.yaml
```

Edit `/etc/mpcium/config.yaml` to include:

- NATS server connection details and credentials
- Consul service discovery configuration
- MPC threshold settings (`mpc_threshold`)
- Event initiator public key (will be updated in Step 5)

#### Step 5: Generate Event Initiator Key

On **one designated node** only:

```bash
mpcium-cli generate-initiator --encrypt
```

⚠️ **Important**: 
- This creates an encrypted private key file with `.key.age` extension that you'll need to securely distribute to application nodes that initiate MPC operations
- Copy the public key from `initiator_identity.json` and update the `event_initiator_pubkey` field in `/etc/mpcium/config.yaml` on **all nodes**

#### Step 6: Configure Each Node

```bash
# Register peers
mpcium-cli register-peers

# Generate node identity (with encryption)
mpcium-cli generate-identity --encrypt
```

#### Step 7: Generate TLS Certificates

#### Step 8: Configure Database Encryption

```bash
cd ~/mpcium/deployments
./setup-mpcium-cred.sh
# Enter BadgerDB password when prompted
# ⚠️ IMPORTANT: Backup password to secure storage (e.g., Bitwarden)
```

#### Step 9: Deploy Service

```bash
sudo ./setup-config.sh
```

#### Step 10: Verify Deployment

```bash
# Check service status
sudo systemctl status mpcium

# Monitor logs
journalctl -f -u mpcium
```

## Directory Structure

After deployment, the following directory structure is created:

```
/opt/mpcium/           # Application home (mpcium:mpcium, 750)
├── db/                # BadgerDB storage (auto-created)
├── backups/           # Encrypted backups (auto-created)
├── identity/          # Node identity files (auto-created)
└── .env               # Environment variables

/etc/mpcium/           # Configuration (root:mpcium, 750)
└── config.yaml        # Main configuration (root:mpcium, 640)
```

## Security Considerations

### File Permissions

- Configuration files are **root-controlled** to prevent tampering
- Application data is **service-owned** for runtime access
- Database encryption is **mandatory** in production

### Network Security

- All inter-node communication uses **Ed25519 signatures**
- Message payloads encrypted with **ECDH key exchange**
- TLS required for NATS connections

### Systemd Security

The service runs with enhanced security:

- **Non-privileged user** (`mpcium`)
- **Read-only** configuration directory
- **Private temp** directory
- **System call filtering**
- **Capability restrictions**

## Monitoring and Maintenance

### Service Management

```bash
# Service status
sudo systemctl status mpcium

# Start/stop/restart
sudo systemctl start mpcium
sudo systemctl stop mpcium
sudo systemctl restart mpcium

# View logs
journalctl -u mpcium
journalctl -f -u mpcium  # Follow logs
```

### Health Checks

The deployment includes Consul-based health monitoring. Check cluster health via your Consul UI.

### Backup Management

BadgerDB automatically creates encrypted backups in `/opt/mpcium/backups/`. Ensure regular backup of:

- Database encryption password
- Node identity files
- Configuration files

## Troubleshooting

### Common Issues

**Service won't start:**

```bash
# Check service logs
journalctl -u mpcium --no-pager

# Verify configuration
sudo ./setup-config.sh verify
```

**Network connectivity:**

- Verify NATS and Consul connectivity
- Check firewall rules between nodes
- Validate TLS certificates

### Log Analysis

Service logs are available via systemd journal:

```bash
# Recent logs
journalctl -u mpcium -n 100

# Logs since specific time
journalctl -u mpcium --since "1 hour ago"

# Filter by log level
journalctl -u mpcium -p err
```
