# Maestro Activation Server

A secure, hardware-based licensing and anti-tampering system for the Maestro Captive Portal IoT devices. This server centralizes device activation, license validation, and provides multi-layered protection against piracy and unauthorized use.

## Overview

The Maestro Activation Server implements a comprehensive anti-tampering and licensing system designed for commercial IoT deployment. It provides:

- **Hardware-bound licensing** tied to unique device fingerprints
- **Centralized activation** server for device validation
- **Multi-layered security** with buried secrets and obfuscation
- **Rate limiting and monitoring** for security events
- **SQLite database** for license and device management
- **RESTful API** for device-server communication

## Architecture

```
┌─────────────────┐    HTTPS/HTTP     ┌─────────────────┐
│   IoT Device    │ ◄──────────────► │ Activation      │
│                 │                  │ Server          │
│ • Hardware ID   │                  │                 │
│ • License Key   │                  │ • SQLite DB     │
│ • Buried Secrets│                  │ • Rate Limiting │
│ • Client Library│                  │ • Audit Logs    │
└─────────────────┘                  └─────────────────┘
```

## Features

### 🔐 **Hardware-Based Security**
- Unique hardware fingerprinting from MAC, CPU serial, board serial
- Cryptographic binding of licenses to specific hardware
- Multiple buried secret locations throughout the system
- Anti-debugging and VM detection

### 🌐 **Centralized License Management**
- RESTful API for device registration and activation
- SQLite database with comprehensive device tracking
- License key generation with hardware binding
- Activation token system with expiration

### 🛡️ **Anti-Tampering Protection**
- Secrets distributed across multiple system locations
- Obfuscated configuration storage
- Integrity checking and tamper detection
- Decoy files to mislead reverse engineering

### 📊 **Monitoring and Security**
- Rate limiting with IP-based blocking
- Comprehensive audit logging
- Security event tracking
- Failed activation attempt monitoring

## Project Structure

```
activation/
├── server/                 # Activation server (C++ Drogon)
│   ├── src/               # Server source code
│   ├── include/           # Header files
│   └── CMakeLists.txt     # Build configuration
├── client/                # Device activation client
│   ├── activation_client.h
│   └── activation_client.cpp
├── database/              # Database schema and management
│   └── schema.sql         # SQLite database schema
├── config/                # Configuration files
│   └── server.conf        # Server configuration
├── scripts/               # Installation and maintenance
│   └── install.sh         # Server installation script
├── keys/                  # SSL certificates (generated)
├── logs/                  # Server logs
└── README.md              # This file
```

## API Endpoints

### Device Management
- `POST /api/v1/register` - Register new device with hardware ID
- `POST /api/v1/activate` - Activate device with license key
- `POST /api/v1/validate` - Validate activation token
- `GET /api/v1/status/{hardware_id}` - Get device status
- `POST /api/v1/deactivate` - Deactivate device

### Server Status
- `GET /api/v1/server/status` - Server health check
- `GET /api/v1/history/{hardware_id}` - Activation history

## Installation

### Prerequisites
- Debian/Ubuntu Linux system
- Root access for system integration
- Internet connection for dependencies

### Quick Install
```bash
cd activation/
chmod +x scripts/install.sh
sudo ./scripts/install.sh
```

### Manual Installation
```bash
# Install dependencies
sudo apt-get update
sudo apt-get install build-essential cmake libssl-dev libjsoncpp-dev libsqlite3-dev libcurl4-openssl-dev

# Install Drogon framework
git clone https://github.com/drogonframework/drogon.git
cd drogon && mkdir build && cd build
cmake .. && make -j$(nproc) && sudo make install

# Build activation server
cd activation/
mkdir build && cd build
cmake .. && make -j$(nproc)
sudo make install
```

## Configuration

### Server Configuration
Edit `/opt/maestro/activation/config/server.conf`:

```ini
[server]
bind_address = 0.0.0.0
http_port = 8080
https_port = 8443

[security]
rate_limit_requests = 10
rate_limit_window_minutes = 15
token_validity_hours = 24

[database]
database_path = /opt/maestro/activation/database/activation.db
```

### SSL Certificates
Self-signed certificates are generated automatically. For production:

```bash
# Replace with your own certificates
sudo cp your.crt /opt/maestro/activation/keys/server.crt
sudo cp your.key /opt/maestro/activation/keys/server.key
sudo chown maestro-activation:maestro-activation /opt/maestro/activation/keys/*
```

## Usage

### Starting the Server
```bash
sudo systemctl start maestro-activation
sudo systemctl enable maestro-activation  # Auto-start on boot
```

### Monitoring
```bash
# Check service status
sudo systemctl status maestro-activation

# View logs
sudo journalctl -u maestro-activation -f

# Test API endpoints
curl http://localhost:8080/api/v1/server/status
```

### Device Integration
```cpp
#include "activation_client.h"

ActivationClient client;
if (client.initialize()) {
    if (client.performActivation()) {
        std::cout << "Device activated successfully" << std::endl;
    }
}
```

## Security Features

### Hardware Fingerprinting
The system generates unique hardware IDs from:
- Primary network interface MAC address
- CPU serial number from `/proc/cpuinfo`
- Board serial from DMI/device-tree
- System UUID

### Secret Burial Locations
Activation secrets are distributed across:
- SystemD service configuration files
- Hidden cache directories
- Obfuscated registry-like storage
- Multiple decoy locations

### Anti-Tampering Measures
- VM and debugger detection
- Integrity checking of critical files
- Rate limiting to prevent brute force
- Comprehensive audit logging

## Database Schema

The SQLite database includes tables for:
- `devices` - Registered hardware and licenses
- `activation_log` - All activation attempts
- `rate_limits` - IP-based rate limiting
- `security_events` - Security monitoring
- `license_keys` - Pre-generated licenses
- `audit_log` - Administrative actions

## Development

### Building
```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)
```

### Testing
```bash
# Test hardware ID extraction
./test_hardware_id

# Test activation flow
curl -X POST http://localhost:8080/api/v1/register \
  -H "Content-Type: application/json" \
  -d '{"hardware_id":"test-hw-id","device_name":"Test Device"}'
```

## Production Deployment

### Security Hardening
1. Replace default encryption keys in source code
2. Use proper SSL certificates from trusted CA
3. Configure firewall to limit access
4. Enable SELinux/AppArmor policies
5. Regular security updates

### Monitoring Setup
- Configure log aggregation (ELK stack, etc.)
- Set up alerting for security events
- Monitor database growth and performance
- Regular backup of activation database

## Troubleshooting

### Common Issues

**Service won't start:**
```bash
# Check logs for errors
sudo journalctl -u maestro-activation -n 50

# Verify permissions
sudo ls -la /opt/maestro/activation/
```

**Database connection errors:**
```bash
# Check database file permissions
sudo ls -la /opt/maestro/activation/database/

# Test database manually
sudo -u maestro-activation sqlite3 /opt/maestro/activation/database/activation.db ".tables"
```

**SSL certificate errors:**
```bash
# Regenerate certificates
sudo openssl genrsa -out /opt/maestro/activation/keys/server.key 2048
sudo openssl req -new -x509 -key /opt/maestro/activation/keys/server.key \
  -out /opt/maestro/activation/keys/server.crt -days 3650
```

## License

Commercial licensing system for Maestro Captive Portal devices.

## Contributing

This is a proprietary security system. External contributions are not accepted to maintain security integrity.

## Support

For technical support and licensing inquiries, contact the Maestro development team.