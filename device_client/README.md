# Maestro Device Activation Client

IoT device-side activation client for the Maestro hardware-based licensing system. This client implements comprehensive anti-tampering protection with hardware fingerprinting and deep system integration.

## Overview

The device activation client provides:

- **Hardware Fingerprinting**: Unique device identification from MAC, CPU, and board serials
- **Deep Secret Burial**: Multi-layered secret storage throughout the system
- **Anti-Tampering Protection**: VM/debugger detection and integrity checks
- **Encrypted Communication**: Secure activation requests to licensing server
- **System Integration**: Hidden configurations in SystemD, NetworkManager, D-Bus, and Udev

## Features

### 🔐 **Hardware Identification**
- MAC address extraction from network interfaces
- CPU serial from `/proc/cpuinfo`
- Board serial from DMI/device-tree
- System UUID from hardware identifiers
- Cryptographic hardware ID generation

### 🛡️ **Secret Burial Locations**
- **SystemD Configs**: `/etc/systemd/system/.maestro_hw_config/`
- **NetworkManager**: `/etc/NetworkManager/conf.d/99-maestro-hw.conf`
- **D-Bus Policy**: `/etc/dbus-1/system.d/maestro-hw-policy.conf`
- **Udev Rules**: `/etc/udev/rules.d/99-maestro-hw.rules`
- **Cache Files**: `/var/cache/maestro/.system_hw_cache`

### 🔒 **Anti-Tampering Features**
- VM detection (VMware, VirtualBox, QEMU)
- Debugger detection via `/proc/self/status`
- Hardware integrity verification
- Obfuscated configuration storage
- Multiple decoy files and paths

## Installation

### Prerequisites
```bash
# Install dependencies
sudo apt-get update
sudo apt-get install build-essential cmake libssl-dev libjsoncpp-dev libcurl4-openssl-dev
```

### Build and Install
```bash
# Clone the repository
git clone https://github.com/aamat09/maestro_activation.git
cd maestro_activation/device_client

# Build the client
mkdir build && cd build
cmake ..
make

# Install system-wide
sudo make install
```

### Manual Compilation
```bash
# Compile test program directly
g++ -std=c++17 -o test_activation \\
    test_activation.cpp maestro_activation_client.cpp \\
    -lssl -lcrypto -lcurl -ljsoncpp

# Run hardware fingerprinting test
sudo ./test_activation
```

## Usage

### Integration in IoT Applications

```cpp
#include "maestro_activation_client.h"

int main() {
    MaestroActivationClient client;

    // Initialize the client (extracts hardware fingerprint)
    if (!client.initialize()) {
        std::cerr << "Failed to initialize: " << client.getLastError() << std::endl;
        return 1;
    }

    // Bury secrets deep in the system
    client.burySecretsDeepInSystem();

    // Perform activation with server
    if (client.performFullActivation()) {
        std::cout << "Device activated successfully!" << std::endl;
    } else {
        std::cerr << "Activation failed: " << client.getLastError() << std::endl;
        return 1;
    }

    // Validate activation status
    if (client.isDeviceActivated() && client.validateActivation()) {
        std::cout << "Device is properly activated and validated" << std::endl;
        // Continue with normal application logic
    } else {
        std::cerr << "Device activation validation failed" << std::endl;
        return 1;
    }

    return 0;
}
```

### Configuration

The client automatically configures itself but you can customize:

1. **Activation Server URL**: Modify the buried configuration:
   ```bash
   # Update server URL in systemd config
   sudo nano /etc/systemd/system/.maestro_hw_config/activation_server.conf
   ```

2. **Security Keys**: Update obfuscation keys in source code (production deployment)

## API Reference

### Core Methods

| Method | Description |
|--------|-------------|
| `initialize()` | Initialize client and extract hardware fingerprint |
| `extractHardwareFingerprint()` | Get device hardware characteristics |
| `burySecretsDeepInSystem()` | Hide secrets in multiple system locations |
| `performFullActivation()` | Complete activation flow with server |
| `validateActivation()` | Verify current activation status |
| `isDeviceActivated()` | Check if device is activated |

### Hardware Fingerprinting

```cpp
DeviceFingerprint fp = client.extractHardwareFingerprint();
std::cout << "MAC: " << fp.mac_address << std::endl;
std::cout << "CPU: " << fp.cpu_serial << std::endl;
std::cout << "Board: " << fp.board_serial << std::endl;
std::cout << "Hardware ID: " << fp.hardware_id << std::endl;
```

### Secret Management

```cpp
// Bury secrets in system (called automatically)
client.burySecretsDeepInSystem();

// Extract buried server URL
std::string server_url = client.extractBuriedSecrets();
```

## Security Architecture

### Multi-Layer Protection

1. **Hardware Binding**: Cryptographically tied to unique hardware identifiers
2. **Secret Distribution**: Keys split across multiple system locations
3. **Obfuscation**: XOR encryption with rotating keys for stored data
4. **Camouflage**: Secrets hidden in legitimate-looking system files
5. **Integrity Checks**: Hardware validation prevents tampering

### Hidden Storage Strategy

- **SystemD**: Server URL in service documentation field
- **NetworkManager**: Obfuscated data in hardware config parameter
- **D-Bus**: Encrypted secrets in XML policy comments
- **Udev**: Master keys in device rule comments
- **Cache**: Hardware fingerprints in system cache files

## Testing and Validation

### Test Hardware Extraction
```bash
# Run comprehensive test
sudo ./test_activation

# Check buried secrets
sudo ls -la /etc/systemd/system/.maestro_hw_config/
sudo cat /etc/NetworkManager/conf.d/99-maestro-hw.conf
```

### Verify Secret Burial
```bash
# Check all hidden locations
sudo find /etc -name "*maestro*" 2>/dev/null
sudo find /var -name "*maestro*" 2>/dev/null
```

### Monitor Activation Logs
```bash
# View activation attempts
sudo tail -f /var/log/maestro_activation.log
```

## Production Deployment

### Security Hardening

1. **Update Encryption Keys**: Replace default keys in source code
2. **Customize Paths**: Modify secret storage locations
3. **Add Obfuscation**: Implement additional layers of protection
4. **Code Signing**: Sign binaries for integrity verification

### Integration Points

- **Captive Portal**: Include in WiFi configuration system
- **Home Assistant**: Integrate with IoT service startup
- **System Services**: Create systemd service for automatic activation
- **Boot Process**: Validate activation during system startup

## Troubleshooting

### Common Issues

**Hardware ID Generation Fails**:
```bash
# Check hardware access
sudo cat /proc/cpuinfo | grep Serial
sudo cat /sys/class/net/*/address
```

**Secret Burial Permission Errors**:
```bash
# Ensure running as root
sudo chown root:root /etc/systemd/system/.maestro_hw_config/
sudo chmod 600 /etc/systemd/system/.maestro_hw_config/*
```

**Activation Server Connection**:
```bash
# Test server connectivity
curl -v http://ACTIVATION_SERVER:8080/api/v1/server/status
```

## License

Commercial licensing system for Maestro IoT devices. Unauthorized use is prohibited.

## Security Notice

This is an anti-tampering system designed to prevent piracy. The code contains multiple security layers and obfuscation techniques. Do not modify unless you understand the security implications.