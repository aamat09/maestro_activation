#include "maestro_activation_client.h"
#include <iostream>
#include <iomanip>

void printSeparator() {
    std::cout << "========================================" << std::endl;
}

void printHeader(const std::string& title) {
    printSeparator();
    std::cout << "  " << title << std::endl;
    printSeparator();
}

int main() {
    printHeader("MAESTRO ACTIVATION CLIENT TEST");

    MaestroActivationClient client;

    // Test initialization
    std::cout << "1. Initializing activation client..." << std::endl;
    if (!client.initialize()) {
        std::cout << "   ERROR: " << client.getLastError() << std::endl;
        return 1;
    }
    std::cout << "   ✓ Client initialized successfully" << std::endl;

    // Extract and display hardware fingerprint
    std::cout << "\\n2. Extracting hardware fingerprint..." << std::endl;
    auto fingerprint = client.extractHardwareFingerprint();

    std::cout << "   MAC Address:  " << fingerprint.mac_address << std::endl;
    std::cout << "   CPU Serial:   " << fingerprint.cpu_serial << std::endl;
    std::cout << "   Board Serial: " << fingerprint.board_serial << std::endl;
    std::cout << "   System UUID:  " << fingerprint.system_uuid << std::endl;
    std::cout << "   Device Model: " << fingerprint.device_model << std::endl;
    std::cout << "   Hardware ID:  " << fingerprint.hardware_id.substr(0, 16) << "..." << std::endl;

    // Bury secrets deep in system
    std::cout << "\\n3. Burying secrets deep in system..." << std::endl;
    client.burySecretsDeepInSystem();
    std::cout << "   ✓ Secrets buried in multiple system locations" << std::endl;

    // Test secret extraction
    std::cout << "\\n4. Testing secret extraction..." << std::endl;
    std::string extracted_url = client.extractBuriedSecrets();
    std::cout << "   Extracted server URL: " << extracted_url << std::endl;

    // Check if already activated
    std::cout << "\\n5. Checking activation status..." << std::endl;
    if (client.isDeviceActivated()) {
        std::cout << "   ✓ Device is already activated" << std::endl;

        if (client.validateActivation()) {
            std::cout << "   ✓ Activation is valid" << std::endl;
        } else {
            std::cout << "   ⚠ Activation validation failed" << std::endl;
        }
    } else {
        std::cout << "   → Device not activated, attempting activation..." << std::endl;

        // Perform full activation
        std::cout << "\\n6. Performing full activation..." << std::endl;
        if (client.performFullActivation()) {
            std::cout << "   ✓ Device activated successfully!" << std::endl;

            // Verify activation
            if (client.validateActivation()) {
                std::cout << "   ✓ Activation verified with server" << std::endl;
            } else {
                std::cout << "   ⚠ Activation verification failed" << std::endl;
            }
        } else {
            std::cout << "   ERROR: Activation failed - " << client.getLastError() << std::endl;
            std::cout << "\\n   This may be because:" << std::endl;
            std::cout << "   - Activation server is not running" << std::endl;
            std::cout << "   - Network connectivity issues" << std::endl;
            std::cout << "   - Device already registered" << std::endl;
        }
    }

    // Final status
    std::cout << "\\n";
    printHeader("ACTIVATION STATUS");
    if (client.isDeviceActivated()) {
        std::cout << "🎉 DEVICE SUCCESSFULLY ACTIVATED 🎉" << std::endl;
        std::cout << "   Hardware ID: " << fingerprint.hardware_id.substr(0, 16) << "..." << std::endl;
        std::cout << "   Status: ACTIVE" << std::endl;
    } else {
        std::cout << "❌ DEVICE NOT ACTIVATED" << std::endl;
        std::cout << "   Hardware ID: " << fingerprint.hardware_id.substr(0, 16) << "..." << std::endl;
        std::cout << "   Status: INACTIVE" << std::endl;
    }

    printSeparator();

    // Show hidden configuration locations
    std::cout << "\\nHidden configuration locations created:" << std::endl;
    std::cout << "  - /etc/systemd/system/.maestro_hw_config/" << std::endl;
    std::cout << "  - /etc/NetworkManager/conf.d/99-maestro-hw.conf" << std::endl;
    std::cout << "  - /etc/dbus-1/system.d/maestro-hw-policy.conf" << std::endl;
    std::cout << "  - /etc/udev/rules.d/99-maestro-hw.rules" << std::endl;
    std::cout << "  - /var/cache/maestro/.system_hw_cache" << std::endl;

    return 0;
}