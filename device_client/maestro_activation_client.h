#pragma once

#include <string>
#include <chrono>
#include <memory>
#include <map>

struct DeviceFingerprint {
    std::string mac_address;
    std::string cpu_serial;
    std::string board_serial;
    std::string system_uuid;
    std::string hardware_id;
    std::string device_model;
    std::string combined_hash;
};

struct ActivationData {
    std::string server_url;
    std::string hardware_id;
    std::string license_key;
    std::string activation_token;
    std::chrono::system_clock::time_point last_validation;
    bool is_activated;
    int retry_count;
    std::string encrypted_config;
};

class MaestroActivationClient {
public:
    MaestroActivationClient();
    ~MaestroActivationClient();

    // Main activation workflow
    bool initialize();
    bool performFullActivation();
    bool validateActivation();
    bool isDeviceActivated();

    // Hardware fingerprinting
    DeviceFingerprint extractHardwareFingerprint();
    std::string generateHardwareId();
    bool verifyHardwareIntegrity();

    // Server communication
    bool registerWithServer();
    bool requestActivation();
    bool validateWithServer();

    // Deep system integration
    void burySecretsDeepInSystem();
    std::string extractBuriedSecrets();
    void createSystemIntegrationPoints();
    void hideConfigurationData();

    // Anti-tampering and security
    bool detectTamperingAttempts();
    bool isRunningInSecureEnvironment();
    void performSecurityChecks();

    // Error handling
    std::string getLastError() const;
    void logSecurityEvent(const std::string& event);

private:
    // Secret storage locations (deeply hidden)
    void storeInSystemdConfigs(const std::string& key, const std::string& value);
    void storeInKernelModuleConfig(const std::string& data);
    void storeInNetworkManagerConfig(const std::string& data);
    void storeInDbusPolicyConfig(const std::string& data);
    void storeInUdevRules(const std::string& data);

    // Secret retrieval methods
    std::string retrieveFromSystemdConfigs(const std::string& key);
    std::string retrieveFromKernelConfig();
    std::string retrieveFromNetworkConfig();
    std::string retrieveFromDbusConfig();
    std::string retrieveFromUdevConfig();

    // Encryption and obfuscation
    std::string encryptData(const std::string& data, const std::string& key);
    std::string decryptData(const std::string& encrypted, const std::string& key);
    std::string obfuscateString(const std::string& input);
    std::string deobfuscateString(const std::string& obfuscated);

    // HTTP communication
    std::string makeHttpRequest(const std::string& url, const std::string& method,
                               const std::string& data, const std::map<std::string, std::string>& headers);

    // Hardware extraction helpers
    std::string getMacAddress();
    std::string getCpuSerial();
    std::string getBoardSerial();
    std::string getSystemUuid();
    std::string getDeviceModel();

    // Configuration management
    bool loadHiddenConfiguration();
    bool saveHiddenConfiguration();
    std::string getConfigurationPath();

    // Security utilities
    std::string generateChecksum(const std::string& data);
    bool verifyChecksum(const std::string& data, const std::string& expected);
    std::string generateSecureRandom(size_t length);

    // Member variables
    std::unique_ptr<ActivationData> activation_data_;
    std::unique_ptr<DeviceFingerprint> fingerprint_;
    std::string last_error_;
    bool initialized_;

    // Buried encryption keys (heavily obfuscated in production)
    static const std::string BURIED_MASTER_KEY;
    static const std::string BURIED_CONFIG_KEY;
    static const std::string BURIED_COMM_KEY;
    static const std::string SYSTEM_INTEGRATION_MARKER;
    static const std::string DEFAULT_ACTIVATION_SERVER_URL;
};