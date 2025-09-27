#pragma once

#include <string>
#include <chrono>
#include <memory>

struct ActivationConfig {
    std::string server_url;
    std::string hardware_id;
    std::string license_key;
    std::string activation_token;
    std::chrono::system_clock::time_point last_validation;
    bool is_activated;
    int retry_count;
};

class ActivationClient {
public:
    ActivationClient();
    ~ActivationClient();

    // Main activation flow
    bool initialize();
    bool performActivation();
    bool validateActivation();
    bool isActivated() const;

    // Configuration management
    bool loadConfiguration();
    bool saveConfiguration();
    void setServerUrl(const std::string& url);

    // Hardware identification
    std::string getHardwareId();
    std::string getDeviceName();
    std::string getMacAddress();
    std::string getCpuSerial();
    std::string getBoardSerial();

    // License management
    bool registerDevice();
    bool activateWithServer();
    bool renewActivation();

    // Security and anti-tampering
    bool verifyIntegrity();
    bool checkTamperingAttempts();
    void burySeedsDeep();
    std::string extractBuriedSecrets();

    // Network communication
    bool testServerConnection();
    std::string makeHttpRequest(const std::string& endpoint, const std::string& method, const std::string& data = "");

    // Error handling
    std::string getLastError() const;
    void clearError();

private:
    // Internal configuration paths (deeply buried)
    std::string getConfigPath();
    std::string getSecretsPath();
    std::string getBackupConfigPath();

    // Obfuscation and hiding
    void obfuscateConfig();
    void deobfuscateConfig();
    void hideInSystemFiles();
    void distributeSecrets();

    // Anti-debugging and VM detection
    bool isRunningInDebugger();
    bool isRunningInVM();
    bool detectTampering();

    // Cryptographic helpers
    std::string encryptConfig(const std::string& data);
    std::string decryptConfig(const std::string& encrypted_data);
    std::string generateChecksum(const std::string& data);
    bool verifyChecksum(const std::string& data, const std::string& expected);

    // Hidden storage locations
    void storeInRegistryAlternative(const std::string& key, const std::string& value);
    std::string retrieveFromRegistryAlternative(const std::string& key);
    void storeInSystemService(const std::string& data);
    std::string retrieveFromSystemService();

    // Member variables
    std::unique_ptr<ActivationConfig> config_;
    std::string last_error_;
    bool initialized_;

    // Security keys (obfuscated in production)
    static const std::string BURIED_KEY_1;
    static const std::string BURIED_KEY_2;
    static const std::string BURIED_KEY_3;

    // Hidden paths and identifiers
    static const std::string SECRET_CONFIG_MARKER;
    static const std::string SYSTEM_INTEGRATION_ID;
};