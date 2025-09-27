#pragma once

#include <sqlite3.h>
#include <string>
#include <memory>
#include <vector>
#include <chrono>

struct Device {
    std::string hardware_id;
    std::string license_key;
    std::string device_name;
    std::string mac_address;
    std::string cpu_serial;
    std::string board_serial;
    bool is_active;
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point last_activation;
    int activation_count;
    std::string client_ip;
    std::string user_agent;
};

struct ActivationAttempt {
    std::string hardware_id;
    std::string client_ip;
    std::string user_agent;
    std::chrono::system_clock::time_point timestamp;
    bool success;
    std::string error_message;
};

class DatabaseManager {
public:
    static DatabaseManager& getInstance();

    bool initialize();
    bool close();

    // Device management
    bool registerDevice(const Device& device);
    bool updateDevice(const Device& device);
    bool deleteDevice(const std::string& hardware_id);
    std::unique_ptr<Device> getDevice(const std::string& hardware_id);
    std::vector<Device> getAllDevices();
    bool isDeviceActive(const std::string& hardware_id);

    // License management
    bool validateLicense(const std::string& hardware_id, const std::string& license_key);
    bool activateDevice(const std::string& hardware_id, const std::string& client_ip, const std::string& user_agent);
    bool deactivateDevice(const std::string& hardware_id);

    // Activation tracking
    bool logActivationAttempt(const ActivationAttempt& attempt);
    std::vector<ActivationAttempt> getActivationHistory(const std::string& hardware_id, int limit = 100);

    // Security and monitoring
    bool isRateLimited(const std::string& client_ip, int max_attempts = 5, int window_minutes = 15);
    bool isSuspiciousActivity(const std::string& hardware_id);
    void cleanupOldLogs(int days_to_keep = 90);

private:
    DatabaseManager() = default;
    ~DatabaseManager();

    DatabaseManager(const DatabaseManager&) = delete;
    DatabaseManager& operator=(const DatabaseManager&) = delete;

    bool createTables();
    bool executeSQL(const std::string& sql);
    sqlite3_stmt* prepareStatement(const std::string& sql);

    sqlite3* db_ = nullptr;
    std::string db_path_ = "/opt/maestro/activation/database/activation.db";
};