#pragma once

#include <string>
#include <vector>
#include <chrono>

class LicenseManager {
public:
    // License key generation
    static std::string generateLicenseKey(const std::string& hardware_id, const std::string& device_name);
    static std::string generateMasterKey();

    // License validation
    static bool validateLicenseKey(const std::string& license_key, const std::string& hardware_id);
    static bool isLicenseExpired(const std::string& license_key);

    // License features and restrictions
    static bool hasFeature(const std::string& license_key, const std::string& feature);
    static int getMaxDevices(const std::string& license_key);
    static std::chrono::system_clock::time_point getExpirationDate(const std::string& license_key);

    // License encoding/decoding
    static std::string encodeLicenseData(const std::string& hardware_id,
                                       const std::string& device_name,
                                       const std::vector<std::string>& features,
                                       std::chrono::system_clock::time_point expiration);

    static bool decodeLicenseData(const std::string& license_key,
                                std::string& hardware_id,
                                std::string& device_name,
                                std::vector<std::string>& features,
                                std::chrono::system_clock::time_point& expiration);

    // Hardware binding
    static std::string bindToHardware(const std::string& base_license, const std::string& hardware_signature);
    static bool verifyHardwareBinding(const std::string& license_key, const std::string& hardware_signature);

    // Anti-tampering features
    static std::string generateChecksum(const std::string& data);
    static bool verifyChecksum(const std::string& data, const std::string& checksum);
    static std::string obfuscateLicense(const std::string& license_key);
    static std::string deobfuscateLicense(const std::string& obfuscated_license);

private:
    // Internal cryptographic functions
    static std::string encryptData(const std::string& data, const std::string& key);
    static std::string decryptData(const std::string& encrypted_data, const std::string& key);
    static std::string generateRandomString(size_t length);
    static std::string sha256Hash(const std::string& data);

    // License format constants
    static constexpr size_t LICENSE_SEGMENT_LENGTH = 4;
    static constexpr size_t LICENSE_SEGMENTS = 5;
    static constexpr char LICENSE_SEPARATOR = '-';

    // Encryption keys (in production, these would be stored securely)
    static const std::string MASTER_ENCRYPTION_KEY;
    static const std::string CHECKSUM_SALT;
};