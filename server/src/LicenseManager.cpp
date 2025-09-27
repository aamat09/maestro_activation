#include "LicenseManager.h"
#include "SecurityUtils.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <random>
#include <json/json.h>

// Static constants (in production, these would be more securely stored)
const std::string LicenseManager::MASTER_ENCRYPTION_KEY = "MAESTRO_LICENSE_MASTER_KEY_2024_SECURE";
const std::string LicenseManager::CHECKSUM_SALT = "CAPTIVE_PORTAL_SALT_VALIDATION_2024";

std::string LicenseManager::generateLicenseKey(const std::string& hardware_id, const std::string& device_name) {
    try {
        // Create license data
        Json::Value license_data;
        license_data["hardware_id"] = hardware_id;
        license_data["device_name"] = device_name;
        license_data["issued_at"] = static_cast<int64_t>(std::time(nullptr));
        license_data["version"] = "1.0";

        // Add features
        Json::Value features(Json::arrayValue);
        features.append("captive_portal");
        features.append("home_assistant");
        features.append("wifi_management");
        license_data["features"] = features;

        // Set expiration (10 years from now)
        auto expiration = std::chrono::system_clock::now() + std::chrono::hours(24 * 365 * 10);
        license_data["expires_at"] = static_cast<int64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(expiration.time_since_epoch()).count()
        );

        // Convert to string
        Json::StreamWriterBuilder builder;
        builder["indentation"] = "";
        std::string json_str = Json::writeString(builder, license_data);

        // Encrypt the data
        std::string encrypted = SecurityUtils::aesEncrypt(json_str, MASTER_ENCRYPTION_KEY);

        // Generate checksum
        std::string checksum = SecurityUtils::hmacSha256(encrypted, CHECKSUM_SALT);

        // Combine encrypted data and checksum
        std::string combined = encrypted + "|" + checksum;

        // Encode to base64
        std::string encoded = SecurityUtils::base64Encode(combined);

        // Format as standard license key (XXXX-XXXX-XXXX-XXXX-XXXX)
        return formatLicenseKey(encoded);

    } catch (const std::exception& e) {
        std::cerr << "License generation error: " << e.what() << std::endl;
        return "";
    }
}

std::string LicenseManager::formatLicenseKey(const std::string& encoded_data) {
    // Create a hash of the encoded data to generate the license key
    std::string hash = SecurityUtils::sha256(encoded_data);

    // Take first 20 characters and format them
    std::string key_chars;
    for (int i = 0; i < 20 && i < hash.length(); i++) {
        char c = std::toupper(hash[i]);
        if (std::isalnum(c)) {
            key_chars += c;
        }
    }

    // Pad with random alphanumeric if needed
    while (key_chars.length() < 20) {
        key_chars += generateRandomChar();
    }

    // Format as XXXX-XXXX-XXXX-XXXX-XXXX
    std::string formatted;
    for (int i = 0; i < 20; i++) {
        if (i > 0 && i % 4 == 0) {
            formatted += "-";
        }
        formatted += key_chars[i];
    }

    return formatted;
}

char LicenseManager::generateRandomChar() {
    const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, chars.length() - 1);
    return chars[dis(gen)];
}

bool LicenseManager::validateLicenseKey(const std::string& license_key, const std::string& hardware_id) {
    try {
        // Remove dashes
        std::string clean_key = license_key;
        clean_key.erase(std::remove(clean_key.begin(), clean_key.end(), '-'), clean_key.end());

        if (clean_key.length() != 20) {
            return false;
        }

        // For validation, we need to check if this key was generated for this hardware_id
        // In production, this would involve decrypting the embedded data
        // For now, we'll do a basic format validation

        // Check format (20 alphanumeric characters)
        for (char c : clean_key) {
            if (!std::isalnum(c)) {
                return false;
            }
        }

        return true;

    } catch (const std::exception&) {
        return false;
    }
}

std::string LicenseManager::encodeLicenseData(const std::string& hardware_id,
                                            const std::string& device_name,
                                            const std::vector<std::string>& features,
                                            std::chrono::system_clock::time_point expiration) {
    try {
        Json::Value license_data;
        license_data["hardware_id"] = hardware_id;
        license_data["device_name"] = device_name;
        license_data["issued_at"] = static_cast<int64_t>(std::time(nullptr));

        Json::Value feature_array(Json::arrayValue);
        for (const auto& feature : features) {
            feature_array.append(feature);
        }
        license_data["features"] = feature_array;

        license_data["expires_at"] = static_cast<int64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(expiration.time_since_epoch()).count()
        );

        Json::StreamWriterBuilder builder;
        builder["indentation"] = "";
        std::string json_str = Json::writeString(builder, license_data);

        // Encrypt
        std::string encrypted = SecurityUtils::aesEncrypt(json_str, MASTER_ENCRYPTION_KEY);

        // Add checksum
        std::string checksum = SecurityUtils::hmacSha256(encrypted, CHECKSUM_SALT);

        // Combine and encode
        std::string combined = encrypted + "|" + checksum;
        return SecurityUtils::base64Encode(combined);

    } catch (const std::exception& e) {
        std::cerr << "License encoding error: " << e.what() << std::endl;
        return "";
    }
}

bool LicenseManager::decodeLicenseData(const std::string& license_key,
                                     std::string& hardware_id,
                                     std::string& device_name,
                                     std::vector<std::string>& features,
                                     std::chrono::system_clock::time_point& expiration) {
    try {
        // For this implementation, we'll store the actual license data separately
        // and use the license key as a lookup. In production, the key itself
        // would contain encrypted license data.

        // This is a simplified validation that checks the key format
        std::string clean_key = license_key;
        clean_key.erase(std::remove(clean_key.begin(), clean_key.end(), '-'), clean_key.end());

        if (clean_key.length() != 20) {
            return false;
        }

        // Set default values (in production, these would be retrieved from encrypted data)
        hardware_id = ""; // Would be extracted from encrypted license
        device_name = "Maestro Device";
        features = {"captive_portal", "home_assistant", "wifi_management"};
        expiration = std::chrono::system_clock::now() + std::chrono::hours(24 * 365 * 10);

        return true;

    } catch (const std::exception&) {
        return false;
    }
}

bool LicenseManager::hasFeature(const std::string& license_key, const std::string& feature) {
    std::vector<std::string> features;
    std::string hardware_id, device_name;
    std::chrono::system_clock::time_point expiration;

    if (!decodeLicenseData(license_key, hardware_id, device_name, features, expiration)) {
        return false;
    }

    return std::find(features.begin(), features.end(), feature) != features.end();
}

bool LicenseManager::isLicenseExpired(const std::string& license_key) {
    std::vector<std::string> features;
    std::string hardware_id, device_name;
    std::chrono::system_clock::time_point expiration;

    if (!decodeLicenseData(license_key, hardware_id, device_name, features, expiration)) {
        return true; // Invalid license is considered expired
    }

    return std::chrono::system_clock::now() > expiration;
}

std::string LicenseManager::generateChecksum(const std::string& data) {
    return SecurityUtils::hmacSha256(data, CHECKSUM_SALT);
}

bool LicenseManager::verifyChecksum(const std::string& data, const std::string& checksum) {
    std::string calculated = generateChecksum(data);
    return SecurityUtils::secureCompare(calculated, checksum);
}

std::string LicenseManager::bindToHardware(const std::string& base_license, const std::string& hardware_signature) {
    // Create hardware-bound license by encrypting base license with hardware signature
    std::string key = SecurityUtils::sha256(hardware_signature + MASTER_ENCRYPTION_KEY);
    return SecurityUtils::aesEncrypt(base_license, key.substr(0, 32));
}

bool LicenseManager::verifyHardwareBinding(const std::string& license_key, const std::string& hardware_signature) {
    try {
        std::string key = SecurityUtils::sha256(hardware_signature + MASTER_ENCRYPTION_KEY);
        std::string decrypted = SecurityUtils::aesDecrypt(license_key, key.substr(0, 32));

        // If decryption succeeds and produces valid data, binding is correct
        return !decrypted.empty() && decrypted.find("hardware_id") != std::string::npos;

    } catch (const std::exception&) {
        return false;
    }
}

std::string LicenseManager::obfuscateLicense(const std::string& license_key) {
    // Simple obfuscation using XOR with rotating key
    std::string key = MASTER_ENCRYPTION_KEY;
    std::string obfuscated;

    for (size_t i = 0; i < license_key.length(); i++) {
        char xor_char = license_key[i] ^ key[i % key.length()];
        obfuscated += xor_char;
    }

    return SecurityUtils::base64Encode(obfuscated);
}

std::string LicenseManager::deobfuscateLicense(const std::string& obfuscated_license) {
    try {
        std::string decoded = SecurityUtils::base64Decode(obfuscated_license);
        std::string key = MASTER_ENCRYPTION_KEY;
        std::string deobfuscated;

        for (size_t i = 0; i < decoded.length(); i++) {
            char xor_char = decoded[i] ^ key[i % key.length()];
            deobfuscated += xor_char;
        }

        return deobfuscated;

    } catch (const std::exception&) {
        return "";
    }
}