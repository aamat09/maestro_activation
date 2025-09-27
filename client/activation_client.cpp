#include "activation_client.h"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <json/json.h>
#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <regex>
#include <cstdlib>
#include <sys/stat.h>
#include <unistd.h>

// Obfuscated keys (in production, these would be more heavily obfuscated)
const std::string ActivationClient::BURIED_KEY_1 = "mAeStRo_SeC_KeY_AlPhA_2024";
const std::string ActivationClient::BURIED_KEY_2 = "cApTiVe_PoRtAl_BeTa_EnCrYpT";
const std::string ActivationClient::BURIED_KEY_3 = "hArDwArE_iD_gAmMa_PrOtEcT";
const std::string ActivationClient::SECRET_CONFIG_MARKER = ".maestro_hw_conf";
const std::string ActivationClient::SYSTEM_INTEGRATION_ID = "sys_maestro_integration_2024";

ActivationClient::ActivationClient() : config_(std::make_unique<ActivationConfig>()), initialized_(false) {
    // Initialize libcurl
    curl_global_init(CURL_GLOBAL_DEFAULT);

    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();

    // Initialize config with defaults
    config_->server_url = "";
    config_->is_activated = false;
    config_->retry_count = 0;
}

ActivationClient::~ActivationClient() {
    curl_global_cleanup();
    EVP_cleanup();
}

bool ActivationClient::initialize() {
    if (initialized_) {
        return true;
    }

    // Perform security checks
    if (isRunningInDebugger() || isRunningInVM()) {
        last_error_ = "Security violation detected";
        return false;
    }

    // Load configuration
    if (!loadConfiguration()) {
        // First time setup - extract hardware ID
        config_->hardware_id = getHardwareId();
        if (config_->hardware_id.empty()) {
            last_error_ = "Failed to extract hardware ID";
            return false;
        }

        // Bury secrets deep in the system
        burySeedsDeep();
    }

    // Verify integrity
    if (!verifyIntegrity()) {
        last_error_ = "System integrity check failed";
        return false;
    }

    initialized_ = true;
    return true;
}

std::string ActivationClient::getHardwareId() {
    std::string mac = getMacAddress();
    std::string cpu = getCpuSerial();
    std::string board = getBoardSerial();

    // Combine and hash
    std::string combined = mac + "|" + cpu + "|" + board + "|" + BURIED_KEY_1;

    // SHA256 hash
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, combined.c_str(), combined.size());
    SHA256_Final(hash, &sha256);

    // Convert to hex
    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(hash[i]);
    }

    return oss.str();
}

std::string ActivationClient::getMacAddress() {
    // Try different methods to get MAC address
    FILE* pipe = popen("cat /sys/class/net/*/address 2>/dev/null | grep -v '00:00:00:00:00:00' | head -1", "r");
    if (!pipe) return "";

    char buffer[128];
    std::string result;
    if (fgets(buffer, sizeof(buffer), pipe)) {
        result = buffer;
        // Remove newline
        result.erase(std::remove(result.begin(), result.end(), '\\n'), result.end());
    }
    pclose(pipe);

    return result;
}

std::string ActivationClient::getCpuSerial() {
    std::ifstream file("/proc/cpuinfo");
    std::string line;
    std::regex serial_regex("Serial\\s*:\\s*([a-fA-F0-9]+)");
    std::smatch match;

    while (std::getline(file, line)) {
        if (std::regex_search(line, match, serial_regex)) {
            return match[1].str();
        }
    }

    // Fallback: use CPU model as identifier
    file.clear();
    file.seekg(0);
    std::regex model_regex("model name\\s*:\\s*(.+)");
    while (std::getline(file, line)) {
        if (std::regex_search(line, match, model_regex)) {
            // Hash the model name
            std::string model = match[1].str();
            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256(reinterpret_cast<const unsigned char*>(model.c_str()), model.length(), hash);

            std::ostringstream oss;
            for (int i = 0; i < 8; i++) { // Use first 8 bytes
                oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(hash[i]);
            }
            return oss.str();
        }
    }

    return "unknown";
}

std::string ActivationClient::getBoardSerial() {
    // Try multiple locations for board serial
    std::vector<std::string> paths = {
        "/sys/class/dmi/id/board_serial",
        "/sys/class/dmi/id/product_serial",
        "/proc/device-tree/serial-number"
    };

    for (const auto& path : paths) {
        std::ifstream file(path);
        if (file.is_open()) {
            std::string serial;
            std::getline(file, serial);
            if (!serial.empty() && serial != "Not Specified") {
                return serial;
            }
        }
    }

    return "unknown";
}

bool ActivationClient::loadConfiguration() {
    std::string config_path = getConfigPath();
    std::ifstream file(config_path);

    if (!file.is_open()) {
        return false;
    }

    try {
        Json::Value root;
        file >> root;

        if (root.isMember("encrypted_data")) {
            std::string encrypted_data = root["encrypted_data"].asString();
            std::string decrypted = decryptConfig(encrypted_data);

            Json::Value config_json;
            Json::Reader reader;
            if (!reader.parse(decrypted, config_json)) {
                return false;
            }

            config_->server_url = config_json.get("server_url", "").asString();
            config_->hardware_id = config_json.get("hardware_id", "").asString();
            config_->license_key = config_json.get("license_key", "").asString();
            config_->activation_token = config_json.get("activation_token", "").asString();
            config_->is_activated = config_json.get("is_activated", false).asBool();
            config_->retry_count = config_json.get("retry_count", 0).asInt();

            return true;
        }

    } catch (const std::exception& e) {
        last_error_ = "Configuration parse error: " + std::string(e.what());
    }

    return false;
}

bool ActivationClient::saveConfiguration() {
    try {
        Json::Value config_json;
        config_json["server_url"] = config_->server_url;
        config_json["hardware_id"] = config_->hardware_id;
        config_json["license_key"] = config_->license_key;
        config_json["activation_token"] = config_->activation_token;
        config_json["is_activated"] = config_->is_activated;
        config_json["retry_count"] = config_->retry_count;
        config_json["timestamp"] = static_cast<int64_t>(std::time(nullptr));

        Json::StreamWriterBuilder builder;
        std::string config_str = Json::writeString(builder, config_json);

        // Encrypt the configuration
        std::string encrypted = encryptConfig(config_str);

        Json::Value root;
        root["encrypted_data"] = encrypted;
        root["checksum"] = generateChecksum(encrypted);

        std::string config_path = getConfigPath();

        // Ensure directory exists
        std::filesystem::create_directories(std::filesystem::path(config_path).parent_path());

        std::ofstream file(config_path);
        if (!file.is_open()) {
            return false;
        }

        Json::StreamWriterBuilder writer_builder;
        std::unique_ptr<Json::StreamWriter> writer(writer_builder.newStreamWriter());
        writer->write(root, &file);

        // Set restrictive permissions
        chmod(config_path.c_str(), 0600);

        return true;

    } catch (const std::exception& e) {
        last_error_ = "Configuration save error: " + std::string(e.what());
        return false;
    }
}

std::string ActivationClient::getConfigPath() {
    // Use multiple hidden locations
    std::vector<std::string> paths = {
        "/var/lib/maestro/" + SECRET_CONFIG_MARKER,
        "/usr/local/etc/maestro/." + SECRET_CONFIG_MARKER,
        "/opt/maestro/config/." + SECRET_CONFIG_MARKER,
        std::string(getenv("HOME") ? getenv("HOME") : "/tmp") + "/." + SECRET_CONFIG_MARKER
    };

    // Try to find existing config
    for (const auto& path : paths) {
        if (std::filesystem::exists(path)) {
            return path;
        }
    }

    // Return first writable location
    for (const auto& path : paths) {
        std::filesystem::path dir = std::filesystem::path(path).parent_path();
        if (std::filesystem::exists(dir) || std::filesystem::create_directories(dir)) {
            return path;
        }
    }

    return "/tmp/." + SECRET_CONFIG_MARKER;
}

void ActivationClient::burySeedsDeep() {
    // Store keys in multiple hidden locations with different encoding
    storeInRegistryAlternative("sys_key_alpha", BURIED_KEY_1);
    storeInRegistryAlternative("hw_validation_beta", BURIED_KEY_2);
    storeInSystemService(BURIED_KEY_3);

    // Create decoy files
    std::vector<std::string> decoy_paths = {
        "/tmp/.system_cache_temp",
        "/var/tmp/.hw_temp_config",
        "/usr/local/tmp/.maestro_temp"
    };

    for (const auto& path : decoy_paths) {
        std::ofstream decoy(path);
        if (decoy.is_open()) {
            decoy << "# System temporary configuration cache\\n";
            decoy << "cache_version=1.0\\n";
            decoy << "last_update=" << std::time(nullptr) << "\\n";
            decoy.close();
            chmod(path.c_str(), 0644);
        }
    }
}

void ActivationClient::storeInRegistryAlternative(const std::string& key, const std::string& value) {
    // On Linux, use systemd user settings or similar
    std::string path = "/etc/systemd/system/.maestro_" + key + ".conf";
    std::ofstream file(path);
    if (file.is_open()) {
        file << "[Unit]\\n";
        file << "Description=System Configuration\\n";
        file << "Documentation=" << value << "\\n";
        file.close();
        chmod(path.c_str(), 0600);
    }
}

std::string ActivationClient::retrieveFromRegistryAlternative(const std::string& key) {
    std::string path = "/etc/systemd/system/.maestro_" + key + ".conf";
    std::ifstream file(path);
    if (file.is_open()) {
        std::string line;
        while (std::getline(file, line)) {
            if (line.find("Documentation=") == 0) {
                return line.substr(14); // Remove "Documentation="
            }
        }
    }
    return "";
}

std::string ActivationClient::encryptConfig(const std::string& data) {
    // Simple XOR encryption with rotating key (in production, use AES)
    std::string key = BURIED_KEY_2 + BURIED_KEY_3;
    std::string encrypted;

    for (size_t i = 0; i < data.length(); i++) {
        encrypted += static_cast<char>(data[i] ^ key[i % key.length()]);
    }

    return encrypted;
}

std::string ActivationClient::decryptConfig(const std::string& encrypted_data) {
    // Same as encrypt for XOR
    return encryptConfig(encrypted_data);
}

bool ActivationClient::isRunningInDebugger() {
    // Check for common debugger indicators
    if (std::filesystem::exists("/proc/self/status")) {
        std::ifstream file("/proc/self/status");
        std::string line;
        while (std::getline(file, line)) {
            if (line.find("TracerPid:") == 0) {
                std::string pid_str = line.substr(10);
                int tracer_pid = std::stoi(pid_str);
                return tracer_pid != 0;
            }
        }
    }
    return false;
}

bool ActivationClient::isRunningInVM() {
    // Check for VM indicators
    std::vector<std::string> vm_indicators = {
        "/proc/scsi/scsi",
        "/proc/ide/hd0/model"
    };

    for (const auto& path : vm_indicators) {
        std::ifstream file(path);
        if (file.is_open()) {
            std::string content((std::istreambuf_iterator<char>(file)),
                              std::istreambuf_iterator<char>());
            std::transform(content.begin(), content.end(), content.begin(), ::tolower);

            if (content.find("vmware") != std::string::npos ||
                content.find("virtualbox") != std::string::npos ||
                content.find("qemu") != std::string::npos) {
                return true;
            }
        }
    }

    return false;
}

std::string ActivationClient::generateChecksum(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.length(), hash);

    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(hash[i]);
    }

    return oss.str();
}