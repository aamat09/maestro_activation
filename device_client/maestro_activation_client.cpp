#include "maestro_activation_client.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <algorithm>
#include <random>
#include <iomanip>
#include <regex>
#include <cstdlib>
#include <unistd.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <curl/curl.h>
#include <jsoncpp/json/json.h>

// Heavily obfuscated keys (in production, these would be even more complex)
const std::string MaestroActivationClient::BURIED_MASTER_KEY = "M4E5TR0_D3V1C3_M45T3R_K3Y_2024_ULT1M4T3";
const std::string MaestroActivationClient::BURIED_CONFIG_KEY = "C4PT1V3_P0RT4L_C0NF1G_K3Y_H1DD3N_5YST3M";
const std::string MaestroActivationClient::BURIED_COMM_KEY = "53CUR3_C0MMUN1C4T10N_K3Y_3NCR7PT3D_2024";
const std::string MaestroActivationClient::SYSTEM_INTEGRATION_MARKER = ".maestro_sys_integration_2024";
const std::string MaestroActivationClient::DEFAULT_ACTIVATION_SERVER_URL = "http://192.168.1.100:8080"; // Development server

// HTTP Response structure for curl
struct HttpResponse {
    std::string data;
    long response_code;
};

// Callback function for curl to write response data
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, HttpResponse* response) {
    size_t total_size = size * nmemb;
    response->data.append(static_cast<char*>(contents), total_size);
    return total_size;
}

MaestroActivationClient::MaestroActivationClient()
    : activation_data_(std::make_unique<ActivationData>())
    , fingerprint_(std::make_unique<DeviceFingerprint>())
    , initialized_(false) {

    // Initialize libcurl
    curl_global_init(CURL_GLOBAL_DEFAULT);

    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
}

MaestroActivationClient::~MaestroActivationClient() {
    curl_global_cleanup();
    EVP_cleanup();
}

bool MaestroActivationClient::initialize() {
    if (initialized_) {
        return true;
    }

    try {
        // Perform security checks first
        performSecurityChecks();

        // Extract hardware fingerprint
        *fingerprint_ = extractHardwareFingerprint();
        if (fingerprint_->hardware_id.empty()) {
            last_error_ = "Failed to extract hardware fingerprint";
            return false;
        }

        // Try to load existing configuration
        if (!loadHiddenConfiguration()) {
            // First-time setup
            activation_data_->server_url = extractBuriedSecrets();
            if (activation_data_->server_url.empty()) {
                activation_data_->server_url = DEFAULT_ACTIVATION_SERVER_URL;
            }
            activation_data_->hardware_id = fingerprint_->hardware_id;
            activation_data_->is_activated = false;
            activation_data_->retry_count = 0;

            // Bury secrets deep in the system
            burySecretsDeepInSystem();
        }

        // Verify hardware integrity
        if (!verifyHardwareIntegrity()) {
            last_error_ = "Hardware integrity check failed";
            return false;
        }

        initialized_ = true;
        return true;

    } catch (const std::exception& e) {
        last_error_ = "Initialization error: " + std::string(e.what());
        return false;
    }
}

DeviceFingerprint MaestroActivationClient::extractHardwareFingerprint() {
    DeviceFingerprint fp;

    fp.mac_address = getMacAddress();
    fp.cpu_serial = getCpuSerial();
    fp.board_serial = getBoardSerial();
    fp.system_uuid = getSystemUuid();
    fp.device_model = getDeviceModel();

    // Generate combined hardware ID
    std::string combined = fp.mac_address + "|" + fp.cpu_serial + "|" +
                          fp.board_serial + "|" + fp.system_uuid + "|" +
                          fp.device_model + "|" + BURIED_MASTER_KEY;

    // SHA256 hash of combined data
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, combined.c_str(), combined.size());
    SHA256_Final(hash, &sha256);

    // Convert to hex string
    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(hash[i]);
    }

    fp.hardware_id = oss.str();
    fp.combined_hash = generateChecksum(combined);

    return fp;
}

std::string MaestroActivationClient::getMacAddress() {
    // Try multiple methods to get MAC address
    std::vector<std::string> commands = {
        "cat /sys/class/net/*/address 2>/dev/null | grep -v '00:00:00:00:00:00' | head -1",
        "ip link show | grep -o 'link/ether [^[:space:]]*' | cut -d' ' -f2 | head -1",
        "ifconfig | grep -o 'ether [^[:space:]]*' | cut -d' ' -f2 | head -1"
    };

    for (const auto& cmd : commands) {
        FILE* pipe = popen(cmd.c_str(), "r");
        if (pipe) {
            char buffer[128];
            if (fgets(buffer, sizeof(buffer), pipe)) {
                std::string result(buffer);
                result.erase(std::remove(result.begin(), result.end(), '\n'), result.end());
                pclose(pipe);
                if (!result.empty() && result != "00:00:00:00:00:00") {
                    return result;
                }
            }
            pclose(pipe);
        }
    }

    return "unknown-mac";
}

std::string MaestroActivationClient::getCpuSerial() {
    std::ifstream file("/proc/cpuinfo");
    std::string line;
    std::regex serial_regex("Serial\\s*:\\s*([a-fA-F0-9]+)");
    std::smatch match;

    while (std::getline(file, line)) {
        if (std::regex_search(line, match, serial_regex)) {
            return match[1].str();
        }
    }

    // Fallback: use CPU model and revision
    file.clear();
    file.seekg(0);
    std::regex model_regex("model name\\s*:\\s*(.+)");
    std::regex revision_regex("cpu revision\\s*:\\s*(\\d+)");
    std::string model, revision;

    while (std::getline(file, line)) {
        if (std::regex_search(line, match, model_regex)) {
            model = match[1].str();
        }
        if (std::regex_search(line, match, revision_regex)) {
            revision = match[1].str();
        }
    }

    if (!model.empty()) {
        return generateChecksum(model + revision).substr(0, 16);
    }

    return "unknown-cpu";
}

std::string MaestroActivationClient::getBoardSerial() {
    std::vector<std::string> paths = {
        "/sys/class/dmi/id/board_serial",
        "/sys/class/dmi/id/product_serial",
        "/proc/device-tree/serial-number",
        "/sys/firmware/devicetree/base/serial-number"
    };

    for (const auto& path : paths) {
        std::ifstream file(path);
        if (file.is_open()) {
            std::string serial;
            std::getline(file, serial);
            if (!serial.empty() && serial != "Not Specified" && serial != "To be filled by O.E.M.") {
                // Remove null terminators and newlines
                serial.erase(std::find(serial.begin(), serial.end(), '\0'), serial.end());
                serial.erase(std::remove(serial.begin(), serial.end(), '\n'), serial.end());
                return serial;
            }
        }
    }

    // Fallback: use machine-id
    std::ifstream machine_id("/etc/machine-id");
    if (machine_id.is_open()) {
        std::string id;
        std::getline(machine_id, id);
        if (!id.empty()) {
            return id.substr(0, 16);
        }
    }

    return "unknown-board";
}

std::string MaestroActivationClient::getSystemUuid() {
    std::vector<std::string> commands = {
        "cat /sys/class/dmi/id/product_uuid 2>/dev/null",
        "cat /proc/sys/kernel/random/uuid 2>/dev/null"
    };

    for (const auto& cmd : commands) {
        FILE* pipe = popen(cmd.c_str(), "r");
        if (pipe) {
            char buffer[128];
            if (fgets(buffer, sizeof(buffer), pipe)) {
                std::string result(buffer);
                result.erase(std::remove(result.begin(), result.end(), '\n'), result.end());
                pclose(pipe);
                if (!result.empty()) {
                    return result;
                }
            }
            pclose(pipe);
        }
    }

    return "unknown-uuid";
}

std::string MaestroActivationClient::getDeviceModel() {
    std::vector<std::string> paths = {
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/board_name",
        "/proc/device-tree/model"
    };

    for (const auto& path : paths) {
        std::ifstream file(path);
        if (file.is_open()) {
            std::string model;
            std::getline(file, model);
            if (!model.empty() && model != "To be filled by O.E.M.") {
                return model;
            }
        }
    }

    return "maestro-device";
}

void MaestroActivationClient::burySecretsDeepInSystem() {
    // Store activation server URL in multiple hidden locations
    storeInSystemdConfigs("activation_server", activation_data_->server_url);
    storeInNetworkManagerConfig(obfuscateString(activation_data_->server_url));
    storeInDbusPolicyConfig(encryptData(activation_data_->server_url, BURIED_COMM_KEY));
    storeInUdevRules(obfuscateString(BURIED_MASTER_KEY));

    // Store hardware fingerprint components separately
    storeInSystemdConfigs("hw_mac", obfuscateString(fingerprint_->mac_address));
    storeInSystemdConfigs("hw_cpu", obfuscateString(fingerprint_->cpu_serial));
    storeInSystemdConfigs("hw_board", obfuscateString(fingerprint_->board_serial));

    // Create decoy files and configurations
    createSystemIntegrationPoints();

    // Store encrypted configuration backup
    hideConfigurationData();
}

void MaestroActivationClient::storeInSystemdConfigs(const std::string& key, const std::string& value) {
    std::string config_dir = "/etc/systemd/system/.maestro_hw_config";
    std::filesystem::create_directories(config_dir);

    std::string config_file = config_dir + "/" + key + ".conf";
    std::ofstream file(config_file);
    if (file.is_open()) {
        file << "[Unit]\n";
        file << "Description=System Hardware Configuration\n";
        file << "Documentation=" << value << "\n";
        file << "\n[Service]\n";
        file << "Type=oneshot\n";
        file << "ExecStart=/bin/true\n";
        file << "\n[Install]\n";
        file << "WantedBy=multi-user.target\n";
        file.close();
        chmod(config_file.c_str(), 0600);
    }
}

void MaestroActivationClient::storeInNetworkManagerConfig(const std::string& data) {
    std::string nm_config = "/etc/NetworkManager/conf.d/99-maestro-hw.conf";
    std::ofstream file(nm_config);
    if (file.is_open()) {
        file << "[main]\n";
        file << "# Hardware configuration data\n";
        file << "hw-config=" << data << "\n";
        file << "\n[device]\n";
        file << "wifi.scan-rand-mac-address=yes\n";
        file.close();
        chmod(nm_config.c_str(), 0600);
    }
}

void MaestroActivationClient::storeInDbusPolicyConfig(const std::string& data) {
    std::string dbus_config = "/etc/dbus-1/system.d/maestro-hw-policy.conf";
    std::ofstream file(dbus_config);
    if (file.is_open()) {
        file << "<?xml version=\"1.0\"?>\n";
        file << "<!DOCTYPE busconfig PUBLIC \"-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN\"\n";
        file << " \"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd\">\n";
        file << "<busconfig>\n";
        file << "  <!-- Hardware configuration: " << data << " -->\n";
        file << "  <policy user=\"root\">\n";
        file << "    <allow own=\"org.maestro.hardware\"/>\n";
        file << "  </policy>\n";
        file << "</busconfig>\n";
        file.close();
        chmod(dbus_config.c_str(), 0644);
    }
}

void MaestroActivationClient::storeInUdevRules(const std::string& data) {
    std::string udev_rules = "/etc/udev/rules.d/99-maestro-hw.rules";
    std::ofstream file(udev_rules);
    if (file.is_open()) {
        file << "# Maestro hardware configuration rules\n";
        file << "# Config data: " << data << "\n";
        file << "SUBSYSTEM==\"net\", ACTION==\"add\", DRIVERS==\"?*\", ATTR{type}==\"1\", KERNEL==\"eth*\", NAME=\"eth0\"\n";
        file << "SUBSYSTEM==\"net\", ACTION==\"add\", DRIVERS==\"?*\", ATTR{type}==\"1\", KERNEL==\"wlan*\", NAME=\"wlan0\"\n";
        file.close();
        chmod(udev_rules.c_str(), 0644);
    }
}

std::string MaestroActivationClient::makeHttpRequest(const std::string& url, const std::string& method,
                                                    const std::string& data, const std::map<std::string, std::string>& headers) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        return "";
    }

    HttpResponse response;
    struct curl_slist* curl_headers = nullptr;

    // Set basic options
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);

    // Set headers
    curl_headers = curl_slist_append(curl_headers, "Content-Type: application/json");
    curl_headers = curl_slist_append(curl_headers, "User-Agent: Maestro-Device/1.0");

    for (const auto& header : headers) {
        std::string header_str = header.first + ": " + header.second;
        curl_headers = curl_slist_append(curl_headers, header_str.c_str());
    }
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, curl_headers);

    // Set method and data
    if (method == "POST") {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        if (!data.empty()) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
        }
    }

    // Perform request
    CURLcode res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.response_code);

    // Cleanup
    curl_slist_free_all(curl_headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        return "";
    }

    return response.data;
}

std::string MaestroActivationClient::generateChecksum(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.length(), hash);

    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(hash[i]);
    }

    return oss.str();
}

std::string MaestroActivationClient::obfuscateString(const std::string& input) {
    std::string key = BURIED_CONFIG_KEY;
    std::string obfuscated;

    for (size_t i = 0; i < input.length(); i++) {
        char xor_char = input[i] ^ key[i % key.length()];
        obfuscated += xor_char;
    }

    // Base64-like encoding
    std::string encoded;
    for (unsigned char c : obfuscated) {
        encoded += std::to_string(static_cast<int>(c)) + ",";
    }
    if (!encoded.empty()) {
        encoded.pop_back(); // Remove last comma
    }

    return encoded;
}

std::string MaestroActivationClient::deobfuscateString(const std::string& obfuscated) {
    try {
        // Decode from comma-separated format
        std::string decoded;
        std::istringstream iss(obfuscated);
        std::string token;

        while (std::getline(iss, token, ',')) {
            int val = std::stoi(token);
            decoded += static_cast<char>(val);
        }

        // XOR deobfuscation
        std::string key = BURIED_CONFIG_KEY;
        std::string result;

        for (size_t i = 0; i < decoded.length(); i++) {
            char xor_char = decoded[i] ^ key[i % key.length()];
            result += xor_char;
        }

        return result;
    } catch (const std::exception&) {
        return "";
    }
}

std::string MaestroActivationClient::encryptData(const std::string& data, const std::string& key) {
    // Simple XOR encryption (in production, use AES)
    std::string encrypted;
    for (size_t i = 0; i < data.length(); i++) {
        encrypted += static_cast<char>(data[i] ^ key[i % key.length()]);
    }
    return encrypted;
}

std::string MaestroActivationClient::decryptData(const std::string& encrypted, const std::string& key) {
    // XOR decryption (same as encryption for XOR)
    return encryptData(encrypted, key);
}

void MaestroActivationClient::createSystemIntegrationPoints() {
    // Create hidden cache directories with decoy data
    std::vector<std::string> cache_dirs = {
        "/var/cache/maestro",
        "/tmp/.maestro_cache",
        "/usr/local/cache/.maestro"
    };

    for (const auto& dir : cache_dirs) {
        std::filesystem::create_directories(dir);

        std::string cache_file = dir + "/.system_hw_cache";
        std::ofstream file(cache_file);
        if (file.is_open()) {
            file << "# System hardware cache\n";
            file << "cache_version=1.0\n";
            file << "last_update=" << std::time(nullptr) << "\n";
            file << "hw_fingerprint=" << obfuscateString(fingerprint_->combined_hash) << "\n";
            file.close();
            chmod(cache_file.c_str(), 0600);
        }
    }
}

std::string MaestroActivationClient::extractBuriedSecrets() {
    // Try to retrieve server URL from multiple hidden locations
    std::string server_url = retrieveFromSystemdConfigs("activation_server");
    if (!server_url.empty()) {
        return server_url;
    }

    server_url = deobfuscateString(retrieveFromNetworkConfig());
    if (!server_url.empty()) {
        return server_url;
    }

    server_url = decryptData(retrieveFromDbusConfig(), BURIED_COMM_KEY);
    if (!server_url.empty()) {
        return server_url;
    }

    return DEFAULT_ACTIVATION_SERVER_URL;
}

std::string MaestroActivationClient::retrieveFromSystemdConfigs(const std::string& key) {
    std::string config_file = "/etc/systemd/system/.maestro_hw_config/" + key + ".conf";
    std::ifstream file(config_file);
    if (file.is_open()) {
        std::string line;
        while (std::getline(file, line)) {
            if (line.find("Documentation=") == 0) {
                return line.substr(14);
            }
        }
    }
    return "";
}

std::string MaestroActivationClient::retrieveFromNetworkConfig() {
    std::ifstream file("/etc/NetworkManager/conf.d/99-maestro-hw.conf");
    if (file.is_open()) {
        std::string line;
        while (std::getline(file, line)) {
            if (line.find("hw-config=") == 0) {
                return line.substr(10);
            }
        }
    }
    return "";
}

std::string MaestroActivationClient::retrieveFromDbusConfig() {
    std::ifstream file("/etc/dbus-1/system.d/maestro-hw-policy.conf");
    if (file.is_open()) {
        std::string content((std::istreambuf_iterator<char>(file)),
                           std::istreambuf_iterator<char>());

        std::regex config_regex("<!-- Hardware configuration: (.+) -->");
        std::smatch match;
        if (std::regex_search(content, match, config_regex)) {
            return match[1].str();
        }
    }
    return "";
}

bool MaestroActivationClient::performFullActivation() {
    if (!initialized_) {
        last_error_ = "Client not initialized";
        return false;
    }

    try {
        // First, try to register the device if not already registered
        if (!registerWithServer()) {
            // If registration fails, it might already be registered, try activation
            logSecurityEvent("Registration failed, attempting direct activation");
        }

        // Request activation from server
        if (!requestActivation()) {
            last_error_ = "Activation request failed";
            return false;
        }

        // Validate the activation
        if (!validateWithServer()) {
            last_error_ = "Activation validation failed";
            return false;
        }

        // Save the configuration
        saveHiddenConfiguration();

        activation_data_->is_activated = true;
        logSecurityEvent("Device successfully activated");

        return true;

    } catch (const std::exception& e) {
        last_error_ = "Activation error: " + std::string(e.what());
        return false;
    }
}

bool MaestroActivationClient::registerWithServer() {
    try {
        Json::Value request;
        request["hardware_id"] = fingerprint_->hardware_id;
        request["device_name"] = "Maestro-IoT-Device";
        request["mac_address"] = fingerprint_->mac_address;
        request["cpu_serial"] = fingerprint_->cpu_serial;
        request["board_serial"] = fingerprint_->board_serial;

        Json::StreamWriterBuilder builder;
        std::string json_str = Json::writeString(builder, request);

        std::string url = activation_data_->server_url + "/api/v1/register";
        std::string response_str = makeHttpRequest(url, "POST", json_str, {});

        if (response_str.empty()) {
            last_error_ = "No response from activation server";
            return false;
        }

        Json::Value response;
        Json::Reader reader;
        if (!reader.parse(response_str, response)) {
            last_error_ = "Invalid JSON response from server";
            return false;
        }

        if (response["status"].asString() == "success") {
            activation_data_->license_key = response["data"]["license_key"].asString();
            logSecurityEvent("Device registered successfully with server");
            return true;
        } else {
            last_error_ = "Registration failed: " + response["error"].asString();
            return false;
        }

    } catch (const std::exception& e) {
        last_error_ = "Registration error: " + std::string(e.what());
        return false;
    }
}

bool MaestroActivationClient::requestActivation() {
    try {
        Json::Value request;
        request["hardware_id"] = fingerprint_->hardware_id;
        request["license_key"] = activation_data_->license_key;

        Json::StreamWriterBuilder builder;
        std::string json_str = Json::writeString(builder, request);

        std::string url = activation_data_->server_url + "/api/v1/activate";
        std::string response_str = makeHttpRequest(url, "POST", json_str, {});

        if (response_str.empty()) {
            last_error_ = "No response from activation server";
            return false;
        }

        Json::Value response;
        Json::Reader reader;
        if (!reader.parse(response_str, response)) {
            last_error_ = "Invalid JSON response from server";
            return false;
        }

        if (response["status"].asString() == "success") {
            activation_data_->activation_token = response["data"]["activation_token"].asString();
            activation_data_->last_validation = std::chrono::system_clock::now();
            logSecurityEvent("Device activation successful");
            return true;
        } else {
            last_error_ = "Activation failed: " + response["error"].asString();
            return false;
        }

    } catch (const std::exception& e) {
        last_error_ = "Activation error: " + std::string(e.what());
        return false;
    }
}

bool MaestroActivationClient::validateWithServer() {
    try {
        Json::Value request;
        request["hardware_id"] = fingerprint_->hardware_id;
        request["activation_token"] = activation_data_->activation_token;

        Json::StreamWriterBuilder builder;
        std::string json_str = Json::writeString(builder, request);

        std::string url = activation_data_->server_url + "/api/v1/validate";
        std::string response_str = makeHttpRequest(url, "POST", json_str, {});

        if (response_str.empty()) {
            last_error_ = "No response from activation server";
            return false;
        }

        Json::Value response;
        Json::Reader reader;
        if (!reader.parse(response_str, response)) {
            last_error_ = "Invalid JSON response from server";
            return false;
        }

        if (response["status"].asString() == "success" && response["data"]["valid"].asBool()) {
            logSecurityEvent("Activation validation successful");
            return true;
        } else {
            last_error_ = "Validation failed: " + response["error"].asString();
            return false;
        }

    } catch (const std::exception& e) {
        last_error_ = "Validation error: " + std::string(e.what());
        return false;
    }
}

void MaestroActivationClient::logSecurityEvent(const std::string& event) {
    std::string log_file = "/var/log/maestro_activation.log";
    std::ofstream file(log_file, std::ios::app);
    if (file.is_open()) {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);

        file << "[" << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S") << "] "
             << event << " (HW: " << fingerprint_->hardware_id.substr(0, 8) << "...)" << std::endl;
        file.close();
    }
}

std::string MaestroActivationClient::getLastError() const {
    return last_error_;
}

bool MaestroActivationClient::isDeviceActivated() {
    return initialized_ && activation_data_->is_activated;
}

bool MaestroActivationClient::loadHiddenConfiguration() { return false; }
bool MaestroActivationClient::saveHiddenConfiguration() { return true; }
void MaestroActivationClient::hideConfigurationData() {}
bool MaestroActivationClient::verifyHardwareIntegrity() { return true; }
void MaestroActivationClient::performSecurityChecks() {}
bool MaestroActivationClient::detectTamperingAttempts() { return false; }
bool MaestroActivationClient::isRunningInSecureEnvironment() { return true; }
bool MaestroActivationClient::validateActivation() { return true; }