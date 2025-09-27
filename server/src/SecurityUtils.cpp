#include "SecurityUtils.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <regex>
#include <cstdio>
#include <memory>
#include <filesystem>

bool SecurityUtils::initializeCrypto() {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Seed random number generator
    if (RAND_status() != 1) {
        // Try to seed from /dev/urandom
        if (RAND_load_file("/dev/urandom", 32) != 32) {
            return false;
        }
    }

    return true;
}

void SecurityUtils::cleanupCrypto() {
    EVP_cleanup();
    ERR_free_strings();
}

std::string SecurityUtils::extractHardwareId() {
    std::string mac = getMacAddress();
    std::string cpu = getCpuSerial();
    std::string board = getBoardSerial();
    std::string uuid = getSystemUuid();

    // Combine all hardware identifiers
    std::string combined = mac + "|" + cpu + "|" + board + "|" + uuid;

    // Create a stable hash
    return sha256(combined);
}

std::string SecurityUtils::getMacAddress() {
    std::string result = executeCommand("cat /sys/class/net/*/address 2>/dev/null | head -1");
    if (result.empty()) {
        result = executeCommand("ip link show | grep -o 'link/ether [^[:space:]]*' | cut -d' ' -f2 | head -1");
    }

    // Remove newlines and normalize
    result.erase(std::remove(result.begin(), result.end(), '\\n'), result.end());
    return result;
}

std::string SecurityUtils::getCpuSerial() {
    std::string result = readFile("/proc/cpuinfo");
    std::regex serial_regex("Serial\\s*:\\s*([a-fA-F0-9]+)");
    std::smatch match;

    if (std::regex_search(result, match, serial_regex)) {
        return match[1].str();
    }

    // Fallback: use CPU model and flags
    std::regex model_regex("model name\\s*:\\s*(.+)");
    if (std::regex_search(result, match, model_regex)) {
        return sha256(match[1].str());
    }

    return "unknown-cpu";
}

std::string SecurityUtils::getBoardSerial() {
    std::string serial = readFile("/sys/class/dmi/id/board_serial");
    if (serial.empty() || serial == "Not Specified\\n") {
        serial = readFile("/sys/class/dmi/id/product_serial");
    }
    if (serial.empty() || serial == "Not Specified\\n") {
        serial = readFile("/proc/device-tree/serial-number");
    }

    // Remove newlines
    serial.erase(std::remove(serial.begin(), serial.end(), '\\n'), serial.end());
    return serial.empty() ? "unknown-board" : serial;
}

std::string SecurityUtils::getSystemUuid() {
    std::string uuid = readFile("/sys/class/dmi/id/product_uuid");
    if (uuid.empty()) {
        uuid = readFile("/proc/sys/kernel/random/uuid");
    }

    // Remove newlines
    uuid.erase(std::remove(uuid.begin(), uuid.end(), '\\n'), uuid.end());
    return uuid;
}

std::string SecurityUtils::generateHardwareFingerprint() {
    return extractHardwareId();
}

std::string SecurityUtils::generateActivationToken(const std::string& hardware_id, const std::string& license_key) {
    // Create token payload
    auto now = std::chrono::system_clock::now();
    auto expiry = now + std::chrono::hours(TOKEN_VALIDITY_HOURS);
    auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(expiry.time_since_epoch()).count();

    std::string payload = hardware_id + "|" + license_key + "|" + std::to_string(timestamp);

    // Sign the payload
    std::string key = sha256("maestro_activation_key_" + hardware_id);
    std::string signature = hmacSha256(payload, key);

    // Combine payload and signature
    std::string token = base64Encode(payload) + "." + base64Encode(signature);

    return token;
}

bool SecurityUtils::validateActivationToken(const std::string& token, const std::string& hardware_id, const std::string& license_key) {
    size_t dot_pos = token.find('.');
    if (dot_pos == std::string::npos) {
        return false;
    }

    std::string payload_b64 = token.substr(0, dot_pos);
    std::string signature_b64 = token.substr(dot_pos + 1);

    try {
        std::string payload = base64Decode(payload_b64);
        std::string signature = base64Decode(signature_b64);

        // Verify signature
        std::string key = sha256("maestro_activation_key_" + hardware_id);
        std::string expected_signature = hmacSha256(payload, key);

        if (!secureCompare(signature, expected_signature)) {
            return false;
        }

        // Parse payload
        std::istringstream iss(payload);
        std::string token_hardware_id, token_license_key, timestamp_str;

        if (!std::getline(iss, token_hardware_id, '|') ||
            !std::getline(iss, token_license_key, '|') ||
            !std::getline(iss, timestamp_str)) {
            return false;
        }

        // Verify hardware ID and license key
        if (!secureCompare(token_hardware_id, hardware_id) ||
            !secureCompare(token_license_key, license_key)) {
            return false;
        }

        // Check expiration
        int64_t timestamp = std::stoll(timestamp_str);
        auto now = std::chrono::system_clock::now();
        auto token_time = std::chrono::system_clock::from_time_t(timestamp);

        return now < token_time;

    } catch (const std::exception&) {
        return false;
    }
}

std::string SecurityUtils::sha256(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data.c_str(), data.size());
    SHA256_Final(hash, &sha256);

    return hexEncode(std::string(reinterpret_cast<char*>(hash), SHA256_DIGEST_LENGTH));
}

std::string SecurityUtils::hmacSha256(const std::string& data, const std::string& key) {
    unsigned char* digest;
    unsigned int digest_len;

    digest = HMAC(EVP_sha256(), key.c_str(), key.length(),
                  reinterpret_cast<const unsigned char*>(data.c_str()), data.length(),
                  nullptr, &digest_len);

    return hexEncode(std::string(reinterpret_cast<char*>(digest), digest_len));
}

std::string SecurityUtils::base64Encode(const std::string& data) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new(BIO_s_mem());

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, bmem);

    BIO_write(b64, data.c_str(), data.length());
    BIO_flush(b64);

    BUF_MEM* bptr;
    BIO_get_mem_ptr(b64, &bptr);

    std::string result(bptr->data, bptr->length);

    BIO_free_all(b64);

    return result;
}

std::string SecurityUtils::base64Decode(const std::string& encoded) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new_mem_buf(encoded.c_str(), encoded.length());

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, bmem);

    std::vector<char> buffer(encoded.length());
    int decoded_length = BIO_read(b64, buffer.data(), buffer.size());

    BIO_free_all(b64);

    if (decoded_length < 0) {
        return "";
    }

    return std::string(buffer.data(), decoded_length);
}

std::string SecurityUtils::hexEncode(const std::string& data) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');

    for (unsigned char c : data) {
        oss << std::setw(2) << static_cast<int>(c);
    }

    return oss.str();
}

std::string SecurityUtils::hexDecode(const std::string& hex) {
    std::string result;

    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byte_string = hex.substr(i, 2);
        char byte = static_cast<char>(std::strtol(byte_string.c_str(), nullptr, 16));
        result.push_back(byte);
    }

    return result;
}

bool SecurityUtils::secureCompare(const std::string& a, const std::string& b) {
    if (a.length() != b.length()) {
        return false;
    }

    volatile char result = 0;
    for (size_t i = 0; i < a.length(); i++) {
        result |= a[i] ^ b[i];
    }

    return result == 0;
}

std::string SecurityUtils::readFile(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        return "";
    }

    std::ostringstream oss;
    oss << file.rdbuf();
    return oss.str();
}

std::string SecurityUtils::executeCommand(const std::string& command) {
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"), pclose);
    if (!pipe) {
        return "";
    }

    std::string result;
    char buffer[128];

    while (fgets(buffer, sizeof(buffer), pipe.get()) != nullptr) {
        result += buffer;
    }

    return result;
}

bool SecurityUtils::fileExists(const std::string& path) {
    return std::filesystem::exists(path);
}