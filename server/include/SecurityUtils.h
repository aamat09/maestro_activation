#pragma once

#include <string>
#include <vector>
#include <chrono>

class SecurityUtils {
public:
    // Cryptographic initialization
    static bool initializeCrypto();
    static void cleanupCrypto();

    // Token management
    static std::string generateActivationToken(const std::string& hardware_id, const std::string& license_key);
    static bool validateActivationToken(const std::string& token, const std::string& hardware_id, const std::string& license_key);

    // Hardware ID extraction and validation
    static std::string extractHardwareId();
    static std::string getMacAddress();
    static std::string getCpuSerial();
    static std::string getBoardSerial();
    static std::string getSystemUuid();
    static std::string generateHardwareFingerprint();

    // Cryptographic functions
    static std::string generateSecureRandom(size_t length);
    static std::string sha256(const std::string& data);
    static std::string sha512(const std::string& data);
    static std::string hmacSha256(const std::string& data, const std::string& key);

    // AES encryption/decryption
    static std::string aesEncrypt(const std::string& plaintext, const std::string& key, const std::string& iv = "");
    static std::string aesDecrypt(const std::string& ciphertext, const std::string& key, const std::string& iv = "");

    // RSA encryption/decryption (for license keys)
    static std::pair<std::string, std::string> generateRsaKeyPair(int key_size = 2048);
    static std::string rsaEncrypt(const std::string& plaintext, const std::string& public_key);
    static std::string rsaDecrypt(const std::string& ciphertext, const std::string& private_key);

    // Digital signatures
    static std::string signData(const std::string& data, const std::string& private_key);
    static bool verifySignature(const std::string& data, const std::string& signature, const std::string& public_key);

    // Base64 encoding/decoding
    static std::string base64Encode(const std::string& data);
    static std::string base64Decode(const std::string& encoded);

    // Hex encoding/decoding
    static std::string hexEncode(const std::string& data);
    static std::string hexDecode(const std::string& hex);

    // Secure string comparison (timing attack resistant)
    static bool secureCompare(const std::string& a, const std::string& b);

    // System security checks
    static bool isRunningInVM();
    static bool isDebuggerPresent();
    static bool isSystemCompromised();
    static std::vector<std::string> detectTamperingAttempts();

    // Anti-reverse engineering
    static void antiDebugInit();
    static bool checkIntegrity();
    static std::string obfuscateString(const std::string& input);
    static std::string deobfuscateString(const std::string& obfuscated);

private:
    // Internal helper functions
    static std::string readFile(const std::string& path);
    static std::string executeCommand(const std::string& command);
    static bool fileExists(const std::string& path);

    // Key derivation
    static std::string deriveKey(const std::string& password, const std::string& salt, int iterations = 10000);

    // Constants
    static constexpr int AES_KEY_SIZE = 32; // 256 bits
    static constexpr int AES_IV_SIZE = 16;  // 128 bits
    static constexpr int TOKEN_VALIDITY_HOURS = 24;
};