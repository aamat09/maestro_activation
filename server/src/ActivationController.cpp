#include "ActivationController.h"
#include "DatabaseManager.h"
#include "LicenseManager.h"
#include "SecurityUtils.h"
#include <iostream>
#include <regex>

void ActivationController::registerDevice(const HttpRequestPtr& req,
                                         std::function<void(const HttpResponsePtr&)>&& callback) {
    auto client_ip = getClientIP(req);
    auto user_agent = getUserAgent(req);

    // Check rate limiting
    if (!checkRateLimit(client_ip)) {
        logSecurityEvent("RATE_LIMIT_EXCEEDED", "Device registration", client_ip);
        auto response = createErrorResponse("Rate limit exceeded", "Too many requests from this IP");
        callback(createJsonResponse(response, k429TooManyRequests));
        return;
    }

    try {
        auto json = *req->getJsonObject();
        std::vector<std::string> required_fields = {"hardware_id", "device_name", "mac_address", "cpu_serial", "board_serial"};

        if (!validateRequestStructure(json, required_fields)) {
            auto response = createErrorResponse("Invalid request", "Missing required fields");
            callback(createJsonResponse(response, k400BadRequest));
            return;
        }

        std::string hardware_id = json["hardware_id"].asString();
        std::string device_name = json["device_name"].asString();
        std::string mac_address = json["mac_address"].asString();
        std::string cpu_serial = json["cpu_serial"].asString();
        std::string board_serial = json["board_serial"].asString();

        // Validate hardware ID format
        if (!isValidHardwareId(hardware_id)) {
            auto response = createErrorResponse("Invalid hardware ID", "Hardware ID format is invalid");
            callback(createJsonResponse(response, k400BadRequest));
            return;
        }

        // Check if device already exists
        auto existing_device = DatabaseManager::getInstance().getDevice(hardware_id);
        if (existing_device) {
            auto response = createErrorResponse("Device already registered", "This device is already in the system");
            callback(createJsonResponse(response, k409Conflict));
            return;
        }

        // Generate license key
        std::string license_key = LicenseManager::generateLicenseKey(hardware_id, device_name);
        if (license_key.empty()) {
            auto response = createErrorResponse("License generation failed", "Could not generate license key");
            callback(createJsonResponse(response, k500InternalServerError));
            return;
        }

        // Create device object
        Device device;
        device.hardware_id = hardware_id;
        device.license_key = license_key;
        device.device_name = device_name;
        device.mac_address = mac_address;
        device.cpu_serial = cpu_serial;
        device.board_serial = board_serial;
        device.is_active = false;
        device.client_ip = client_ip;
        device.user_agent = user_agent;

        // Register device in database
        if (!DatabaseManager::getInstance().registerDevice(device)) {
            auto response = createErrorResponse("Registration failed", "Could not save device to database");
            callback(createJsonResponse(response, k500InternalServerError));
            return;
        }

        // Log successful registration
        ActivationAttempt attempt;
        attempt.hardware_id = hardware_id;
        attempt.client_ip = client_ip;
        attempt.user_agent = user_agent;
        attempt.success = true;
        DatabaseManager::getInstance().logActivationAttempt(attempt);

        // Return success with license key
        Json::Value data;
        data["hardware_id"] = hardware_id;
        data["license_key"] = license_key;
        data["device_name"] = device_name;
        data["status"] = "registered";

        auto response = createSuccessResponse(data);
        callback(createJsonResponse(response, k201Created));

    } catch (const std::exception& e) {
        auto response = createErrorResponse("Server error", e.what());
        callback(createJsonResponse(response, k500InternalServerError));
    }
}

void ActivationController::activateDevice(const HttpRequestPtr& req,
                                         std::function<void(const HttpResponsePtr&)>&& callback) {
    auto client_ip = getClientIP(req);
    auto user_agent = getUserAgent(req);

    if (!checkRateLimit(client_ip)) {
        auto response = createErrorResponse("Rate limit exceeded", "Too many activation attempts");
        callback(createJsonResponse(response, k429TooManyRequests));
        return;
    }

    try {
        auto json = *req->getJsonObject();
        std::vector<std::string> required_fields = {"hardware_id", "license_key"};

        if (!validateRequestStructure(json, required_fields)) {
            auto response = createErrorResponse("Invalid request", "Missing hardware_id or license_key");
            callback(createJsonResponse(response, k400BadRequest));
            return;
        }

        std::string hardware_id = json["hardware_id"].asString();
        std::string license_key = json["license_key"].asString();

        // Validate hardware ID and license key
        if (!isValidHardwareId(hardware_id) || !isValidLicenseKey(license_key)) {
            ActivationAttempt attempt{hardware_id, client_ip, user_agent, {}, false, "Invalid credentials format"};
            DatabaseManager::getInstance().logActivationAttempt(attempt);

            auto response = createErrorResponse("Invalid credentials", "Hardware ID or license key format is invalid");
            callback(createJsonResponse(response, k400BadRequest));
            return;
        }

        // Validate license
        if (!DatabaseManager::getInstance().validateLicense(hardware_id, license_key)) {
            ActivationAttempt attempt{hardware_id, client_ip, user_agent, {}, false, "License validation failed"};
            DatabaseManager::getInstance().logActivationAttempt(attempt);

            logSecurityEvent("INVALID_LICENSE", "License validation failed for " + hardware_id, client_ip);
            auto response = createErrorResponse("Authentication failed", "Invalid hardware ID or license key");
            callback(createJsonResponse(response, k401Unauthorized));
            return;
        }

        // Activate device
        if (!DatabaseManager::getInstance().activateDevice(hardware_id, client_ip, user_agent)) {
            ActivationAttempt attempt{hardware_id, client_ip, user_agent, {}, false, "Database activation failed"};
            DatabaseManager::getInstance().logActivationAttempt(attempt);

            auto response = createErrorResponse("Activation failed", "Could not activate device");
            callback(createJsonResponse(response, k500InternalServerError));
            return;
        }

        // Log successful activation
        ActivationAttempt attempt{hardware_id, client_ip, user_agent, {}, true, ""};
        DatabaseManager::getInstance().logActivationAttempt(attempt);

        // Generate activation token
        std::string activation_token = SecurityUtils::generateActivationToken(hardware_id, license_key);

        Json::Value data;
        data["hardware_id"] = hardware_id;
        data["status"] = "activated";
        data["activation_token"] = activation_token;
        data["timestamp"] = static_cast<int64_t>(std::time(nullptr));

        auto response = createSuccessResponse(data);
        callback(createJsonResponse(response, k200OK));

    } catch (const std::exception& e) {
        auto response = createErrorResponse("Server error", e.what());
        callback(createJsonResponse(response, k500InternalServerError));
    }
}

void ActivationController::validateDevice(const HttpRequestPtr& req,
                                        std::function<void(const HttpResponsePtr&)>&& callback) {
    try {
        auto json = *req->getJsonObject();
        std::vector<std::string> required_fields = {"hardware_id", "activation_token"};

        if (!validateRequestStructure(json, required_fields)) {
            auto response = createErrorResponse("Invalid request", "Missing hardware_id or activation_token");
            callback(createJsonResponse(response, k400BadRequest));
            return;
        }

        std::string hardware_id = json["hardware_id"].asString();
        std::string activation_token = json["activation_token"].asString();

        // Get device from database
        auto device = DatabaseManager::getInstance().getDevice(hardware_id);
        if (!device) {
            auto response = createErrorResponse("Device not found", "Hardware ID not registered");
            callback(createJsonResponse(response, k404NotFound));
            return;
        }

        // Validate activation token
        if (!SecurityUtils::validateActivationToken(activation_token, hardware_id, device->license_key)) {
            logSecurityEvent("INVALID_TOKEN", "Token validation failed for " + hardware_id, getClientIP(req));
            auto response = createErrorResponse("Invalid token", "Activation token is invalid or expired");
            callback(createJsonResponse(response, k401Unauthorized));
            return;
        }

        Json::Value data;
        data["hardware_id"] = hardware_id;
        data["device_name"] = device->device_name;
        data["is_active"] = device->is_active;
        data["activation_count"] = device->activation_count;
        data["valid"] = true;

        auto response = createSuccessResponse(data);
        callback(createJsonResponse(response, k200OK));

    } catch (const std::exception& e) {
        auto response = createErrorResponse("Server error", e.what());
        callback(createJsonResponse(response, k500InternalServerError));
    }
}

void ActivationController::serverStatus(const HttpRequestPtr& req,
                                       std::function<void(const HttpResponsePtr&)>&& callback) {
    Json::Value data;
    data["status"] = "running";
    data["version"] = "1.0.0";
    data["timestamp"] = static_cast<int64_t>(std::time(nullptr));
    data["service"] = "Maestro Activation Server";

    auto response = createSuccessResponse(data);
    callback(createJsonResponse(response, k200OK));
}

// Helper methods
Json::Value ActivationController::createErrorResponse(const std::string& error, const std::string& details) {
    Json::Value response;
    response["status"] = "error";
    response["error"] = error;
    if (!details.empty()) {
        response["details"] = details;
    }
    response["timestamp"] = static_cast<int64_t>(std::time(nullptr));
    return response;
}

Json::Value ActivationController::createSuccessResponse(const Json::Value& data) {
    Json::Value response;
    response["status"] = "success";
    response["timestamp"] = static_cast<int64_t>(std::time(nullptr));
    if (!data.isNull()) {
        response["data"] = data;
    }
    return response;
}

bool ActivationController::validateRequestStructure(const Json::Value& json, const std::vector<std::string>& required_fields) {
    for (const auto& field : required_fields) {
        if (!json.isMember(field) || json[field].asString().empty()) {
            return false;
        }
    }
    return true;
}

bool ActivationController::isValidHardwareId(const std::string& hardware_id) {
    // Hardware ID should be 32-64 characters, alphanumeric and hyphens
    std::regex pattern("^[a-fA-F0-9\\-]{32,64}$");
    return std::regex_match(hardware_id, pattern);
}

bool ActivationController::isValidLicenseKey(const std::string& license_key) {
    // License key should be in format XXXX-XXXX-XXXX-XXXX-XXXX
    std::regex pattern("^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$");
    return std::regex_match(license_key, pattern);
}

HttpResponsePtr ActivationController::createJsonResponse(const Json::Value& json, HttpStatusCode status) {
    auto response = HttpResponse::newHttpJsonResponse(json);
    response->setStatusCode(status);
    response->addHeader("Content-Type", "application/json");
    response->addHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    response->addHeader("X-Content-Type-Options", "nosniff");
    response->addHeader("X-Frame-Options", "DENY");
    return response;
}

std::string ActivationController::getClientIP(const HttpRequestPtr& req) {
    // Check for proxy headers first
    auto xff_header = req->getHeader("X-Forwarded-For");
    if (!xff_header.empty()) {
        return xff_header.substr(0, xff_header.find(','));
    }

    auto real_ip = req->getHeader("X-Real-IP");
    if (!real_ip.empty()) {
        return real_ip;
    }

    return req->getPeerAddr().toIp();
}

std::string ActivationController::getUserAgent(const HttpRequestPtr& req) {
    return req->getHeader("User-Agent");
}

bool ActivationController::checkRateLimit(const std::string& client_ip) {
    return !DatabaseManager::getInstance().isRateLimited(client_ip, 10, 15); // 10 requests per 15 minutes
}

void ActivationController::logSecurityEvent(const std::string& event, const std::string& details,
                                           const std::string& client_ip) {
    std::cout << "[SECURITY] " << event << " from " << client_ip << ": " << details << std::endl;
}