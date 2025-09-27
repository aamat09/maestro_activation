#pragma once

#include <drogon/HttpController.h>
#include <json/json.h>

using namespace drogon;

class ActivationController : public HttpController<ActivationController> {
public:
    METHOD_LIST_BEGIN
    METHOD_ADD(ActivationController::registerDevice, "/api/v1/register", Post, Options);
    METHOD_ADD(ActivationController::activateDevice, "/api/v1/activate", Post, Options);
    METHOD_ADD(ActivationController::validateDevice, "/api/v1/validate", Post, Options);
    METHOD_ADD(ActivationController::getDeviceStatus, "/api/v1/status/{hardware_id}", Get, Options);
    METHOD_ADD(ActivationController::deactivateDevice, "/api/v1/deactivate", Post, Options);
    METHOD_ADD(ActivationController::getActivationHistory, "/api/v1/history/{hardware_id}", Get, Options);
    METHOD_ADD(ActivationController::serverStatus, "/api/v1/server/status", Get);
    METHOD_LIST_END

    // Device registration and management
    void registerDevice(const HttpRequestPtr& req,
                       std::function<void(const HttpResponsePtr&)>&& callback);

    void activateDevice(const HttpRequestPtr& req,
                       std::function<void(const HttpResponsePtr&)>&& callback);

    void validateDevice(const HttpRequestPtr& req,
                       std::function<void(const HttpResponsePtr&)>&& callback);

    void getDeviceStatus(const HttpRequestPtr& req,
                        std::function<void(const HttpResponsePtr&)>&& callback,
                        const std::string& hardware_id);

    void deactivateDevice(const HttpRequestPtr& req,
                         std::function<void(const HttpResponsePtr&)>&& callback);

    void getActivationHistory(const HttpRequestPtr& req,
                             std::function<void(const HttpResponsePtr&)>&& callback,
                             const std::string& hardware_id);

    void serverStatus(const HttpRequestPtr& req,
                     std::function<void(const HttpResponsePtr&)>&& callback);

private:
    // Helper methods
    Json::Value createErrorResponse(const std::string& error, const std::string& details = "");
    Json::Value createSuccessResponse(const Json::Value& data = Json::Value::null);

    bool validateRequestStructure(const Json::Value& json, const std::vector<std::string>& required_fields);
    bool isValidHardwareId(const std::string& hardware_id);
    bool isValidLicenseKey(const std::string& license_key);

    HttpResponsePtr createJsonResponse(const Json::Value& json, HttpStatusCode status = k200OK);
    std::string getClientIP(const HttpRequestPtr& req);
    std::string getUserAgent(const HttpRequestPtr& req);

    // Security helpers
    bool checkRateLimit(const std::string& client_ip);
    bool validateSecurityHeaders(const HttpRequestPtr& req);
    void logSecurityEvent(const std::string& event, const std::string& details,
                         const std::string& client_ip);
};