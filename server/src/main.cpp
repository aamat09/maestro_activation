#include <drogon/drogon.h>
#include <iostream>
#include <csignal>
#include "DatabaseManager.h"
#include "ActivationController.h"
#include "LicenseManager.h"
#include "SecurityUtils.h"

using namespace drogon;

void signalHandler(int signal) {
    std::cout << "\nShutting down Maestro Activation Server..." << std::endl;
    app().quit();
}

int main() {
    // Register signal handlers
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    try {
        // Initialize database
        DatabaseManager::getInstance().initialize();

        // Initialize security components
        SecurityUtils::initializeCrypto();

        std::cout << "Maestro Activation Server starting..." << std::endl;

        // Configure Drogon
        app().setLogPath("/opt/maestro/activation/logs")
             .setLogLevel(trantor::Logger::kInfo)
             .setThreadNum(4)
             .setMaxConnectionNum(1000)
             .setMaxConnectionNumPerIP(10)
             .enableCompressedResponse(true)
             .enableSession(3600); // 1 hour session timeout

        // Add listener for HTTPS (production)
        app().addListener("0.0.0.0", 8443, true, "/opt/maestro/activation/keys/server.crt",
                         "/opt/maestro/activation/keys/server.key");

        // Add listener for HTTP (development/fallback)
        app().addListener("0.0.0.0", 8080, false);

        // Load controllers
        app().registerController(std::make_shared<ActivationController>());

        // Configure CORS for development
        app().registerPreRoutingAdvice([](const HttpRequestPtr &req) {
            return HttpResponsePtr{};
        });

        app().registerPostRoutingAdvice([](const HttpRequestPtr &req, const HttpResponsePtr &resp) {
            resp->addHeader("Access-Control-Allow-Origin", "*");
            resp->addHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
            resp->addHeader("Access-Control-Allow-Headers", "Content-Type,Authorization");
        });

        std::cout << "Server ready:" << std::endl;
        std::cout << "  HTTPS: https://localhost:8443" << std::endl;
        std::cout << "  HTTP:  http://localhost:8080" << std::endl;

        // Run the server
        app().run();

    } catch (const std::exception &e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "Maestro Activation Server stopped." << std::endl;
    return 0;
}