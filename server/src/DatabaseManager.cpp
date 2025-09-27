#include "DatabaseManager.h"
#include <iostream>
#include <filesystem>
#include <iomanip>
#include <sstream>

DatabaseManager& DatabaseManager::getInstance() {
    static DatabaseManager instance;
    return instance;
}

DatabaseManager::~DatabaseManager() {
    close();
}

bool DatabaseManager::initialize() {
    // Create directory if it doesn't exist
    std::filesystem::path db_dir = std::filesystem::path(db_path_).parent_path();
    std::filesystem::create_directories(db_dir);

    int result = sqlite3_open(db_path_.c_str(), &db_);
    if (result != SQLITE_OK) {
        std::cerr << "Failed to open database: " << sqlite3_errmsg(db_) << std::endl;
        return false;
    }

    // Enable foreign keys
    executeSQL("PRAGMA foreign_keys = ON;");

    // Set journal mode for better performance
    executeSQL("PRAGMA journal_mode = WAL;");

    return createTables();
}

bool DatabaseManager::close() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
    return true;
}

bool DatabaseManager::createTables() {
    const std::string devices_table = R"(
        CREATE TABLE IF NOT EXISTS devices (
            hardware_id TEXT PRIMARY KEY,
            license_key TEXT UNIQUE NOT NULL,
            device_name TEXT,
            mac_address TEXT,
            cpu_serial TEXT,
            board_serial TEXT,
            is_active BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_activation TIMESTAMP,
            activation_count INTEGER DEFAULT 0,
            client_ip TEXT,
            user_agent TEXT
        );
    )";

    const std::string activation_log_table = R"(
        CREATE TABLE IF NOT EXISTS activation_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hardware_id TEXT NOT NULL,
            client_ip TEXT NOT NULL,
            user_agent TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            success BOOLEAN NOT NULL,
            error_message TEXT,
            FOREIGN KEY (hardware_id) REFERENCES devices(hardware_id)
        );
    )";

    const std::string rate_limit_table = R"(
        CREATE TABLE IF NOT EXISTS rate_limits (
            client_ip TEXT PRIMARY KEY,
            attempt_count INTEGER DEFAULT 1,
            first_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    )";

    return executeSQL(devices_table) &&
           executeSQL(activation_log_table) &&
           executeSQL(rate_limit_table);
}

bool DatabaseManager::executeSQL(const std::string& sql) {
    char* error_message = nullptr;
    int result = sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &error_message);

    if (result != SQLITE_OK) {
        std::cerr << "SQL error: " << error_message << std::endl;
        sqlite3_free(error_message);
        return false;
    }

    return true;
}

sqlite3_stmt* DatabaseManager::prepareStatement(const std::string& sql) {
    sqlite3_stmt* stmt;
    int result = sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);

    if (result != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db_) << std::endl;
        return nullptr;
    }

    return stmt;
}

bool DatabaseManager::registerDevice(const Device& device) {
    const std::string sql = R"(
        INSERT INTO devices (hardware_id, license_key, device_name, mac_address,
                           cpu_serial, board_serial, is_active, client_ip, user_agent)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
    )";

    sqlite3_stmt* stmt = prepareStatement(sql);
    if (!stmt) return false;

    sqlite3_bind_text(stmt, 1, device.hardware_id.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, device.license_key.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, device.device_name.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, device.mac_address.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, device.cpu_serial.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, device.board_serial.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 7, device.is_active ? 1 : 0);
    sqlite3_bind_text(stmt, 8, device.client_ip.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 9, device.user_agent.c_str(), -1, SQLITE_STATIC);

    int result = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return result == SQLITE_DONE;
}

std::unique_ptr<Device> DatabaseManager::getDevice(const std::string& hardware_id) {
    const std::string sql = R"(
        SELECT hardware_id, license_key, device_name, mac_address, cpu_serial,
               board_serial, is_active, created_at, last_activation, activation_count,
               client_ip, user_agent
        FROM devices WHERE hardware_id = ?;
    )";

    sqlite3_stmt* stmt = prepareStatement(sql);
    if (!stmt) return nullptr;

    sqlite3_bind_text(stmt, 1, hardware_id.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        auto device = std::make_unique<Device>();
        device->hardware_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        device->license_key = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        device->device_name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        device->mac_address = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        device->cpu_serial = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        device->board_serial = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        device->is_active = sqlite3_column_int(stmt, 6) == 1;
        device->activation_count = sqlite3_column_int(stmt, 9);
        device->client_ip = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 10));
        device->user_agent = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 11));

        sqlite3_finalize(stmt);
        return device;
    }

    sqlite3_finalize(stmt);
    return nullptr;
}

bool DatabaseManager::validateLicense(const std::string& hardware_id, const std::string& license_key) {
    auto device = getDevice(hardware_id);
    return device && device->license_key == license_key;
}

bool DatabaseManager::activateDevice(const std::string& hardware_id, const std::string& client_ip, const std::string& user_agent) {
    const std::string sql = R"(
        UPDATE devices
        SET is_active = 1, last_activation = CURRENT_TIMESTAMP, activation_count = activation_count + 1,
            client_ip = ?, user_agent = ?
        WHERE hardware_id = ?;
    )";

    sqlite3_stmt* stmt = prepareStatement(sql);
    if (!stmt) return false;

    sqlite3_bind_text(stmt, 1, client_ip.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, user_agent.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, hardware_id.c_str(), -1, SQLITE_STATIC);

    int result = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return result == SQLITE_DONE && sqlite3_changes(db_) > 0;
}

bool DatabaseManager::logActivationAttempt(const ActivationAttempt& attempt) {
    const std::string sql = R"(
        INSERT INTO activation_log (hardware_id, client_ip, user_agent, success, error_message)
        VALUES (?, ?, ?, ?, ?);
    )";

    sqlite3_stmt* stmt = prepareStatement(sql);
    if (!stmt) return false;

    sqlite3_bind_text(stmt, 1, attempt.hardware_id.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, attempt.client_ip.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, attempt.user_agent.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 4, attempt.success ? 1 : 0);
    sqlite3_bind_text(stmt, 5, attempt.error_message.c_str(), -1, SQLITE_STATIC);

    int result = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return result == SQLITE_DONE;
}

bool DatabaseManager::isRateLimited(const std::string& client_ip, int max_attempts, int window_minutes) {
    const std::string sql = R"(
        SELECT attempt_count, first_attempt FROM rate_limits
        WHERE client_ip = ? AND datetime(first_attempt, '+' || ? || ' minutes') > datetime('now');
    )";

    sqlite3_stmt* stmt = prepareStatement(sql);
    if (!stmt) return false;

    sqlite3_bind_text(stmt, 1, client_ip.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, window_minutes);

    bool rate_limited = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        int attempt_count = sqlite3_column_int(stmt, 0);
        rate_limited = attempt_count >= max_attempts;
    }

    sqlite3_finalize(stmt);

    // Update rate limit counter
    const std::string update_sql = R"(
        INSERT OR REPLACE INTO rate_limits (client_ip, attempt_count, first_attempt, last_attempt)
        VALUES (?,
                COALESCE((SELECT attempt_count FROM rate_limits WHERE client_ip = ?
                         AND datetime(first_attempt, '+' || ? || ' minutes') > datetime('now')), 0) + 1,
                COALESCE((SELECT first_attempt FROM rate_limits WHERE client_ip = ?
                         AND datetime(first_attempt, '+' || ? || ' minutes') > datetime('now')), datetime('now')),
                datetime('now'));
    )";

    sqlite3_stmt* update_stmt = prepareStatement(update_sql);
    if (update_stmt) {
        sqlite3_bind_text(update_stmt, 1, client_ip.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(update_stmt, 2, client_ip.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(update_stmt, 3, window_minutes);
        sqlite3_bind_text(update_stmt, 4, client_ip.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(update_stmt, 5, window_minutes);
        sqlite3_step(update_stmt);
        sqlite3_finalize(update_stmt);
    }

    return rate_limited;
}