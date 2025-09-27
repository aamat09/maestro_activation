-- Maestro Activation Server Database Schema
-- SQLite Database for License Management and Device Tracking

-- Enable foreign keys for referential integrity
PRAGMA foreign_keys = ON;

-- Set journal mode for better performance and reliability
PRAGMA journal_mode = WAL;

-- Create devices table for registered hardware
CREATE TABLE IF NOT EXISTS devices (
    hardware_id TEXT PRIMARY KEY,
    license_key TEXT UNIQUE NOT NULL,
    device_name TEXT NOT NULL,
    mac_address TEXT,
    cpu_serial TEXT,
    board_serial TEXT,
    system_uuid TEXT,
    hardware_fingerprint TEXT,
    is_active BOOLEAN DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_activation TIMESTAMP,
    activation_count INTEGER DEFAULT 0,
    max_activations INTEGER DEFAULT 100,
    client_ip TEXT,
    user_agent TEXT,
    license_features TEXT, -- JSON array of features
    license_expires_at TIMESTAMP,
    notes TEXT
);

-- Create activation log for tracking all activation attempts
CREATE TABLE IF NOT EXISTS activation_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hardware_id TEXT NOT NULL,
    client_ip TEXT NOT NULL,
    user_agent TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    success BOOLEAN NOT NULL,
    error_message TEXT,
    activation_token TEXT,
    request_data TEXT, -- JSON of request details
    FOREIGN KEY (hardware_id) REFERENCES devices(hardware_id)
);

-- Create rate limiting table for DDoS protection
CREATE TABLE IF NOT EXISTS rate_limits (
    client_ip TEXT PRIMARY KEY,
    attempt_count INTEGER DEFAULT 1,
    first_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    blocked_until TIMESTAMP
);

-- Create security events table for monitoring
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    hardware_id TEXT,
    client_ip TEXT NOT NULL,
    user_agent TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    severity TEXT DEFAULT 'INFO', -- DEBUG, INFO, WARNING, ERROR, CRITICAL
    description TEXT NOT NULL,
    additional_data TEXT -- JSON for extra context
);

-- Create license keys table for pre-generated licenses
CREATE TABLE IF NOT EXISTS license_keys (
    license_key TEXT PRIMARY KEY,
    hardware_id TEXT,
    issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    features TEXT, -- JSON array
    max_devices INTEGER DEFAULT 1,
    is_used BOOLEAN DEFAULT 0,
    revoked BOOLEAN DEFAULT 0,
    revoked_at TIMESTAMP,
    revoked_reason TEXT,
    FOREIGN KEY (hardware_id) REFERENCES devices(hardware_id)
);

-- Create system configuration table
CREATE TABLE IF NOT EXISTS system_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    description TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create audit log for administrative actions
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL, -- device, license, config, etc.
    entity_id TEXT,
    old_values TEXT, -- JSON
    new_values TEXT, -- JSON
    admin_user TEXT,
    client_ip TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    notes TEXT
);

-- Indexes for performance optimization
CREATE INDEX IF NOT EXISTS idx_devices_hardware_id ON devices(hardware_id);
CREATE INDEX IF NOT EXISTS idx_devices_license_key ON devices(license_key);
CREATE INDEX IF NOT EXISTS idx_devices_is_active ON devices(is_active);
CREATE INDEX IF NOT EXISTS idx_devices_created_at ON devices(created_at);

CREATE INDEX IF NOT EXISTS idx_activation_log_hardware_id ON activation_log(hardware_id);
CREATE INDEX IF NOT EXISTS idx_activation_log_timestamp ON activation_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_activation_log_success ON activation_log(success);
CREATE INDEX IF NOT EXISTS idx_activation_log_client_ip ON activation_log(client_ip);

CREATE INDEX IF NOT EXISTS idx_rate_limits_client_ip ON rate_limits(client_ip);
CREATE INDEX IF NOT EXISTS idx_rate_limits_first_attempt ON rate_limits(first_attempt);

CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_security_events_event_type ON security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_security_events_client_ip ON security_events(client_ip);
CREATE INDEX IF NOT EXISTS idx_security_events_hardware_id ON security_events(hardware_id);

CREATE INDEX IF NOT EXISTS idx_license_keys_hardware_id ON license_keys(hardware_id);
CREATE INDEX IF NOT EXISTS idx_license_keys_is_used ON license_keys(is_used);
CREATE INDEX IF NOT EXISTS idx_license_keys_expires_at ON license_keys(expires_at);

-- Initialize system configuration with default values
INSERT OR IGNORE INTO system_config (key, value, description) VALUES
('server_version', '1.0.0', 'Activation server version'),
('database_version', '1.0', 'Database schema version'),
('rate_limit_enabled', 'true', 'Enable rate limiting'),
('rate_limit_requests', '10', 'Max requests per window'),
('rate_limit_window_minutes', '15', 'Rate limit window in minutes'),
('max_devices_per_license', '1', 'Maximum devices per license key'),
('default_license_validity_years', '10', 'Default license validity in years'),
('security_logging_enabled', 'true', 'Enable security event logging'),
('audit_logging_enabled', 'true', 'Enable audit logging'),
('vm_detection_enabled', 'true', 'Enable virtual machine detection'),
('debugger_detection_enabled', 'true', 'Enable debugger detection'),
('token_validity_hours', '24', 'Activation token validity in hours'),
('cleanup_old_logs_days', '90', 'Days to keep old log entries'),
('backup_interval_hours', '24', 'Database backup interval'),
('last_cleanup', '0', 'Timestamp of last cleanup operation'),
('total_devices_registered', '0', 'Total number of registered devices'),
('total_activations', '0', 'Total number of successful activations');

-- Create triggers for automatic maintenance

-- Update total counters when devices are registered
CREATE TRIGGER IF NOT EXISTS trigger_device_registered
AFTER INSERT ON devices
BEGIN
    UPDATE system_config
    SET value = CAST((CAST(value AS INTEGER) + 1) AS TEXT)
    WHERE key = 'total_devices_registered';
END;

-- Update activation counter on successful activations
CREATE TRIGGER IF NOT EXISTS trigger_activation_success
AFTER INSERT ON activation_log
WHEN NEW.success = 1
BEGIN
    UPDATE system_config
    SET value = CAST((CAST(value AS INTEGER) + 1) AS TEXT)
    WHERE key = 'total_activations';
END;

-- Automatically clean up old rate limit entries
CREATE TRIGGER IF NOT EXISTS trigger_cleanup_rate_limits
AFTER INSERT ON rate_limits
BEGIN
    DELETE FROM rate_limits
    WHERE datetime(first_attempt, '+1 day') < datetime('now');
END;

-- Views for easier querying

-- Active devices view
CREATE VIEW IF NOT EXISTS view_active_devices AS
SELECT
    hardware_id,
    license_key,
    device_name,
    is_active,
    created_at,
    last_activation,
    activation_count,
    client_ip
FROM devices
WHERE is_active = 1;

-- Recent activations view
CREATE VIEW IF NOT EXISTS view_recent_activations AS
SELECT
    al.hardware_id,
    d.device_name,
    al.client_ip,
    al.timestamp,
    al.success,
    al.error_message
FROM activation_log al
LEFT JOIN devices d ON al.hardware_id = d.hardware_id
WHERE al.timestamp > datetime('now', '-7 days')
ORDER BY al.timestamp DESC;

-- Security events summary view
CREATE VIEW IF NOT EXISTS view_security_summary AS
SELECT
    event_type,
    severity,
    COUNT(*) as event_count,
    MAX(timestamp) as last_occurrence
FROM security_events
WHERE timestamp > datetime('now', '-24 hours')
GROUP BY event_type, severity
ORDER BY event_count DESC;