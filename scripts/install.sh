#!/bin/bash

# Maestro Activation Server Installation Script
# This script installs and configures the activation server with deep system integration

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
INSTALL_PREFIX="/opt/maestro/activation"
SERVICE_USER="maestro-activation"
LOG_FILE="/tmp/maestro_activation_install.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
    exit 1
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root (use sudo)"
    fi
}

# Install system dependencies
install_dependencies() {
    log "Installing system dependencies..."

    # Update package list
    apt-get update -qq

    # Install build dependencies
    apt-get install -y \
        build-essential \
        cmake \
        pkg-config \
        libssl-dev \
        libjsoncpp-dev \
        libsqlite3-dev \
        libcurl4-openssl-dev \
        git \
        wget \
        curl \
        systemd \
        logrotate

    log "System dependencies installed successfully"
}

# Install Drogon framework
install_drogon() {
    log "Installing Drogon framework..."

    local drogon_dir="/tmp/drogon_build"

    if ! command -v drogon_ctl &> /dev/null; then
        # Clone and build Drogon
        rm -rf "$drogon_dir"
        git clone https://github.com/drogonframework/drogon.git "$drogon_dir"

        cd "$drogon_dir"
        git checkout v1.9.1  # Use stable version

        mkdir -p build
        cd build

        cmake .. -DCMAKE_BUILD_TYPE=Release
        make -j$(nproc)
        make install

        # Update library cache
        ldconfig

        # Cleanup
        rm -rf "$drogon_dir"

        log "Drogon framework installed successfully"
    else
        log "Drogon framework already installed"
    fi
}

# Create system user and directories
setup_system_user() {
    log "Setting up system user and directories..."

    # Create service user
    if ! id "$SERVICE_USER" &>/dev/null; then
        useradd --system --shell /bin/false --home "$INSTALL_PREFIX" "$SERVICE_USER"
        log "Created service user: $SERVICE_USER"
    fi

    # Create directory structure
    mkdir -p "$INSTALL_PREFIX"/{bin,config,database,keys,logs,backups}
    mkdir -p /var/lib/maestro/activation
    mkdir -p /etc/systemd/system

    # Set ownership and permissions
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_PREFIX"
    chown -R "$SERVICE_USER:$SERVICE_USER" /var/lib/maestro

    chmod 750 "$INSTALL_PREFIX"
    chmod 700 "$INSTALL_PREFIX"/{keys,database}
    chmod 755 "$INSTALL_PREFIX"/{bin,config,logs,backups}

    log "System user and directories configured"
}

# Build the activation server
build_server() {
    log "Building Maestro Activation Server..."

    cd "$PROJECT_ROOT"

    # Clean previous build
    rm -rf build
    mkdir build
    cd build

    # Configure with CMake
    cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX"

    # Build
    make -j$(nproc)

    # Install
    make install

    log "Activation server built and installed successfully"
}

# Generate SSL certificates
generate_ssl_certificates() {
    log "Generating SSL certificates..."

    local cert_dir="$INSTALL_PREFIX/keys"
    local key_file="$cert_dir/server.key"
    local cert_file="$cert_dir/server.crt"

    if [[ ! -f "$cert_file" ]]; then
        # Generate private key
        openssl genrsa -out "$key_file" 2048

        # Generate self-signed certificate
        openssl req -new -x509 -key "$key_file" -out "$cert_file" -days 3650 \
            -subj "/C=US/ST=State/L=City/O=Maestro/OU=Activation/CN=maestro-activation"

        # Set permissions
        chown "$SERVICE_USER:$SERVICE_USER" "$key_file" "$cert_file"
        chmod 600 "$key_file"
        chmod 644 "$cert_file"

        log "SSL certificates generated"
    else
        log "SSL certificates already exist"
    fi
}

# Setup database
setup_database() {
    log "Setting up database..."

    local db_file="$INSTALL_PREFIX/database/activation.db"
    local schema_file="$PROJECT_ROOT/database/schema.sql"

    # Initialize database with schema
    if [[ ! -f "$db_file" ]]; then
        sqlite3 "$db_file" < "$schema_file"
        chown "$SERVICE_USER:$SERVICE_USER" "$db_file"
        chmod 600 "$db_file"
        log "Database initialized with schema"
    else
        log "Database already exists"
    fi
}

# Install configuration files
install_config() {
    log "Installing configuration files..."

    # Copy server configuration
    cp "$PROJECT_ROOT/config/server.conf" "$INSTALL_PREFIX/config/"
    chown "$SERVICE_USER:$SERVICE_USER" "$INSTALL_PREFIX/config/server.conf"
    chmod 640 "$INSTALL_PREFIX/config/server.conf"

    log "Configuration files installed"
}

# Create systemd service
create_systemd_service() {
    log "Creating systemd service..."

    cat > /etc/systemd/system/maestro-activation.service << EOF
[Unit]
Description=Maestro Activation Server
Documentation=https://github.com/aamat09/maestro_captive
After=network.target
Wants=network.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_PREFIX
ExecStart=$INSTALL_PREFIX/bin/maestro_activation_server
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=10
KillMode=mixed
TimeoutStopSec=30

# Security settings
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=$INSTALL_PREFIX /var/lib/maestro

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096
MemoryLimit=512M

# Environment
Environment=HOME=$INSTALL_PREFIX
Environment=USER=$SERVICE_USER

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd
    systemctl daemon-reload
    systemctl enable maestro-activation.service

    log "Systemd service created and enabled"
}

# Setup log rotation
setup_log_rotation() {
    log "Setting up log rotation..."

    cat > /etc/logrotate.d/maestro-activation << EOF
$INSTALL_PREFIX/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 $SERVICE_USER $SERVICE_USER
    postrotate
        systemctl reload maestro-activation.service > /dev/null 2>&1 || true
    endscript
}
EOF

    log "Log rotation configured"
}

# Bury system integration secrets
bury_system_secrets() {
    log "Burying system integration secrets..."

    # Create hidden system service configuration
    local system_config_dir="/etc/systemd/system/.maestro_integration"
    mkdir -p "$system_config_dir"

    # Store obfuscated keys in systemd configuration files
    cat > "$system_config_dir/sys_key_alpha.conf" << EOF
[Unit]
Description=System Configuration Alpha
Documentation=mAeStRo_SeC_KeY_AlPhA_2024

[Service]
Type=oneshot
ExecStart=/bin/true

[Install]
WantedBy=multi-user.target
EOF

    cat > "$system_config_dir/hw_validation_beta.conf" << EOF
[Unit]
Description=Hardware Validation Beta
Documentation=cApTiVe_PoRtAl_BeTa_EnCrYpT

[Service]
Type=oneshot
ExecStart=/bin/true

[Install]
WantedBy=multi-user.target
EOF

    # Set restrictive permissions
    chmod 600 "$system_config_dir"/*.conf
    chown root:root "$system_config_dir"/*.conf

    # Create decoy cache files
    mkdir -p /var/cache/maestro
    echo "# System cache configuration" > /var/cache/maestro/.system_cache
    echo "cache_version=1.0" >> /var/cache/maestro/.system_cache
    echo "last_update=$(date +%s)" >> /var/cache/maestro/.system_cache

    # Hide configuration in multiple locations
    echo "hArDwArE_iD_gAmMa_PrOtEcT" > /etc/machine-id.maestro.bak
    chmod 600 /etc/machine-id.maestro.bak

    log "System integration secrets buried successfully"
}

# Setup firewall rules
setup_firewall() {
    log "Setting up firewall rules..."

    if command -v ufw &> /dev/null; then
        # Allow activation server ports
        ufw allow 8080/tcp comment "Maestro Activation HTTP"
        ufw allow 8443/tcp comment "Maestro Activation HTTPS"

        log "UFW firewall rules added"
    elif command -v firewall-cmd &> /dev/null; then
        # For systems with firewalld
        firewall-cmd --permanent --add-port=8080/tcp
        firewall-cmd --permanent --add-port=8443/tcp
        firewall-cmd --reload

        log "Firewalld rules added"
    else
        warning "No firewall detected. Please manually configure ports 8080 and 8443"
    fi
}

# Start and test service
start_and_test() {
    log "Starting Maestro Activation Server..."

    # Start the service
    systemctl start maestro-activation.service

    # Wait a moment for startup
    sleep 3

    # Check service status
    if systemctl is-active --quiet maestro-activation.service; then
        log "Service started successfully"

        # Test HTTP endpoint
        if curl -f -s http://localhost:8080/api/v1/server/status >/dev/null 2>&1; then
            log "HTTP endpoint responding correctly"
        else
            warning "HTTP endpoint not responding"
        fi

        # Test HTTPS endpoint (may fail with self-signed cert)
        if curl -f -s -k https://localhost:8443/api/v1/server/status >/dev/null 2>&1; then
            log "HTTPS endpoint responding correctly"
        else
            warning "HTTPS endpoint not responding (normal with self-signed certificates)"
        fi
    else
        error "Failed to start service. Check logs: journalctl -u maestro-activation.service"
    fi
}

# Main installation function
main() {
    log "Starting Maestro Activation Server installation..."

    check_root
    install_dependencies
    install_drogon
    setup_system_user
    build_server
    generate_ssl_certificates
    setup_database
    install_config
    create_systemd_service
    setup_log_rotation
    bury_system_secrets
    setup_firewall
    start_and_test

    log ""
    log "╔════════════════════════════════════════════════════════════╗"
    log "║                    INSTALLATION COMPLETE                   ║"
    log "╠════════════════════════════════════════════════════════════╣"
    log "║ Maestro Activation Server is now running                  ║"
    log "║                                                            ║"
    log "║ HTTP:  http://localhost:8080                               ║"
    log "║ HTTPS: https://localhost:8443                              ║"
    log "║                                                            ║"
    log "║ Service: systemctl status maestro-activation              ║"
    log "║ Logs:    journalctl -u maestro-activation -f              ║"
    log "║ Config:  $INSTALL_PREFIX/config/server.conf ║"
    log "╚════════════════════════════════════════════════════════════╝"
    log ""
    log "Installation log saved to: $LOG_FILE"
}

# Run main function
main "$@"