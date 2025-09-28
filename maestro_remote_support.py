#!/usr/bin/env python3
"""
Maestro Remote Support Manager
Secure, customer-controlled remote access system using RustDesk
"""

import os
import sys
import json
import time
import secrets
import string
import subprocess
import threading
import logging
from datetime import datetime, timedelta
from pathlib import Path
from flask import Flask, request, jsonify
from cryptography.fernet import Fernet
import yaml

# Configuration
CONFIG_DIR = "/opt/maestro/remote-support/config"
LOG_DIR = "/opt/maestro/remote-support/logs"
SCRIPTS_DIR = "/opt/maestro/remote-support/scripts"
SESSION_FILE = "/tmp/maestro_support_session.json"
RUSTDESK_CONFIG = "/opt/maestro/rustdesk-config/RustDesk.toml"

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f"{LOG_DIR}/remote_support.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("MaestroRemoteSupport")

class RemoteSupportManager:
    def __init__(self):
        self.config = self.load_config()
        self.session_data = {}
        self.session_timer = None
        self.app = Flask(__name__)
        self.setup_routes()

    def load_config(self):
        """Load remote support configuration"""
        config_file = os.path.join(CONFIG_DIR, "remote_support.yaml")
        try:
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)

            # Decrypt sensitive data
            if 'encrypted_server_key' in config:
                cipher = Fernet(self.get_master_key())
                config['server_key'] = cipher.decrypt(
                    config['encrypted_server_key'].encode()
                ).decode()

            return config
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            return self.get_default_config()

    def get_default_config(self):
        """Default configuration for remote support"""
        return {
            'server_url': 'rustdesk.maestro-support.com',
            'server_port': 21116,
            'relay_port': 21117,
            'api_port': 21118,
            'max_session_duration': 7200,  # 2 hours
            'session_warning_time': 300,   # 5 minutes before expiry
            'auto_accept_connections': False,
            'require_customer_approval': True,
            'log_all_sessions': True,
            'allowed_support_hours': {
                'start': '08:00',
                'end': '20:00',
                'timezone': 'UTC'
            }
        }

    def get_master_key(self):
        """Get or generate master encryption key"""
        key_file = os.path.join(CONFIG_DIR, ".support_key")
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
            os.chmod(key_file, 0o600)
            return key

    def generate_session_password(self, length=12):
        """Generate secure one-time session password"""
        alphabet = string.ascii_letters + string.digits
        # Exclude confusing characters
        alphabet = alphabet.replace('0', '').replace('O', '').replace('1', '').replace('l', '').replace('I', '')
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    def generate_session_id(self):
        """Generate unique session ID"""
        return f"MS-{int(time.time())}-{secrets.token_hex(4).upper()}"

    def configure_rustdesk(self, session_id, password):
        """Configure RustDesk client for support session"""
        try:
            # Ensure RustDesk config directory exists
            config_dir = os.path.dirname(RUSTDESK_CONFIG)
            os.makedirs(config_dir, exist_ok=True)

            rustdesk_config = {
                'id': session_id,
                'password': password,
                'relay-server': self.config['server_url'],
                'api-server': f"https://{self.config['server_url']}:{self.config['api_port']}",
                'key': self.config.get('server_key', ''),
                'custom-rendezvous-server': f"{self.config['server_url']}:{self.config['server_port']}",
                'direct-access-port': 0,
                'whitelist': '',
                'approve-mode': 'click' if self.config['require_customer_approval'] else 'password',
                'enable-audio': True,
                'enable-clipboard': True,
                'enable-file-transfer': False,  # Disabled for security
                'auto-disconnect-timeout': self.config['max_session_duration']
            }

            # Write RustDesk configuration
            with open(RUSTDESK_CONFIG, 'w') as f:
                for key, value in rustdesk_config.items():
                    if isinstance(value, bool):
                        f.write(f"{key} = {str(value).lower()}\\n")
                    elif isinstance(value, int):
                        f.write(f"{key} = {value}\\n")
                    else:
                        f.write(f"{key} = '{value}'\\n")

            logger.info(f"RustDesk configured for session {session_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to configure RustDesk: {e}")
            return False

    def start_rustdesk_service(self):
        """Start RustDesk host service (test implementation)"""
        try:
            # For testing, we'll simulate starting RustDesk
            logger.info("RustDesk service started successfully (test mode)")
            return True

        except Exception as e:
            logger.error(f"Failed to start RustDesk service: {e}")
            return False

    def stop_rustdesk_service(self):
        """Stop RustDesk host service (test implementation)"""
        try:
            # Clean up configuration
            if os.path.exists(RUSTDESK_CONFIG):
                os.remove(RUSTDESK_CONFIG)

            logger.info("RustDesk service stopped (test mode)")
            return True

        except Exception as e:
            logger.error(f"Failed to stop RustDesk service: {e}")
            return False

    def check_rustdesk_installed(self):
        """Check if RustDesk is installed"""
        try:
            result = subprocess.run(['which', 'rustdesk'], capture_output=True)
            return result.returncode == 0
        except:
            return False

    def install_rustdesk(self):
        """Install RustDesk client"""
        try:
            logger.info("Installing RustDesk...")

            # Download and install RustDesk for Debian/Ubuntu
            install_script = f"""#!/bin/bash
cd /tmp
wget -q https://github.com/rustdesk/rustdesk/releases/latest/download/rustdesk-1.2.3-x86_64.deb
dpkg -i rustdesk-1.2.3-x86_64.deb || apt-get install -f -y
rm -f rustdesk-1.2.3-x86_64.deb
"""

            with open('/tmp/install_rustdesk.sh', 'w') as f:
                f.write(install_script)

            os.chmod('/tmp/install_rustdesk.sh', 0o755)
            result = subprocess.run(['/tmp/install_rustdesk.sh'], capture_output=True, text=True)

            if result.returncode == 0:
                logger.info("RustDesk installed successfully")
                return True
            else:
                logger.error(f"RustDesk installation failed: {result.stderr}")
                return False

        except Exception as e:
            logger.error(f"Failed to install RustDesk: {e}")
            return False

    def start_support_session(self, customer_name="", support_tier="standard"):
        """Start a new remote support session"""
        try:
            # Check if session already active
            if self.is_session_active():
                return {
                    'success': False,
                    'error': 'Support session already active'
                }

            # Generate session credentials
            session_id = self.generate_session_id()
            password = self.generate_session_password()

            # Configure RustDesk
            if not self.configure_rustdesk(session_id, password):
                return {
                    'success': False,
                    'error': 'Failed to configure remote access'
                }

            # Start RustDesk service
            if not self.start_rustdesk_service():
                return {
                    'success': False,
                    'error': 'Failed to start remote access service'
                }

            # Create session data
            session_start = datetime.now()
            session_end = session_start + timedelta(seconds=self.config['max_session_duration'])

            self.session_data = {
                'session_id': session_id,
                'password': password,
                'customer_name': customer_name,
                'support_tier': support_tier,
                'start_time': session_start.isoformat(),
                'end_time': session_end.isoformat(),
                'status': 'active',
                'connections': 0
            }

            # Save session data
            with open(SESSION_FILE, 'w') as f:
                json.dump(self.session_data, f, indent=2)

            # Start session timer
            self.start_session_timer()

            # Log session start
            logger.info(f"Support session started: {session_id} for {customer_name}")

            return {
                'success': True,
                'session_id': session_id,
                'password': password,
                'expires_at': session_end.isoformat(),
                'duration_minutes': self.config['max_session_duration'] // 60
            }

        except Exception as e:
            logger.error(f"Failed to start support session: {e}")
            return {
                'success': False,
                'error': f'Internal error: {str(e)}'
            }

    def end_support_session(self, reason="customer_request"):
        """End the current support session"""
        try:
            if not self.is_session_active():
                return {
                    'success': False,
                    'error': 'No active session to end'
                }

            # Stop RustDesk service
            self.stop_rustdesk_service()

            # Cancel timer
            if self.session_timer:
                self.session_timer.cancel()
                self.session_timer = None

            # Log session end
            logger.info(f"Support session ended: {self.session_data.get('session_id')} - Reason: {reason}")

            # Archive session data
            self.archive_session(reason)

            # Clean up
            self.session_data = {}
            if os.path.exists(SESSION_FILE):
                os.remove(SESSION_FILE)

            return {
                'success': True,
                'message': 'Support session ended successfully'
            }

        except Exception as e:
            logger.error(f"Failed to end support session: {e}")
            return {
                'success': False,
                'error': f'Internal error: {str(e)}'
            }

    def is_session_active(self):
        """Check if a support session is currently active"""
        return bool(self.session_data and self.session_data.get('status') == 'active')

    def get_session_status(self):
        """Get current session status"""
        if not self.is_session_active():
            return {
                'active': False,
                'message': 'No active support session'
            }

        now = datetime.now()
        end_time = datetime.fromisoformat(self.session_data['end_time'])
        remaining_seconds = (end_time - now).total_seconds()

        return {
            'active': True,
            'session_id': self.session_data['session_id'],
            'customer_name': self.session_data.get('customer_name', ''),
            'start_time': self.session_data['start_time'],
            'end_time': self.session_data['end_time'],
            'remaining_seconds': max(0, int(remaining_seconds)),
            'remaining_minutes': max(0, int(remaining_seconds // 60)),
            'connections': self.session_data.get('connections', 0)
        }

    def start_session_timer(self):
        """Start automatic session expiry timer"""
        duration = self.config['max_session_duration']

        def expire_session():
            logger.info("Support session expired automatically")
            self.end_support_session("timeout")

        self.session_timer = threading.Timer(duration, expire_session)
        self.session_timer.start()

    def archive_session(self, end_reason):
        """Archive completed session data"""
        try:
            archive_dir = os.path.join(LOG_DIR, "sessions")
            os.makedirs(archive_dir, exist_ok=True)

            session_log = {
                **self.session_data,
                'end_reason': end_reason,
                'actual_end_time': datetime.now().isoformat()
            }

            # Remove sensitive data from archive
            session_log.pop('password', None)

            filename = f"session_{self.session_data['session_id']}.json"
            with open(os.path.join(archive_dir, filename), 'w') as f:
                json.dump(session_log, f, indent=2)

        except Exception as e:
            logger.error(f"Failed to archive session: {e}")

    def setup_routes(self):
        """Setup Flask API routes"""

        @self.app.route('/api/support/start', methods=['POST'])
        def start_session():
            data = request.get_json() or {}
            customer_name = data.get('customer_name', '')
            support_tier = data.get('support_tier', 'standard')

            result = self.start_support_session(customer_name, support_tier)
            return jsonify(result)

        @self.app.route('/api/support/end', methods=['POST'])
        def end_session():
            result = self.end_support_session("customer_request")
            return jsonify(result)

        @self.app.route('/api/support/status', methods=['GET'])
        def get_status():
            status = self.get_session_status()
            return jsonify(status)

        @self.app.route('/api/support/extend', methods=['POST'])
        def extend_session():
            if not self.is_session_active():
                return jsonify({
                    'success': False,
                    'error': 'No active session to extend'
                })

            # Extend by 1 hour (requires explicit customer approval)
            data = request.get_json() or {}
            if not data.get('customer_approved'):
                return jsonify({
                    'success': False,
                    'error': 'Customer approval required for session extension'
                })

            # Update end time
            current_end = datetime.fromisoformat(self.session_data['end_time'])
            new_end = current_end + timedelta(hours=1)
            self.session_data['end_time'] = new_end.isoformat()

            # Restart timer
            if self.session_timer:
                self.session_timer.cancel()
            self.start_session_timer()

            logger.info(f"Session extended: {self.session_data['session_id']}")

            return jsonify({
                'success': True,
                'new_end_time': new_end.isoformat()
            })

    def run_api_server(self, host='127.0.0.1', port=8765):
        """Run the Flask API server"""
        logger.info(f"Starting Remote Support API server on {host}:{port}")
        self.app.run(host=host, port=port, debug=False)

def main():
    """Main entry point"""
    try:
        # Ensure directories exist
        os.makedirs(CONFIG_DIR, exist_ok=True)
        os.makedirs(LOG_DIR, exist_ok=True)
        os.makedirs(SCRIPTS_DIR, exist_ok=True)

        # Start the remote support manager
        manager = RemoteSupportManager()

        if len(sys.argv) > 1:
            command = sys.argv[1]

            if command == 'start-session':
                result = manager.start_support_session()
                print(json.dumps(result, indent=2))

            elif command == 'end-session':
                result = manager.end_support_session()
                print(json.dumps(result, indent=2))

            elif command == 'status':
                status = manager.get_session_status()
                print(json.dumps(status, indent=2))

            elif command == 'server':
                manager.run_api_server(host='0.0.0.0')

            else:
                print("Usage: maestro_remote_support.py [start-session|end-session|status|server]")

        else:
            # Default: run API server
            manager.run_api_server(host='0.0.0.0')

    except KeyboardInterrupt:
        logger.info("Remote Support Manager stopped by user")
    except Exception as e:
        logger.error(f"Remote Support Manager error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()