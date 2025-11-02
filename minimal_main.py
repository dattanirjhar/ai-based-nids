#!/usr/bin/env python3
"""
AI-based Network Intrusion Detection System - Minimal Entry Point
"""

import os
import sys
import signal
import time
import logging
import argparse
from pathlib import Path

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.config.settings import get_config
from src.alert_system.log_manager import get_log_manager

class NIDSApplication:
    """Main NIDS Application Class - Minimal Version"""

    def __init__(self):
        self.config = get_config()
        self.log_manager = get_log_manager()
        self.running = False

        # Setup logging
        self._setup_logging()

        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        self.logger = logging.getLogger(__name__)
        self.logger.info("AI-based NIDS Application initialized (minimal mode)")

    def _setup_logging(self):
        """Setup logging configuration"""
        log_config = self.config.get_section('logging')
        log_level = getattr(logging, log_config.get('level', 'INFO').upper())
        log_file = log_config.get('file', 'data/logs/nids.log')

        # Ensure log directory exists
        os.makedirs(os.path.dirname(log_file), exist_ok=True)

        # Configure root logger
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.logger.info(f"Received signal {signum}, initiating shutdown...")
        self.shutdown()
        sys.exit(0)

    def start(self):
        """Start the NIDS application in web-only mode"""
        self.logger.info("Starting AI-based NIDS in WEB INTERFACE mode...")
        self.logger.warning("Full NIDS features require implementation of network monitoring modules")
        
        self.running = True

        try:
            # Import and start web interface
            from src.web_interface.app import create_app, socketio
            
            app = create_app()
            if app:
                web_config = self.config.get_section('web')
                host = web_config.get('host', '0.0.0.0')
                port = web_config.get('port', 5000)
                debug = web_config.get('debug', False)

                self.logger.info(f"Starting web interface on {host}:{port}")
                self.logger.info(f"Dashboard available at: http://localhost:{port}")
                
                # Run with SocketIO
                socketio.run(app, host=host, port=port, debug=debug, allow_unsafe_werkzeug=True)
            else:
                self.logger.error("Failed to create web application")
                return False

        except Exception as e:
            self.logger.error(f"Error starting NIDS: {e}", exc_info=True)
            return False

        return True

    def shutdown(self):
        """Shutdown the NIDS application"""
        if not self.running:
            return

        self.logger.info("Shutting down AI-based NIDS...")
        self.running = False

        try:
            # Cleanup log manager
            if hasattr(self, 'log_manager'):
                self.log_manager.cleanup()

            self.logger.info("NIDS shutdown completed successfully")

        except Exception as e:
            self.logger.error(f"Error during shutdown: {e}")


def create_directories():
    """Create necessary directories"""
    directories = [
        'data/logs',
        'data/models',
        'data/datasets',
        'data/backups',
        'config'
    ]

    for directory in directories:
        os.makedirs(directory, exist_ok=True)


def check_permissions():
    """Check if we have necessary permissions"""
    try:
        import socket
        # Basic socket test
        test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_socket.close()
        return True
    except Exception:
        return False


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='AI-based Network Intrusion Detection System')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--config', help='Path to configuration file')
    parser.add_argument('--check-permissions', action='store_true', help='Check system permissions')
    parser.add_argument('--version', action='version', version='AI-based NIDS 1.0.0')

    args = parser.parse_args()

    # Create necessary directories
    create_directories()

    # Check permissions if requested
    if args.check_permissions:
        if check_permissions():
            print("✓ System permissions check passed")
            return 0
        else:
            print("✗ System permissions check failed")
            print("  Note: Full packet capture requires root/admin privileges")
            print("  Web interface will work without elevated permissions")
            return 1

    # Initialize and start the application
    app = NIDSApplication()

    try:
        # Start the application
        print("\n" + "="*60)
        print("  AI-based Network Intrusion Detection System")
        print("  Starting in WEB INTERFACE mode...")
        print("="*60 + "\n")
        
        success = app.start()
        return 0 if success else 1

    except KeyboardInterrupt:
        print("\n\nReceived keyboard interrupt, shutting down...")
        app.shutdown()
        return 0
    except Exception as e:
        print(f"\n\nFatal error: {e}")
        app.shutdown()
        return 1


if __name__ == '__main__':
    sys.exit(main())
