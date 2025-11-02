#!/usr/bin/env python3
"""
AI-based Network Intrusion Detection System - Main Application Entry Point
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
from src.network_monitor.packet_capture import get_packet_capture
from src.network_monitor.protocol_analyzer import get_protocol_analyzer
from src.network_monitor.traffic_features import get_traffic_feature_extractor
from src.ml_detection.feature_extractor import get_ml_feature_extractor
from src.ml_detection.model_trainer import get_model_trainer
from src.ml_detection.anomaly_detector import get_anomaly_detector
from src.ml_detection.signature_engine import get_signature_engine
from src.alert_system.alert_manager import get_alert_manager
from src.alert_system.notification_handlers import get_notification_manager


class NIDSApplication:
    """Main NIDS Application Class"""

    def __init__(self):
        self.config = get_config()
        self.log_manager = get_log_manager()
        self.running = False
        self.components = {}

        # Setup logging
        self._setup_logging()

        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        self.logger = logging.getLogger(__name__)
        self.logger.info("AI-based NIDS Application initialized")

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

    def initialize_components(self):
        """Initialize all NIDS components"""
        self.logger.info("Initializing NIDS components...")

        try:
            # Network monitoring components
            self.logger.info("Initializing network monitoring components...")
            self.components['packet_capture'] = get_packet_capture()
            self.components['protocol_analyzer'] = get_protocol_analyzer()
            self.components['traffic_features'] = get_traffic_feature_extractor()

            # Machine learning components
            self.logger.info("Initializing machine learning components...")
            self.components['ml_feature_extractor'] = get_ml_feature_extractor()
            self.components['model_trainer'] = get_model_trainer()
            self.components['anomaly_detector'] = get_anomaly_detector(self.components['model_trainer'])

            # Signature engine
            self.logger.info("Initializing signature engine...")
            self.components['signature_engine'] = get_signature_engine()

            # Alert system components
            self.logger.info("Initializing alert system components...")
            self.components['alert_manager'] = get_alert_manager()
            self.components['notification_manager'] = get_notification_manager()

            # Setup alert handlers
            self._setup_alert_handlers()

            # Setup packet handlers
            self._setup_packet_handlers()

            self.logger.info("All components initialized successfully")
            return True

        except Exception as e:
            self.logger.error(f"Failed to initialize components: {e}")
            return False

    def _setup_alert_handlers(self):
        """Setup alert handlers for different alert types"""
        alert_manager = self.components['alert_manager']
        notification_manager = self.components['notification_manager']

        # Add notification handler to alert manager
        alert_manager.add_alert_handler(notification_manager.send_notifications)

        # Add custom alert handlers if needed
        def log_alert_handler(alert):
            self.log_manager.log_event(
                event_type="alert_generated",
                component="alert_manager",
                message=f"Alert generated: {alert.attack_type} from {alert.source_ip}",
                details={
                    "alert_id": alert.id,
                    "priority": alert.priority.value,
                    "confidence": alert.confidence,
                    "attack_type": alert.attack_type
                }
            )

        alert_manager.add_alert_handler(log_alert_handler)

    def _setup_packet_handlers(self):
        """Setup packet processing handlers"""
        packet_capture = self.components['packet_capture']
        protocol_analyzer = self.components['protocol_analyzer']
        traffic_features = self.components['traffic_features']
        anomaly_detector = self.components['anomaly_detector']
        signature_engine = self.components['signature_engine']
        alert_manager = self.components['alert_manager']

        def packet_handler(packet_info):
            """Main packet processing pipeline"""
            try:
                # Protocol analysis
                protocol_analysis = protocol_analyzer.analyze_packet(packet_info)

                # Extract traffic features
                flow_result, window_result = traffic_features.process_packet(packet_info)

                # ML anomaly detection
                if flow_result:
                    detection_result = anomaly_detector.detect_flow_anomaly(flow_result.flow_features)
                    if detection_result.is_anomaly:
                        alert = alert_manager.create_alert_from_detection(detection_result)

                # Signature-based detection
                signature_matches = signature_engine.analyze_packet(packet_info, protocol_analysis.get('protocol_specific'))
                for match in signature_matches:
                    alert = alert_manager.create_alert_from_signature(match)

                # Log packet processing
                self.log_manager.log_event(
                    event_type="packet_processed",
                    component="packet_processor",
                    message=f"Processed packet: {packet_info.protocol} from {packet_info.src_ip}",
                    details={
                        "packet_size": packet_info.packet_size,
                        "protocol": packet_info.protocol,
                        "signature_matches": len(signature_matches),
                        "anomaly_detected": detection_result.is_anomaly if flow_result else False
                    }
                )

            except Exception as e:
                self.logger.error(f"Error processing packet: {e}")

        # Add packet handler to packet capture
        packet_capture.add_packet_handler(packet_handler)

    def start(self):
        """Start the NIDS application"""
        if not self.initialize_components():
            self.logger.error("Failed to initialize components, exiting...")
            return False

        self.logger.info("Starting AI-based Network Intrusion Detection System...")
        self.running = True

        try:
            # Start notification manager
            self.components['notification_manager'].start()

            # Start packet capture
            packet_capture = self.components['packet_capture']
            interface = self.config.get('network.interface')
            packet_filter = self.config.get('network.capture_filter', '')

            self.logger.info(f"Starting packet capture on interface: {interface or 'auto-detect'}")
            packet_capture.start_capture(packet_filter)

            # Log system start
            self.log_manager.log_event(
                event_type="system_start",
                component="main_application",
                message="NIDS system started successfully",
                details={
                    "interface": interface,
                    "packet_filter": packet_filter,
                    "components": list(self.components.keys())
                }
            )

            # Main monitoring loop
            self._monitoring_loop()

        except Exception as e:
            self.logger.error(f"Error starting NIDS: {e}")
            return False

        return True

    def _monitoring_loop(self):
        """Main monitoring loop"""
        self.logger.info("Entering main monitoring loop...")

        try:
            while self.running:
                # Periodic tasks
                self._perform_periodic_tasks()

                # Sleep for a short interval
                time.sleep(10)

        except KeyboardInterrupt:
            self.logger.info("Received keyboard interrupt")
        except Exception as e:
            self.logger.error(f"Error in monitoring loop: {e}")

    def _perform_periodic_tasks(self):
        """Perform periodic maintenance tasks"""
        try:
            # Get statistics from components
            packet_capture = self.components['packet_capture']
            alert_manager = self.components['alert_manager']

            # Log statistics every 5 minutes
            if int(time.time()) % 300 == 0:
                stats = packet_capture.get_statistics()
                alert_stats = alert_manager.get_statistics()

                self.log_manager.log_event(
                    event_type="statistics_update",
                    component="main_application",
                    message="System statistics update",
                    details={
                        "packet_stats": stats,
                        "alert_stats": alert_stats.__dict__
                    }
                )

            # Cleanup old alerts (daily)
            if int(time.time()) % 86400 == 0:
                alert_manager.cleanup_old_alerts()
                self.log_manager.archive_old_logs()

        except Exception as e:
            self.logger.error(f"Error in periodic tasks: {e}")

    def shutdown(self):
        """Shutdown the NIDS application"""
        if not self.running:
            return

        self.logger.info("Shutting down AI-based Network Intrusion Detection System...")
        self.running = False

        try:
            # Stop packet capture
            if 'packet_capture' in self.components:
                self.components['packet_capture'].stop_capture()
                self.logger.info("Packet capture stopped")

            # Stop notification manager
            if 'notification_manager' in self.components:
                self.components['notification_manager'].stop()
                self.logger.info("Notification manager stopped")

            # Save models and data
            if 'ml_feature_extractor' in self.components:
                self.components['ml_feature_extractor'].save_models()

            if 'model_trainer' in self.components:
                self.components['model_trainer'].save_models()

            # Cleanup components
            for component_name in ['anomaly_detector', 'signature_engine', 'alert_manager']:
                if component_name in self.components:
                    try:
                        # Call cleanup if available
                        if hasattr(self.components[component_name], 'cleanup'):
                            self.components[component_name].cleanup()
                    except Exception as e:
                        self.logger.error(f"Error cleaning up {component_name}: {e}")

            # Log system shutdown
            self.log_manager.log_event(
                event_type="system_shutdown",
                component="main_application",
                message="NIDS system shutdown completed",
                details={"shutdown_time": time.time()}
            )

            # Cleanup log manager
            self.log_manager.cleanup()

            self.logger.info("NIDS shutdown completed successfully")

        except Exception as e:
            self.logger.error(f"Error during shutdown: {e}")

    def get_status(self):
        """Get current system status"""
        status = {
            "running": self.running,
            "components": {},
            "uptime": time.time() - getattr(self, 'start_time', time.time())
        }

        for name, component in self.components.items():
            try:
                if hasattr(component, 'get_statistics'):
                    status["components"][name] = component.get_statistics()
                elif hasattr(component, 'is_running'):
                    status["components"][name] = {"running": component.is_running()}
                else:
                    status["components"][name] = {"status": "active"}
            except Exception as e:
                status["components"][name] = {"error": str(e)}

        return status


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
    # Check if we can create network sockets
    try:
        import socket
        test_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        test_socket.close()
        return True
    except (OSError, PermissionError):
        return False


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='AI-based Network Intrusion Detection System')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--config', help='Path to configuration file')
    parser.add_argument('--check-permissions', action='store_true', help='Check system permissions')
    parser.add_argument('--status', action='store_true', help='Show system status')
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
            print("  This application requires root privileges for packet capture")
            print("  Try running with: sudo python main.py")
            return 1

    # Initialize and start the application
    app = NIDSApplication()
    app.start_time = time.time()

    try:
        if args.status:
            # Show status and exit
            print("NIDS System Status:")
            print("-" * 40)
            status = app.get_status()
            print(f"Running: {status['running']}")
            print(f"Uptime: {status['uptime']:.2f} seconds")
            print(f"Components: {len(status['components'])}")
            for name, comp_status in status['components'].items():
                print(f"  {name}: {comp_status}")
            return 0

        # Start the application
        success = app.start()
        return 0 if success else 1

    except Exception as e:
        print(f"Fatal error: {e}")
        app.shutdown()
        return 1


if __name__ == '__main__':
    sys.exit(main())
