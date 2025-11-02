"""
Notification Handlers Module
Multiple notification channels for alert delivery
"""

import smtplib
import logging
import json
import time
import socket
import requests
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart
from typing import Dict, List, Any, Optional
from datetime import datetime
from dataclasses import dataclass
import threading
from queue import Queue, Empty
import os

try:
    import syslog
    SYSLOG_AVAILABLE = True
except ImportError:
    SYSLOG_AVAILABLE = False

from .alert_manager import Alert, AlertPriority, AlertStatus
from ..config.settings import get_config

logger = logging.getLogger(__name__)


@dataclass
class NotificationResult:
    """Result of notification delivery"""
    channel: str
    success: bool
    message: str
    timestamp: float
    retry_count: int = 0
    error: Optional[str] = None


class BaseNotificationHandler:
    """Base class for notification handlers"""

    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self.config = config
        self.enabled = config.get('enabled', True)
        self.notification_queue = Queue()
        self.worker_thread = None
        self.running = False

    def start(self):
        """Start the notification handler"""
        if not self.enabled:
            logger.info(f"Notification handler {self.name} is disabled")
            return

        self.running = True
        self.worker_thread = threading.Thread(target=self._worker, daemon=True)
        self.worker_thread.start()
        logger.info(f"Started notification handler: {self.name}")

    def stop(self):
        """Stop the notification handler"""
        self.running = False
        if self.worker_thread:
            self.worker_thread.join(timeout=5)
        logger.info(f"Stopped notification handler: {self.name}")

    def send_notification(self, alert: Alert):
        """Queue notification for delivery"""
        if self.enabled:
            self.notification_queue.put(alert)

    def _worker(self):
        """Worker thread for processing notifications"""
        while self.running:
            try:
                alert = self.notification_queue.get(timeout=1)
                self._process_notification(alert)
                self.notification_queue.task_done()
            except Empty:
                continue
            except Exception as e:
                logger.error(f"Error in notification worker for {self.name}: {e}")

    def _process_notification(self, alert: Alert) -> NotificationResult:
        """Process a single notification (to be implemented by subclasses)"""
        raise NotImplementedError


class EmailNotificationHandler(BaseNotificationHandler):
    """Email notification handler"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__("email", config)
        self.smtp_server = config.get('smtp_server', 'localhost')
        self.smtp_port = config.get('smtp_port', 587)
        self.username = config.get('username', '')
        self.password = config.get('password', '')
        self.use_tls = config.get('use_tls', True)
        self.from_address = config.get('from_address', 'nids@example.com')
        self.to_addresses = config.get('to_addresses', [])

    def _process_notification(self, alert: Alert) -> NotificationResult:
        """Send email notification"""
        if not self.to_addresses:
            return NotificationResult(
                channel=self.name,
                success=False,
                message="No recipient addresses configured",
                timestamp=time.time()
            )

        try:
            # Create email message
            msg = MimeMultipart()
            msg['From'] = self.from_address
            msg['To'] = ', '.join(self.to_addresses)
            msg['Subject'] = f"[NIDS ALERT] {alert.priority.value}: {alert.attack_type.upper()}"

            # Create email body
            body = self._create_email_body(alert)
            msg.attach(MimeText(body, 'html'))

            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls()
                if self.username and self.password:
                    server.login(self.username, self.password)
                server.send_message(msg)

            return NotificationResult(
                channel=self.name,
                success=True,
                message=f"Email sent to {len(self.to_addresses)} recipients",
                timestamp=time.time()
            )

        except Exception as e:
            logger.error(f"Failed to send email notification: {e}")
            return NotificationResult(
                channel=self.name,
                success=False,
                message="Failed to send email",
                timestamp=time.time(),
                error=str(e)
            )

    def _create_email_body(self, alert: Alert) -> str:
        """Create HTML email body"""
        priority_colors = {
            AlertPriority.LOW: '#28a745',
            AlertPriority.MEDIUM: '#ffc107',
            AlertPriority.HIGH: '#fd7e14',
            AlertPriority.CRITICAL: '#dc3545'
        }

        color = priority_colors.get(alert.priority, '#6c757d')

        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; margin: 20px;">
            <div style="border: 2px solid {color}; border-radius: 8px; padding: 20px; margin-bottom: 20px;">
                <h2 style="color: {color}; margin-top: 0;">🚨 NIDS Security Alert</h2>
                <table style="width: 100%; border-collapse: collapse;">
                    <tr>
                        <td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>Priority:</strong></td>
                        <td style="padding: 8px; border-bottom: 1px solid #ddd; color: {color}; font-weight: bold;">{alert.priority.value}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>Attack Type:</strong></td>
                        <td style="padding: 8px; border-bottom: 1px solid #ddd;">{alert.attack_type.upper()}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>Source IP:</strong></td>
                        <td style="padding: 8px; border-bottom: 1px solid #ddd;">{alert.source}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>Target IP:</strong></td>
                        <td style="padding: 8px; border-bottom: 1px solid #ddd;">{alert.target_ip or 'N/A'}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>Confidence:</strong></td>
                        <td style="padding: 8px; border-bottom: 1px solid #ddd;">{alert.confidence:.2%}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>Time:</strong></td>
                        <td style="padding: 8px; border-bottom: 1px solid #ddd;">{datetime.fromtimestamp(alert.timestamp).strftime('%Y-%m-%d %H:%M:%S')}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>Status:</strong></td>
                        <td style="padding: 8px; border-bottom: 1px solid #ddd;">{alert.status.value}</td>
                    </tr>
                </table>

                <h3>Details:</h3>
                <pre style="background-color: #f8f9fa; padding: 15px; border-radius: 4px; overflow-x: auto;">
{json.dumps(alert.details, indent=2, default=str)}
                </pre>

                <div style="margin-top: 20px; padding: 10px; background-color: #f8f9fa; border-radius: 4px;">
                    <p style="margin: 0; font-size: 12px; color: #6c757d;">
                        Alert ID: {alert.id} | Generated by AI-based NIDS
                    </p>
                </div>
            </div>
        </body>
        </html>
        """
        return html_body


class SyslogNotificationHandler(BaseNotificationHandler):
    """Syslog notification handler"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__("syslog", config)
        self.facility = config.get('facility', 'local0')
        self.address = config.get('address', '/dev/log')

        if not SYSLOG_AVAILABLE:
            logger.warning("Syslog module not available, syslog notifications disabled")
            self.enabled = False

    def _process_notification(self, alert: Alert) -> NotificationResult:
        """Send syslog notification"""
        if not SYSLOG_AVAILABLE:
            return NotificationResult(
                channel=self.name,
                success=False,
                message="Syslog module not available",
                timestamp=time.time()
            )

        try:
            # Map priority to syslog level
            priority_map = {
                AlertPriority.LOW: syslog.LOG_INFO,
                AlertPriority.MEDIUM: syslog.LOG_WARNING,
                AlertPriority.HIGH: syslog.LOG_ERR,
                AlertPriority.CRITICAL: syslog.LOG_CRIT
            }

            syslog_level = priority_map.get(alert.priority, syslog.LOG_WARNING)

            # Create syslog message
            message = f"NIDS Alert [{alert.priority.value}] {alert.attack_type.upper()}: " \
                     f"Source: {alert.source_ip}, Target: {alert.target_ip or 'N/A'}, " \
                     f"Confidence: {alert.confidence:.2%}, ID: {alert.id}"

            # Send to syslog
            syslog.openlog(ident='nids', facility=self.facility)
            syslog.syslog(syslog_level, message)
            syslog.closelog()

            return NotificationResult(
                channel=self.name,
                success=True,
                message="Syslog notification sent",
                timestamp=time.time()
            )

        except Exception as e:
            logger.error(f"Failed to send syslog notification: {e}")
            return NotificationResult(
                channel=self.name,
                success=False,
                message="Failed to send syslog",
                timestamp=time.time(),
                error=str(e)
            )


class WebhookNotificationHandler(BaseNotificationHandler):
    """Webhook notification handler"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__("webhook", config)
        self.url = config.get('url', '')
        self.timeout = config.get('timeout', 10)
        self.retry_attempts = config.get('retry_attempts', 3)
        self.retry_delay = config.get('retry_delay', 1)

        if not self.url:
            logger.warning("Webhook URL not configured, webhook notifications disabled")
            self.enabled = False

    def _process_notification(self, alert: Alert) -> NotificationResult:
        """Send webhook notification"""
        if not self.url:
            return NotificationResult(
                channel=self.name,
                success=False,
                message="Webhook URL not configured",
                timestamp=time.time()
            )

        # Prepare webhook payload
        payload = {
            'alert_id': alert.id,
            'timestamp': alert.timestamp,
            'priority': alert.priority.value,
            'status': alert.status.value,
            'source_ip': alert.source_ip,
            'target_ip': alert.target_ip,
            'attack_type': alert.attack_type,
            'confidence': alert.confidence,
            'source': alert.source,
            'details': alert.details,
            'metadata': alert.metadata
        }

        # Try sending with retries
        for attempt in range(self.retry_attempts + 1):
            try:
                response = requests.post(
                    self.url,
                    json=payload,
                    timeout=self.timeout,
                    headers={'Content-Type': 'application/json'}
                )
                response.raise_for_status()

                return NotificationResult(
                    channel=self.name,
                    success=True,
                    message=f"Webhook sent successfully (status: {response.status_code})",
                    timestamp=time.time(),
                    retry_count=attempt
                )

            except Exception as e:
                if attempt == self.retry_attempts:
                    logger.error(f"Failed to send webhook after {self.retry_attempts + 1} attempts: {e}")
                    return NotificationResult(
                        channel=self.name,
                        success=False,
                        message=f"Failed to send webhook after {self.retry_attempts + 1} attempts",
                        timestamp=time.time(),
                        retry_count=attempt,
                        error=str(e)
                    )
                else:
                    logger.warning(f"Webhook attempt {attempt + 1} failed, retrying: {e}")
                    time.sleep(self.retry_delay)


class ConsoleNotificationHandler(BaseNotificationHandler):
    """Console notification handler with color coding"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__("console", config)
        self.enabled = config.get('enabled', True)

        # ANSI color codes
        self.colors = {
            'RED': '\033[91m',
            'YELLOW': '\033[93m',
            'GREEN': '\033[92m',
            'BLUE': '\033[94m',
            'MAGENTA': '\033[95m',
            'CYAN': '\033[96m',
            'WHITE': '\033[97m',
            'BOLD': '\033[1m',
            'UNDERLINE': '\033[4m',
            'END': '\033[0m'
        }

        # Priority colors
        self.priority_colors = {
            AlertPriority.LOW: self.colors['GREEN'],
            AlertPriority.MEDIUM: self.colors['YELLOW'],
            AlertPriority.HIGH: self.colors['RED'],
            AlertPriority.CRITICAL: self.colors['RED'] + self.colors['BOLD']
        }

    def _process_notification(self, alert: Alert) -> NotificationResult:
        """Print alert to console with color coding"""
        try:
            priority_color = self.priority_colors.get(alert.priority, self.colors['WHITE'])
            timestamp = datetime.fromtimestamp(alert.timestamp).strftime('%Y-%m-%d %H:%M:%S')

            # Create formatted console output
            console_output = f"""
{priority_color}{'='*60}{self.colors['END']}
{priority_color}{self.colors['BOLD']}🚨 NIDS SECURITY ALERT 🚨{self.colors['END']}
{priority_color}{'='*60}{self.colors['END']}

{self.colors['BOLD']}Priority:{self.colors['END']} {priority_color}{alert.priority.value}{self.colors['END']}
{self.colors['BOLD']}Attack Type:{self.colors['END']} {alert.attack_type.upper()}
{self.colors['BOLD'}Source IP:{self.colors['END']} {alert.source_ip}
{self.colors['BOLD'}Target IP:{self.colors['END']} {alert.target_ip or 'N/A'}
{self.colors['BOLD'}Confidence:{self.colors['END']} {alert.confidence:.2%}
{self.colors['BOLD'}Time:{self.colors['END']} {timestamp}
{self.colors['BOLD']}Alert ID:{self.colors['END']} {alert.id}

{self.colors['BOLD']}Details:{self.colors['END']}
{self.colors['CYAN']}{json.dumps(alert.details, indent=2, default=str)}{self.colors['END']}

{priority_color}{'='*60}{self.colors['END']}
"""

            print(console_output)

            return NotificationResult(
                channel=self.name,
                success=True,
                message="Alert printed to console",
                timestamp=time.time()
            )

        except Exception as e:
            logger.error(f"Failed to print console notification: {e}")
            return NotificationResult(
                channel=self.name,
                success=False,
                message="Failed to print to console",
                timestamp=time.time(),
                error=str(e)
            )


class FileNotificationHandler(BaseNotificationHandler):
    """File notification handler for logging alerts to files"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__("file", config)
        self.log_file = config.get('log_file', 'data/logs/alerts.log')
        self.rotation_size = config.get('rotation_size_mb', 100) * 1024 * 1024
        self.backup_count = config.get('backup_count', 5)

        # Ensure log directory exists
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)

    def _process_notification(self, alert: Alert) -> NotificationResult:
        """Write alert to log file"""
        try:
            # Check if rotation is needed
            if self._should_rotate_log():
                self._rotate_log()

            # Create log entry
            log_entry = {
                'timestamp': alert.timestamp,
                'alert_id': alert.id,
                'priority': alert.priority.value,
                'status': alert.status.value,
                'source_ip': alert.source_ip,
                'target_ip': alert.target_ip,
                'attack_type': alert.attack_type,
                'confidence': alert.confidence,
                'source': alert.source,
                'details': alert.details,
                'metadata': alert.metadata
            }

            # Write to file
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(log_entry, default=str) + '\n')

            return NotificationResult(
                channel=self.name,
                success=True,
                message=f"Alert logged to {self.log_file}",
                timestamp=time.time()
            )

        except Exception as e:
            logger.error(f"Failed to write alert to file: {e}")
            return NotificationResult(
                channel=self.name,
                success=False,
                message="Failed to write to log file",
                timestamp=time.time(),
                error=str(e)
            )

    def _should_rotate_log(self) -> bool:
        """Check if log file should be rotated"""
        if not os.path.exists(self.log_file):
            return False
        return os.path.getsize(self.log_file) >= self.rotation_size

    def _rotate_log(self):
        """Rotate log file"""
        try:
            # Remove oldest backup if exists
            oldest_backup = f"{self.log_file}.{self.backup_count}"
            if os.path.exists(oldest_backup):
                os.remove(oldest_backup)

            # Rotate existing backups
            for i in range(self.backup_count - 1, 0, -1):
                old_file = f"{self.log_file}.{i}"
                new_file = f"{self.log_file}.{i + 1}"
                if os.path.exists(old_file):
                    os.rename(old_file, new_file)

            # Move current log to backup
            if os.path.exists(self.log_file):
                os.rename(self.log_file, f"{self.log_file}.1")

            logger.info(f"Rotated log file: {self.log_file}")

        except Exception as e:
            logger.error(f"Failed to rotate log file: {e}")


class NotificationManager:
    """Manages multiple notification handlers"""

    def __init__(self):
        self.config = get_config()
        self.notification_config = self.config.get_section('notifications')

        self.handlers: Dict[str, BaseNotificationHandler] = {}
        self.notification_history: List[NotificationResult] = []
        self.max_history = 1000

        # Initialize handlers
        self._initialize_handlers()

    def _initialize_handlers(self):
        """Initialize notification handlers based on configuration"""
        # Email handler
        if self.notification_config.get('email', {}).get('enabled', False):
            self.handlers['email'] = EmailNotificationHandler(
                self.notification_config.get('email', {})
            )

        # Syslog handler
        if self.notification_config.get('syslog', {}).get('enabled', True):
            self.handlers['syslog'] = SyslogNotificationHandler(
                self.notification_config.get('syslog', {})
            )

        # Webhook handler
        if self.notification_config.get('webhook', {}).get('enabled', False):
            self.handlers['webhook'] = WebhookNotificationHandler(
                self.notification_config.get('webhook', {})
            )

        # Console handler (always enabled for debugging)
        self.handlers['console'] = ConsoleNotificationHandler(
            self.notification_config.get('console', {'enabled': True})
        )

        # File handler
        if self.notification_config.get('file', {}).get('enabled', True):
            self.handlers['file'] = FileNotificationHandler(
                self.notification_config.get('file', {'enabled': True})
            )

        logger.info(f"Initialized {len(self.handlers)} notification handlers: {list(self.handlers.keys())}")

    def start(self):
        """Start all notification handlers"""
        for handler in self.handlers.values():
            handler.start()
        logger.info("Notification manager started")

    def stop(self):
        """Stop all notification handlers"""
        for handler in self.handlers.values():
            handler.stop()
        logger.info("Notification manager stopped")

    def send_notifications(self, alert: Alert):
        """Send alert through all enabled handlers"""
        for handler in self.handlers.values():
            handler.send_notification(alert)

    def send_test_notification(self, handler_name: Optional[str] = None) -> bool:
        """Send a test notification"""
        from datetime import datetime
        import uuid

        test_alert = Alert(
            id=str(uuid.uuid4()),
            timestamp=time.time(),
            priority=AlertPriority.MEDIUM,
            status=AlertStatus.NEW,
            source_ip="192.168.1.100",
            target_ip="192.168.1.1",
            attack_type="test_alert",
            confidence=1.0,
            details={
                "message": "This is a test notification from the NIDS system",
                "test": True,
                "timestamp": datetime.now().isoformat()
            },
            source="test"
        )

        if handler_name and handler_name in self.handlers:
            self.handlers[handler_name].send_notification(test_alert)
            return True
        else:
            self.send_notifications(test_alert)
            return True

    def get_handler_status(self) -> Dict[str, Any]:
        """Get status of all notification handlers"""
        status = {}
        for name, handler in self.handlers.items():
            status[name] = {
                'enabled': handler.enabled,
                'running': handler.running,
                'queue_size': handler.notification_queue.qsize() if hasattr(handler, 'notification_queue') else 0,
                'config': {k: v for k, v in handler.config.items() if k not in ['password', 'username']}  # Hide sensitive data
            }
        return status

    def get_notification_history(self, limit: int = 100) -> List[NotificationResult]:
        """Get notification history"""
        return self.notification_history[-limit:]

    def add_notification_result(self, result: NotificationResult):
        """Add notification result to history"""
        self.notification_history.append(result)
        if len(self.notification_history) > self.max_history:
            self.notification_history.pop(0)

    def get_statistics(self) -> Dict[str, Any]:
        """Get notification statistics"""
        if not self.notification_history:
            return {
                'total_notifications': 0,
                'success_rate': 0.0,
                'channel_stats': {},
                'recent_failures': 0
            }

        total = len(self.notification_history)
        successful = sum(1 for r in self.notification_history if r.success)
        success_rate = (successful / total) * 100

        # Channel statistics
        channel_stats = {}
        for result in self.notification_history:
            if result.channel not in channel_stats:
                channel_stats[result.channel] = {'total': 0, 'successful': 0}
            channel_stats[result.channel]['total'] += 1
            if result.success:
                channel_stats[result.channel]['successful'] += 1

        # Calculate success rates per channel
        for channel in channel_stats:
            stats = channel_stats[channel]
            stats['success_rate'] = (stats['successful'] / stats['total']) * 100

        # Recent failures (last hour)
        current_time = time.time()
        recent_failures = sum(
            1 for r in self.notification_history
            if not r.success and (current_time - r.timestamp) <= 3600
        )

        return {
            'total_notifications': total,
            'success_rate': success_rate,
            'channel_stats': channel_stats,
            'recent_failures': recent_failures,
            'active_handlers': len([h for h in self.handlers.values() if h.running])
        }


# Global notification manager instance
_notification_manager_instance = None

def get_notification_manager() -> NotificationManager:
    """Get or create the global notification manager instance"""
    global _notification_manager_instance
    if _notification_manager_instance is None:
        _notification_manager_instance = NotificationManager()
    return _notification_manager_instance

def cleanup_notification_manager():
    """Cleanup the global notification manager instance"""
    global _notification_manager_instance
    if _notification_manager_instance:
        _notification_manager_instance.stop()
        _notification_manager_instance = None