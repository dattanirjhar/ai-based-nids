"""
Configuration Management Module
Handles system configuration with support for YAML files and environment variables
"""

import os
import yaml
from typing import Dict, Any, Optional, Union
from pathlib import Path
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ConfigManager:
    """
    Configuration manager with support for YAML files and environment variables
    """

    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize configuration manager

        Args:
            config_file: Path to configuration YAML file
        """
        self.config_file = config_file or self._find_config_file()
        self.config_data: Dict[str, Any] = {}
        self._load_config()

    def _find_config_file(self) -> str:
        """Find configuration file in standard locations"""
        possible_paths = [
            'config/settings.yaml',
            'config/settings.yml',
            '/app/config/settings.yaml',
            '/app/config/settings.yml',
            os.path.expanduser('~/.nids/settings.yaml'),
            '/etc/nids/settings.yaml'
        ]

        for path in possible_paths:
            if os.path.exists(path):
                return path

        # If no config file found, return default path
        return 'config/settings.yaml'

    def _load_config(self):
        """Load configuration from file and environment variables"""
        # Load default configuration
        self.config_data = self._get_default_config()

        # Load from file if it exists
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    file_config = yaml.safe_load(f) or {}
                    self._merge_config(self.config_data, file_config)
                logger.info(f"Loaded configuration from {self.config_file}")
            except Exception as e:
                logger.error(f"Error loading config file {self.config_file}: {e}")
        else:
            logger.info(f"Config file {self.config_file} not found, using defaults")

        # Override with environment variables
        self._load_env_overrides()

    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration values"""
        return {
            # Network monitoring settings
            'network': {
                'interface': None,  # Auto-detect if None
                'promiscuous_mode': True,
                'packet_buffer_size': 1000,
                'capture_filter': '',
                'flow_timeout': 60.0,
                'feature_window_size': 10.0
            },

            # Machine learning settings
            'ml': {
                'model_directory': 'data/models',
                'feature_directory': 'data/features',
                'models': {
                    'random_forest': {
                        'enabled': True,
                        'n_estimators': 100,
                        'max_depth': 10,
                        'random_state': 42
                    },
                    'isolation_forest': {
                        'enabled': True,
                        'contamination': 0.1,
                        'random_state': 42
                    },
                    'one_class_svm': {
                        'enabled': True,
                        'kernel': 'rbf',
                        'gamma': 'scale',
                        'nu': 0.1
                    }
                },
                'training': {
                    'test_size': 0.2,
                    'random_state': 42,
                    'cross_validation_folds': 5,
                    'retrain_interval_days': 7
                },
                'detection': {
                    'confidence_threshold': 0.7,
                    'ensemble_voting': 'majority',
                    'feature_selection_k': 20
                }
            },

            # Alert system settings
            'alerts': {
                'enabled': True,
                'priority_levels': {
                    'LOW': 0.6,
                    'MEDIUM': 0.7,
                    'HIGH': 0.8,
                    'CRITICAL': 0.9
                },
                'rate_limiting': {
                    'enabled': True,
                    'max_alerts_per_minute': 10,
                    'burst_size': 5
                },
                'correlation': {
                    'enabled': True,
                    'time_window': 300,  # 5 minutes
                    'similarity_threshold': 0.8
                },
                'storage': {
                    'retention_days': 30,
                    'max_alerts': 10000
                }
            },

            # Notification settings
            'notifications': {
                'email': {
                    'enabled': False,
                    'smtp_server': 'localhost',
                    'smtp_port': 587,
                    'username': '',
                    'password': '',
                    'use_tls': True,
                    'from_address': 'nids@example.com',
                    'to_addresses': []
                },
                'syslog': {
                    'enabled': True,
                    'facility': 'local0',
                    'address': '/dev/log'
                },
                'webhook': {
                    'enabled': False,
                    'url': '',
                    'timeout': 10,
                    'retry_attempts': 3
                }
            },

            # Web interface settings
            'web': {
                'host': '0.0.0.0',
                'port': 5000,
                'debug': False,
                'secret_key': 'change-this-in-production',
                'authentication': {
                    'enabled': False,
                    'username': 'admin',
                    'password': 'admin123',
                    'session_timeout': 3600
                },
                'websocket': {
                    'enabled': True,
                    'port': 5001
                },
                'static_files': {
                    'cache_timeout': 3600
                }
            },

            # Database settings
            'database': {
                'type': 'sqlite',
                'path': 'data/nids.db',
                'backup': {
                    'enabled': True,
                    'interval_hours': 24,
                    'retention_days': 7
                }
            },

            # Logging settings
            'logging': {
                'level': 'INFO',
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                'file': 'data/logs/nids.log',
                'max_size_mb': 100,
                'backup_count': 5,
                'console': True
            },

            # Security settings
            'security': {
                'max_login_attempts': 3,
                'lockout_duration': 300,
                'allowed_ips': [],  # Empty means allow all
                'tls': {
                    'enabled': False,
                    'cert_file': '',
                    'key_file': ''
                }
            },

            # Performance settings
            'performance': {
                'max_concurrent_flows': 10000,
                'cleanup_interval': 60,
                'batch_size': 100,
                'memory_limit_mb': 1024
            },

            # Internal network ranges
            'internal_networks': [
                '10.0.0.0/8',
                '172.16.0.0/12',
                '192.168.0.0/16',
                '127.0.0.0/8'
            ],

            # Known attack signatures
            'signatures': {
                'port_scan': {
                    'enabled': True,
                    'threshold_ports': 10,
                    'time_window': 60
                },
                'syn_flood': {
                    'enabled': True,
                    'threshold_packets': 100,
                    'time_window': 10
                },
                'dns_amplification': {
                    'enabled': True,
                    'threshold_queries': 50,
                    'time_window': 60
                },
                'ssh_brute_force': {
                    'enabled': True,
                    'threshold_attempts': 5,
                    'time_window': 300
                }
            }
        }

    def _merge_config(self, base: Dict[str, Any], override: Dict[str, Any]):
        """Recursively merge configuration dictionaries"""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value

    def _load_env_overrides(self):
        """Load configuration overrides from environment variables"""
        env_mappings = {
            # Network settings
            'NIDS_INTERFACE': ('network', 'interface'),
            'NIDS_PROMISCUOUS_MODE': ('network', 'promiscuous_mode'),
            'NIDS_PACKET_BUFFER_SIZE': ('network', 'packet_buffer_size'),

            # ML settings
            'NIDS_MODEL_DIR': ('ml', 'model_directory'),
            'NIDS_CONFIDENCE_THRESHOLD': ('ml', 'detection', 'confidence_threshold'),

            # Alert settings
            'NIDS_ALERTS_ENABLED': ('alerts', 'enabled'),
            'NIDS_CRITICAL_THRESHOLD': ('alerts', 'priority_levels', 'CRITICAL'),

            # Web settings
            'NIDS_WEB_HOST': ('web', 'host'),
            'NIDS_WEB_PORT': ('web', 'port'),
            'NIDS_SECRET_KEY': ('web', 'secret_key'),

            # Database settings
            'NIDS_DB_PATH': ('database', 'path'),

            # Logging settings
            'NIDS_LOG_LEVEL': ('logging', 'level'),
            'NIDS_LOG_FILE': ('logging', 'file'),

            # Email settings
            'NIDS_SMTP_SERVER': ('notifications', 'email', 'smtp_server'),
            'NIDS_SMTP_PORT': ('notifications', 'email', 'smtp_port'),
            'NIDS_EMAIL_USER': ('notifications', 'email', 'username'),
            'NIDS_EMAIL_PASS': ('notifications', 'email', 'password'),
            'NIDS_EMAIL_FROM': ('notifications', 'email', 'from_address'),
            'NIDS_EMAIL_TO': ('notifications', 'email', 'to_addresses'),
        }

        for env_var, config_path in env_mappings.items():
            if env_var in os.environ:
                value = os.environ[env_var]

                # Convert to appropriate type
                value = self._convert_env_value(value)

                # Set in configuration
                self._set_nested_value(self.config_data, config_path, value)

    def _convert_env_value(self, value: str) -> Union[str, int, float, bool, list]:
        """Convert environment variable string to appropriate type"""
        # Boolean conversion
        if value.lower() in ('true', 'yes', '1', 'on'):
            return True
        elif value.lower() in ('false', 'no', '0', 'off'):
            return False

        # Numeric conversion
        try:
            if '.' in value:
                return float(value)
            else:
                return int(value)
        except ValueError:
            pass

        # List conversion (comma-separated)
        if ',' in value:
            return [item.strip() for item in value.split(',')]

        # Default to string
        return value

    def _set_nested_value(self, config: Dict[str, Any], path: tuple, value: Any):
        """Set a nested configuration value"""
        current = config
        for key in path[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        current[path[-1]] = value

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation

        Args:
            key: Configuration key (e.g., 'network.interface')
            default: Default value if key not found

        Returns:
            Configuration value or default
        """
        keys = key.split('.')
        current = self.config_data

        try:
            for k in keys:
                current = current[k]
            return current
        except (KeyError, TypeError):
            return default

    def set(self, key: str, value: Any):
        """
        Set configuration value using dot notation

        Args:
            key: Configuration key (e.g., 'network.interface')
            value: Value to set
        """
        keys = key.split('.')
        current = self.config_data

        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]

        current[keys[-1]] = value

    def reload(self):
        """Reload configuration from file and environment"""
        self._load_config()

    def save(self, file_path: Optional[str] = None):
        """
        Save current configuration to file

        Args:
            file_path: Path to save configuration (uses default if None)
        """
        save_path = file_path or self.config_file

        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(save_path), exist_ok=True)

        try:
            with open(save_path, 'w') as f:
                yaml.dump(self.config_data, f, default_flow_style=False, indent=2)
            logger.info(f"Configuration saved to {save_path}")
        except Exception as e:
            logger.error(f"Error saving configuration to {save_path}: {e}")

    def validate(self) -> List[str]:
        """
        Validate configuration and return list of issues

        Returns:
            List of validation error messages
        """
        issues = []

        # Validate network settings
        if self.get('network.packet_buffer_size', 0) <= 0:
            issues.append("network.packet_buffer_size must be positive")

        if self.get('network.flow_timeout', 0) <= 0:
            issues.append("network.flow_timeout must be positive")

        # Validate ML settings
        if not (0 <= self.get('ml.detection.confidence_threshold', 0) <= 1):
            issues.append("ml.detection.confidence_threshold must be between 0 and 1")

        # Validate alert settings
        if self.get('alerts.rate_limiting.max_alerts_per_minute', 0) <= 0:
            issues.append("alerts.rate_limiting.max_alerts_per_minute must be positive")

        # Validate web settings
        if not (1 <= self.get('web.port', 0) <= 65535):
            issues.append("web.port must be between 1 and 65535")

        if self.get('web.secret_key') == 'change-this-in-production':
            issues.append("web.secret_key should be changed in production")

        # Validate database settings
        db_path = self.get('database.path')
        if not db_path:
            issues.append("database.path must be specified")

        # Validate logging settings
        log_level = self.get('logging.level', '').upper()
        if log_level not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
            issues.append("logging.level must be one of: DEBUG, INFO, WARNING, ERROR, CRITICAL")

        return issues

    def get_all(self) -> Dict[str, Any]:
        """Get all configuration data"""
        return self.config_data.copy()

    def get_section(self, section: str) -> Dict[str, Any]:
        """
        Get a configuration section

        Args:
            section: Section name (e.g., 'network', 'ml')

        Returns:
            Configuration section dictionary
        """
        return self.get(section, {})

    def update_section(self, section: str, updates: Dict[str, Any]):
        """
        Update a configuration section

        Args:
            section: Section name
            updates: Dictionary of updates to apply
        """
        current = self.get(section, {})
        self._merge_config(current, updates)
        self.set(section, current)

    def is_production(self) -> bool:
        """Check if running in production mode"""
        return (
            not self.get('web.debug', True) and
            self.get('web.secret_key') != 'change-this-in-production'
        )

    def get_model_config(self, model_name: str) -> Dict[str, Any]:
        """
        Get configuration for a specific ML model

        Args:
            model_name: Name of the model (e.g., 'random_forest')

        Returns:
            Model configuration dictionary
        """
        return self.get(f'ml.models.{model_name}', {})

    def get_notification_config(self, notification_type: str) -> Dict[str, Any]:
        """
        Get configuration for a specific notification type

        Args:
            notification_type: Type of notification (e.g., 'email', 'syslog')

        Returns:
            Notification configuration dictionary
        """
        return self.get(f'notifications.{notification_type}', {})


# Global configuration instance
_config_manager_instance = None

def get_config(config_file: Optional[str] = None) -> ConfigManager:
    """Get or create the global configuration manager instance"""
    global _config_manager_instance
    if _config_manager_instance is None:
        _config_manager_instance = ConfigManager(config_file)
    return _config_manager_instance

def reload_config():
    """Reload the global configuration"""
    global _config_manager_instance
    if _config_manager_instance:
        _config_manager_instance.reload()

def validate_config() -> List[str]:
    """Validate the global configuration"""
    config = get_config()
    return config.validate()

def save_config(file_path: Optional[str] = None):
    """Save the global configuration"""
    config = get_config()
    config.save(file_path)


# Convenience functions for commonly accessed settings
def get_network_config() -> Dict[str, Any]:
    """Get network configuration"""
    return get_config().get_section('network')

def get_ml_config() -> Dict[str, Any]:
    """Get machine learning configuration"""
    return get_config().get_section('ml')

def get_alert_config() -> Dict[str, Any]:
    """Get alert configuration"""
    return get_config().get_section('alerts')

def get_web_config() -> Dict[str, Any]:
    """Get web interface configuration"""
    return get_config().get_section('web')

def get_logging_config() -> Dict[str, Any]:
    """Get logging configuration"""
    return get_config().get_section('logging')

def get_internal_networks() -> list:
    """Get list of internal network ranges"""
    return get_config().get('internal_networks', [])

def is_debug_mode() -> bool:
    """Check if debug mode is enabled"""
    return get_config().get('web.debug', False)

def get_confidence_threshold() -> float:
    """Get ML confidence threshold"""
    return get_config().get('ml.detection.confidence_threshold', 0.7)