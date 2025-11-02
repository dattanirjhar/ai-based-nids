"""
Log Manager Module
Comprehensive logging system with structured JSON logging, rotation, and search capabilities
"""

import logging
import json
import os
import time
import gzip
import shutil
from typing import Dict, List, Any, Optional, Union
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from pathlib import Path
import threading
from queue import Queue, Empty
import logging.handlers
import re

from ..config.settings import get_config

logger = logging.getLogger(__name__)


@dataclass
class LogEntry:
    """Structured log entry"""
    timestamp: float
    level: str
    component: str
    message: str
    details: Optional[Dict[str, Any]] = None
    source_ip: Optional[str] = None
    session_id: Optional[str] = None
    user_id: Optional[str] = None
    tags: Optional[List[str]] = None


class StructuredFormatter(logging.Formatter):
    """Custom formatter for structured JSON logging"""

    def __init__(self, include_extra_fields: bool = True):
        super().__init__()
        self.include_extra_fields = include_extra_fields

    def format(self, record):
        """Format log record as JSON"""
        log_entry = {
            'timestamp': record.created,
            'level': record.levelname,
            'component': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
            'thread': record.thread,
            'thread_name': record.threadName,
            'process': record.process
        }

        # Add exception information if present
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)

        # Add extra fields if enabled
        if self.include_extra_fields:
            extra_fields = {}
            for key, value in record.__dict__.items():
                if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 'pathname',
                              'filename', 'module', 'lineno', 'funcName', 'created', 'msecs',
                              'relativeCreated', 'thread', 'threadName', 'processName',
                              'process', 'getMessage', 'exc_info', 'exc_text', 'stack_info']:
                    extra_fields[key] = value

            if extra_fields:
                log_entry['extra'] = extra_fields

        return json.dumps(log_entry, default=str)


class NIDSLogHandler(logging.handlers.RotatingFileHandler):
    """Custom log handler with enhanced rotation and compression"""

    def __init__(self, filename, max_bytes=100*1024*1024, backup_count=5, encoding='utf8', compress=True):
        super().__init__(filename, maxBytes=max_bytes, backupCount=backup_count, encoding=encoding)
        self.compress = compress

    def doRollover(self):
        """Perform log rotation with optional compression"""
        if self.stream:
            self.stream.close()
            self.stream = None

        # Rotate files
        if self.backupCount > 0:
            # Remove oldest backup
            oldest_log = f"{self.baseFilename}.{self.backupCount}"
            if os.path.exists(oldest_log):
                os.remove(oldest_log)
            if self.compress and os.path.exists(f"{oldest_log}.gz"):
                os.remove(f"{oldest_log}.gz")

            # Rotate existing backups
            for i in range(self.backupCount - 1, 0, -1):
                src = f"{self.baseFilename}.{i}"
                dst = f"{self.baseFilename}.{i + 1}"

                if os.path.exists(src):
                    # Compress old file if enabled
                    if self.compress and i == 1:
                        self._compress_file(src, f"{dst}.gz")
                        os.remove(src)
                    else:
                        if os.path.exists(dst):
                            os.remove(dst)
                        os.rename(src, dst)

                # Handle compressed files
                src_gz = f"{src}.gz"
                dst_gz = f"{dst}.gz"
                if os.path.exists(src_gz):
                    if os.path.exists(dst_gz):
                        os.remove(dst_gz)
                    os.rename(src_gz, dst_gz)

            # Move current log to backup
            dst = f"{self.baseFilename}.1"
            if os.path.exists(dst):
                os.remove(dst)
            os.rename(self.baseFilename, dst)

            # Compress the rotated file if enabled
            if self.compress:
                self._compress_file(dst, f"{dst}.gz")
                os.remove(dst)

        # Create new log file
        self.stream = open(self.baseFilename, 'a', encoding=self.encoding)

    def _compress_file(self, src_path: str, dst_path: str):
        """Compress a file using gzip"""
        try:
            with open(src_path, 'rb') as src_file:
                with gzip.open(dst_path, 'wb') as dst_file:
                    shutil.copyfileobj(src_file, dst_file)
        except Exception as e:
            logger.error(f"Failed to compress log file {src_path}: {e}")


class LogManager:
    """
    Comprehensive log management system with structured logging and search capabilities
    """

    def __init__(self):
        """Initialize log manager"""
        self.config = get_config()
        self.log_config = self.config.get_section('logging')

        # Log configuration
        self.log_level = getattr(logging, self.log_config.get('level', 'INFO').upper())
        self.log_format = self.log_config.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        self.log_file = self.log_config.get('file', 'data/logs/nids.log')
        self.max_size_mb = self.log_config.get('max_size_mb', 100)
        self.backup_count = self.log_config.get('backup_count', 5)
        self.console_logging = self.log_config.get('console', True)

        # Log directories
        self.log_dir = os.path.dirname(self.log_file)
        self.archive_dir = os.path.join(self.log_dir, 'archive')

        # Ensure directories exist
        os.makedirs(self.log_dir, exist_ok=True)
        os.makedirs(self.archive_dir, exist_ok=True)

        # Loggers
        self.loggers: Dict[str, logging.Logger] = {}
        self.handlers: Dict[str, logging.Handler] = {}

        # Search index (in-memory cache for recent logs)
        self.log_cache: List[LogEntry] = []
        self.max_cache_size = 10000

        # Background processing
        self.log_queue = Queue()
        self.processing_thread = None
        self.running = False

        # Initialize logging system
        self._setup_logging()

    def _setup_logging(self):
        """Setup the logging system"""
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(self.log_level)

        # Clear existing handlers
        root_logger.handlers.clear()

        # Create formatter
        if self.log_config.get('structured', True):
            formatter = StructuredFormatter()
        else:
            formatter = logging.Formatter(self.log_format)

        # File handler
        try:
            file_handler = NIDSLogHandler(
                self.log_file,
                max_bytes=self.max_size_mb * 1024 * 1024,
                backup_count=self.backup_count,
                compress=self.log_config.get('compress', True)
            )
            file_handler.setLevel(self.log_level)
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)
            self.handlers['file'] = file_handler
        except Exception as e:
            logger.error(f"Failed to setup file handler: {e}")

        # Console handler
        if self.console_logging:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(self.log_level)
            console_handler.setFormatter(formatter)
            root_logger.addHandler(console_handler)
            self.handlers['console'] = console_handler

        # Component-specific loggers
        self._setup_component_loggers()

        # Start background processing
        self._start_background_processing()

        logger.info("Log manager initialized")

    def _setup_component_loggers(self):
        """Setup loggers for different NIDS components"""
        components = [
            'network_monitor',
            'ml_detection',
            'alert_system',
            'web_interface',
            'config'
        ]

        for component in components:
            component_logger = logging.getLogger(component)
            component_logger.setLevel(self.log_level)
            self.loggers[component] = component_logger

    def _start_background_processing(self):
        """Start background log processing"""
        self.running = True
        self.processing_thread = threading.Thread(target=self._background_worker, daemon=True)
        self.processing_thread.start()

    def _background_worker(self):
        """Background worker for processing log entries"""
        while self.running:
            try:
                log_entry = self.log_queue.get(timeout=1)
                self._process_log_entry(log_entry)
                self.log_queue.task_done()
            except Empty:
                continue
            except Exception as e:
                logger.error(f"Error in log background worker: {e}")

    def _process_log_entry(self, log_entry: LogEntry):
        """Process a structured log entry"""
        # Add to cache
        self.log_cache.append(log_entry)
        if len(self.log_cache) > self.max_cache_size:
            self.log_cache.pop(0)

    def create_logger(self, name: str, component: str = None) -> logging.Logger:
        """
        Create a logger for a specific component

        Args:
            name: Logger name
            component: Component category

        Returns:
            Logger instance
        """
        logger_instance = logging.getLogger(name)
        logger_instance.setLevel(self.log_level)

        if component:
            # Add component to logger context
            logger_instance = logging.LoggerAdapter(logger_instance, {'component': component})

        return logger_instance

    def log_structured(self, level: str, component: str, message: str,
                      details: Optional[Dict[str, Any]] = None,
                      source_ip: Optional[str] = None,
                      session_id: Optional[str] = None,
                      user_id: Optional[str] = None,
                      tags: Optional[List[str]] = None):
        """
        Log a structured entry

        Args:
            level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            component: Component name
            message: Log message
            details: Additional details
            source_ip: Source IP address
            session_id: Session ID
            user_id: User ID
            tags: List of tags
        """
        log_entry = LogEntry(
            timestamp=time.time(),
            level=level.upper(),
            component=component,
            message=message,
            details=details,
            source_ip=source_ip,
            session_id=session_id,
            user_id=user_id,
            tags=tags or []
        )

        # Add to processing queue
        self.log_queue.put(log_entry)

        # Also log to standard logger
        logger_instance = self.loggers.get(component, logging.getLogger(component))
        log_level = getattr(logging, level.upper())
        logger_instance.log(log_level, message, extra={
            'details': details,
            'source_ip': source_ip,
            'session_id': session_id,
            'user_id': user_id,
            'tags': tags
        })

    def log_event(self, event_type: str, component: str, message: str,
                 details: Optional[Dict[str, Any]] = None,
                 level: str = 'INFO', **kwargs):
        """
        Log a specific event type

        Args:
            event_type: Type of event
            component: Component name
            message: Log message
            details: Event details
            level: Log level
            **kwargs: Additional log fields
        """
        if details is None:
            details = {}

        details['event_type'] = event_type
        details.update(kwargs)

        self.log_structured(
            level=level,
            component=component,
            message=message,
            details=details,
            **{k: v for k, v in kwargs.items() if k in ['source_ip', 'session_id', 'user_id', 'tags']}
        )

    def search_logs(self, query: str, level: Optional[str] = None,
                   component: Optional[str] = None,
                   start_time: Optional[float] = None,
                   end_time: Optional[float] = None,
                   source_ip: Optional[str] = None,
                   limit: int = 1000) -> List[LogEntry]:
        """
        Search through cached logs

        Args:
            query: Search query (supports regex)
            level: Filter by log level
            component: Filter by component
            start_time: Start timestamp
            end_time: End timestamp
            source_ip: Filter by source IP
            limit: Maximum results

        Returns:
            List of matching log entries
        """
        results = []

        try:
            # Compile regex pattern
            pattern = re.compile(query, re.IGNORECASE)
        except re.error:
            # If invalid regex, treat as literal string
            pattern = re.compile(re.escape(query), re.IGNORECASE)

        for entry in self.log_cache:
            # Apply filters
            if level and entry.level != level.upper():
                continue

            if component and entry.component != component:
                continue

            if start_time and entry.timestamp < start_time:
                continue

            if end_time and entry.timestamp > end_time:
                continue

            if source_ip and entry.source_ip != source_ip:
                continue

            # Search in message and details
            searchable_text = entry.message
            if entry.details:
                searchable_text += " " + json.dumps(entry.details, default=str)

            if pattern.search(searchable_text):
                results.append(entry)

                if len(results) >= limit:
                    break

        # Sort by timestamp (newest first)
        results.sort(key=lambda e: e.timestamp, reverse=True)

        return results

    def get_log_statistics(self) -> Dict[str, Any]:
        """Get logging statistics"""
        if not self.log_cache:
            return {
                'total_entries': 0,
                'level_distribution': {},
                'component_distribution': {},
                'time_range': None,
                'top_source_ips': [],
                'recent_errors': 0
            }

        # Level distribution
        level_counts = {}
        for entry in self.log_cache:
            level_counts[entry.level] = level_counts.get(entry.level, 0) + 1

        # Component distribution
        component_counts = {}
        for entry in self.log_cache:
            component_counts[entry.component] = component_counts.get(entry.component, 0) + 1

        # Time range
        timestamps = [entry.timestamp for entry in self.log_cache]
        time_range = {
            'earliest': min(timestamps),
            'latest': max(timestamps),
            'span_hours': (max(timestamps) - min(timestamps)) / 3600
        }

        # Top source IPs
        source_ip_counts = {}
        for entry in self.log_cache:
            if entry.source_ip:
                source_ip_counts[entry.source_ip] = source_ip_counts.get(entry.source_ip, 0) + 1

        top_source_ips = sorted(source_ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        # Recent errors (last hour)
        current_time = time.time()
        recent_errors = sum(
            1 for entry in self.log_cache
            if entry.level in ['ERROR', 'CRITICAL'] and (current_time - entry.timestamp) <= 3600
        )

        return {
            'total_entries': len(self.log_cache),
            'level_distribution': level_counts,
            'component_distribution': component_counts,
            'time_range': time_range,
            'top_source_ips': top_source_ips,
            'recent_errors': recent_errors,
            'cache_size': len(self.log_cache),
            'max_cache_size': self.max_cache_size
        }

    def export_logs(self, file_path: str, format: str = 'json',
                   query: Optional[str] = None,
                   start_time: Optional[float] = None,
                   end_time: Optional[float] = None,
                   level_filter: Optional[List[str]] = None):
        """
        Export logs to file

        Args:
            file_path: Output file path
            format: Export format ('json', 'csv', 'txt')
            query: Search query
            start_time: Start timestamp
            end_time: End timestamp
            level_filter: List of levels to include
        """
        try:
            # Get filtered logs
            if query:
                logs = self.search_logs(query, start_time=start_time, end_time=end_time, limit=100000)
            else:
                logs = []
                for entry in self.log_cache:
                    if start_time and entry.timestamp < start_time:
                        continue
                    if end_time and entry.timestamp > end_time:
                        continue
                    if level_filter and entry.level not in level_filter:
                        continue
                    logs.append(entry)

            # Sort by timestamp
            logs.sort(key=lambda e: e.timestamp)

            if format.lower() == 'json':
                export_data = {
                    'export_timestamp': datetime.now().isoformat(),
                    'total_entries': len(logs),
                    'query': query,
                    'time_range': {
                        'start': start_time,
                        'end': end_time
                    },
                    'logs': [asdict(log) for log in logs]
                }

                with open(file_path, 'w') as f:
                    json.dump(export_data, f, indent=2, default=str)

            elif format.lower() == 'csv':
                import pandas as pd
                data = []
                for log in logs:
                    row = {
                        'timestamp': datetime.fromtimestamp(log.timestamp).isoformat(),
                        'level': log.level,
                        'component': log.component,
                        'message': log.message,
                        'source_ip': log.source_ip,
                        'session_id': log.session_id,
                        'user_id': log.user_id,
                        'tags': ','.join(log.tags) if log.tags else ''
                    }
                    if log.details:
                        for key, value in log.details.items():
                            row[f'detail_{key}'] = value
                    data.append(row)

                df = pd.DataFrame(data)
                df.to_csv(file_path, index=False)

            elif format.lower() == 'txt':
                with open(file_path, 'w') as f:
                    f.write(f"NIDS Log Export\n")
                    f.write(f"Generated: {datetime.now().isoformat()}\n")
                    f.write(f"Total entries: {len(logs)}\n")
                    f.write(f"Query: {query or 'None'}\n")
                    f.write("=" * 80 + "\n\n")

                    for log in logs:
                        timestamp = datetime.fromtimestamp(log.timestamp).strftime('%Y-%m-%d %H:%M:%S')
                        f.write(f"[{timestamp}] {log.level} {log.component}: {log.message}\n")
                        if log.source_ip:
                            f.write(f"  Source IP: {log.source_ip}\n")
                        if log.details:
                            f.write(f"  Details: {json.dumps(log.details, default=str)}\n")
                        f.write("\n")

            logger.info(f"Exported {len(logs)} log entries to {file_path}")

        except Exception as e:
            logger.error(f"Failed to export logs: {e}")

    def archive_old_logs(self, days: int = 30):
        """Archive old log files"""
        try:
            cutoff_time = time.time() - (days * 24 * 3600)

            # Archive rotated log files
            for filename in os.listdir(self.log_dir):
                if filename.endswith('.log') or filename.endswith('.log.1') or filename.endswith('.log.gz'):
                    file_path = os.path.join(self.log_dir, filename)
                    file_mtime = os.path.getmtime(file_path)

                    if file_mtime < cutoff_time:
                        archive_path = os.path.join(self.archive_dir, filename)
                        shutil.move(file_path, archive_path)
                        logger.info(f"Archived log file: {filename}")

        except Exception as e:
            logger.error(f"Failed to archive old logs: {e}")

    def cleanup(self):
        """Cleanup log manager"""
        self.running = False
        if self.processing_thread:
            self.processing_thread.join(timeout=5)

        # Close all handlers
        for handler in self.handlers.values():
            handler.close()

        logger.info("Log manager cleaned up")

    def get_recent_logs(self, count: int = 100, level: Optional[str] = None,
                       component: Optional[str] = None) -> List[LogEntry]:
        """
        Get recent log entries

        Args:
            count: Number of entries to return
            level: Filter by level
            component: Filter by component

        Returns:
            List of recent log entries
        """
        recent = self.log_cache[-count:] if self.log_cache else []

        # Apply filters
        if level:
            recent = [e for e in recent if e.level == level.upper()]

        if component:
            recent = [e for e in recent if e.component == component]

        # Return newest first
        recent.reverse()
        return recent

    def set_log_level(self, level: str):
        """Set log level for all loggers"""
        log_level = getattr(logging, level.upper())
        logging.getLogger().setLevel(log_level)

        for logger_instance in self.loggers.values():
            logger_instance.setLevel(log_level)

        for handler in self.handlers.values():
            handler.setLevel(log_level)

        logger.info(f"Log level changed to {level.upper()}")

    def flush_logs(self):
        """Flush all log handlers"""
        for handler in self.handlers.values():
            if hasattr(handler, 'flush'):
                handler.flush()


# Global log manager instance
_log_manager_instance = None

def get_log_manager() -> LogManager:
    """Get or create the global log manager instance"""
    global _log_manager_instance
    if _log_manager_instance is None:
        _log_manager_instance = LogManager()
    return _log_manager_instance

def cleanup_log_manager():
    """Cleanup the global log manager instance"""
    global _log_manager_instance
    if _log_manager_instance:
        _log_manager_instance.cleanup()
        _log_manager_instance = None

# Convenience functions
def log_event(event_type: str, component: str, message: str, details: Optional[Dict[str, Any]] = None, **kwargs):
    """Log an event using the global log manager"""
    log_manager = get_log_manager()
    log_manager.log_event(event_type, component, message, details, **kwargs)

def log_structured(level: str, component: str, message: str, details: Optional[Dict[str, Any]] = None, **kwargs):
    """Log a structured entry using the global log manager"""
    log_manager = get_log_manager()
    log_manager.log_structured(level, component, message, details, **kwargs)