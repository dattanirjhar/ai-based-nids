"""
Alert Manager Module
Centralized alert management and correlation system
"""

import time
import uuid
import json
import logging
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
from datetime import datetime, timedelta
import hashlib
from enum import Enum

from ..ml_detection.anomaly_detector import DetectionResult
from ..ml_detection.signature_engine import SignatureMatch
from ..config.settings import get_config

logger = logging.getLogger(__name__)


class AlertPriority(Enum):
    """Alert priority levels"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertStatus(Enum):
    """Alert status values"""
    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


@dataclass
class Alert:
    """Alert data structure"""
    id: str
    timestamp: float
    priority: AlertPriority
    status: AlertStatus
    source_ip: str
    target_ip: Optional[str]
    attack_type: str
    confidence: float
    details: Dict[str, Any]
    source: str  # 'ml_detection', 'signature_engine', 'manual'
    correlation_id: Optional[str] = None
    assigned_to: Optional[str] = None
    resolved_at: Optional[float] = None
    notes: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class AlertCorrelation:
    """Alert correlation information"""
    correlation_id: str
    alert_ids: List[str]
    source_ips: Set[str]
    target_ips: Set[str]
    attack_types: Set[str]
    first_seen: float
    last_seen: float
    alert_count: int
    severity_score: float
    correlation_confidence: float
    description: str


@dataclass
class AlertStatistics:
    """Alert system statistics"""
    total_alerts: int
    active_alerts: int
    resolved_alerts: int
    alerts_by_priority: Dict[str, int]
    alerts_by_type: Dict[str, int]
    alerts_by_source: Dict[str, int]
    average_resolution_time: float
    alerts_per_hour: float
    top_source_ips: List[Tuple[str, int]]
    top_attack_types: List[Tuple[str, int]]
    correlation_groups: int


class AlertManager:
    """
    Centralized alert management with correlation, deduplication, and rate limiting
    """

    def __init__(self):
        """Initialize alert manager"""
        self.config = get_config()
        self.alert_config = self.config.get_section('alerts')

        # Alert storage
        self.alerts: Dict[str, Alert] = {}
        self.alert_queue: deque = deque(maxlen=10000)
        self.active_alerts: Dict[str, Alert] = {}
        self.resolved_alerts: Dict[str, Alert] = {}

        # Correlation
        self.correlations: Dict[str, AlertCorrelation] = {}
        self.correlation_window = self.alert_config.get('correlation', {}).get('time_window', 300)  # 5 minutes
        self.similarity_threshold = self.alert_config.get('correlation', {}).get('similarity_threshold', 0.8)

        # Rate limiting
        rate_limit_config = self.alert_config.get('rate_limiting', {})
        self.rate_limiting_enabled = rate_limit_config.get('enabled', True)
        self.max_alerts_per_minute = rate_limit_config.get('max_alerts_per_minute', 10)
        self.burst_size = rate_limit_config.get('burst_size', 5)
        self.rate_limit_tracker: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))

        # Deduplication
        self.deduplication_window = 60  # 1 minute
        self.alert_hashes: Dict[str, float] = {}  # hash -> timestamp

        # Statistics
        self.stats = AlertStatistics(
            total_alerts=0,
            active_alerts=0,
            resolved_alerts=0,
            alerts_by_priority=defaultdict(int),
            alerts_by_type=defaultdict(int),
            alerts_by_source=defaultdict(int),
            average_resolution_time=0.0,
            alerts_per_hour=0.0,
            top_source_ips=[],
            top_attack_types=[],
            correlation_groups=0
        )

        # Storage configuration
        storage_config = self.alert_config.get('storage', {})
        self.max_alerts = storage_config.get('max_alerts', 10000)
        self.retention_days = storage_config.get('retention_days', 30)

        # Alert handlers (callbacks)
        self.alert_handlers: List[callable] = []

        logger.info("Alert manager initialized")

    def create_alert_from_detection(self, detection: DetectionResult) -> Optional[Alert]:
        """
        Create an alert from ML detection result

        Args:
            detection: Detection result from anomaly detector

        Returns:
            Created alert or None if filtered out
        """
        if not detection.is_anomaly:
            return None

        # Determine priority based on confidence
        priority = self._determine_priority_from_confidence(detection.confidence)

        # Create alert details
        details = {
            'anomaly_score': detection.anomaly_score,
            'model_predictions': detection.model_predictions,
            'detection_method': detection.detection_method,
            'feature_vector_shape': detection.feature_vector.shape if detection.feature_vector is not None else None,
            'metadata': detection.metadata or {}
        }

        alert = Alert(
            id=str(uuid.uuid4()),
            timestamp=detection.timestamp,
            priority=priority,
            status=AlertStatus.NEW,
            source_ip=detection.metadata.get('source_ip', 'unknown') if detection.metadata else 'unknown',
            target_ip=detection.metadata.get('target_ip') if detection.metadata else None,
            attack_type='anomaly_detection',
            confidence=detection.confidence,
            details=details,
            source='ml_detection',
            metadata={'detection_result': asdict(detection)}
        )

        return self._process_alert(alert)

    def create_alert_from_signature(self, signature_match: SignatureMatch) -> Optional[Alert]:
        """
        Create an alert from signature match

        Args:
            signature_match: Signature match result

        Returns:
            Created alert or None if filtered out
        """
        # Map signature severity to alert priority
        priority_mapping = {
            'LOW': AlertPriority.LOW,
            'MEDIUM': AlertPriority.MEDIUM,
            'HIGH': AlertPriority.HIGH,
            'CRITICAL': AlertPriority.CRITICAL
        }

        priority = priority_mapping.get(signature_match.severity, AlertPriority.MEDIUM)

        # Create alert details
        details = {
            'signature_id': signature_match.signature_id,
            'signature_name': signature_match.signature_name,
            'matched_pattern': signature_match.matched_pattern,
            'category': signature_match.category,
            'context': signature_match.context,
            'description': signature_match.description
        }

        alert = Alert(
            id=str(uuid.uuid4()),
            timestamp=signature_match.timestamp,
            priority=priority,
            status=AlertStatus.NEW,
            source_ip=signature_match.source_ip,
            target_ip=signature_match.target_ip,
            attack_type=signature_match.category.lower(),
            confidence=signature_match.confidence,
            details=details,
            source='signature_engine',
            metadata={'signature_match': asdict(signature_match)}
        )

        return self._process_alert(alert)

    def create_manual_alert(self, source_ip: str, attack_type: str, priority: AlertPriority,
                          details: Dict[str, Any], target_ip: Optional[str] = None) -> Optional[Alert]:
        """
        Create a manual alert

        Args:
            source_ip: Source IP address
            attack_type: Type of attack
            priority: Alert priority
            details: Alert details
            target_ip: Target IP address (optional)

        Returns:
            Created alert or None if filtered out
        """
        alert = Alert(
            id=str(uuid.uuid4()),
            timestamp=time.time(),
            priority=priority,
            status=AlertStatus.NEW,
            source_ip=source_ip,
            target_ip=target_ip,
            attack_type=attack_type.lower(),
            confidence=1.0,  # Manual alerts have full confidence
            details=details,
            source='manual',
            metadata={'manual_creation': True}
        )

        return self._process_alert(alert)

    def _process_alert(self, alert: Alert) -> Optional[Alert]:
        """Process and potentially filter an alert"""
        # Check rate limiting
        if self.rate_limiting_enabled and self._is_rate_limited(alert):
            logger.debug(f"Alert rate limited: {alert.id}")
            return None

        # Check deduplication
        if self._is_duplicate(alert):
            logger.debug(f"Duplicate alert filtered: {alert.id}")
            return None

        # Store alert
        self.alerts[alert.id] = alert
        self.alert_queue.append(alert)
        self.active_alerts[alert.id] = alert

        # Update statistics
        self._update_statistics(alert)

        # Correlation
        correlation_id = self._correlate_alert(alert)
        if correlation_id:
            alert.correlation_id = correlation_id

        # Trigger alert handlers
        self._trigger_alert_handlers(alert)

        logger.info(f"Created alert: {alert.id} - {alert.attack_type} from {alert.source_ip}")
        return alert

    def _determine_priority_from_confidence(self, confidence: float) -> AlertPriority:
        """Determine alert priority from confidence score"""
        if confidence >= 0.9:
            return AlertPriority.CRITICAL
        elif confidence >= 0.8:
            return AlertPriority.HIGH
        elif confidence >= 0.7:
            return AlertPriority.MEDIUM
        else:
            return AlertPriority.LOW

    def _is_rate_limited(self, alert: Alert) -> bool:
        """Check if alert should be rate limited"""
        current_time = time.time()
        rate_key = f"{alert.source_ip}_{alert.attack_type}"

        # Get recent alerts for this rate key
        recent_alerts = self.rate_limit_tracker[rate_key]

        # Clean old alerts (older than 1 minute)
        minute_ago = current_time - 60
        while recent_alerts and recent_alerts[0] < minute_ago:
            recent_alerts.popleft()

        # Check if we've exceeded the rate limit
        if len(recent_alerts) >= self.max_alerts_per_minute:
            return True

        # Add current alert timestamp
        recent_alerts.append(current_time)

        return False

    def _is_duplicate(self, alert: Alert) -> bool:
        """Check if alert is a duplicate of a recent alert"""
        # Create hash for deduplication
        hash_content = f"{alert.source_ip}_{alert.attack_type}_{alert.priority}"
        alert_hash = hashlib.md5(hash_content.encode()).hexdigest()

        current_time = time.time()

        # Check if we've seen this hash recently
        if alert_hash in self.alert_hashes:
            last_seen = self.alert_hashes[alert_hash]
            if current_time - last_seen < self.deduplication_window:
                return True

        # Update hash timestamp
        self.alert_hashes[alert_hash] = current_time

        # Clean old hashes
        old_hashes = [
            hash_val for hash_val, timestamp in self.alert_hashes.items()
            if current_time - timestamp > self.deduplication_window * 2
        ]
        for hash_val in old_hashes:
            del self.alert_hashes[hash_val]

        return False

    def _correlate_alert(self, alert: Alert) -> Optional[str]:
        """Correlate alert with existing alerts"""
        current_time = time.time()

        # Find existing correlations that might match
        for correlation_id, correlation in self.correlations.items():
            # Check time window
            if current_time - correlation.last_seen > self.correlation_window:
                continue

            # Check similarity
            similarity = self._calculate_alert_similarity(alert, correlation)
            if similarity >= self.similarity_threshold:
                # Update existing correlation
                correlation.alert_ids.append(alert.id)
                correlation.source_ips.add(alert.source_ip)
                if alert.target_ip:
                    correlation.target_ips.add(alert.target_ip)
                correlation.attack_types.add(alert.attack_type)
                correlation.last_seen = current_time
                correlation.alert_count += 1

                # Update severity score
                priority_scores = {
                    AlertPriority.LOW: 1,
                    AlertPriority.MEDIUM: 2,
                    AlertPriority.HIGH: 3,
                    AlertPriority.CRITICAL: 4
                }
                correlation.severity_score = max(correlation.severity_score, priority_scores[alert.priority])

                logger.debug(f"Alert {alert.id} correlated to {correlation_id}")
                return correlation_id

        # Check if we should create a new correlation
        if self._should_create_correlation(alert):
            correlation_id = str(uuid.uuid4())
            priority_scores = {
                AlertPriority.LOW: 1,
                AlertPriority.MEDIUM: 2,
                AlertPriority.HIGH: 3,
                AlertPriority.CRITICAL: 4
            }

            new_correlation = AlertCorrelation(
                correlation_id=correlation_id,
                alert_ids=[alert.id],
                source_ips={alert.source_ip},
                target_ips={alert.target_ip} if alert.target_ip else set(),
                attack_types={alert.attack_type},
                first_seen=current_time,
                last_seen=current_time,
                alert_count=1,
                severity_score=priority_scores[alert.priority],
                correlation_confidence=1.0,
                description=f"Correlated {alert.attack_type} activity"
            )

            self.correlations[correlation_id] = new_correlation
            logger.debug(f"Created new correlation: {correlation_id}")
            return correlation_id

        return None

    def _calculate_alert_similarity(self, alert: Alert, correlation: AlertCorrelation) -> float:
        """Calculate similarity between alert and correlation"""
        similarity_score = 0.0
        factors = 0

        # Source IP similarity
        if alert.source_ip in correlation.source_ips:
            similarity_score += 1.0
        factors += 1

        # Attack type similarity
        if alert.attack_type in correlation.attack_types:
            similarity_score += 1.0
        factors += 1

        # Target IP similarity
        if alert.target_ip and alert.target_ip in correlation.target_ips:
            similarity_score += 1.0
        elif alert.target_ip is None:
            similarity_score += 0.5  # Partial credit for missing target
        factors += 1

        # Time proximity (more recent = higher similarity)
        time_diff = alert.timestamp - correlation.last_seen
        if time_diff <= self.correlation_window:
            time_similarity = 1.0 - (time_diff / self.correlation_window)
            similarity_score += time_similarity
        factors += 1

        return similarity_score / factors if factors > 0 else 0.0

    def _should_create_correlation(self, alert: Alert) -> bool:
        """Determine if a new correlation should be created"""
        # Only create correlations for certain attack types
        correlatable_types = ['port_scan', 'dos', 'brute_force', 'anomaly_detection']
        if alert.attack_type not in correlatable_types:
            return False

        # Check if there are similar recent alerts
        recent_alerts = [
            a for a in self.alert_queue
            if (alert.timestamp - a.timestamp) <= self.correlation_window
        ]

        similar_alerts = 0
        for recent_alert in recent_alerts:
            if recent_alert.source_ip == alert.source_ip and recent_alert.attack_type == alert.attack_type:
                similar_alerts += 1

        # Create correlation if we have 2+ similar recent alerts
        return similar_alerts >= 1

    def _trigger_alert_handlers(self, alert: Alert):
        """Trigger all registered alert handlers"""
        for handler in self.alert_handlers:
            try:
                handler(alert)
            except Exception as e:
                logger.error(f"Error in alert handler: {e}")

    def _update_statistics(self, alert: Alert):
        """Update alert statistics"""
        self.stats.total_alerts += 1
        self.stats.active_alerts += 1
        self.stats.alerts_by_priority[alert.priority.value] += 1
        self.stats.alerts_by_type[alert.attack_type] += 1
        self.stats.alerts_by_source[alert.source] += 1

        # Calculate alerts per hour
        current_time = time.time()
        recent_alerts = [
            a for a in self.alert_queue
            if current_time - a.timestamp <= 3600  # Last hour
        ]
        self.stats.alerts_per_hour = len(recent_alerts)

        # Update top lists periodically
        if self.stats.total_alerts % 100 == 0:
            self._update_top_lists()

    def _update_top_lists(self):
        """Update top source IPs and attack types"""
        # Top source IPs
        source_counts = [(ip, count) for ip, count in self.stats.alerts_by_source.items()]
        source_counts.sort(key=lambda x: x[1], reverse=True)
        self.stats.top_source_ips = source_counts[:10]

        # Top attack types
        attack_counts = [(attack, count) for attack, count in self.stats.alerts_by_type.items()]
        attack_counts.sort(key=lambda x: x[1], reverse=True)
        self.stats.top_attack_types = attack_counts[:10]

        self.stats.correlation_groups = len(self.correlations)

    def acknowledge_alert(self, alert_id: str, assigned_to: Optional[str] = None) -> bool:
        """Acknowledge an alert"""
        if alert_id not in self.alerts:
            return False

        alert = self.alerts[alert_id]
        alert.status = AlertStatus.ACKNOWLEDGED
        if assigned_to:
            alert.assigned_to = assigned_to

        logger.info(f"Alert acknowledged: {alert_id} by {assigned_to or 'system'}")
        return True

    def resolve_alert(self, alert_id: str, notes: Optional[str] = None) -> bool:
        """Resolve an alert"""
        if alert_id not in self.alerts:
            return False

        alert = self.alerts[alert_id]
        alert.status = AlertStatus.RESOLVED
        alert.resolved_at = time.time()
        if notes:
            alert.notes = notes

        # Move from active to resolved
        if alert_id in self.active_alerts:
            del self.active_alerts[alert_id]
        self.resolved_alerts[alert_id] = alert

        # Update statistics
        self.stats.active_alerts = len(self.active_alerts)
        self.stats.resolved_alerts = len(self.resolved_alerts)

        # Calculate average resolution time
        if self.stats.resolved_alerts > 0:
            total_resolution_time = sum(
                alert.resolved_at - alert.timestamp
                for alert in self.resolved_alerts.values()
                if alert.resolved_at
            )
            self.stats.average_resolution_time = total_resolution_time / self.stats.resolved_alerts

        logger.info(f"Alert resolved: {alert_id}")
        return True

    def get_alerts(self, status: Optional[AlertStatus] = None, priority: Optional[AlertPriority] = None,
                  limit: int = 100, offset: int = 0) -> List[Alert]:
        """
        Get alerts with optional filtering

        Args:
            status: Filter by status
            priority: Filter by priority
            limit: Maximum number of alerts to return
            offset: Offset for pagination

        Returns:
            List of alerts
        """
        alerts = list(self.alerts.values())

        # Apply filters
        if status:
            alerts = [a for a in alerts if a.status == status]

        if priority:
            alerts = [a for a in alerts if a.priority == priority]

        # Sort by timestamp (newest first)
        alerts.sort(key=lambda a: a.timestamp, reverse=True)

        # Apply pagination
        return alerts[offset:offset + limit]

    def get_active_alerts(self, priority_filter: Optional[AlertPriority] = None) -> List[Alert]:
        """Get active alerts"""
        alerts = list(self.active_alerts.values())

        if priority_filter:
            alerts = [a for a in alerts if a.priority == priority_filter]

        # Sort by priority and timestamp
        priority_order = {
            AlertPriority.CRITICAL: 0,
            AlertPriority.HIGH: 1,
            AlertPriority.MEDIUM: 2,
            AlertPriority.LOW: 3
        }

        alerts.sort(key=lambda a: (priority_order[a.priority], a.timestamp), reverse=True)
        return alerts

    def get_alert_by_id(self, alert_id: str) -> Optional[Alert]:
        """Get alert by ID"""
        return self.alerts.get(alert_id)

    def get_correlation_groups(self, limit: int = 50) -> List[AlertCorrelation]:
        """Get alert correlation groups"""
        correlations = list(self.correlations.values())

        # Sort by severity score and alert count
        correlations.sort(key=lambda c: (c.severity_score, c.alert_count), reverse=True)

        return correlations[:limit]

    def get_statistics(self) -> AlertStatistics:
        """Get current alert statistics"""
        # Update dynamic statistics
        self.stats.active_alerts = len(self.active_alerts)
        self.stats.resolved_alerts = len(self.resolved_alerts)
        self.stats.correlation_groups = len(self.correlations)

        return self.stats

    def add_alert_handler(self, handler: callable):
        """Add an alert handler callback"""
        self.alert_handlers.append(handler)

    def remove_alert_handler(self, handler: callable):
        """Remove an alert handler callback"""
        if handler in self.alert_handlers:
            self.alert_handlers.remove(handler)

    def cleanup_old_alerts(self):
        """Clean up old alerts based on retention policy"""
        current_time = time.time()
        cutoff_time = current_time - (self.retention_days * 24 * 3600)

        # Find old alerts
        old_alert_ids = [
            alert_id for alert_id, alert in self.alerts.items()
            if alert.timestamp < cutoff_time and alert.status == AlertStatus.RESOLVED
        ]

        # Remove old alerts
        for alert_id in old_alert_ids:
            if alert_id in self.alerts:
                del self.alerts[alert_id]
            if alert_id in self.resolved_alerts:
                del self.resolved_alerts[alert_id]

        # Clean up old correlations
        old_correlation_ids = [
            corr_id for corr_id, correlation in self.correlations.items()
            if correlation.last_seen < cutoff_time
        ]

        for corr_id in old_correlation_ids:
            del self.correlations[corr_id]

        if old_alert_ids:
            logger.info(f"Cleaned up {len(old_alert_ids)} old alerts")

    def export_alerts(self, file_path: str, format: str = 'json',
                     time_range: Optional[Tuple[float, float]] = None):
        """Export alerts to file"""
        try:
            # Filter alerts by time range if specified
            if time_range:
                start_time, end_time = time_range
                filtered_alerts = [
                    alert for alert in self.alerts.values()
                    if start_time <= alert.timestamp <= end_time
                ]
            else:
                filtered_alerts = list(self.alerts.values())

            if format.lower() == 'json':
                # Convert to serializable format
                export_data = {
                    'export_timestamp': datetime.now().isoformat(),
                    'total_alerts': len(filtered_alerts),
                    'alerts': [self._alert_to_dict(alert) for alert in filtered_alerts],
                    'statistics': asdict(self.get_statistics())
                }

                with open(file_path, 'w') as f:
                    json.dump(export_data, f, indent=2, default=str)

            elif format.lower() == 'csv':
                import pandas as pd
                data = []
                for alert in filtered_alerts:
                    data.append({
                        'id': alert.id,
                        'timestamp': datetime.fromtimestamp(alert.timestamp).isoformat(),
                        'priority': alert.priority.value,
                        'status': alert.status.value,
                        'source_ip': alert.source_ip,
                        'target_ip': alert.target_ip,
                        'attack_type': alert.attack_type,
                        'confidence': alert.confidence,
                        'source': alert.source,
                        'correlation_id': alert.correlation_id,
                        'assigned_to': alert.assigned_to,
                        'resolved_at': datetime.fromtimestamp(alert.resolved_at).isoformat() if alert.resolved_at else None,
                        'notes': alert.notes
                    })

                df = pd.DataFrame(data)
                df.to_csv(file_path, index=False)

            logger.info(f"Exported {len(filtered_alerts)} alerts to {file_path}")

        except Exception as e:
            logger.error(f"Error exporting alerts: {e}")

    def _alert_to_dict(self, alert: Alert) -> Dict[str, Any]:
        """Convert alert to dictionary for JSON serialization"""
        return {
            'id': alert.id,
            'timestamp': alert.timestamp,
            'priority': alert.priority.value,
            'status': alert.status.value,
            'source_ip': alert.source_ip,
            'target_ip': alert.target_ip,
            'attack_type': alert.attack_type,
            'confidence': alert.confidence,
            'details': alert.details,
            'source': alert.source,
            'correlation_id': alert.correlation_id,
            'assigned_to': alert.assigned_to,
            'resolved_at': alert.resolved_at,
            'notes': alert.notes,
            'metadata': alert.metadata
        }

    def reset_statistics(self):
        """Reset alert statistics"""
        self.stats = AlertStatistics(
            total_alerts=len(self.alerts),
            active_alerts=len(self.active_alerts),
            resolved_alerts=len(self.resolved_alerts),
            alerts_by_priority=defaultdict(int),
            alerts_by_type=defaultdict(int),
            alerts_by_source=defaultdict(int),
            average_resolution_time=0.0,
            alerts_per_hour=0.0,
            top_source_ips=[],
            top_attack_types=[],
            correlation_groups=len(self.correlations)
        )

        # Recalculate from current alerts
        for alert in self.alerts.values():
            self.stats.alerts_by_priority[alert.priority.value] += 1
            self.stats.alerts_by_type[alert.attack_type] += 1
            self.stats.alerts_by_source[alert.source] += 1

        self._update_top_lists()
        logger.info("Alert statistics reset")


# Global alert manager instance
_alert_manager_instance = None

def get_alert_manager() -> AlertManager:
    """Get or create the global alert manager instance"""
    global _alert_manager_instance
    if _alert_manager_instance is None:
        _alert_manager_instance = AlertManager()
    return _alert_manager_instance

def cleanup_alert_manager():
    """Cleanup the global alert manager instance"""
    global _alert_manager_instance
    _alert_manager_instance = None