"""
Data Models Module
Pydantic models for data validation and database schemas
"""

from typing import Dict, List, Any, Optional, Union
from datetime import datetime
from dataclasses import dataclass
from enum import Enum
import json

try:
    from pydantic import BaseModel, Field, validator
    from pydantic.types import constr, conint
    PYDANTIC_AVAILABLE = True
except ImportError:
    # Fallback when Pydantic is not available
    PYDANTIC_AVAILABLE = False
    BaseModel = object

    def Field(default=None, **kwargs):
        return default

    def validator(field_name, **kwargs):
        def decorator(func):
            return func
        return decorator

from ..alert_system.alert_manager import Alert, AlertPriority, AlertStatus
from ..ml_detection.anomaly_detector import DetectionResult
from ..ml_detection.signature_engine import SignatureMatch


# Enums
class ProtocolType(str, Enum):
    """Network protocol types"""
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    ARP = "ARP"
    UNKNOWN = "UNKNOWN"


class AttackType(str, Enum):
    """Attack type classifications"""
    PORT_SCAN = "port_scan"
    DOS = "dos"
    BRUTE_FORCE = "brute_force"
    DNS_AMPLIFICATION = "dns_amplification"
    MALWARE = "malware"
    TUNNELING = "tunneling"
    SUSPICIOUS = "suspicious"
    ANOMALY_DETECTION = "anomaly_detection"
    UNKNOWN = "unknown"


class SeverityLevel(str, Enum):
    """Severity levels"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# Base Models (if Pydantic is available)
if PYDANTIC_AVAILABLE:

    class PacketInfo(BaseModel):
        """Packet information model"""
        timestamp: float
        src_ip: str
        dst_ip: str
        src_port: Optional[int] = None
        dst_port: Optional[int] = None
        protocol: ProtocolType
        packet_size: int
        payload_size: int
        flags: List[str] = []
        ttl: int = 0

        @validator('protocol', pre=True)
        def normalize_protocol(cls, v):
            return v.upper() if isinstance(v, str) else v

        @validator('src_ip', 'dst_ip')
        def validate_ip(cls, v):
            import ipaddress
            try:
                ipaddress.ip_address(v)
                return v
            except ValueError:
                raise ValueError(f"Invalid IP address: {v}")

    class FlowFeatures(BaseModel):
        """Network flow features model"""
        flow_key: str
        src_ip: str
        dst_ip: str
        src_port: int
        dst_port: int
        protocol: ProtocolType

        # Basic features
        packet_count: int = Field(ge=0)
        byte_count: int = Field(ge=0)
        duration: float = Field(ge=0)
        start_time: float
        end_time: float

        # Temporal features
        packets_per_second: float = Field(ge=0)
        bytes_per_second: float = Field(ge=0)
        avg_inter_arrival_time: float = Field(ge=0)
        std_inter_arrival_time: float = Field(ge=0)

        # Packet size features
        avg_packet_size: float = Field(ge=0)
        std_packet_size: float = Field(ge=0)
        min_packet_size: int = Field(ge=0)
        max_packet_size: int = Field(ge=0)

        # Directional features
        src_to_dst_packets: int = Field(ge=0)
        dst_to_src_packets: int = Field(ge=0)
        src_to_dst_bytes: int = Field(ge=0)
        dst_to_src_bytes: int = Field(ge=0)

        # Behavioral features
        is_internal_src: bool
        is_internal_dst: bool
        is_well_known_port: bool
        port_scan_indicator: float = Field(ge=0, le=1)
        syn_flood_ratio: float = Field(ge=0, le=1)
        burstiness: float = Field(ge=0)
        regularity: float = Field(ge=0, le=1)

        # Additional fields
        tcp_flags_count: Dict[str, int] = {}
        icmp_types_count: Dict[str, int] = {}

    class AlertModel(BaseModel):
        """Alert model for API responses"""
        id: str
        timestamp: float
        priority: SeverityLevel
        status: str
        source_ip: str
        target_ip: Optional[str] = None
        attack_type: AttackType
        confidence: float = Field(ge=0, le=1)
        details: Dict[str, Any] = {}
        source: str
        correlation_id: Optional[str] = None
        assigned_to: Optional[str] = None
        resolved_at: Optional[float] = None
        notes: Optional[str] = None
        metadata: Optional[Dict[str, Any]] = None

        @validator('priority', pre=True)
        def normalize_priority(cls, v):
            if isinstance(v, str):
                return v.upper()
            return v

        @validator('attack_type', pre=True)
        def normalize_attack_type(cls, v):
            if isinstance(v, str):
                return v.lower()
            return v

        class Config:
            json_encoders = {
                datetime: lambda v: v.isoformat(),
                float: lambda v: round(v, 6)
            }

    class DetectionResultModel(BaseModel):
        """Detection result model for API responses"""
        timestamp: float
        is_anomaly: bool
        anomaly_score: float = Field(ge=0, le=1)
        confidence: float = Field(ge=0, le=1)
        model_predictions: Dict[str, Dict[str, Any]]
        detection_method: str
        metadata: Optional[Dict[str, Any]] = None

    class SignatureMatchModel(BaseModel):
        """Signature match model for API responses"""
        signature_id: str
        signature_name: str
        severity: SeverityLevel
        category: str
        confidence: float = Field(ge=0, le=1)
        timestamp: float
        source_ip: str
        target_ip: str
        matched_pattern: str
        context: Dict[str, Any]
        description: str

    class NetworkStatistics(BaseModel):
        """Network statistics model"""
        timestamp: float
        total_packets: int = Field(ge=0)
        bytes_captured: int = Field(ge=0)
        packets_per_second: float = Field(ge=0)
        bytes_per_second: float = Field(ge=0)
        protocol_distribution: Dict[str, int]
        top_source_ips: List[Dict[str, Any]]
        top_destination_ips: List[Dict[str, Any]]
        active_connections: int = Field(ge=0)
        capture_rate: float = Field(ge=0)

    class SystemResources(BaseModel):
        """System resource usage model"""
        timestamp: float
        cpu_percent: float = Field(ge=0, le=100)
        memory_percent: float = Field(ge=0, le=100)
        disk_percent: float = Field(ge=0, le=100)
        network_io: Dict[str, int]
        process_count: int = Field(ge=0)
        uptime_seconds: float = Field(ge=0)

    class AlertStatistics(BaseModel):
        """Alert statistics model"""
        total_alerts: int = Field(ge=0)
        active_alerts: int = Field(ge=0)
        resolved_alerts: int = Field(ge=0)
        alerts_by_priority: Dict[str, int]
        alerts_by_type: Dict[str, int]
        alerts_by_source: Dict[str, int]
        average_resolution_time: float = Field(ge=0)
        alerts_per_hour: float = Field(ge=0)
        top_source_ips: List[Dict[str, int]]
        top_attack_types: List[Dict[str, int]]
        correlation_groups: int = Field(ge=0)

    class MLModelInfo(BaseModel):
        """Machine learning model information"""
        name: str
        type: str
        accuracy: float = Field(ge=0, le=1)
        precision: float = Field(ge=0, le=1)
        recall: float = Field(ge=0, le=1)
        f1_score: float = Field(ge=0, le=1)
        training_time: float = Field(ge=0)
        prediction_time: float = Field(ge=0)
        last_trained: Optional[datetime] = None
        parameters: Dict[str, Any] = {}
        feature_importance: Optional[Dict[str, float]] = None

    class UserSession(BaseModel):
        """User session model"""
        session_id: str
        user_id: str
        username: str
        created_at: datetime
        last_activity: datetime
        ip_address: str
        user_agent: Optional[str] = None
        is_active: bool = True
        permissions: List[str] = []

    class SystemConfiguration(BaseModel):
        """System configuration model"""
        network_interface: Optional[str] = None
        promiscuous_mode: bool = True
        packet_buffer_size: int = Field(ge=100, le=100000)
        confidence_threshold: float = Field(ge=0, le=1)
        alert_rate_limiting: bool = True
        max_alerts_per_minute: int = Field(ge=1, le=1000)
        retention_days: int = Field(ge=1, le=365)
        log_level: str = Field(regex="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")

    class APIResponse(BaseModel):
        """Generic API response model"""
        success: bool
        message: str
        data: Optional[Any] = None
        timestamp: datetime = Field(default_factory=datetime.now)
        error: Optional[str] = None

    class PaginatedResponse(BaseModel):
        """Paginated API response model"""
        success: bool
        data: List[Any]
        pagination: Dict[str, Any]
        timestamp: datetime = Field(default_factory=datetime.now)

    class WebSocketMessage(BaseModel):
        """WebSocket message model"""
        type: str
        data: Dict[str, Any]
        timestamp: datetime = Field(default_factory=datetime.now)
        channel: Optional[str] = None

# Data transfer objects (DTOs)
@dataclass
class AlertDTO:
    """Alert data transfer object"""
    id: str
    timestamp: float
    priority: AlertPriority
    status: AlertStatus
    source_ip: str
    target_ip: Optional[str]
    attack_type: str
    confidence: float
    details: Dict[str, Any]
    source: str
    correlation_id: Optional[str] = None
    assigned_to: Optional[str] = None
    resolved_at: Optional[float] = None
    notes: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

    @classmethod
    def from_alert(cls, alert: Alert) -> 'AlertDTO':
        """Create DTO from Alert object"""
        return cls(
            id=alert.id,
            timestamp=alert.timestamp,
            priority=alert.priority,
            status=alert.status,
            source_ip=alert.source_ip,
            target_ip=alert.target_ip,
            attack_type=alert.attack_type,
            confidence=alert.confidence,
            details=alert.details,
            source=alert.source,
            correlation_id=alert.correlation_id,
            assigned_to=alert.assigned_to,
            resolved_at=alert.resolved_at,
            notes=alert.notes,
            metadata=alert.metadata
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'id': self.id,
            'timestamp': self.timestamp,
            'priority': self.priority.value,
            'status': self.status.value,
            'source_ip': self.source_ip,
            'target_ip': self.target_ip,
            'attack_type': self.attack_type,
            'confidence': self.confidence,
            'details': self.details,
            'source': self.source,
            'correlation_id': self.correlation_id,
            'assigned_to': self.assigned_to,
            'resolved_at': self.resolved_at,
            'notes': self.notes,
            'metadata': self.metadata
        }


@dataclass
class NetworkStatsDTO:
    """Network statistics data transfer object"""
    timestamp: float
    total_packets: int
    bytes_captured: int
    packets_per_second: float
    bytes_per_second: float
    protocol_distribution: Dict[str, int]
    top_source_ips: List[Dict[str, Any]]
    top_destination_ips: List[Dict[str, Any]]
    active_connections: int
    capture_rate: float

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'timestamp': self.timestamp,
            'total_packets': self.total_packets,
            'bytes_captured': self.bytes_captured,
            'packets_per_second': self.packets_per_second,
            'bytes_per_second': self.bytes_per_second,
            'protocol_distribution': self.protocol_distribution,
            'top_source_ips': self.top_source_ips,
            'top_destination_ips': self.top_destination_ips,
            'active_connections': self.active_connections,
            'capture_rate': self.capture_rate
        }


# Database schemas (SQLite)
class DatabaseSchema:
    """Database schema definitions"""

    ALERTS_TABLE = """
    CREATE TABLE IF NOT EXISTS alerts (
        id TEXT PRIMARY KEY,
        timestamp REAL NOT NULL,
        priority TEXT NOT NULL,
        status TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        target_ip TEXT,
        attack_type TEXT NOT NULL,
        confidence REAL NOT NULL,
        details TEXT,
        source TEXT NOT NULL,
        correlation_id TEXT,
        assigned_to TEXT,
        resolved_at REAL,
        notes TEXT,
        metadata TEXT,
        created_at REAL DEFAULT (strftime('%s', 'now'))
    );
    """

    NETWORK_STATS_TABLE = """
    CREATE TABLE IF NOT EXISTS network_stats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp REAL NOT NULL,
        total_packets INTEGER NOT NULL,
        bytes_captured INTEGER NOT NULL,
        packets_per_second REAL NOT NULL,
        bytes_per_second REAL NOT NULL,
        protocol_distribution TEXT NOT NULL,
        top_source_ips TEXT NOT NULL,
        top_destination_ips TEXT NOT NULL,
        active_connections INTEGER NOT NULL,
        capture_rate REAL NOT NULL,
        created_at REAL DEFAULT (strftime('%s', 'now'))
    );
    """

    SIGNATURE_MATCHES_TABLE = """
    CREATE TABLE IF NOT EXISTS signature_matches (
        id TEXT PRIMARY KEY,
        signature_id TEXT NOT NULL,
        signature_name TEXT NOT NULL,
        severity TEXT NOT NULL,
        category TEXT NOT NULL,
        confidence REAL NOT NULL,
        timestamp REAL NOT NULL,
        source_ip TEXT NOT NULL,
        target_ip TEXT NOT NULL,
        matched_pattern TEXT NOT NULL,
        context TEXT NOT NULL,
        description TEXT NOT NULL,
        created_at REAL DEFAULT (strftime('%s', 'now'))
    );
    """

    DETECTION_RESULTS_TABLE = """
    CREATE TABLE IF NOT EXISTS detection_results (
        id TEXT PRIMARY KEY,
        timestamp REAL NOT NULL,
        is_anomaly BOOLEAN NOT NULL,
        anomaly_score REAL NOT NULL,
        confidence REAL NOT NULL,
        model_predictions TEXT NOT NULL,
        detection_method TEXT NOT NULL,
        metadata TEXT,
        created_at REAL DEFAULT (strftime('%s', 'now'))
    );
    """

    SYSTEM_LOGS_TABLE = """
    CREATE TABLE IF NOT EXISTS system_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp REAL NOT NULL,
        level TEXT NOT NULL,
        component TEXT NOT NULL,
        message TEXT NOT NULL,
        details TEXT,
        source_ip TEXT,
        session_id TEXT,
        user_id TEXT,
        tags TEXT,
        created_at REAL DEFAULT (strftime('%s', 'now'))
    );
    """

    USER_SESSIONS_TABLE = """
    CREATE TABLE IF NOT EXISTS user_sessions (
        session_id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        username TEXT NOT NULL,
        created_at REAL NOT NULL,
        last_activity REAL NOT NULL,
        ip_address TEXT NOT NULL,
        user_agent TEXT,
        is_active BOOLEAN DEFAULT 1,
        permissions TEXT
    );
    """

    # Indexes for performance
    INDEXES = [
        "CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);",
        "CREATE INDEX IF NOT EXISTS idx_alerts_priority ON alerts(priority);",
        "CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip);",
        "CREATE INDEX IF NOT EXISTS idx_alerts_attack_type ON alerts(attack_type);",
        "CREATE INDEX IF NOT EXISTS idx_network_stats_timestamp ON network_stats(timestamp);",
        "CREATE INDEX IF NOT EXISTS idx_signature_matches_timestamp ON signature_matches(timestamp);",
        "CREATE INDEX IF NOT EXISTS idx_detection_results_timestamp ON detection_results(timestamp);",
        "CREATE INDEX IF NOT EXISTS idx_system_logs_timestamp ON system_logs(timestamp);",
        "CREATE INDEX IF NOT EXISTS idx_user_sessions_last_activity ON user_sessions(last_activity);",
    ]

    @classmethod
    def get_all_tables(cls) -> List[str]:
        """Get all table creation statements"""
        return [
            cls.ALERTS_TABLE,
            cls.NETWORK_STATS_TABLE,
            cls.SIGNATURE_MATCHES_TABLE,
            cls.DETECTION_RESULTS_TABLE,
            cls.SYSTEM_LOGS_TABLE,
            cls.USER_SESSIONS_TABLE
        ]

    @classmethod
    def get_all_indexes(cls) -> List[str]:
        """Get all index creation statements"""
        return cls.INDEXES


# Serialization utilities
class SerializationUtils:
    """Utilities for data serialization and deserialization"""

    @staticmethod
    def serialize_alert(alert: Alert) -> str:
        """Serialize alert to JSON string"""
        return json.dumps(alert.to_dict() if hasattr(alert, 'to_dict') else alert.__dict__, default=str)

    @staticmethod
    def deserialize_alert(data: Union[str, Dict[str, Any]]) -> Alert:
        """Deserialize alert from JSON string or dictionary"""
        if isinstance(data, str):
            data = json.loads(data)

        return Alert(**data)

    @staticmethod
    def serialize_detection_result(result: DetectionResult) -> str:
        """Serialize detection result to JSON string"""
        return json.dumps(result.__dict__, default=str)

    @staticmethod
    def serialize_signature_match(match: SignatureMatch) -> str:
        """Serialize signature match to JSON string"""
        return json.dumps(match.__dict__, default=str)

    @staticmethod
    def serialize_datetime(dt: datetime) -> str:
        """Serialize datetime to ISO string"""
        return dt.isoformat()

    @staticmethod
    def deserialize_datetime(dt_str: str) -> datetime:
        """Deserialize datetime from ISO string"""
        return datetime.fromisoformat(dt_str)


# Validation utilities
class ValidationUtils:
    """Utilities for data validation"""

    @staticmethod
    def validate_ip_address(ip: str) -> bool:
        """Validate IP address"""
        import ipaddress
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    @staticmethod
    def validate_port(port: int) -> bool:
        """Validate port number"""
        return 0 <= port <= 65535

    @staticmethod
    def validate_confidence(confidence: float) -> bool:
        """Validate confidence score"""
        return 0.0 <= confidence <= 1.0

    @staticmethod
    def validate_timestamp(timestamp: float) -> bool:
        """Validate timestamp"""
        return timestamp > 0 and timestamp <= (datetime.now().timestamp() + 86400)  # Allow 1 day future

    @staticmethod
    def sanitize_string(value: str, max_length: int = 255) -> str:
        """Sanitize string input"""
        if not value:
            return ""
        # Remove potential harmful characters
        sanitized = re.sub(r'[<>"\'\x00-\x1f\x7f-\x9f]', '', str(value))
        return sanitized[:max_length]

    @staticmethod
    def validate_json_structure(data: Dict[str, Any], required_fields: List[str]) -> bool:
        """Validate JSON structure has required fields"""
        return all(field in data for field in required_fields)


# Import regex for string sanitization
import re