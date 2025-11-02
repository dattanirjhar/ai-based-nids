"""
Signature Engine Module
Traditional signature-based detection using rule-based pattern matching
"""

import re
import json
import time
import logging
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
from datetime import datetime, timedelta
import ipaddress
import os

from ..network_monitor.packet_capture import PacketInfo
from ..config.settings import get_config

logger = logging.getLogger(__name__)


@dataclass
class SignatureMatch:
    """Result of signature matching"""
    signature_id: str
    signature_name: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    category: str  # PORT_SCAN, DOS, BRUTE_FORCE, etc.
    confidence: float
    timestamp: float
    source_ip: str
    target_ip: str
    matched_pattern: str
    context: Dict[str, Any]
    description: str


@dataclass
class SignatureRule:
    """Signature rule definition"""
    id: str
    name: str
    description: str
    category: str
    severity: str
    pattern: str
    pattern_type: str  # regex, simple, behavioral
    conditions: Dict[str, Any]
    time_window: Optional[float] = None
    threshold: Optional[int] = None
    enabled: bool = True


class SignatureEngine:
    """
    Signature-based detection engine with rule-based pattern matching
    """

    def __init__(self, signatures_file: Optional[str] = None):
        """
        Initialize signature engine

        Args:
            signatures_file: Path to signatures JSON file
        """
        self.config = get_config()
        self.signatures_file = signatures_file or 'data/signatures.json'

        # Detection state
        self.signatures: Dict[str, SignatureRule] = {}
        self.pattern_cache: Dict[str, re.Pattern] = {}
        self.behavioral_state: Dict[str, Any] = defaultdict(lambda: defaultdict(list))
        self.matches: deque = deque(maxlen=10000)

        # Statistics
        self.stats = {
            'total_matches': 0,
            'category_counts': defaultdict(int),
            'severity_counts': defaultdict(int),
            'source_ips': defaultdict(int),
            'target_ips': defaultdict(int),
            'last_match_time': None,
            'detection_rate': 0.0
        }

        # Load signatures
        self._load_signatures()
        self._load_default_signatures()

    def _load_signatures(self):
        """Load signatures from JSON file"""
        if os.path.exists(self.signatures_file):
            try:
                with open(self.signatures_file, 'r') as f:
                    signatures_data = json.load(f)

                for sig_data in signatures_data.get('signatures', []):
                    signature = SignatureRule(**sig_data)
                    self.signatures[signature.id] = signature

                    # Pre-compile regex patterns
                    if signature.pattern_type == 'regex':
                        try:
                            self.pattern_cache[signature.id] = re.compile(
                                signature.pattern,
                                re.IGNORECASE
                            )
                        except re.error as e:
                            logger.error(f"Invalid regex pattern in signature {signature.id}: {e}")

                logger.info(f"Loaded {len(self.signatures)} signatures from {self.signatures_file}")

            except Exception as e:
                logger.error(f"Error loading signatures from {self.signatures_file}: {e}")
        else:
            logger.info(f"Signatures file {self.signatures_file} not found, using defaults")

    def _load_default_signatures(self):
        """Load default signature definitions"""
        default_signatures = [
            # Port Scan Signatures
            SignatureRule(
                id="port_scan_basic",
                name="Basic Port Scan Detection",
                description="Detects basic port scanning activity",
                category="PORT_SCAN",
                severity="MEDIUM",
                pattern="",
                pattern_type="behavioral",
                conditions={
                    "min_unique_ports": 10,
                    "max_time_window": 60,
                    "same_target": True
                },
                time_window=60.0,
                threshold=10,
                enabled=True
            ),
            SignatureRule(
                id="port_scan_aggressive",
                name="Aggressive Port Scan Detection",
                description="Detects aggressive port scanning with many ports",
                category="PORT_SCAN",
                severity="HIGH",
                pattern="",
                pattern_type="behavioral",
                conditions={
                    "min_unique_ports": 50,
                    "max_time_window": 30,
                    "same_target": True
                },
                time_window=30.0,
                threshold=50,
                enabled=True
            ),
            SignatureRule(
                id="port_scan_xmas",
                name="XMAS Port Scan Detection",
                description="Detects XMAS port scan (FIN, PSH, URG flags)",
                category="PORT_SCAN",
                severity="HIGH",
                pattern="",
                pattern_type="simple",
                conditions={
                    "tcp_flags": ["F", "P", "U"],
                    "no_ack_flag": True
                },
                enabled=True
            ),
            SignatureRule(
                id="port_scan_null",
                name="NULL Port Scan Detection",
                description="Detects NULL port scan (no TCP flags)",
                category="PORT_SCAN",
                severity="HIGH",
                pattern="",
                pattern_type="simple",
                conditions={
                    "tcp_flags": [],
                    "protocol": "TCP"
                },
                enabled=True
            ),

            # DoS Attack Signatures
            SignatureRule(
                id="syn_flood",
                name="SYN Flood Attack",
                description="Detects SYN flood attacks",
                category="DOS",
                severity="HIGH",
                pattern="",
                pattern_type="behavioral",
                conditions={
                    "tcp_syn_only": True,
                    "no_ack_response": True,
                    "same_target": True
                },
                time_window=10.0,
                threshold=100,
                enabled=True
            ),
            SignatureRule(
                id="udp_flood",
                name="UDP Flood Attack",
                description="Detects UDP flood attacks",
                category="DOS",
                severity="HIGH",
                pattern="",
                pattern_type="behavioral",
                conditions={
                    "protocol": "UDP",
                    "high_packet_rate": True,
                    "same_target": True
                },
                time_window=10.0,
                threshold=1000,
                enabled=True
            ),
            SignatureRule(
                id="icmp_flood",
                name="ICMP Flood Attack",
                description="Detects ICMP flood attacks",
                category="DOS",
                severity="MEDIUM",
                pattern="",
                pattern_type="behavioral",
                conditions={
                    "protocol": "ICMP",
                    "high_packet_rate": True,
                    "same_target": True
                },
                time_window=10.0,
                threshold=500,
                enabled=True
            ),

            # DNS Amplification Signatures
            SignatureRule(
                id="dns_amplification",
                name="DNS Amplification Attack",
                description="Detects DNS amplification attacks",
                category="DNS_AMPLIFICATION",
                severity="HIGH",
                pattern="",
                pattern_type="behavioral",
                conditions={
                    "protocol": "UDP",
                    "dst_port": 53,
                    "high_query_rate": True,
                    "same_source": True
                },
                time_window=60.0,
                threshold=50,
                enabled=True
            ),

            # Brute Force Signatures
            SignatureRule(
                id="ssh_brute_force",
                name="SSH Brute Force Attack",
                description="Detects SSH brute force attempts",
                category="BRUTE_FORCE",
                severity="MEDIUM",
                pattern="",
                pattern_type="behavioral",
                conditions={
                    "dst_port": 22,
                    "protocol": "TCP",
                    "failed_attempts": True,
                    "same_target": True
                },
                time_window=300.0,
                threshold=5,
                enabled=True
            ),
            SignatureRule(
                id="rdp_brute_force",
                name="RDP Brute Force Attack",
                description="Detects RDP brute force attempts",
                category="BRUTE_FORCE",
                severity="MEDIUM",
                pattern="",
                pattern_type="behavioral",
                conditions={
                    "dst_port": 3389,
                    "protocol": "TCP",
                    "failed_attempts": True,
                    "same_target": True
                },
                time_window=300.0,
                threshold=5,
                enabled=True
            ),

            # Suspicious Traffic Signatures
            SignatureRule(
                id="icmp_tunneling",
                name="ICMP Tunneling",
                description="Detects potential ICMP tunneling",
                category="TUNNELING",
                severity="MEDIUM",
                pattern="",
                pattern_type="simple",
                conditions={
                    "protocol": "ICMP",
                    "large_payload": True,
                    "payload_size_min": 64
                },
                enabled=True
            ),
            SignatureRule(
                id="suspicious_user_agent",
                name="Suspicious User Agent",
                description="Detects suspicious HTTP user agents",
                category="SUSPICIOUS",
                severity="LOW",
                pattern=".*(sqlmap|nmap|nikto|burp|metasploit).*",
                pattern_type="regex",
                conditions={
                    "protocol": "TCP",
                    "dst_port": [80, 443, 8080, 8443],
                    "http_user_agent": True
                },
                enabled=True
            ),

            # Malware Communication Signatures
            SignatureRule(
                id="c2_dns_query",
                name="Command and Control DNS Query",
                description="Detects potential C2 communication via DNS",
                category="MALWARE",
                severity="HIGH",
                pattern="^[a-f0-9]{32,}\\..*",
                pattern_type="regex",
                conditions={
                    "protocol": "UDP",
                    "dst_port": 53,
                    "dns_query": True,
                    "long_domain": True
                },
                enabled=True
            ),
            SignatureRule(
                id="suspicious_port_usage",
                name="Suspicious Port Usage",
                description="Detects traffic on suspicious ports",
                category="SUSPICIOUS",
                severity="LOW",
                pattern="",
                pattern_type="simple",
                conditions={
                    "dst_port": [1337, 31337, 4444, 5555, 6667, 12345],
                    "rare_ports": True
                },
                enabled=True
            )
        ]

        # Add default signatures if they don't exist
        for signature in default_signatures:
            if signature.id not in self.signatures:
                self.signatures[signature.id] = signature
                if signature.pattern_type == 'regex':
                    try:
                        self.pattern_cache[signature.id] = re.compile(
                            signature.pattern,
                            re.IGNORECASE
                        )
                    except re.error as e:
                        logger.error(f"Invalid regex pattern in default signature {signature.id}: {e}")

        logger.info(f"Loaded {len(default_signatures)} default signatures")

    def analyze_packet(self, packet_info: PacketInfo, additional_context: Optional[Dict[str, Any]] = None) -> List[SignatureMatch]:
        """
        Analyze a packet against all signature rules

        Args:
            packet_info: Packet information to analyze
            additional_context: Additional context from protocol analysis

        Returns:
            List of signature matches
        """
        matches = []
        current_time = packet_info.timestamp

        # Update behavioral state
        self._update_behavioral_state(packet_info, current_time)

        # Check each signature
        for signature in self.signatures.values():
            if not signature.enabled:
                continue

            try:
                match = self._check_signature(signature, packet_info, additional_context, current_time)
                if match:
                    matches.append(match)
                    self._update_statistics(match)

            except Exception as e:
                logger.error(f"Error checking signature {signature.id}: {e}")

        return matches

    def _update_behavioral_state(self, packet_info: PacketInfo, current_time: float):
        """Update behavioral tracking state"""
        # Cleanup old entries
        self._cleanup_behavioral_state(current_time)

        # Track port scanning activity
        if packet_info.dst_port:
            key = f"port_scan_{packet_info.src_ip}_{packet_info.dst_ip}"
            self.behavioral_state[key]['ports'].append(packet_info.dst_port)
            self.behavioral_state[key]['timestamps'].append(current_time)

        # Track SYN flood activity
        if packet_info.protocol.upper() == 'TCP' and 'S' in packet_info.flags and 'A' not in packet_info.flags:
            key = f"syn_flood_{packet_info.dst_ip}"
            self.behavioral_state[key]['syn_packets'].append({
                'src_ip': packet_info.src_ip,
                'timestamp': current_time
            })

        # Track UDP flood activity
        if packet_info.protocol.upper() == 'UDP':
            key = f"udp_flood_{packet_info.dst_ip}"
            self.behavioral_state[key]['packets'].append({
                'src_ip': packet_info.src_ip,
                'timestamp': current_time
            })

        # Track DNS queries
        if packet_info.protocol.upper() == 'UDP' and packet_info.dst_port == 53:
            key = f"dns_queries_{packet_info.src_ip}"
            self.behavioral_state[key]['queries'].append({
                'timestamp': current_time,
                'dst_ip': packet_info.dst_ip
            })

        # Track brute force attempts
        if packet_info.dst_port in [22, 3389, 21, 23, 25, 110, 143]:  # Common service ports
            key = f"brute_force_{packet_info.dst_ip}_{packet_info.dst_port}"
            self.behavioral_state[key]['attempts'].append({
                'src_ip': packet_info.src_ip,
                'timestamp': current_time
            })

    def _cleanup_behavioral_state(self, current_time: float):
        """Clean up old behavioral state entries"""
        max_age = 3600  # 1 hour

        keys_to_remove = []
        for key, state in self.behavioral_state.items():
            # Clean up timestamps
            for timestamp_list in ['timestamps', 'syn_packets', 'packets', 'queries', 'attempts']:
                if timestamp_list in state:
                    if hasattr(state[timestamp_list], '__iter__'):
                        # List of dictionaries or timestamps
                        filtered = []
                        for item in state[timestamp_list]:
                            if isinstance(item, dict):
                                if current_time - item.get('timestamp', 0) < max_age:
                                    filtered.append(item)
                            else:
                                if current_time - item < max_age:
                                    filtered.append(item)
                        state[timestamp_list] = filtered
                    else:
                        # Single timestamp
                        if current_time - state[timestamp_list] >= max_age:
                            state[timestamp_list] = None

            # Remove empty states
            if all(not state.get(k) for k in ['ports', 'timestamps', 'syn_packets', 'packets', 'queries', 'attempts']):
                keys_to_remove.append(key)

        for key in keys_to_remove:
            del self.behavioral_state[key]

    def _check_signature(self, signature: SignatureRule, packet_info: PacketInfo,
                        additional_context: Optional[Dict[str, Any]], current_time: float) -> Optional[SignatureMatch]:
        """Check if a packet matches a signature"""
        if signature.pattern_type == 'simple':
            return self._check_simple_signature(signature, packet_info, additional_context)
        elif signature.pattern_type == 'regex':
            return self._check_regex_signature(signature, packet_info, additional_context)
        elif signature.pattern_type == 'behavioral':
            return self._check_behavioral_signature(signature, packet_info, current_time)
        else:
            logger.warning(f"Unknown pattern type: {signature.pattern_type}")
            return None

    def _check_simple_signature(self, signature: SignatureRule, packet_info: PacketInfo,
                               additional_context: Optional[Dict[str, Any]]) -> Optional[SignatureMatch]:
        """Check simple pattern-based signature"""
        conditions = signature.conditions

        # Check protocol
        if 'protocol' in conditions:
            if isinstance(conditions['protocol'], list):
                if packet_info.protocol.upper() not in [p.upper() for p in conditions['protocol']]:
                    return None
            elif packet_info.protocol.upper() != conditions['protocol'].upper():
                return None

        # Check ports
        if 'src_port' in conditions:
            if isinstance(conditions['src_port'], list):
                if packet_info.src_port not in conditions['src_port']:
                    return None
            elif packet_info.src_port != conditions['src_port']:
                return None

        if 'dst_port' in conditions:
            if isinstance(conditions['dst_port'], list):
                if packet_info.dst_port not in conditions['dst_port']:
                    return None
            elif packet_info.dst_port != conditions['dst_port']:
                return None

        # Check TCP flags
        if 'tcp_flags' in conditions:
            expected_flags = set(conditions['tcp_flags'])
            actual_flags = set(packet_info.flags)
            if expected_flags != actual_flags:
                return None

        if 'no_ack_flag' in conditions and conditions['no_ack_flag']:
            if 'A' in packet_info.flags:
                return None

        # Check payload size
        if 'payload_size_min' in conditions:
            if packet_info.payload_size < conditions['payload_size_min']:
                return None

        if 'large_payload' in conditions and conditions['large_payload']:
            if packet_info.payload_size <= 64:
                return None

        # Check HTTP user agent (if available in context)
        if 'http_user_agent' in conditions and additional_context:
            user_agent = additional_context.get('http_user_agent', '')
            if not user_agent:
                return None

        # All conditions matched
        return SignatureMatch(
            signature_id=signature.id,
            signature_name=signature.name,
            severity=signature.severity,
            category=signature.category,
            confidence=0.9,  # High confidence for pattern matches
            timestamp=packet_info.timestamp,
            source_ip=packet_info.src_ip,
            target_ip=packet_info.dst_ip,
            matched_pattern=signature.name,
            context={
                'protocol': packet_info.protocol,
                'src_port': packet_info.src_port,
                'dst_port': packet_info.dst_port,
                'packet_size': packet_info.packet_size,
                'flags': packet_info.flags
            },
            description=signature.description
        )

    def _check_regex_signature(self, signature: SignatureRule, packet_info: PacketInfo,
                              additional_context: Optional[Dict[str, Any]]) -> Optional[SignatureMatch]:
        """Check regex-based signature"""
        if signature.id not in self.pattern_cache:
            return None

        pattern = self.pattern_cache[signature.id]
        conditions = signature.conditions

        # Get text to match against
        text_to_match = ""

        # Check protocol and ports first
        if 'protocol' in conditions:
            if isinstance(conditions['protocol'], list):
                if packet_info.protocol.upper() not in [p.upper() for p in conditions['protocol']]:
                    return None
            elif packet_info.protocol.upper() != conditions['protocol'].upper():
                return None

        if 'dst_port' in conditions:
            if isinstance(conditions['dst_port'], list):
                if packet_info.dst_port not in conditions['dst_port']:
                    return None
            elif packet_info.dst_port != conditions['dst_port']:
                return None

        # Get context data for regex matching
        if additional_context:
            if 'http_user_agent' in conditions and conditions['http_user_agent']:
                text_to_match += additional_context.get('http_user_agent', '') + " "
            if 'dns_query' in conditions and conditions['dns_query']:
                text_to_match += additional_context.get('dns_query', '') + " "
            if 'http_uri' in conditions and conditions['http_uri']:
                text_to_match += additional_context.get('http_uri', '') + " "

        # Try to extract payload data if available
        if hasattr(packet_info, 'raw_packet') and packet_info.raw_packet:
            try:
                # Attempt to extract payload text
                payload = str(packet_info.raw_packet.payload)
                text_to_match += payload + " "
            except:
                pass

        # Apply regex pattern
        if pattern.search(text_to_match):
            return SignatureMatch(
                signature_id=signature.id,
                signature_name=signature.name,
                severity=signature.severity,
                category=signature.category,
                confidence=0.8,  # High confidence for regex matches
                timestamp=packet_info.timestamp,
                source_ip=packet_info.src_ip,
                target_ip=packet_info.dst_ip,
                matched_pattern=signature.pattern,
                context={
                    'protocol': packet_info.protocol,
                    'src_port': packet_info.src_port,
                    'dst_port': packet_info.dst_port,
                    'matched_text': pattern.search(text_to_match).group() if pattern.search(text_to_match) else ''
                },
                description=signature.description
            )

        return None

    def _check_behavioral_signature(self, signature: SignatureRule, packet_info: PacketInfo,
                                   current_time: float) -> Optional[SignatureMatch]:
        """Check behavioral signature"""
        conditions = signature.conditions
        time_window = signature.time_window or 60.0
        threshold = signature.threshold or 10

        # Port Scan Detection
        if signature.category == "PORT_SCAN":
            if 'same_target' in conditions and conditions['same_target']:
                key = f"port_scan_{packet_info.src_ip}_{packet_info.dst_ip}"
            else:
                key = f"port_scan_{packet_info.src_ip}"

            if key in self.behavioral_state:
                recent_ports = []
                recent_timestamps = self.behavioral_state[key].get('timestamps', [])

                # Filter by time window
                recent_timestamps = [t for t in recent_timestamps if current_time - t <= time_window]
                recent_ports = self.behavioral_state[key].get('ports', [])[:len(recent_timestamps)]

                unique_ports = len(set(recent_ports))
                if unique_ports >= conditions.get('min_unique_ports', threshold):
                    return SignatureMatch(
                        signature_id=signature.id,
                        signature_name=signature.name,
                        severity=signature.severity,
                        category=signature.category,
                        confidence=min(unique_ports / (threshold * 2), 1.0),
                        timestamp=current_time,
                        source_ip=packet_info.src_ip,
                        target_ip=packet_info.dst_ip,
                        matched_pattern=f"Port scan: {unique_ports} ports in {time_window}s",
                        context={
                            'unique_ports': unique_ports,
                            'total_scans': len(recent_timestamps),
                            'time_window': time_window
                        },
                        description=signature.description
                    )

        # SYN Flood Detection
        elif signature.id == "syn_flood":
            key = f"syn_flood_{packet_info.dst_ip}"
            if key in self.behavioral_state:
                recent_syn = [
                    p for p in self.behavioral_state[key].get('syn_packets', [])
                    if current_time - p['timestamp'] <= time_window
                ]

                if len(recent_syn) >= threshold:
                    unique_sources = len(set(p['src_ip'] for p in recent_syn))
                    return SignatureMatch(
                        signature_id=signature.id,
                        signature_name=signature.name,
                        severity=signature.severity,
                        category=signature.category,
                        confidence=min(len(recent_syn) / (threshold * 2), 1.0),
                        timestamp=current_time,
                        source_ip=packet_info.src_ip,
                        target_ip=packet_info.dst_ip,
                        matched_pattern=f"SYN flood: {len(recent_syn)} SYN packets in {time_window}s",
                        context={
                            'syn_packets': len(recent_syn),
                            'unique_sources': unique_sources,
                            'time_window': time_window
                        },
                        description=signature.description
                    )

        # UDP Flood Detection
        elif signature.id == "udp_flood":
            key = f"udp_flood_{packet_info.dst_ip}"
            if key in self.behavioral_state:
                recent_udp = [
                    p for p in self.behavioral_state[key].get('packets', [])
                    if current_time - p['timestamp'] <= time_window
                ]

                if len(recent_udp) >= threshold:
                    return SignatureMatch(
                        signature_id=signature.id,
                        signature_name=signature.name,
                        severity=signature.severity,
                        category=signature.category,
                        confidence=min(len(recent_udp) / (threshold * 2), 1.0),
                        timestamp=current_time,
                        source_ip=packet_info.src_ip,
                        target_ip=packet_info.dst_ip,
                        matched_pattern=f"UDP flood: {len(recent_udp)} UDP packets in {time_window}s",
                        context={
                            'udp_packets': len(recent_udp),
                            'time_window': time_window
                        },
                        description=signature.description
                    )

        # DNS Amplification Detection
        elif signature.id == "dns_amplification":
            key = f"dns_queries_{packet_info.src_ip}"
            if key in self.behavioral_state:
                recent_queries = [
                    q for q in self.behavioral_state[key].get('queries', [])
                    if current_time - q['timestamp'] <= time_window
                ]

                if len(recent_queries) >= threshold:
                    unique_targets = len(set(q['dst_ip'] for q in recent_queries))
                    return SignatureMatch(
                        signature_id=signature.id,
                        signature_name=signature.name,
                        severity=signature.severity,
                        category=signature.category,
                        confidence=min(len(recent_queries) / (threshold * 2), 1.0),
                        timestamp=current_time,
                        source_ip=packet_info.src_ip,
                        target_ip=packet_info.dst_ip,
                        matched_pattern=f"DNS amplification: {len(recent_queries)} queries in {time_window}s",
                        context={
                            'dns_queries': len(recent_queries),
                            'unique_targets': unique_targets,
                            'time_window': time_window
                        },
                        description=signature.description
                    )

        # Brute Force Detection
        elif signature.category == "BRUTE_FORCE":
            key = f"brute_force_{packet_info.dst_ip}_{packet_info.dst_port}"
            if key in self.behavioral_state:
                recent_attempts = [
                    a for a in self.behavioral_state[key].get('attempts', [])
                    if current_time - a['timestamp'] <= time_window
                ]

                if len(recent_attempts) >= threshold:
                    return SignatureMatch(
                        signature_id=signature.id,
                        signature_name=signature.name,
                        severity=signature.severity,
                        category=signature.category,
                        confidence=min(len(recent_attempts) / (threshold * 2), 1.0),
                        timestamp=current_time,
                        source_ip=packet_info.src_ip,
                        target_ip=packet_info.dst_ip,
                        matched_pattern=f"Brute force: {len(recent_attempts)} attempts in {time_window}s",
                        context={
                            'attempts': len(recent_attempts),
                            'service_port': packet_info.dst_port,
                            'time_window': time_window
                        },
                        description=signature.description
                    )

        return None

    def _update_statistics(self, match: SignatureMatch):
        """Update detection statistics"""
        self.stats['total_matches'] += 1
        self.stats['category_counts'][match.category] += 1
        self.stats['severity_counts'][match.severity] += 1
        self.stats['source_ips'][match.source_ip] += 1
        self.stats['target_ips'][match.target_ip] += 1
        self.stats['last_match_time'] = match.timestamp

        # Calculate detection rate (matches per minute)
        if self.stats['total_matches'] > 1:
            time_span = match.timestamp - (self.matches[0].timestamp if self.matches else match.timestamp)
            if time_span > 0:
                self.stats['detection_rate'] = (self.stats['total_matches'] / time_span) * 60

        self.matches.append(match)

    def get_recent_matches(self, count: int = 100, category: Optional[str] = None,
                          severity: Optional[str] = None) -> List[SignatureMatch]:
        """
        Get recent signature matches

        Args:
            count: Number of matches to return
            category: Filter by category
            severity: Filter by severity

        Returns:
            List of recent signature matches
        """
        recent = list(self.matches)[-count:]

        if category:
            recent = [m for m in recent if m.category == category]

        if severity:
            recent = [m for m in recent if m.severity == severity]

        return recent

    def get_statistics(self) -> Dict[str, Any]:
        """Get detection statistics"""
        return {
            'total_signatures': len(self.signatures),
            'enabled_signatures': len([s for s in self.signatures.values() if s.enabled]),
            'total_matches': self.stats['total_matches'],
            'detection_rate': self.stats['detection_rate'],
            'category_distribution': dict(self.stats['category_counts']),
            'severity_distribution': dict(self.stats['severity_counts']),
            'top_source_ips': dict(sorted(self.stats['source_ips'].items(), key=lambda x: x[1], reverse=True)[:10]),
            'top_target_ips': dict(sorted(self.stats['target_ips'].items(), key=lambda x: x[1], reverse=True)[:10]),
            'last_match_time': self.stats['last_match_time'],
            'behavioral_state_size': len(self.behavioral_state)
        }

    def add_signature(self, signature: SignatureRule):
        """Add a new signature rule"""
        self.signatures[signature.id] = signature

        if signature.pattern_type == 'regex':
            try:
                self.pattern_cache[signature.id] = re.compile(
                    signature.pattern,
                    re.IGNORECASE
                )
            except re.error as e:
                logger.error(f"Invalid regex pattern in signature {signature.id}: {e}")

        logger.info(f"Added new signature: {signature.id}")

    def remove_signature(self, signature_id: str) -> bool:
        """Remove a signature rule"""
        if signature_id in self.signatures:
            del self.signatures[signature_id]
            if signature_id in self.pattern_cache:
                del self.pattern_cache[signature_id]
            logger.info(f"Removed signature: {signature_id}")
            return True
        return False

    def enable_signature(self, signature_id: str) -> bool:
        """Enable a signature rule"""
        if signature_id in self.signatures:
            self.signatures[signature_id].enabled = True
            logger.info(f"Enabled signature: {signature_id}")
            return True
        return False

    def disable_signature(self, signature_id: str) -> bool:
        """Disable a signature rule"""
        if signature_id in self.signatures:
            self.signatures[signature_id].enabled = False
            logger.info(f"Disabled signature: {signature_id}")
            return True
        return False

    def save_signatures(self, file_path: Optional[str] = None):
        """Save signatures to JSON file"""
        save_path = file_path or self.signatures_file

        try:
            signatures_data = {
                'signatures': [asdict(signature) for signature in self.signatures.values()],
                'export_timestamp': datetime.now().isoformat(),
                'total_signatures': len(self.signatures)
            }

            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            with open(save_path, 'w') as f:
                json.dump(signatures_data, f, indent=2)

            logger.info(f"Saved {len(self.signatures)} signatures to {save_path}")

        except Exception as e:
            logger.error(f"Error saving signatures: {e}")

    def export_matches(self, file_path: str, time_range: Optional[Tuple[float, float]] = None):
        """Export signature matches to CSV file"""
        try:
            import pandas as pd

            # Filter matches by time range if specified
            if time_range:
                start_time, end_time = time_range
                filtered_matches = [
                    m for m in self.matches
                    if start_time <= m.timestamp <= end_time
                ]
            else:
                filtered_matches = list(self.matches)

            # Convert to DataFrame
            data = []
            for match in filtered_matches:
                data.append({
                    'timestamp': datetime.fromtimestamp(match.timestamp).isoformat(),
                    'signature_id': match.signature_id,
                    'signature_name': match.signature_name,
                    'category': match.category,
                    'severity': match.severity,
                    'confidence': match.confidence,
                    'source_ip': match.source_ip,
                    'target_ip': match.target_ip,
                    'matched_pattern': match.matched_pattern,
                    'description': match.description
                })

            df = pd.DataFrame(data)
            df.to_csv(file_path, index=False)
            logger.info(f"Exported {len(df)} signature matches to {file_path}")

        except Exception as e:
            logger.error(f"Error exporting matches: {e}")

    def reset_statistics(self):
        """Reset detection statistics"""
        self.stats = {
            'total_matches': 0,
            'category_counts': defaultdict(int),
            'severity_counts': defaultdict(int),
            'source_ips': defaultdict(int),
            'target_ips': defaultdict(int),
            'last_match_time': None,
            'detection_rate': 0.0
        }
        self.matches.clear()
        self.behavioral_state.clear()
        logger.info("Signature engine statistics reset")


# Global signature engine instance
_signature_engine_instance = None

def get_signature_engine(signatures_file: Optional[str] = None) -> SignatureEngine:
    """Get or create the global signature engine instance"""
    global _signature_engine_instance
    if _signature_engine_instance is None:
        _signature_engine_instance = SignatureEngine(signatures_file)
    return _signature_engine_instance

def cleanup_signature_engine():
    """Cleanup the global signature engine instance"""
    global _signature_engine_instance
    _signature_engine_instance = None