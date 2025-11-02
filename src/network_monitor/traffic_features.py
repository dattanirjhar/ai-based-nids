"""
Traffic Features Extractor Module
Extracts statistical and behavioral features from network traffic for ML analysis
"""

import time
import math
from collections import defaultdict, deque
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import statistics
import ipaddress

from .packet_capture import PacketInfo
from .protocol_analyzer import ProtocolAnalyzer


@dataclass
class FlowFeatures:
    """Features extracted from a network flow (5-tuple)"""
    flow_key: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str

    # Basic flow features
    packet_count: int
    byte_count: int
    duration: float
    start_time: float
    end_time: float

    # Temporal features
    packets_per_second: float
    bytes_per_second: float
    avg_inter_arrival_time: float
    std_inter_arrival_time: float

    # Packet size features
    avg_packet_size: float
    std_packet_size: float
    min_packet_size: int
    max_packet_size: int

    # Directional features
    src_to_dst_packets: int
    dst_to_src_packets: int
    src_to_dst_bytes: int
    dst_to_src_bytes: int

    # Protocol-specific features
    tcp_flags_count: Dict[str, int]
    icmp_types_count: Dict[str, int]

    # Behavioral features
    is_internal_src: bool
    is_internal_dst: bool
    is_well_known_port: bool
    port_scan_indicator: float
    syn_flood_ratio: float

    # Statistical features
    burstiness: float
    regularity: float


@dataclass
class WindowFeatures:
    """Features extracted from a time window"""
    window_start: float
    window_end: float
    window_duration: float

    # Aggregate traffic features
    total_packets: int
    total_bytes: int
    unique_sources: int
    unique_destinations: int
    unique_ports: int

    # Protocol distribution
    protocol_ratios: Dict[str, float]

    # Traffic patterns
    new_flows_per_second: float
    avg_flow_duration: float
    flow_diversity: float

    # Anomaly indicators
    port_scan_score: float
    dos_score: float
    data_exfiltration_score: float
    unusual_protocol_score: float


class TrafficFeatureExtractor:
    """
    Extracts features from network traffic for machine learning analysis
    """

    def __init__(self,
                 flow_timeout: float = 60.0,
                 feature_window_size: float = 10.0,
                 max_flows: int = 10000):
        """
        Initialize feature extractor

        Args:
            flow_timeout: Timeout in seconds for flow expiration
            feature_window_size: Size of time windows for feature extraction
            max_flows: Maximum number of flows to track
        """
        self.flow_timeout = flow_timeout
        self.feature_window_size = feature_window_size
        self.max_flows = max_flows

        # Flow tracking
        self.active_flows: Dict[str, Dict[str, Any]] = {}
        self.completed_flows: deque = deque(maxlen=1000)

        # Time window tracking
        self.current_window: Dict[str, Any] = {}
        self.window_history: deque = deque(maxlen=100)

        # Internal network configuration (can be updated)
        self.internal_networks = [
            ipaddress.ip_network('10.0.0.0/8'),
            ipaddress.ip_network('172.16.0.0/12'),
            ipaddress.ip_network('192.168.0.0/16'),
            ipaddress.ip_network('127.0.0.0/8')
        ]

        # Well-known ports
        self.well_known_ports = set(range(1, 1024))

        # Initialize tracking structures
        self._initialize_tracking()

    def _initialize_tracking(self):
        """Initialize tracking data structures"""
        current_time = time.time()

        self.current_window = {
            'start_time': current_time,
            'end_time': current_time,
            'packets': [],
            'flows': set(),
            'unique_sources': set(),
            'unique_destinations': set(),
            'unique_ports': set(),
            'protocol_counts': defaultdict(int),
            'port_scan_candidates': defaultdict(int),
            'dos_candidates': defaultdict(int)
        }

    def extract_packet_features(self, packet_info: PacketInfo) -> Dict[str, Any]:
        """
        Extract features from a single packet

        Args:
            packet_info: Packet information

        Returns:
            Dictionary with packet-level features
        """
        features = {
            'timestamp': packet_info.timestamp,
            'protocol': packet_info.protocol,
            'packet_size': packet_info.packet_size,
            'payload_size': packet_info.payload_size,
            'src_ip': packet_info.src_ip,
            'dst_ip': packet_info.dst_ip,
            'src_port': packet_info.src_port or 0,
            'dst_port': packet_info.dst_port or 0,
            'ttl': packet_info.ttl,
        }

        # Add protocol-specific features
        if packet_info.protocol.upper() == 'TCP':
            features.update({
                'tcp_flags': packet_info.flags,
                'tcp_flag_count': len(packet_info.flags),
                'is_syn': 'S' in packet_info.flags,
                'is_ack': 'A' in packet_info.flags,
                'is_fin': 'F' in packet_info.flags,
                'is_rst': 'R' in packet_info.flags,
                'is_psh': 'P' in packet_info.flags,
            })

        # Add network classification features
        features.update({
            'is_internal_src': self._is_internal_ip(packet_info.src_ip),
            'is_internal_dst': self._is_internal_ip(packet_info.dst_ip),
            'is_well_known_src': packet_info.src_port in self.well_known_ports if packet_info.src_port else False,
            'is_well_known_dst': packet_info.dst_port in self.well_known_ports if packet_info.dst_port else False,
            'is_cross_boundary': (
                self._is_internal_ip(packet_info.src_ip) !=
                self._is_internal_ip(packet_info.dst_ip)
            )
        })

        return features

    def process_packet(self, packet_info: PacketInfo) -> Tuple[Optional[FlowFeatures], Optional[WindowFeatures]]:
        """
        Process a packet and update flow and window features

        Args:
            packet_info: Packet information

        Returns:
            Tuple of (flow_features, window_features) if available
        """
        current_time = packet_info.timestamp

        # Extract packet features
        packet_features = self.extract_packet_features(packet_info)

        # Update current window
        self._update_window(packet_info, packet_features)

        # Update flow tracking
        flow_features = self._update_flow(packet_info, packet_features)

        # Check if window is complete
        window_features = None
        if current_time - self.current_window['start_time'] >= self.feature_window_size:
            window_features = self._finalize_window()

        # Cleanup old flows
        self._cleanup_old_flows(current_time)

        return flow_features, window_features

    def _update_flow(self, packet_info: PacketInfo, packet_features: Dict[str, Any]) -> Optional[FlowFeatures]:
        """Update flow tracking with new packet"""
        # Create flow key (5-tuple)
        flow_key = self._get_flow_key(packet_info)

        current_time = packet_info.timestamp

        if flow_key not in self.active_flows:
            # Create new flow
            if len(self.active_flows) >= self.max_flows:
                self._expire_oldest_flow()

            self.active_flows[flow_key] = {
                'src_ip': packet_info.src_ip,
                'dst_ip': packet_info.dst_ip,
                'src_port': packet_info.src_port or 0,
                'dst_port': packet_info.dst_port or 0,
                'protocol': packet_info.protocol,
                'start_time': current_time,
                'end_time': current_time,
                'packet_count': 0,
                'byte_count': 0,
                'src_to_dst_packets': 0,
                'dst_to_src_packets': 0,
                'src_to_dst_bytes': 0,
                'dst_to_src_bytes': 0,
                'packet_sizes': [],
                'inter_arrival_times': [],
                'tcp_flags_count': defaultdict(int),
                'icmp_types_count': defaultdict(int),
                'last_packet_time': current_time,
                'packet_timestamps': deque(maxlen=1000)
            }

        # Update flow
        flow = self.active_flows[flow_key]

        # Update basic counters
        flow['packet_count'] += 1
        flow['byte_count'] += packet_info.packet_size
        flow['end_time'] = current_time
        flow['packet_sizes'].append(packet_info.packet_size)

        # Track timestamps for inter-arrival time calculation
        if flow['last_packet_time']:
            inter_arrival = current_time - flow['last_packet_time']
            flow['inter_arrival_times'].append(inter_arrival)
        flow['last_packet_time'] = current_time
        flow['packet_timestamps'].append(current_time)

        # Update directional counters
        # Determine direction based on IP comparison (consistency)
        if (packet_info.src_ip, packet_info.src_port or 0) <= (packet_info.dst_ip, packet_info.dst_port or 0):
            flow['src_to_dst_packets'] += 1
            flow['src_to_dst_bytes'] += packet_info.packet_size
        else:
            flow['dst_to_src_packets'] += 1
            flow['dst_to_src_bytes'] += packet_info.packet_size

        # Update protocol-specific counters
        if packet_info.protocol.upper() == 'TCP':
            for flag in packet_info.flags:
                flow['tcp_flags_count'][flag] += 1

        # Check if flow should be finalized
        duration = current_time - flow['start_time']
        if duration > self.flow_timeout or flow['packet_count'] > 1000:
            return self._finalize_flow(flow_key)

        return None

    def _update_window(self, packet_info: PacketInfo, packet_features: Dict[str, Any]):
        """Update current time window with packet information"""
        window = self.current_window
        current_time = packet_info.timestamp

        # Update window time bounds
        window['end_time'] = current_time

        # Add packet to window
        window['packets'].append(packet_features)

        # Update flow tracking
        flow_key = self._get_flow_key(packet_info)
        window['flows'].add(flow_key)

        # Update unique entities
        window['unique_sources'].add(packet_info.src_ip)
        window['unique_destinations'].add(packet_info.dst_ip)
        if packet_info.src_port:
            window['unique_ports'].add(packet_info.src_port)
        if packet_info.dst_port:
            window['unique_ports'].add(packet_info.dst_port)

        # Update protocol counts
        window['protocol_counts'][packet_info.protocol.upper()] += 1

        # Update port scan candidates
        if packet_features.get('is_cross_boundary', False):
            dst_ip_port = f"{packet_info.dst_ip}:{packet_info.dst_port or 0}"
            window['port_scan_candidates'][dst_ip_port] += 1

        # Update DoS candidates
        if packet_info.dst_ip:
            window['dos_candidates'][packet_info.dst_ip] += 1

    def _finalize_flow(self, flow_key: str) -> FlowFeatures:
        """Finalize a flow and extract features"""
        flow_data = self.active_flows[flow_key]

        # Calculate duration
        duration = flow_data['end_time'] - flow_data['start_time']

        # Calculate temporal features
        if duration > 0:
            packets_per_second = flow_data['packet_count'] / duration
            bytes_per_second = flow_data['byte_count'] / duration
        else:
            packets_per_second = 0
            bytes_per_second = 0

        # Calculate inter-arrival time statistics
        if flow_data['inter_arrival_times']:
            avg_inter_arrival = statistics.mean(flow_data['inter_arrival_times'])
            std_inter_arrival = statistics.stdev(flow_data['inter_arrival_times']) if len(flow_data['inter_arrival_times']) > 1 else 0
        else:
            avg_inter_arrival = 0
            std_inter_arrival = 0

        # Calculate packet size statistics
        if flow_data['packet_sizes']:
            avg_packet_size = statistics.mean(flow_data['packet_sizes'])
            std_packet_size = statistics.stdev(flow_data['packet_sizes']) if len(flow_data['packet_sizes']) > 1 else 0
            min_packet_size = min(flow_data['packet_sizes'])
            max_packet_size = max(flow_data['packet_sizes'])
        else:
            avg_packet_size = 0
            std_packet_size = 0
            min_packet_size = 0
            max_packet_size = 0

        # Calculate behavioral features
        is_internal_src = self._is_internal_ip(flow_data['src_ip'])
        is_internal_dst = self._is_internal_ip(flow_data['dst_ip'])
        is_well_known_port = (flow_data['dst_port'] in self.well_known_ports or
                             flow_data['src_port'] in self.well_known_ports)

        # Calculate port scan indicator
        unique_ports = len(set([flow_data['src_port'], flow_data['dst_port']]))
        port_scan_indicator = 1.0 if unique_ports > 10 and flow_data['packet_count'] < 50 else 0.0

        # Calculate SYN flood ratio
        syn_count = flow_data['tcp_flags_count'].get('S', 0)
        syn_flood_ratio = syn_count / flow_data['packet_count'] if flow_data['packet_count'] > 0 else 0

        # Calculate burstiness (coefficient of variation of inter-arrival times)
        if avg_inter_arrival > 0:
            burstiness = std_inter_arrival / avg_inter_arrival
        else:
            burstiness = 0

        # Calculate regularity (inverse of burstiness)
        regularity = 1.0 / (1.0 + burstiness)

        # Create flow features object
        flow_features = FlowFeatures(
            flow_key=flow_key,
            src_ip=flow_data['src_ip'],
            dst_ip=flow_data['dst_ip'],
            src_port=flow_data['src_port'],
            dst_port=flow_data['dst_port'],
            protocol=flow_data['protocol'],

            # Basic features
            packet_count=flow_data['packet_count'],
            byte_count=flow_data['byte_count'],
            duration=duration,
            start_time=flow_data['start_time'],
            end_time=flow_data['end_time'],

            # Temporal features
            packets_per_second=packets_per_second,
            bytes_per_second=bytes_per_second,
            avg_inter_arrival_time=avg_inter_arrival,
            std_inter_arrival_time=std_inter_arrival,

            # Packet size features
            avg_packet_size=avg_packet_size,
            std_packet_size=std_packet_size,
            min_packet_size=min_packet_size,
            max_packet_size=max_packet_size,

            # Directional features
            src_to_dst_packets=flow_data['src_to_dst_packets'],
            dst_to_src_packets=flow_data['dst_to_src_packets'],
            src_to_dst_bytes=flow_data['src_to_dst_bytes'],
            dst_to_src_bytes=flow_data['dst_to_src_bytes'],

            # Protocol-specific features
            tcp_flags_count=dict(flow_data['tcp_flags_count']),
            icmp_types_count=dict(flow_data['icmp_types_count']),

            # Behavioral features
            is_internal_src=is_internal_src,
            is_internal_dst=is_internal_dst,
            is_well_known_port=is_well_known_port,
            port_scan_indicator=port_scan_indicator,
            syn_flood_ratio=syn_flood_ratio,

            # Statistical features
            burstiness=burstiness,
            regularity=regularity
        )

        # Move to completed flows
        self.completed_flows.append(flow_features)
        del self.active_flows[flow_key]

        return flow_features

    def _finalize_window(self) -> WindowFeatures:
        """Finalize current time window and extract features"""
        window = self.current_window

        # Calculate window duration
        window_duration = window['end_time'] - window['start_time']

        # Calculate basic traffic features
        total_packets = len(window['packets'])
        total_bytes = sum(p['packet_size'] for p in window['packets'])

        # Calculate unique entities
        unique_sources = len(window['unique_sources'])
        unique_destinations = len(window['unique_destinations'])
        unique_ports = len(window['unique_ports'])

        # Calculate protocol distribution
        protocol_ratios = {}
        if total_packets > 0:
            for protocol, count in window['protocol_counts'].items():
                protocol_ratios[protocol] = count / total_packets

        # Calculate traffic patterns
        new_flows_per_second = len(window['flows']) / window_duration if window_duration > 0 else 0

        # Calculate average flow duration from completed flows
        avg_flow_duration = 0
        if self.completed_flows:
            recent_flows = [f for f in self.completed_flows if f.end_time >= window['start_time']]
            if recent_flows:
                avg_flow_duration = statistics.mean([f.duration for f in recent_flows])

        # Calculate flow diversity (unique flows per packet)
        flow_diversity = len(window['flows']) / total_packets if total_packets > 0 else 0

        # Calculate anomaly scores
        port_scan_score = self._calculate_port_scan_score(window)
        dos_score = self._calculate_dos_score(window)
        data_exfiltration_score = self._calculate_data_exfiltration_score(window)
        unusual_protocol_score = self._calculate_unusual_protocol_score(window)

        # Create window features object
        window_features = WindowFeatures(
            window_start=window['start_time'],
            window_end=window['end_time'],
            window_duration=window_duration,

            # Aggregate traffic features
            total_packets=total_packets,
            total_bytes=total_bytes,
            unique_sources=unique_sources,
            unique_destinations=unique_destinations,
            unique_ports=unique_ports,

            # Protocol distribution
            protocol_ratios=protocol_ratios,

            # Traffic patterns
            new_flows_per_second=new_flows_per_second,
            avg_flow_duration=avg_flow_duration,
            flow_diversity=flow_diversity,

            # Anomaly indicators
            port_scan_score=port_scan_score,
            dos_score=dos_score,
            data_exfiltration_score=data_exfiltration_score,
            unusual_protocol_score=unusual_protocol_score
        )

        # Add to history and reset current window
        self.window_history.append(window_features)
        self._initialize_tracking()

        return window_features

    def _calculate_port_scan_score(self, window: Dict[str, Any]) -> float:
        """Calculate port scan detection score"""
        if not window['port_scan_candidates']:
            return 0.0

        # Group by source IP
        src_ip_groups = defaultdict(list)
        for dst_ip_port, count in window['port_scan_candidates'].items():
            parts = dst_ip_port.split(':')
            if len(parts) == 2:
                dst_ip = parts[0]
                # We need to infer source IP from packets
                for packet in window['packets']:
                    if packet['dst_ip'] == dst_ip:
                        src_ip = packet['src_ip']
                        src_ip_groups[src_ip].append(int(parts[1]))
                        break

        # Calculate port scan score for each source IP
        max_score = 0.0
        for src_ip, ports in src_ip_groups.items():
            unique_ports = len(set(ports))
            if unique_ports > 10:
                score = min(unique_ports / 50.0, 1.0)  # Normalize to [0, 1]
                max_score = max(max_score, score)

        return max_score

    def _calculate_dos_score(self, window: Dict[str, Any]) -> float:
        """Calculate DoS attack detection score"""
        if not window['dos_candidates']:
            return 0.0

        # Calculate packet rate per destination
        window_duration = window['end_time'] - window['start_time']
        if window_duration == 0:
            return 0.0

        max_packets_per_second = 0
        for dst_ip, packet_count in window['dos_candidates'].items():
            packets_per_second = packet_count / window_duration
            max_packets_per_second = max(max_packets_per_second, packets_per_second)

        # Normalize score (high packet rate indicates potential DoS)
        if max_packets_per_second > 1000:  # Threshold for DoS
            return min(max_packets_per_second / 10000.0, 1.0)

        return 0.0

    def _calculate_data_exfiltration_score(self, window: Dict[str, Any]) -> float:
        """Calculate data exfiltration detection score"""
        if not window['packets']:
            return 0.0

        # Look for large outbound transfers from internal to external
        outbound_bytes = 0
        total_outbound_packets = 0

        for packet in window['packets']:
            if (packet.get('is_internal_src', False) and
                not packet.get('is_internal_dst', True)):
                outbound_bytes += packet['packet_size']
                total_outbound_packets += 1

        if total_outbound_packets == 0:
            return 0.0

        # Calculate average outbound packet size
        avg_outbound_size = outbound_bytes / total_outbound_packets

        # High outbound volume with large packets could indicate exfiltration
        if outbound_bytes > 10 * 1024 * 1024:  # 10MB threshold
            return min(outbound_bytes / (100 * 1024 * 1024), 1.0)  # Normalize to 100MB

        return 0.0

    def _calculate_unusual_protocol_score(self, window: Dict[str, Any]) -> float:
        """Calculate unusual protocol usage score"""
        total_packets = len(window['packets'])
        if total_packets == 0:
            return 0.0

        # Look for unusual protocol patterns
        unusual_indicators = 0

        # High ICMP usage (could be tunneling)
        icmp_ratio = window['protocol_counts'].get('ICMP', 0) / total_packets
        if icmp_ratio > 0.1:  # More than 10% ICMP
            unusual_indicators += 1

        # TCP with unusual flag combinations
        for packet in window['packets']:
            if packet['protocol'] == 'TCP':
                tcp_flags = packet.get('tcp_flags', [])
                # Check for Xmas scan, null scan, etc.
                if set(tcp_flags) in [{'F', 'P', 'U'}, set(), {'F'}]:
                    unusual_indicators += 1
                    break

        return min(unusual_indicators / 2.0, 1.0)

    def _get_flow_key(self, packet_info: PacketInfo) -> str:
        """Generate a unique flow key from packet information"""
        return f"{packet_info.src_ip}:{packet_info.src_port or 0}-{packet_info.dst_ip}:{packet_info.dst_port or 0}-{packet_info.protocol}"

    def _is_internal_ip(self, ip_str: str) -> bool:
        """Check if IP address is in internal network ranges"""
        try:
            ip = ipaddress.ip_address(ip_str)
            for network in self.internal_networks:
                if ip in network:
                    return True
            return False
        except ValueError:
            return False

    def _expire_oldest_flow(self):
        """Remove the oldest flow from tracking"""
        if self.active_flows:
            oldest_key = min(self.active_flows.keys(),
                           key=lambda k: self.active_flows[k]['start_time'])
            self._finalize_flow(oldest_key)

    def _cleanup_old_flows(self, current_time: float):
        """Remove flows that have exceeded timeout"""
        expired_flows = []

        for flow_key, flow_data in self.active_flows.items():
            if current_time - flow_data['end_time'] > self.flow_timeout:
                expired_flows.append(flow_key)

        for flow_key in expired_flows:
            self._finalize_flow(flow_key)

    def get_feature_vector(self, flow_features: FlowFeatures) -> List[float]:
        """
        Convert flow features to a numerical vector for ML processing

        Args:
            flow_features: Flow features object

        Returns:
            List of numerical features
        """
        vector = [
            # Basic features
            float(flow_features.packet_count),
            float(flow_features.byte_count),
            float(flow_features.duration),

            # Temporal features
            float(flow_features.packets_per_second),
            float(flow_features.bytes_per_second),
            float(flow_features.avg_inter_arrival_time),
            float(flow_features.std_inter_arrival_time),

            # Packet size features
            float(flow_features.avg_packet_size),
            float(flow_features.std_packet_size),
            float(flow_features.min_packet_size),
            float(flow_features.max_packet_size),

            # Directional features
            float(flow_features.src_to_dst_packets),
            float(flow_features.dst_to_src_packets),
            float(flow_features.src_to_dst_bytes),
            float(flow_features.dst_to_src_bytes),

            # Behavioral features
            float(1 if flow_features.is_internal_src else 0),
            float(1 if flow_features.is_internal_dst else 0),
            float(1 if flow_features.is_well_known_port else 0),
            float(flow_features.port_scan_indicator),
            float(flow_features.syn_flood_ratio),

            # Statistical features
            float(flow_features.burstiness),
            float(flow_features.regularity),
        ]

        # Add TCP flags (one-hot encoded)
        tcp_flags = ['S', 'A', 'F', 'R', 'P', 'U']
        for flag in tcp_flags:
            vector.append(float(flow_features.tcp_flags_count.get(flag, 0)))

        # Add protocol encoding (one-hot)
        protocols = ['TCP', 'UDP', 'ICMP']
        for protocol in protocols:
            vector.append(float(1 if flow_features.protocol == protocol else 0))

        return vector

    def get_feature_names(self) -> List[str]:
        """Get list of feature names for the feature vector"""
        names = [
            # Basic features
            'packet_count', 'byte_count', 'duration',

            # Temporal features
            'packets_per_second', 'bytes_per_second',
            'avg_inter_arrival_time', 'std_inter_arrival_time',

            # Packet size features
            'avg_packet_size', 'std_packet_size',
            'min_packet_size', 'max_packet_size',

            # Directional features
            'src_to_dst_packets', 'dst_to_src_packets',
            'src_to_dst_bytes', 'dst_to_src_bytes',

            # Behavioral features
            'is_internal_src', 'is_internal_dst', 'is_well_known_port',
            'port_scan_indicator', 'syn_flood_ratio',

            # Statistical features
            'burstiness', 'regularity',
        ]

        # TCP flags
        tcp_flags = ['S', 'A', 'F', 'R', 'P', 'U']
        for flag in tcp_flags:
            names.append(f'tcp_flag_{flag}')

        # Protocols
        protocols = ['TCP', 'UDP', 'ICMP']
        for protocol in protocols:
            names.append(f'protocol_{protocol}')

        return names

    def get_statistics(self) -> Dict[str, Any]:
        """Get current feature extraction statistics"""
        current_time = time.time()

        return {
            'active_flows': len(self.active_flows),
            'completed_flows': len(self.completed_flows),
            'window_count': len(self.window_history),
            'current_window_duration': current_time - self.current_window['start_time'],
            'current_window_packets': len(self.current_window['packets']),
            'memory_usage_estimate': len(self.active_flows) * 1000 +  # Rough estimate
                                   len(self.completed_flows) * 500 +
                                   len(self.window_history) * 2000
        }


# Global feature extractor instance
_traffic_feature_extractor_instance = None

def get_traffic_feature_extractor() -> TrafficFeatureExtractor:
    """Get or create the global traffic feature extractor instance"""
    global _traffic_feature_extractor_instance
    if _traffic_feature_extractor_instance is None:
        _traffic_feature_extractor_instance = TrafficFeatureExtractor()
    return _traffic_feature_extractor_instance

def cleanup_traffic_feature_extractor():
    """Cleanup the global traffic feature extractor instance"""
    global _traffic_feature_extractor_instance
    _traffic_feature_extractor_instance = None