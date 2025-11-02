"""
Protocol Analyzer Module
Performs deep packet inspection and protocol analysis
"""

import struct
import socket
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from collections import defaultdict, deque
from datetime import datetime, timedelta
import time

try:
    from scapy.all import IP, TCP, UDP, ICMP, ARP, DNS, Raw
    from scapy.layers.inet import TCP, UDP
    from scapy.layers.dns import DNSQR, DNSRR
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from .packet_capture import PacketInfo


@dataclass
class TCPConnection:
    """Represents a TCP connection state"""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    state: str
    start_time: float
    last_activity: float
    packet_count: int
    byte_count: int
    flags_seen: List[str]
    connection_duration: float = 0.0


@dataclass
class UDPSession:
    """Represents a UDP session"""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    start_time: float
    last_activity: float
    packet_count: int
    byte_count: int


@dataclass
class ICMPInfo:
    """ICMP packet analysis information"""
    type_code: str
    description: str
    is_ping: bool
    is_error: bool


@dataclass
class DNSInfo:
    """DNS query/response analysis"""
    query_type: str
    query_name: str
    response_code: str
    is_query: bool
    ttl: Optional[int] = None


class ProtocolAnalyzer:
    """
    Analyzes network protocols and tracks connection states
    """

    def __init__(self, connection_timeout: int = 300):
        """
        Initialize protocol analyzer

        Args:
            connection_timeout: Timeout in seconds for inactive connections
        """
        self.connection_timeout = connection_timeout
        self.tcp_connections: Dict[str, TCPConnection] = {}
        self.udp_sessions: Dict[str, UDPSession] = {}
        self.protocol_stats = defaultdict(int)
        self.port_usage = defaultdict(int)
        self.connection_history = deque(maxlen=1000)
        self.last_cleanup = time.time()

    def analyze_packet(self, packet_info: PacketInfo) -> Dict[str, Any]:
        """
        Analyze a packet and extract protocol-specific information

        Args:
            packet_info: Packet information from packet capture

        Returns:
            Dictionary with analysis results
        """
        analysis = {
            'protocol': packet_info.protocol,
            'timestamp': packet_info.timestamp,
            'basic_info': {
                'src_ip': packet_info.src_ip,
                'dst_ip': packet_info.dst_ip,
                'src_port': packet_info.src_port,
                'dst_port': packet_info.dst_port,
                'packet_size': packet_info.packet_size
            },
            'protocol_specific': {},
            'security_flags': []
        }

        if not SCAPY_AVAILABLE:
            return analysis

        try:
            # Analyze based on protocol
            if packet_info.protocol.upper() == 'TCP':
                analysis['protocol_specific'] = self._analyze_tcp(packet_info)
                self._update_tcp_connection(packet_info)

            elif packet_info.protocol.upper() == 'UDP':
                analysis['protocol_specific'] = self._analyze_udp(packet_info)
                self._update_udp_session(packet_info)

            elif packet_info.protocol.upper() == 'ICMP':
                analysis['protocol_specific'] = self._analyze_icmp(packet_info)

            # Check for security-relevant patterns
            analysis['security_flags'] = self._check_security_flags(packet_info, analysis)

            # Update statistics
            self._update_statistics(packet_info)

            # Periodic cleanup
            self._cleanup_old_connections()

        except Exception as e:
            print(f"Error analyzing packet: {e}")

        return analysis

    def _analyze_tcp(self, packet_info: PacketInfo) -> Dict[str, Any]:
        """Analyze TCP-specific information"""
        tcp_info = {}

        if not hasattr(packet_info, 'raw_packet') or not packet_info.raw_packet:
            return tcp_info

        try:
            packet = packet_info.raw_packet

            if TCP in packet:
                tcp = packet[TCP]
                tcp_info.update({
                    'flags': packet_info.flags,
                    'seq': tcp.seq,
                    'ack': tcp.ack,
                    'window': tcp.window,
                    'urgent': tcp.urgptr,
                    'options': len(tcp.options) if tcp.options else 0,
                    'payload_size': len(tcp.payload) if tcp.payload else 0,
                    'is_syn': 'S' in packet_info.flags,
                    'is_ack': 'A' in packet_info.flags,
                    'is_fin': 'F' in packet_info.flags,
                    'is_rst': 'R' in packet_info.flags,
                    'is_psh': 'P' in packet_info.flags,
                    'is_urg': 'U' in packet_info.flags
                })

                # TCP state analysis
                tcp_info['connection_state'] = self._determine_tcp_state(packet_info)

                # Check for common services
                tcp_info['service'] = self._identify_tcp_service(packet_info.dst_port)

                # TCP flags analysis
                tcp_info['flags_analysis'] = self._analyze_tcp_flags(packet_info.flags)

        except Exception as e:
            print(f"Error analyzing TCP packet: {e}")

        return tcp_info

    def _analyze_udp(self, packet_info: PacketInfo) -> Dict[str, Any]:
        """Analyze UDP-specific information"""
        udp_info = {}

        if not hasattr(packet_info, 'raw_packet') or not packet_info.raw_packet:
            return udp_info

        try:
            packet = packet_info.raw_packet

            if UDP in packet:
                udp = packet[UDP]
                udp_info.update({
                    'payload_size': len(udp.payload) if udp.payload else 0,
                    'length': udp.len,
                    'checksum': udp.chksum,
                    'service': self._identify_udp_service(packet_info.dst_port)
                })

                # DNS analysis
                if DNS in packet:
                    udp_info['dns'] = self._analyze_dns(packet[DNS])

        except Exception as e:
            print(f"Error analyzing UDP packet: {e}")

        return udp_info

    def _analyze_icmp(self, packet_info: PacketInfo) -> Dict[str, Any]:
        """Analyze ICMP-specific information"""
        icmp_info = {}

        if not hasattr(packet_info, 'raw_packet') or not packet_info.raw_packet:
            return icmp_info

        try:
            packet = packet_info.raw_packet

            if ICMP in packet:
                icmp = packet[ICMP]
                icmp_info.update({
                    'type': icmp.type,
                    'code': icmp.code,
                    'checksum': icmp.chksum,
                    'id': icmp.id if hasattr(icmp, 'id') else None,
                    'seq': icmp.seq if hasattr(icmp, 'seq') else None,
                    'description': self._get_icmp_description(icmp.type, icmp.code),
                    'is_ping': icmp.type == 8 and icmp.code == 0,  # Echo request
                    'is_ping_reply': icmp.type == 0 and icmp.code == 0,  # Echo reply
                    'is_error': icmp.type in [3, 4, 5, 11, 12],  # Error messages
                    'payload_size': len(icmp.payload) if icmp.payload else 0
                })

        except Exception as e:
            print(f"Error analyzing ICMP packet: {e}")

        return icmp_info

    def _analyze_dns(self, dns_packet) -> Dict[str, Any]:
        """Analyze DNS query/response information"""
        dns_info = {}

        try:
            dns_info.update({
                'id': dns_packet.id,
                'qr': dns_packet.qr,  # Query (0) or Response (1)
                'opcode': dns_packet.opcode,
                'aa': dns_packet.aa,  # Authoritative Answer
                'tc': dns_packet.tc,  # Truncated
                'rd': dns_packet.rd,  # Recursion Desired
                'ra': dns_packet.ra,  # Recursion Available
                'rcode': dns_packet.rcode,  # Response Code
                'qdcount': dns_packet.qdcount,  # Question Count
                'ancount': dns_packet.ancount,  # Answer Count
                'nscount': dns_packet.nscount,  # Authority Count
                'arcount': dns_packet.arcount,  # Additional Count
            })

            # Extract queries
            if dns_packet.qd:
                queries = []
                for qd in dns_packet.qd:
                    queries.append({
                        'qname': qd.qname.decode('utf-8') if isinstance(qd.qname, bytes) else str(qd.qname),
                        'qtype': qd.qtype,
                        'qclass': qd.qclass
                    })
                dns_info['queries'] = queries

            # Extract answers
            if dns_packet.an:
                answers = []
                for an in dns_packet.an:
                    answers.append({
                        'rrname': an.rrname.decode('utf-8') if isinstance(an.rrname, bytes) else str(an.rrname),
                        'type': an.type,
                        'rclass': an.rclass,
                        'ttl': an.ttl,
                        'rdata': str(an.rdata)
                    })
                dns_info['answers'] = answers

        except Exception as e:
            print(f"Error analyzing DNS packet: {e}")

        return dns_info

    def _update_tcp_connection(self, packet_info: PacketInfo):
        """Update TCP connection state tracking"""
        if not packet_info.src_port or not packet_info.dst_port:
            return

        # Create connection key (sorted to handle both directions)
        conn_key = self._get_connection_key(packet_info.src_ip, packet_info.src_port,
                                           packet_info.dst_ip, packet_info.dst_port, 'tcp')

        current_time = packet_info.timestamp

        if conn_key in self.tcp_connections:
            # Update existing connection
            conn = self.tcp_connections[conn_key]
            conn.last_activity = current_time
            conn.packet_count += 1
            conn.byte_count += packet_info.packet_size
            conn.connection_duration = current_time - conn.start_time

            # Update flags seen
            for flag in packet_info.flags:
                if flag not in conn.flags_seen:
                    conn.flags_seen.append(flag)

            # Update state
            conn.state = self._determine_tcp_state(packet_info)
        else:
            # Create new connection
            self.tcp_connections[conn_key] = TCPConnection(
                src_ip=packet_info.src_ip,
                dst_ip=packet_info.dst_ip,
                src_port=packet_info.src_port,
                dst_port=packet_info.dst_port,
                state=self._determine_tcp_state(packet_info),
                start_time=current_time,
                last_activity=current_time,
                packet_count=1,
                byte_count=packet_info.packet_size,
                flags_seen=packet_info.flags.copy()
            )

    def _update_udp_session(self, packet_info: PacketInfo):
        """Update UDP session tracking"""
        if not packet_info.src_port or not packet_info.dst_port:
            return

        session_key = self._get_connection_key(packet_info.src_ip, packet_info.src_port,
                                              packet_info.dst_ip, packet_info.dst_port, 'udp')

        current_time = packet_info.timestamp

        if session_key in self.udp_sessions:
            # Update existing session
            session = self.udp_sessions[session_key]
            session.last_activity = current_time
            session.packet_count += 1
            session.byte_count += packet_info.packet_size
        else:
            # Create new session
            self.udp_sessions[session_key] = UDPSession(
                src_ip=packet_info.src_ip,
                dst_ip=packet_info.dst_ip,
                src_port=packet_info.src_port,
                dst_port=packet_info.dst_port,
                start_time=current_time,
                last_activity=current_time,
                packet_count=1,
                byte_count=packet_info.packet_size
            )

    def _get_connection_key(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: str) -> str:
        """Generate a unique key for a connection/session"""
        # Sort IPs to handle both directions of the same connection
        if (src_ip, src_port) < (dst_ip, dst_port):
            return f"{protocol}:{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        else:
            return f"{protocol}:{dst_ip}:{dst_port}-{src_ip}:{src_port}"

    def _determine_tcp_state(self, packet_info: PacketInfo) -> str:
        """Determine TCP connection state based on flags"""
        flags = set(packet_info.flags)

        if 'S' in flags and 'A' not in flags:
            return 'SYN_SENT'
        elif 'S' in flags and 'A' in flags:
            return 'SYN_RECEIVED'
        elif 'F' in flags and 'A' in flags:
            return 'CLOSED'
        elif 'R' in flags:
            return 'RESET'
        elif 'A' in flags:
            return 'ESTABLISHED'
        else:
            return 'UNKNOWN'

    def _identify_tcp_service(self, port: int) -> str:
        """Identify common TCP services by port number"""
        tcp_services = {
            20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'TELNET',
            25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
            143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S',
            3389: 'RDP', 5432: 'POSTGRESQL', 3306: 'MYSQL',
            6379: 'REDIS', 27017: 'MONGODB'
        }
        return tcp_services.get(port, f'UNKNOWN-{port}')

    def _identify_udp_service(self, port: int) -> str:
        """Identify common UDP services by port number"""
        udp_services = {
            53: 'DNS', 67: 'DHCP-SERVER', 68: 'DHCP-CLIENT',
            123: 'NTP', 161: 'SNMP', 500: 'IPSEC-IKE',
            514: 'SYSLOG', 4500: 'IPSEC-NAT-T'
        }
        return udp_services.get(port, f'UNKNOWN-{port}')

    def _analyze_tcp_flags(self, flags: List[str]) -> Dict[str, Any]:
        """Analyze TCP flags for suspicious patterns"""
        flag_analysis = {
            'is_scan': False,
            'is_xmas_scan': False,
            'is_null_scan': False,
            'is_fin_scan': False,
            'scan_type': None
        }

        flag_set = set(flags)

        # Xmas scan (FIN, PSH, URG set)
        if {'F', 'P', 'U'}.issubset(flag_set) and 'A' not in flag_set:
            flag_analysis['is_xmas_scan'] = True
            flag_analysis['is_scan'] = True
            flag_analysis['scan_type'] = 'XMAS'

        # Null scan (no flags set)
        if len(flag_set) == 0:
            flag_analysis['is_null_scan'] = True
            flag_analysis['is_scan'] = True
            flag_analysis['scan_type'] = 'NULL'

        # FIN scan (only FIN flag set)
        if flag_set == {'F'}:
            flag_analysis['is_fin_scan'] = True
            flag_analysis['is_scan'] = True
            flag_analysis['scan_type'] = 'FIN'

        return flag_analysis

    def _get_icmp_description(self, icmp_type: int, icmp_code: int) -> str:
        """Get human-readable description for ICMP type and code"""
        icmp_types = {
            0: "Echo Reply",
            3: "Destination Unreachable",
            4: "Source Quench",
            5: "Redirect",
            8: "Echo Request",
            11: "Time Exceeded",
            12: "Parameter Problem",
            13: "Timestamp Request",
            14: "Timestamp Reply",
            15: "Information Request",
            16: "Information Reply"
        }

        type_desc = icmp_types.get(icmp_type, f"Type {icmp_type}")

        # Add code-specific information for common types
        if icmp_type == 3:  # Destination Unreachable
            codes = {
                0: "Network Unreachable",
                1: "Host Unreachable",
                2: "Protocol Unreachable",
                3: "Port Unreachable",
                4: "Fragmentation Needed",
                5: "Source Route Failed"
            }
            code_desc = codes.get(icmp_code, f"Code {icmp_code}")
            return f"{type_desc} - {code_desc}"

        return type_desc

    def _check_security_flags(self, packet_info: PacketInfo, analysis: Dict[str, Any]) -> List[str]:
        """Check for security-relevant patterns in the packet"""
        security_flags = []

        # Check for TCP scan patterns
        if packet_info.protocol.upper() == 'TCP':
            protocol_specific = analysis.get('protocol_specific', {})
            flags_analysis = protocol_specific.get('flags_analysis', {})

            if flags_analysis.get('is_scan'):
                security_flags.append(f"TCP_SCAN_{flags_analysis.get('scan_type', 'UNKNOWN')}")

        # Check for unusual ports
        if packet_info.dst_port and packet_info.dst_port > 1024:
            security_flags.append("HIGH_PORT")

        # Check for ICMP tunneling
        if packet_info.protocol.upper() == 'ICMP':
            protocol_specific = analysis.get('protocol_specific', {})
            if protocol_specific.get('payload_size', 0) > 64:
                security_flags.append("ICMP_TUNNEL")

        # Check for DNS anomalies
        if packet_info.protocol.upper() == 'UDP':
            protocol_specific = analysis.get('protocol_specific', {})
            if 'dns' in protocol_specific:
                dns = protocol_specific['dns']
                if dns.get('rcode') not in [0, 3]:  # Non-standard response codes
                    security_flags.append("DNS_ANOMALY")

        return security_flags

    def _update_statistics(self, packet_info: PacketInfo):
        """Update protocol usage statistics"""
        self.protocol_stats[packet_info.protocol.upper()] += 1

        if packet_info.src_port:
            self.port_usage[packet_info.src_port] += 1
        if packet_info.dst_port:
            self.port_usage[packet_info.dst_port] += 1

    def _cleanup_old_connections(self):
        """Remove inactive connections and sessions"""
        current_time = time.time()

        # Only cleanup periodically to avoid performance impact
        if current_time - self.last_cleanup < 60:  # Cleanup every minute
            return

        self.last_cleanup = current_time

        # Cleanup TCP connections
        expired_tcp = [
            key for key, conn in self.tcp_connections.items()
            if current_time - conn.last_activity > self.connection_timeout
        ]

        for key in expired_tcp:
            conn = self.tcp_connections[key]
            self.connection_history.append(conn)
            del self.tcp_connections[key]

        # Cleanup UDP sessions
        expired_udp = [
            key for key, session in self.udp_sessions.items()
            if current_time - session.last_activity > self.connection_timeout
        ]

        for key in expired_udp:
            del self.udp_sessions[key]

    def get_connection_stats(self) -> Dict[str, Any]:
        """Get current connection statistics"""
        current_time = time.time()

        # TCP connection stats
        tcp_stats = {
            'total_connections': len(self.tcp_connections),
            'established': len([c for c in self.tcp_connections.values() if c.state == 'ESTABLISHED']),
            'connecting': len([c for c in self.tcp_connections.values() if c.state in ['SYN_SENT', 'SYN_RECEIVED']]),
            'closing': len([c for c in self.tcp_connections.values() if c.state in ['CLOSED', 'RESET']]),
        }

        # Calculate average connection duration
        if self.tcp_connections:
            total_duration = sum(
                current_time - conn.start_time for conn in self.tcp_connections.values()
            )
            tcp_stats['avg_duration'] = total_duration / len(self.tcp_connections)
        else:
            tcp_stats['avg_duration'] = 0

        # UDP session stats
        udp_stats = {
            'total_sessions': len(self.udp_sessions),
        }

        if self.udp_sessions:
            total_packets = sum(session.packet_count for session in self.udp_sessions.values())
            udp_stats['avg_packets_per_session'] = total_packets / len(self.udp_sessions)
        else:
            udp_stats['avg_packets_per_session'] = 0

        return {
            'tcp': tcp_stats,
            'udp': udp_stats,
            'protocol_distribution': dict(self.protocol_stats),
            'top_ports': dict(sorted(self.port_usage.items(), key=lambda x: x[1], reverse=True)[:10]),
            'connection_history_size': len(self.connection_history)
        }

    def get_active_connections(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get list of currently active connections"""
        connections = []

        # TCP connections
        for conn in list(self.tcp_connections.values())[:limit]:
            connections.append({
                'protocol': 'TCP',
                'src_ip': conn.src_ip,
                'dst_ip': conn.dst_ip,
                'src_port': conn.src_port,
                'dst_port': conn.dst_port,
                'state': conn.state,
                'duration': time.time() - conn.start_time,
                'packet_count': conn.packet_count,
                'byte_count': conn.byte_count,
                'last_activity': time.time() - conn.last_activity
            })

        # UDP sessions
        for session in list(self.udp_sessions.values())[:limit - len(connections)]:
            connections.append({
                'protocol': 'UDP',
                'src_ip': session.src_ip,
                'dst_ip': session.dst_ip,
                'src_port': session.src_port,
                'dst_port': session.dst_port,
                'state': 'ACTIVE',
                'duration': time.time() - session.start_time,
                'packet_count': session.packet_count,
                'byte_count': session.byte_count,
                'last_activity': time.time() - session.last_activity
            })

        # Sort by last activity (most recent first)
        connections.sort(key=lambda x: x['last_activity'])

        return connections[:limit]


# Global protocol analyzer instance
_protocol_analyzer_instance = None

def get_protocol_analyzer() -> ProtocolAnalyzer:
    """Get or create the global protocol analyzer instance"""
    global _protocol_analyzer_instance
    if _protocol_analyzer_instance is None:
        _protocol_analyzer_instance = ProtocolAnalyzer()
    return _protocol_analyzer_instance

def cleanup_protocol_analyzer():
    """Cleanup the global protocol analyzer instance"""
    global _protocol_analyzer_instance
    _protocol_analyzer_instance = None