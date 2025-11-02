"""
Network Packet Capture Module
Handles real-time packet capture and basic analysis using Scapy
"""

import threading
import time
from collections import deque
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, get_if_list, conf
    from scapy.layers.inet import Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available. Packet capture will be disabled.")

from ..config.settings import get_config


@dataclass
class PacketInfo:
    """Data class for packet information"""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    packet_size: int
    payload_size: int
    flags: List[str]
    ttl: int
    raw_packet: Any


class PacketCapture:
    """
    Real-time packet capture and buffering system
    """

    def __init__(self, interface: Optional[str] = None, buffer_size: int = 1000):
        """
        Initialize packet capture

        Args:
            interface: Network interface to monitor (auto-detect if None)
            buffer_size: Number of packets to keep in memory buffer
        """
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is required for packet capture")

        self.config = get_config()
        self.interface = interface or self._get_default_interface()
        self.buffer_size = buffer_size
        self.packet_buffer = deque(maxlen=buffer_size)
        self.is_capturing = False
        self.capture_thread = None
        self.packet_handlers: List[Callable[[PacketInfo], None]] = []
        self.stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'arp_packets': 0,
            'bytes_captured': 0,
            'start_time': None,
            'capture_rate': 0.0
        }

    def _get_default_interface(self) -> str:
        """Get the default network interface"""
        try:
            interfaces = get_if_list()
            # Try to find a non-loopback interface
            for iface in interfaces:
                if not iface.startswith('lo') and not iface.startswith('docker'):
                    return iface
            return interfaces[0] if interfaces else 'eth0'
        except Exception:
            return 'eth0'

    def add_packet_handler(self, handler: Callable[[PacketInfo], None]):
        """Add a callback function to handle captured packets"""
        self.packet_handlers.append(handler)

    def remove_packet_handler(self, handler: Callable[[PacketInfo], None]):
        """Remove a packet handler callback"""
        if handler in self.packet_handlers:
            self.packet_handlers.remove(handler)

    def _packet_handler(self, packet):
        """Internal packet processing handler"""
        try:
            # Extract basic packet information
            packet_info = self._extract_packet_info(packet)

            if packet_info:
                # Add to buffer
                self.packet_buffer.append(packet_info)

                # Update statistics
                self._update_stats(packet_info)

                # Call registered handlers
                for handler in self.packet_handlers:
                    try:
                        handler(packet_info)
                    except Exception as e:
                        print(f"Error in packet handler: {e}")

        except Exception as e:
            print(f"Error processing packet: {e}")

    def _extract_packet_info(self, packet) -> Optional[PacketInfo]:
        """Extract relevant information from a packet"""
        try:
            timestamp = time.time()

            # Default values
            src_ip = dst_ip = "unknown"
            src_port = dst_port = None
            protocol = "unknown"
            packet_size = len(packet)
            payload_size = 0
            flags = []
            ttl = 0

            # Extract IP layer information
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                ttl = packet[IP].ttl
                payload_size = len(packet[IP].payload)

                # Check for TCP
                if TCP in packet:
                    protocol = "TCP"
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    flags = [str(flag) for flag in packet[TCP].flags]

                # Check for UDP
                elif UDP in packet:
                    protocol = "UDP"
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport

                # Check for ICMP
                elif ICMP in packet:
                    protocol = "ICMP"

            # Check for ARP
            elif ARP in packet:
                protocol = "ARP"
                src_ip = packet[ARP].psrc
                dst_ip = packet[ARP].pdst

            return PacketInfo(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                packet_size=packet_size,
                payload_size=payload_size,
                flags=flags,
                ttl=ttl,
                raw_packet=packet
            )

        except Exception as e:
            print(f"Error extracting packet info: {e}")
            return None

    def _update_stats(self, packet_info: PacketInfo):
        """Update capture statistics"""
        self.stats['total_packets'] += 1
        self.stats['bytes_captured'] += packet_info.packet_size

        # Protocol-specific stats
        protocol = packet_info.protocol.upper()
        if protocol == 'TCP':
            self.stats['tcp_packets'] += 1
        elif protocol == 'UDP':
            self.stats['udp_packets'] += 1
        elif protocol == 'ICMP':
            self.stats['icmp_packets'] += 1
        elif protocol == 'ARP':
            self.stats['arp_packets'] += 1

        # Calculate capture rate
        if self.stats['start_time']:
            elapsed = time.time() - self.stats['start_time']
            if elapsed > 0:
                self.stats['capture_rate'] = self.stats['total_packets'] / elapsed

    def start_capture(self, packet_filter: Optional[str] = None):
        """
        Start packet capture in a separate thread

        Args:
            packet_filter: BPF filter string (e.g., "tcp port 80")
        """
        if self.is_capturing:
            print("Packet capture is already running")
            return

        self.is_capturing = True
        self.stats['start_time'] = time.time()

        def capture_worker():
            try:
                print(f"Starting packet capture on interface: {self.interface}")
                if packet_filter:
                    print(f"Using filter: {packet_filter}")

                # Configure scapy settings
                conf.sniff_promisc = self.config.get('network.promiscuous_mode', True)

                sniff(
                    iface=self.interface,
                    prn=self._packet_handler,
                    filter=packet_filter,
                    store=False,  # Don't store packets in memory
                    stop_filter=lambda x: not self.is_capturing
                )

            except Exception as e:
                print(f"Error in packet capture: {e}")
                self.is_capturing = False

        self.capture_thread = threading.Thread(target=capture_worker, daemon=True)
        self.capture_thread.start()

        # Wait a moment to ensure capture starts
        time.sleep(0.1)

    def stop_capture(self):
        """Stop packet capture"""
        if not self.is_capturing:
            return

        print("Stopping packet capture...")
        self.is_capturing = False

        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=2.0)

        print("Packet capture stopped")

    def get_recent_packets(self, count: int = 100) -> List[PacketInfo]:
        """
        Get the most recent packets from the buffer

        Args:
            count: Number of packets to retrieve

        Returns:
            List of recent PacketInfo objects
        """
        return list(self.packet_buffer)[-count:]

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get current capture statistics

        Returns:
            Dictionary containing capture statistics
        """
        stats = self.stats.copy()

        # Add additional computed statistics
        if stats['total_packets'] > 0:
            stats['tcp_percentage'] = (stats['tcp_packets'] / stats['total_packets']) * 100
            stats['udp_percentage'] = (stats['udp_packets'] / stats['total_packets']) * 100
            stats['icmp_percentage'] = (stats['icmp_packets'] / stats['total_packets']) * 100
            stats['arp_percentage'] = (stats['arp_packets'] / stats['total_packets']) * 100
        else:
            stats['tcp_percentage'] = 0
            stats['udp_percentage'] = 0
            stats['icmp_percentage'] = 0
            stats['arp_percentage'] = 0

        # Add buffer status
        stats['buffer_usage'] = len(self.packet_buffer)
        stats['buffer_capacity'] = self.buffer_size
        stats['buffer_percentage'] = (len(self.packet_buffer) / self.buffer_size) * 100

        # Add uptime
        if stats['start_time']:
            stats['uptime_seconds'] = time.time() - stats['start_time']
        else:
            stats['uptime_seconds'] = 0

        return stats

    def clear_buffer(self):
        """Clear the packet buffer"""
        self.packet_buffer.clear()

    def is_running(self) -> bool:
        """Check if packet capture is currently running"""
        return self.is_capturing

    def get_interface_info(self) -> Dict[str, Any]:
        """
        Get information about available network interfaces

        Returns:
            Dictionary with interface information
        """
        try:
            interfaces = get_if_list()
            return {
                'current_interface': self.interface,
                'available_interfaces': interfaces,
                'interface_count': len(interfaces)
            }
        except Exception as e:
            return {
                'current_interface': self.interface,
                'available_interfaces': [self.interface],
                'interface_count': 1,
                'error': str(e)
            }


# Global packet capture instance
_packet_capture_instance = None

def get_packet_capture() -> PacketCapture:
    """Get or create the global packet capture instance"""
    global _packet_capture_instance
    if _packet_capture_instance is None:
        _packet_capture_instance = PacketCapture()
    return _packet_capture_instance

def cleanup_packet_capture():
    """Cleanup the global packet capture instance"""
    global _packet_capture_instance
    if _packet_capture_instance:
        _packet_capture_instance.stop_capture()
        _packet_capture_instance = None