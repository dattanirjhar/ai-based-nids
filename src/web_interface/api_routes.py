"""
API Routes Module
RESTful API endpoints for NIDS management and data access
"""

import os
import sys
import time
import json
import logging
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify, send_file
from functools import wraps

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.config.settings import get_config
from src.config.models import APIResponse, PaginatedResponse
from src.alert_system.log_manager import get_log_manager
from src.network_monitor.packet_capture import get_packet_capture
from src.network_monitor.protocol_analyzer import get_protocol_analyzer
from src.ml_detection.anomaly_detector import get_anomaly_detector
from src.ml_detection.signature_engine import get_signature_engine
from src.ml_detection.model_trainer import get_model_trainer
from src.alert_system.alert_manager import get_alert_manager
from src.alert_system.notification_handlers import get_notification_manager

# Create Blueprint
api_bp = Blueprint('api', __name__, url_prefix='/api')

# Initialize logger
logger = logging.getLogger(__name__)

# Global components
components = {}


def initialize_api_components():
    """Initialize API components"""
    global components
    try:
        components.update({
            'log_manager': get_log_manager(),
            'packet_capture': get_packet_capture(),
            'protocol_analyzer': get_protocol_analyzer(),
            'anomaly_detector': get_anomaly_detector(),
            'signature_engine': get_signature_engine(),
            'model_trainer': get_model_trainer(),
            'alert_manager': get_alert_manager(),
            'notification_manager': get_notification_manager()
        })
        logger.info("API components initialized successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize API components: {e}")
        return False


def require_component(component_name):
    """Decorator to ensure component is available"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if component_name not in components:
                return jsonify(APIResponse(
                    success=False,
                    message=f"{component_name} not available"
                ).dict()), 503
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def validate_json_fields(required_fields):
    """Decorator to validate required JSON fields"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            data = request.get_json()
            if not data:
                return jsonify(APIResponse(
                    success=False,
                    message="No JSON data provided"
                ).dict()), 400

            missing_fields = [field for field in required_fields if field not in data]
            if missing_fields:
                return jsonify(APIResponse(
                    success=False,
                    message=f"Missing required fields: {', '.join(missing_fields)}"
                ).dict()), 400

            return f(*args, **kwargs)
        return decorated_function
    return decorator


# Health and Status endpoints
@api_bp.route('/health')
def health_check():
    """System health check"""
    try:
        component_status = {}
        for name, component in components.items():
            try:
                if hasattr(component, 'is_running'):
                    component_status[name] = component.is_running()
                elif hasattr(component, 'is_initialized'):
                    component_status[name] = component.is_initialized
                else:
                    component_status[name] = 'active'
            except:
                component_status[name] = 'error'

        return jsonify(APIResponse(
            success=True,
            message="System is healthy",
            data={
                'status': 'healthy',
                'timestamp': time.time(),
                'components': component_status,
                'uptime': time.time() - getattr(health_check, 'start_time', time.time())
            }
        ).dict())

    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify(APIResponse(
            success=False,
            message="Health check failed",
            error=str(e)
        ).dict()), 500


@api_bp.route('/status')
def get_system_status():
    """Get detailed system status"""
    try:
        status = {
            'timestamp': time.time(),
            'components': {}
        }

        # Packet capture status
        if 'packet_capture' in components:
            pc = components['packet_capture']
            status['components']['packet_capture'] = {
                'is_capturing': pc.is_running(),
                'interface': pc.interface,
                'buffer_usage': len(pc.packet_buffer),
                'buffer_capacity': pc.buffer_size,
                'statistics': pc.get_statistics()
            }

        # Alert system status
        if 'alert_manager' in components:
            am = components['alert_manager']
            stats = am.get_statistics()
            status['components']['alert_system'] = stats.__dict__

        # ML models status
        if 'anomaly_detector' in components:
            ad = components['anomaly_detector']
            status['components']['anomaly_detector'] = ad.get_detector_status()

        # Signature engine status
        if 'signature_engine' in components:
            se = components['signature_engine']
            status['components']['signature_engine'] = se.get_statistics()

        return jsonify(APIResponse(
            success=True,
            message="System status retrieved",
            data=status
        ).dict())

    except Exception as e:
        logger.error(f"Error getting system status: {e}")
        return jsonify(APIResponse(
            success=False,
            message="Failed to get system status",
            error=str(e)
        ).dict()), 500


# Alert management endpoints
@api_bp.route('/alerts')
@require_component('alert_manager')
def get_alerts():
    """Get alerts with filtering and pagination"""
    try:
        # Get query parameters
        status = request.args.get('status')
        priority = request.args.get('priority')
        attack_type = request.args.get('attack_type')
        source_ip = request.args.get('source_ip')
        limit = min(int(request.args.get('limit', 100)), 1000)
        offset = int(request.args.get('offset', 0))
        time_range = request.args.get('time_range')  # 1h, 6h, 24h, 7d, 30d

        alert_manager = components['alert_manager']

        # Convert filters
        status_filter = None
        if status:
            from src.alert_system.alert_manager import AlertStatus
            status_filter = AlertStatus(status.upper())

        priority_filter = None
        if priority:
            from src.alert_system.alert_manager import AlertPriority
            priority_filter = AlertPriority(priority.upper())

        # Get alerts
        alerts = alert_manager.get_alerts(
            status=status_filter,
            priority=priority_filter,
            limit=limit,
            offset=offset
        )

        # Apply additional filters
        if attack_type:
            alerts = [a for a in alerts if a.attack_type == attack_type.lower()]

        if source_ip:
            alerts = [a for a in alerts if a.source_ip == source_ip]

        # Convert to dictionary format
        alert_data = [alert.to_dict() for alert in alerts]

        # Get total count (approximate)
        total_alerts = len(alert_manager.alerts)

        return jsonify(APIResponse(
            success=True,
            message=f"Retrieved {len(alert_data)} alerts",
            data={
                'alerts': alert_data,
                'pagination': {
                    'total': total_alerts,
                    'limit': limit,
                    'offset': offset,
                    'has_more': offset + len(alert_data) < total_alerts
                }
            }
        ).dict())

    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        return jsonify(APIResponse(
            success=False,
            message="Failed to retrieve alerts",
            error=str(e)
        ).dict()), 500


@api_bp.route('/alerts/<alert_id>')
@require_component('alert_manager')
def get_alert(alert_id):
    """Get specific alert by ID"""
    try:
        alert_manager = components['alert_manager']
        alert = alert_manager.get_alert_by_id(alert_id)

        if alert:
            return jsonify(APIResponse(
                success=True,
                message="Alert retrieved successfully",
                data=alert.to_dict()
            ).dict())
        else:
            return jsonify(APIResponse(
                success=False,
                message="Alert not found"
            ).dict()), 404

    except Exception as e:
        logger.error(f"Error getting alert {alert_id}: {e}")
        return jsonify(APIResponse(
            success=False,
            message="Failed to retrieve alert",
            error=str(e)
        ).dict()), 500


@api_bp.route('/alerts/<alert_id>/acknowledge', methods=['POST'])
@require_component('alert_manager')
@validate_json_fields([])
def acknowledge_alert(alert_id):
    """Acknowledge an alert"""
    try:
        data = request.get_json() or {}
        assigned_to = data.get('assigned_to')

        alert_manager = components['alert_manager']
        success = alert_manager.acknowledge_alert(alert_id, assigned_to)

        if success:
            return jsonify(APIResponse(
                success=True,
                message="Alert acknowledged successfully"
            ).dict())
        else:
            return jsonify(APIResponse(
                success=False,
                message="Failed to acknowledge alert"
            ).dict()), 400

    except Exception as e:
        logger.error(f"Error acknowledging alert {alert_id}: {e}")
        return jsonify(APIResponse(
            success=False,
            message="Failed to acknowledge alert",
            error=str(e)
        ).dict()), 500


@api_bp.route('/alerts/<alert_id>/resolve', methods=['POST'])
@require_component('alert_manager')
@validate_json_fields([])
def resolve_alert(alert_id):
    """Resolve an alert"""
    try:
        data = request.get_json() or {}
        notes = data.get('notes')

        alert_manager = components['alert_manager']
        success = alert_manager.resolve_alert(alert_id, notes)

        if success:
            return jsonify(APIResponse(
                success=True,
                message="Alert resolved successfully"
            ).dict())
        else:
            return jsonify(APIResponse(
                success=False,
                message="Failed to resolve alert"
            ).dict()), 400

    except Exception as e:
        logger.error(f"Error resolving alert {alert_id}: {e}")
        return jsonify(APIResponse(
            success=False,
            message="Failed to resolve alert",
            error=str(e)
        ).dict()), 500


@api_bp.route('/alerts/statistics')
@require_component('alert_manager')
def get_alert_statistics():
    """Get alert statistics"""
    try:
        alert_manager = components['alert_manager']
        stats = alert_manager.get_statistics()

        return jsonify(APIResponse(
            success=True,
            message="Alert statistics retrieved",
            data=stats.__dict__
        ).dict())

    except Exception as e:
        logger.error(f"Error getting alert statistics: {e}")
        return jsonify(APIResponse(
            success=False,
            message="Failed to get alert statistics",
            error=str(e)
        ).dict()), 500


# Network monitoring endpoints
@api_bp.route('/network/interfaces')
@require_component('packet_capture')
def get_network_interfaces():
    """Get available network interfaces"""
    try:
        packet_capture = components['packet_capture']
        interfaces = packet_capture.get_interface_info()

        return jsonify(APIResponse(
            success=True,
            message="Network interfaces retrieved",
            data=interfaces
        ).dict())

    except Exception as e:
        logger.error(f"Error getting network interfaces: {e}")
        return jsonify(APIResponse(
            success=False,
            message="Failed to get network interfaces",
            error=str(e)
        ).dict()), 500


@api_bp.route('/network/statistics')
@require_component('packet_capture')
def get_network_statistics():
    """Get network statistics"""
    try:
        packet_capture = components['packet_capture']
        stats = packet_capture.get_statistics()

        return jsonify(APIResponse(
            success=True,
            message="Network statistics retrieved",
            data=stats
        ).dict())

    except Exception as e:
        logger.error(f"Error getting network statistics: {e}")
        return jsonify(APIResponse(
            success=False,
            message="Failed to get network statistics",
            error=str(e)
        ).dict()), 500


@api_bp.route('/network/traffic')
@require_component('packet_capture')
def get_traffic_data():
    """Get recent traffic data"""
    try:
        count = min(int(request.args.get('count', 100)), 1000)
        protocol_filter = request.args.get('protocol')

        packet_capture = components['packet_capture']
        packets = packet_capture.get_recent_packets(count)

        # Apply protocol filter
        if protocol_filter:
            packets = [p for p in packets if p.protocol.upper() == protocol_filter.upper()]

        # Convert to dictionary format
        packet_data = []
        for packet in packets:
            packet_data.append({
                'timestamp': packet.timestamp,
                'src_ip': packet.src_ip,
                'dst_ip': packet.dst_ip,
                'src_port': packet.src_port,
                'dst_port': packet.dst_port,
                'protocol': packet.protocol,
                'packet_size': packet.packet_size,
                'payload_size': packet.payload_size,
                'flags': packet.flags,
                'ttl': packet.ttl
            })

        return jsonify(APIResponse(
            success=True,
            message=f"Retrieved {len(packet_data)} packets",
            data={
                'packets': packet_data,
                'count': len(packet_data)
            }
        ).dict())

    except Exception as e:
        logger.error(f"Error getting traffic data: {e}")
        return jsonify(APIResponse(
            success=False,
            message="Failed to get traffic data",
            error=str(e)
        ).dict()), 500


@api_bp.route('/network/connections')
@require_component('protocol_analyzer')
def get_active_connections():
    """Get active network connections"""
    try:
        limit = min(int(request.args.get('limit', 100)), 1000)

        protocol_analyzer = components['protocol_analyzer']
        connections = protocol_analyzer.get_active_connections(limit)

        return jsonify(APIResponse(
            success=True,
            message=f"Retrieved {len(connections)} connections",
            data={
                'connections': connections,
                'count': len(connections)
            }
        ).dict())

    except Exception as e:
        logger.error(f"Error getting connections: {e}")
        return jsonify(APIResponse(
            success=False,
            message="Failed to get connections",
            error=str(e)
        ).dict()), 500


# Machine learning endpoints
@api_bp.route('/ml/models')
@require_component('anomaly_detector')
def get_ml_models():
    """Get ML model information"""
    try:
        anomaly_detector = components['anomaly_detector']
        model_info = anomaly_detector.get_model_performance_summary()

        return jsonify(APIResponse(
            success=True,
            message="ML models information retrieved",
            data=model_info
        ).dict())

    except Exception as e:
        logger.error(f"Error getting ML models: {e}")
        return jsonify(APIResponse(
            success=False,
            message="Failed to get ML models",
            error=str(e)
        ).dict()), 500


@api_bp.route('/ml/anomalies')
@require_component('anomaly_detector')
def get_anomaly_detections():
    """Get recent anomaly detections"""
    try:
        count = min(int(request.args.get('count', 100)), 1000)
        anomaly_only = request.args.get('anomaly_only', 'true').lower() == 'true'

        anomaly_detector = components['anomaly_detector']
        detections = anomaly_detector.get_recent_detections(count, anomaly_only)

        # Convert to dictionary format
        detection_data = []
        for detection in detections:
            detection_data.append({
                'timestamp': detection.timestamp,
                'is_anomaly': detection.is_anomaly,
                'anomaly_score': detection.anomaly_score,
                'confidence': detection.confidence,
                'detection_method': detection.detection_method,
                'model_predictions': detection.model_predictions,
                'metadata': detection.metadata
            })

        return jsonify(APIResponse(
            success=True,
            message=f"Retrieved {len(detection_data)} detections",
            data={
                'detections': detection_data,
                'count': len(detection_data)
            }
        ).dict())

    except Exception as e:
        logger.error(f"Error getting anomaly detections: {e}")
        return jsonify(APIResponse(
            success=False,
            message="Failed to get anomaly detections",
            error=str(e)
        ).dict()), 500


@api_bp.route('/ml/train', methods=['POST'])
@require_component('model_trainer')
@validate_json_fields(['features', 'labels'])
def train_models():
    """Train ML models (simplified for demo)"""
    try:
        data = request.get_json()
        # In a real implementation, this would use actual training data
        # For now, return a success message

        return jsonify(APIResponse(
            success=True,
            message="Model training initiated (demo mode)",
            data={'status': 'training_started', 'estimated_time': '5-10 minutes'}
        ).dict())

    except Exception as e:
        logger.error(f"Error training models: {e}")
        return jsonify(APIResponse(
            success=False,
            message="Failed to train models",
            error=str(e)
        ).dict()), 500


# Signature engine endpoints
@api_bp.route('/signatures')
@require_component('signature_engine')
def get_signatures():
    """Get signature rules"""
    try:
        signature_engine = components['signature_engine']
        signatures = signature_engine.signatures

        # Convert to dictionary format
        signature_data = []
        for sig_id, signature in signatures.items():
            signature_data.append({
                'id': signature.id,
                'name': signature.name,
                'description': signature.description,
                'category': signature.category,
                'severity': signature.severity,
                'enabled': signature.enabled,
                'pattern_type': signature.pattern_type
            })

        return jsonify(APIResponse(
            success=True,
            message=f"Retrieved {len(signature_data)} signatures",
            data={
                'signatures': signature_data,
                'count': len(signature_data)
            }
        ).dict())

    except Exception as e:
        logger.error(f"Error getting signatures: {e}")
        return jsonify(APIResponse(
            success=False,
            message="Failed to get signatures",
            error=str(e)
        ).dict()), 500


@api_bp.route('/signatures/<signature_id>/enable', methods=['POST'])
@require_component('signature_engine')
def enable_signature(signature_id):
    """Enable a signature rule"""
    try:
        signature_engine = components['signature_engine']
        success = signature_engine.enable_signature(signature_id)

        if success:
            return jsonify(APIResponse(
                success=True,
                message="Signature enabled successfully"
            ).dict())
        else:
            return jsonify(APIResponse(
                success=False,
                message="Failed to enable signature"
            ).dict()), 400

    except Exception as e:
        logger.error(f"Error enabling signature {signature_id}: {e}")
        return jsonify(APIResponse(
            success=False,
            message="Failed to enable signature",
            error=str(e)
        ).dict()), 500


@api_bp.route('/signatures/<signature_id>/disable', methods=['POST'])
@require_component('signature_engine')
def disable_signature(signature_id):
    """Disable a signature rule"""
    try:
        signature_engine = components['signature_engine']
        success = signature_engine.disable_signature(signature_id)

        if success:
            return jsonify(APIResponse(
                success=True,
                message="Signature disabled successfully"
            ).dict())
        else:
            return jsonify(APIResponse(
                success=False,
                message="Failed to disable signature"
            ).dict()), 400

    except Exception as e:
        logger.error(f"Error disabling signature {signature_id}: {e}")
        return jsonify(APIResponse(
            success=False,
            message="Failed to disable signature",
            error=str(e)
        ).dict()), 500


# System management endpoints
@api_bp.route('/system/config')
def get_system_config():
    """Get system configuration"""
    try:
        config = get_config()
        web_config = config.get_section('web')
        network_config = config.get_section('network')
        ml_config = config.get_section('ml')

        # Hide sensitive information
        safe_config = {
            'web': {
                'host': web_config.get('host'),
                'port': web_config.get('port'),
                'debug': web_config.get('debug')
            },
            'network': {
                'interface': network_config.get('interface'),
                'promiscuous_mode': network_config.get('promiscuous_mode'),
                'packet_buffer_size': network_config.get('packet_buffer_size')
            },
            'ml': {
                'confidence_threshold': ml_config.get('detection', {}).get('confidence_threshold'),
                'ensemble_voting': ml_config.get('detection', {}).get('ensemble_voting')
            }
        }

        return jsonify(APIResponse(
            success=True,
            message="Configuration retrieved",
            data=safe_config
        ).dict())

    except Exception as e:
        logger.error(f"Error getting configuration: {e}")
        return jsonify(APIResponse(
            success=False,
            message="Failed to get configuration",
            error=str(e)
        ).dict()), 500


@api_bp.route('/system/logs')
@require_component('log_manager')
def get_system_logs():
    """Get system logs"""
    try:
        level = request.args.get('level')
        component = request.args.get('component')
        limit = min(int(request.args.get('limit', 1000)), 5000)
        query = request.args.get('query')

        log_manager = components['log_manager']
        logs = log_manager.search_logs(
            query=query or '',
            level=level,
            component=component,
            limit=limit
        )

        # Convert to dictionary format
        log_data = []
        for log in logs:
            log_data.append({
                'timestamp': log.timestamp,
                'level': log.level,
                'component': log.component,
                'message': log.message,
                'details': log.details,
                'source_ip': log.source_ip,
                'tags': log.tags
            })

        return jsonify(APIResponse(
            success=True,
            message=f"Retrieved {len(log_data)} log entries",
            data={
                'logs': log_data,
                'count': len(log_data)
            }
        ).dict())

    except Exception as e:
        logger.error(f"Error getting logs: {e}")
        return jsonify(APIResponse(
            success=False,
            message="Failed to get logs",
            error=str(e)
        ).dict()), 500


@api_bp.route('/system/export')
def export_system_data():
    """Export system data"""
    try:
        format_type = request.args.get('format', 'json')
        if format_type not in ['json', 'csv']:
            return jsonify(APIResponse(
                success=False,
                message="Unsupported export format"
            ).dict()), 400

        # Generate export file
        timestamp = int(time.time())
        filename = f"nids_export_{timestamp}.{format_type}"
        filepath = os.path.join('/tmp', filename)

        if 'alert_manager' in components:
            alert_manager = components['alert_manager']
            alert_manager.export_alerts(filepath, format_type)

        return send_from_directory('/tmp', filename, as_attachment=True)

    except Exception as e:
        logger.error(f"Error exporting data: {e}")
        return jsonify(APIResponse(
            success=False,
            message="Failed to export data",
            error=str(e)
        ).dict()), 500


# Notification endpoints
@api_bp.route('/notifications/test', methods=['POST'])
@require_component('notification_manager')
@validate_json_fields([])
def test_notifications():
    """Send test notification"""
    try:
        data = request.get_json() or {}
        channel = data.get('channel')  # Optional specific channel

        notification_manager = components['notification_manager']
        success = notification_manager.send_test_notification(channel)

        if success:
            return jsonify(APIResponse(
                success=True,
                message="Test notification sent successfully"
            ).dict())
        else:
            return jsonify(APIResponse(
                success=False,
                message="Failed to send test notification"
            ).dict()), 500

    except Exception as e:
        logger.error(f"Error sending test notification: {e}")
        return jsonify(APIResponse(
            success=False,
            message="Failed to send test notification",
            error=str(e)
        ).dict()), 500


@api_bp.route('/notifications/status')
@require_component('notification_manager')
def get_notification_status():
    """Get notification system status"""
    try:
        notification_manager = components['notification_manager']
        status = notification_manager.get_handler_status()

        return jsonify(APIResponse(
            success=True,
            message="Notification status retrieved",
            data=status
        ).dict())

    except Exception as e:
        logger.error(f"Error getting notification status: {e}")
        return jsonify(APIResponse(
            success=False,
            message="Failed to get notification status",
            error=str(e)
        ).dict()), 500


# Initialize components when module is imported
initialize_api_components()