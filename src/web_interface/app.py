"""
Flask Web Application for AI-based NIDS
Main application with WebSocket support for real-time updates
"""

import os
import sys
import json
import time
import logging
from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS
from werkzeug.exceptions import NotFound
from threading import Thread
import eventlet

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.config.settings import get_config
from src.config.models import APIResponse
from src.alert_system.log_manager import get_log_manager
from src.network_monitor.packet_capture import get_packet_capture
from src.ml_detection.anomaly_detector import get_anomaly_detector
from src.ml_detection.signature_engine import get_signature_engine
from src.alert_system.alert_manager import get_alert_manager
from src.alert_system.notification_handlers import get_notification_manager

# Initialize eventlet for WebSocket support
eventlet.monkey_patch()

# Initialize Flask app
app = Flask(__name__,
           template_folder='templates',
           static_folder='static')

# Load configuration
config = get_config()
web_config = config.get_section('web')

# Configure Flask
app.config['SECRET_KEY'] = web_config.get('secret_key', 'change-this-in-production')
app.config['DEBUG'] = web_config.get('debug', False)
app.config['CORS_HEADERS'] = 'Content-Type'

# Initialize extensions
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# Initialize logger
logger = logging.getLogger(__name__)

# Global components
components = {}
notification_handlers = []


def initialize_components():
    """Initialize all NIDS components for the web interface"""
    global components, notification_handlers

    try:
        # Initialize core components
        components['log_manager'] = get_log_manager()
        components['packet_capture'] = get_packet_capture()
        components['anomaly_detector'] = get_anomaly_detector()
        components['signature_engine'] = get_signature_engine()
        components['alert_manager'] = get_alert_manager()
        components['notification_manager'] = get_notification_manager()

        # Setup alert handlers for real-time updates
        setup_alert_handlers()

        logger.info("Web interface components initialized successfully")
        return True

    except Exception as e:
        logger.error(f"Failed to initialize web interface components: {e}")
        return False


def setup_alert_handlers():
    """Setup alert handlers for real-time WebSocket updates"""
    global components, notification_handlers

    if 'alert_manager' not in components:
        return

    alert_manager = components['alert_manager']

    def websocket_alert_handler(alert):
        """Send alert to WebSocket clients"""
        try:
            alert_data = {
                'id': alert.id,
                'timestamp': alert.timestamp,
                'priority': alert.priority.value,
                'status': alert.status.value,
                'source_ip': alert.source_ip,
                'target_ip': alert.target_ip,
                'attack_type': alert.attack_type,
                'confidence': alert.confidence,
                'details': alert.details,
                'source': alert.source
            }

            socketio.emit('new_alert', alert_data, room='alerts')
            logger.debug(f"Alert sent to WebSocket clients: {alert.id}")

        except Exception as e:
            logger.error(f"Error sending alert to WebSocket: {e}")

    # Register the handler
    alert_manager.add_alert_handler(websocket_alert_handler)
    notification_handlers.append(websocket_alert_handler)

    logger.info("WebSocket alert handler registered")


# WebSocket event handlers
@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    logger.info(f"Client connected: {request.sid}")
    emit('status', {'message': 'Connected to NIDS WebSocket'})

    # Send initial data
    send_initial_data()


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logger.info(f"Client disconnected: {request.sid}")


@socketio.on('join_room')
def handle_join_room(data):
    """Handle joining a WebSocket room"""
    room = data.get('room')
    if room:
        join_room(room)
        logger.debug(f"Client {request.sid} joined room: {room}")
        emit('status', {'message': f'Joined room: {room}'})


@socketio.on('leave_room')
def handle_leave_room(data):
    """Handle leaving a WebSocket room"""
    room = data.get('room')
    if room:
        leave_room(room)
        logger.debug(f"Client {request.sid} left room: {room}")
        emit('status', {'message': f'Left room: {room}'})


def send_initial_data():
    """Send initial data to newly connected client"""
    try:
        # Get current statistics
        if 'packet_capture' in components:
            packet_stats = components['packet_capture'].get_statistics()
            socketio.emit('packet_stats', packet_stats)

        if 'alert_manager' in components:
            alert_stats = components['alert_manager'].get_statistics()
            socketio.emit('alert_stats', alert_stats.__dict__)

        if 'anomaly_detector' in components:
            anomaly_stats = components['anomaly_detector'].get_detector_status()
            socketio.emit('anomaly_stats', anomaly_stats)

        logger.debug("Initial data sent to WebSocket client")

    except Exception as e:
        logger.error(f"Error sending initial data: {e}")


# HTTP Routes
@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')


@app.route('/health')
def health_check():
    """Health check endpoint"""
    try:
        # Check component status
        component_status = {}
        for name, component in components.items():
            try:
                if hasattr(component, 'is_running'):
                    component_status[name] = component.is_running()
                elif hasattr(component, 'get_statistics'):
                    component_status[name] = 'active'
                else:
                    component_status[name] = 'available'
            except:
                component_status[name] = 'error'

        return jsonify({
            'status': 'healthy',
            'timestamp': time.time(),
            'components': component_status
        })

    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': time.time()
        }), 500


@app.route('/api/stats')
def get_statistics():
    """Get system statistics"""
    try:
        stats = {}

        # Packet capture statistics
        if 'packet_capture' in components:
            stats['packet_capture'] = components['packet_capture'].get_statistics()

        # Alert statistics
        if 'alert_manager' in components:
            stats['alerts'] = components['alert_manager'].get_statistics().__dict__

        # Anomaly detector statistics
        if 'anomaly_detector' in components:
            stats['anomaly_detector'] = components['anomaly_detector'].get_detector_status()

        # Signature engine statistics
        if 'signature_engine' in components:
            stats['signature_engine'] = components['signature_engine'].get_statistics()

        return jsonify(APIResponse(
            success=True,
            message="Statistics retrieved successfully",
            data=stats
        ).dict())

    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        return jsonify(APIResponse(
            success=False,
            message="Failed to retrieve statistics",
            error=str(e)
        ).dict()), 500


@app.route('/api/alerts')
def get_alerts():
    """Get alerts with filtering and pagination"""
    try:
        # Get query parameters
        status = request.args.get('status')
        priority = request.args.get('priority')
        limit = int(request.args.get('limit', 100))
        offset = int(request.args.get('offset', 0))

        if 'alert_manager' in components:
            alert_manager = components['alert_manager']

            # Convert string parameters to enum values if provided
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

            # Convert to dictionary format
            alert_data = [alert.to_dict() for alert in alerts]

            return jsonify(APIResponse(
                success=True,
                message=f"Retrieved {len(alert_data)} alerts",
                data={
                    'alerts': alert_data,
                    'total': len(alert_data),
                    'limit': limit,
                    'offset': offset
                }
            ).dict())

        else:
            return jsonify(APIResponse(
                success=False,
                message="Alert manager not available"
            ).dict()), 503

    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        return jsonify(APIResponse(
            success=False,
            message="Failed to retrieve alerts",
            error=str(e)
        ).dict()), 500


@app.route('/api/alerts/<alert_id>')
def get_alert(alert_id):
    """Get specific alert by ID"""
    try:
        if 'alert_manager' in components:
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
        else:
            return jsonify(APIResponse(
                success=False,
                message="Alert manager not available"
            ).dict()), 503

    except Exception as e:
        logger.error(f"Error getting alert {alert_id}: {e}")
        return jsonify(APIResponse(
            success=False,
            message="Failed to retrieve alert",
            error=str(e)
        ).dict()), 500


@app.route('/api/alerts/<alert_id>/acknowledge', methods=['POST'])
def acknowledge_alert(alert_id):
    """Acknowledge an alert"""
    try:
        if 'alert_manager' in components:
            alert_manager = components['alert_manager']

            # Get assigned user from request
            data = request.get_json() or {}
            assigned_to = data.get('assigned_to')

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
        else:
            return jsonify(APIResponse(
                success=False,
                message="Alert manager not available"
            ).dict()), 503

    except Exception as e:
        logger.error(f"Error acknowledging alert {alert_id}: {e}")
        return jsonify(APIResponse(
            success=False,
            message="Failed to acknowledge alert",
            error=str(e)
        ).dict()), 500


@app.route('/api/alerts/<alert_id>/resolve', methods=['POST'])
def resolve_alert(alert_id):
    """Resolve an alert"""
    try:
        if 'alert_manager' in components:
            alert_manager = components['alert_manager']

            # Get notes from request
            data = request.get_json() or {}
            notes = data.get('notes')

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
        else:
            return jsonify(APIResponse(
                success=False,
                message="Alert manager not available"
            ).dict()), 503

    except Exception as e:
        logger.error(f"Error resolving alert {alert_id}: {e}")
        return jsonify(APIResponse(
            success=False,
            message="Failed to resolve alert",
            error=str(e)
        ).dict()), 500


@app.route('/api/traffic')
def get_traffic_data():
    """Get real-time traffic data"""
    try:
        if 'packet_capture' in components:
            packet_capture = components['packet_capture']

            # Get recent packets
            recent_packets = packet_capture.get_recent_packets(100)

            # Convert to list of dictionaries
            packet_data = []
            for packet in recent_packets:
                packet_data.append({
                    'timestamp': packet.timestamp,
                    'src_ip': packet.src_ip,
                    'dst_ip': packet.dst_ip,
                    'src_port': packet.src_port,
                    'dst_port': packet.dst_port,
                    'protocol': packet.protocol,
                    'packet_size': packet.packet_size,
                    'flags': packet.flags
                })

            # Get statistics
            stats = packet_capture.get_statistics()

            return jsonify(APIResponse(
                success=True,
                message="Traffic data retrieved successfully",
                data={
                    'packets': packet_data,
                    'statistics': stats
                }
            ).dict())
        else:
            return jsonify(APIResponse(
                success=False,
                message="Packet capture not available"
            ).dict()), 503

    except Exception as e:
        logger.error(f"Error getting traffic data: {e}")
        return jsonify(APIResponse(
            success=False,
            message="Failed to retrieve traffic data",
            error=str(e)
        ).dict()), 500


@app.route('/api/models')
def get_model_info():
    """Get ML model information"""
    try:
        model_info = {}

        if 'anomaly_detector' in components:
            anomaly_detector = components['anomaly_detector']
            model_info['anomaly_detector'] = anomaly_detector.get_model_performance_summary()

        return jsonify(APIResponse(
            success=True,
            message="Model information retrieved successfully",
            data=model_info
        ).dict())

    except Exception as e:
        logger.error(f"Error getting model info: {e}")
        return jsonify(APIResponse(
            success=False,
            message="Failed to retrieve model information",
            error=str(e)
        ).dict()), 500


@app.route('/api/logs')
def get_logs():
    """Get system logs"""
    try:
        # Get query parameters
        level = request.args.get('level')
        component = request.args.get('component')
        limit = int(request.args.get('limit', 1000))
        query = request.args.get('query')

        if 'log_manager' in components:
            log_manager = components['log_manager']

            # Get logs with filters
            logs = log_manager.search_logs(
                query=query or '',
                level=level,
                component=component,
                limit=limit
            )

            # Convert to list of dictionaries
            log_data = []
            for log in logs:
                log_data.append({
                    'timestamp': log.timestamp,
                    'level': log.level,
                    'component': log.component,
                    'message': log.message,
                    'details': log.details,
                    'source_ip': log.source_ip,
                    'session_id': log.session_id,
                    'user_id': log.user_id,
                    'tags': log.tags
                })

            return jsonify(APIResponse(
                success=True,
                message=f"Retrieved {len(log_data)} log entries",
                data={
                    'logs': log_data,
                    'total': len(log_data)
                }
            ).dict())
        else:
            return jsonify(APIResponse(
                success=False,
                message="Log manager not available"
            ).dict()), 503

    except Exception as e:
        logger.error(f"Error getting logs: {e}")
        return jsonify(APIResponse(
            success=False,
            message="Failed to retrieve logs",
            error=str(e)
        ).dict()), 500


@app.route('/api/export/<format>')
def export_data(format):
    """Export data in various formats"""
    try:
        if format not in ['json', 'csv', 'txt']:
            return jsonify(APIResponse(
                success=False,
                message="Unsupported export format"
            ).dict()), 400

        # Get query parameters
        start_time = request.args.get('start_time')
        end_time = request.args.get('end_time')
        query = request.args.get('query')

        # Convert timestamps if provided
        start_ts = float(start_time) if start_time else None
        end_ts = float(end_time) if end_time else None

        # Generate filename
        timestamp = int(time.time())
        filename = f"nids_export_{timestamp}.{format}"
        filepath = os.path.join('/tmp', filename)

        if 'alert_manager' in components:
            alert_manager = components['alert_manager']
            alert_manager.export_alerts(filepath, format, (start_ts, end_ts) if start_ts else None)
        else:
            return jsonify(APIResponse(
                success=False,
                message="Alert manager not available"
            ).dict()), 503

        # Return file for download
        return send_from_directory('/tmp', filename, as_attachment=True)

    except Exception as e:
        logger.error(f"Error exporting data: {e}")
        return jsonify(APIResponse(
            success=False,
            message="Failed to export data",
            error=str(e)
        ).dict()), 500


# Error handlers
@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify(APIResponse(
        success=False,
        message="Endpoint not found",
        error=str(error)
    ).dict()), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f"Internal server error: {error}")
    return jsonify(APIResponse(
        success=False,
        message="Internal server error",
        error=str(error)
    ).dict()), 500


# Background thread for periodic updates
def background_updater():
    """Background thread for periodic data updates"""
    while True:
        try:
            # Send periodic updates to connected clients
            if components:
                # Update packet statistics
                if 'packet_capture' in components:
                    packet_stats = components['packet_capture'].get_statistics()
                    socketio.emit('packet_stats', packet_stats, room='alerts')

                # Update alert statistics
                if 'alert_manager' in components:
                    alert_stats = components['alert_manager'].get_statistics()
                    socketio.emit('alert_stats', alert_stats.__dict__, room='alerts')

            # Sleep for 30 seconds
            eventlet.sleep(30)

        except Exception as e:
            logger.error(f"Error in background updater: {e}")
            eventlet.sleep(30)


def create_app():
    """Application factory"""
    # Initialize components
    if not initialize_components():
        logger.error("Failed to initialize web application components")
        return None

    # Start background updater
    updater_thread = Thread(target=background_updater, daemon=True)
    updater_thread.start()

    logger.info("Flask web application initialized")
    return app


if __name__ == '__main__':
    # Create and run the application
    app = create_app()
    if app:
        web_config = get_config().get_section('web')
        host = web_config.get('host', '0.0.0.0')
        port = web_config.get('port', 5000)
        debug = web_config.get('debug', False)

        logger.info(f"Starting NIDS web interface on {host}:{port}")
        socketio.run(app, host=host, port=port, debug=debug)
    else:
        logger.error("Failed to create web application")
        sys.exit(1)