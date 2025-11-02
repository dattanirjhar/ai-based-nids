# AI-based Network Intrusion Detection System

A comprehensive AI-powered Network Intrusion Detection System (NIDS) that bridges the gap between signature-based and anomaly-based detection approaches.

![NIDS Dashboard](https://img.shields.io/badge/Status-Active-brightgreen) ![Python](https://img.shields.io/badge/Python-3.9+-blue) ![Docker](https://img.shields.io/badge/Docker-Ready-blue) ![License](https://img.shields.io/badge/License-MIT-green)

## Overview

The AI-based NIDS monitors live network traffic on a single machine, analyzes patterns using machine learning, and triggers alerts for potential threats. It combines traditional signature-based detection with advanced anomaly detection to provide comprehensive network security monitoring.

### Key Features

 **Live Traffic Monitoring & Anomaly Detection**
- Real-time packet capture using Scapy
- ML-powered anomaly detection with multiple algorithms
- Configurable sensitivity thresholds

 **Alert System for Potential Threats**
- Multi-channel notifications (Email, Syslog, Webhook, Console)
- Alert correlation and deduplication
- Real-time alert visualization

 **Interactive Dashboard**
- Real-time traffic monitoring charts
- Attack statistics and threat visualization
- System resource monitoring
- Cyberpunk-themed security operations center interface

 **Hybrid Detection Approach**
- Signature-based detection for known threats
- ML-based detection for zero-day threats
- Ensemble voting for improved accuracy

## Architecture

```
ai-based-nids/
├── src/
│   ├── network_monitor/          # Packet capture and analysis
│   │   ├── packet_capture.py     # Real-time packet capture
│   │   ├── protocol_analyzer.py  # Deep packet inspection
│   │   └── traffic_features.py    # Feature extraction
│   ├── ml_detection/             # Machine learning components
│   │   ├── feature_extractor.py   # ML feature engineering
│   │   ├── model_trainer.py       # Model training pipeline
│   │   ├── anomaly_detector.py    # Real-time anomaly detection
│   │   └── signature_engine.py    # Signature-based detection
│   ├── alert_system/             # Alert management
│   │   ├── alert_manager.py       # Centralized alert management
│   │   ├── notification_handlers.py # Multi-channel notifications
│   │   └── log_manager.py         # Comprehensive logging
│   ├── web_interface/             # Web application
│   │   ├── app.py                # Flask web server
│   │   ├── api_routes.py          # REST API endpoints
│   │   ├── templates/            # HTML templates
│   │   └── static/               # CSS/JS assets
│   └── config/                   # Configuration management
│       ├── settings.py           # System configuration
│       └── models.py             # Data models and validation
├── data/                        # Data storage
│   ├── models/                  # Trained ML models
│   ├── logs/                    # System logs
│   └── datasets/               # Training datasets
├── tests/                       # Test suite
├── requirements.txt             # Python dependencies
├── Dockerfile                   # Docker configuration
├── docker-compose.yml           # Multi-container deployment
├── main.py                     # Application entry point
└── README.md                   # This file
```

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Python 3.9+ (for local development)
- Linux system (required for packet capture)
- Administrative privileges (for raw socket access)

### Docker Deployment (Recommended)

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd ai-based-nids
   ```

2. **Build and run with Docker Compose**
   ```bash
   docker-compose up -d
   ```

3. **Access the dashboard**
   Open your browser and navigate to:
   - Dashboard: http://localhost:5000
   - API Documentation: http://localhost:5000/api/health

4. **Monitor the system**
   ```bash
   # View logs
   docker-compose logs -f nids

   # Check system status
   curl http://localhost:5000/api/health
   ```

### Local Development

1. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the application**
   ```bash
   sudo python main.py
   ```
   ⚠️ **Note:** Requires root privileges for packet capture

3. **Access the dashboard**
   Navigate to: http://localhost:5000

## Configuration

The system uses YAML-based configuration files. Create `config/settings.yaml` to customize:

```yaml
# Network monitoring
network:
  interface: null  # Auto-detect if null
  promiscuous_mode: true
  packet_buffer_size: 1000
  capture_filter: ""

# Machine learning
ml:
  detection:
    confidence_threshold: 0.7
    ensemble_voting: "majority"

# Alert system
alerts:
  enabled: true
  rate_limiting:
    enabled: true
    max_alerts_per_minute: 10

# Web interface
web:
  host: "0.0.0.0"
  port: 5000
  debug: false
```

## Dashboard Features

### Real-time Monitoring
- **Live Traffic Monitor**: Real-time packet capture visualization
- **Alert Timeline**: Chronological display of security alerts
- **Network Topology**: Protocol distribution and traffic patterns
- **System Resources**: CPU, memory, network, and disk usage

### Threat Detection
- **Port Scan Detection**: Identifies network reconnaissance
- **DoS Attack Detection**: Detects denial-of-service attacks
- **Brute Force Detection**: Monitors authentication attacks
- **Anomaly Detection**: ML-based unusual pattern detection

### Alert Management
- **Multi-channel Notifications**: Email, syslog, webhook, console
- **Alert Correlation**: Groups related alerts
- **Priority Levels**: LOW, MEDIUM, HIGH, CRITICAL
- **Alert Actions**: Acknowledge, resolve, investigate

## Machine Learning Pipeline

### Supported Algorithms
- **Random Forest**: Primary classification model
- **Isolation Forest**: Anomaly detection
- **One-Class SVM**: Novelty detection
- **Logistic Regression**: Baseline comparison

### Feature Engineering
- Flow-based features (5-tuple analysis)
- Temporal features (time-windowed statistics)
- Protocol-specific features
- Behavioral features (burstiness, regularity)

### Model Training
- Automated model retraining
- Cross-validation with 5-fold strategy
- Performance metrics tracking
- Model versioning with A/B testing

## 📡 API Endpoints

### System Status
- `GET /api/health` - System health check
- `GET /api/status` - Detailed system status
- `GET /api/stats` - System statistics

### Alert Management
- `GET /api/alerts` - List alerts with filtering
- `GET /api/alerts/{id}` - Get specific alert
- `POST /api/alerts/{id}/acknowledge` - Acknowledge alert
- `POST /api/alerts/{id}/resolve` - Resolve alert

### Network Monitoring
- `GET /api/network/interfaces` - Available interfaces
- `GET /api/network/statistics` - Network statistics
- `GET /api/network/traffic` - Recent traffic data

### Machine Learning
- `GET /api/ml/models` - Model information
- `GET /api/ml/anomalies` - Recent detections
- `POST /api/ml/train` - Train models

## Docker Deployment

### Multi-Container Architecture
- **nids**: Main NIDS application
- **redis**: Alert queue and caching
- **elasticsearch**: Log aggregation
- **kibana**: Log visualization
- **prometheus**: Metrics collection
- **grafana**: Metrics visualization

### Production Deployment
```bash
# Production mode
docker-compose -f docker-compose.yml up -d

# Development mode
docker-compose -f docker-compose.yml --profile dev up -d

# Testing mode
docker-compose -f docker-compose.yml --profile test up -d
```

### Environment Variables
```bash
# Network monitoring
NIDS_INTERFACE=eth0
NIDS_PROMISCUOUS_MODE=true

# ML detection
NIDS_CONFIDENCE_THRESHOLD=0.7

# Web interface
NIDS_WEB_HOST=0.0.0.0
NIDS_WEB_PORT=5000

# Database
NIDS_DB_PATH=/app/data/nids.db
```

## Testing

### Unit Tests
```bash
# Run all tests
docker-compose exec nids python -m pytest tests/

# Run with coverage
docker-compose exec nids python -m pytest tests/ --cov=src
```

### Manual Testing Procedures

1. **Port Scan Detection**
   ```bash
   nmap -p 1-1000 <target_ip>
   ```

2. **DoS Attack Simulation**
   ```bash
   hping3 -S --flood <target_ip>
   ```

3. **Anomaly Detection**
   ```bash
   # Generate unusual traffic patterns
   # Monitor dashboard for alerts
   ```

4. **Dashboard Functionality**
   - Navigate to http://localhost:5000
   - Test real-time graph updates
   - Verify alert filtering and search
   - Test responsive design

## Performance Requirements

### System Requirements
- **CPU**: 2+ cores for real-time processing
- **Memory**: 4GB+ RAM (8GB recommended for production)
- **Storage**: 50GB+ for logs and models
- **Network**: Gigabit for high-throughput environments

### Performance Targets
- **Packet Processing**: >10,000 packets/second
- **Detection Latency**: <100ms from packet capture to alert
- **False Positive Rate**: <2% in production environments
- **System Uptime**: >99.9% availability
- **Dashboard Response**: <2 second page load times

## Security Considerations

### Deployment Security
- Run containers as non-root user
- Use network namespaces for isolation
- Implement TLS for web interface
- Role-based access control for dashboard
- Regular security updates for dependencies

### Data Privacy
- Encrypt sensitive payload data at rest
- Implement data retention policies
- Anonymize IP addresses in logs (optional)
- Secure API key management
- GDPR compliance considerations

## Advanced Configuration

### Custom Signatures
Add custom detection rules in `config/signatures.json`:

```json
{
  "signatures": [
    {
      "id": "custom_rule",
      "name": "Custom Attack Pattern",
      "description": "Detects specific attack pattern",
      "category": "CUSTOM",
      "severity": "HIGH",
      "pattern": "regex_pattern_here",
      "pattern_type": "regex",
      "conditions": {
        "protocol": "TCP",
        "dst_port": [8080, 8443]
      },
      "enabled": true
    }
  ]
}
```

### ML Model Training
```bash
# Train models with NSL-KDD dataset
python main.py --train-models

# Evaluate model performance
python main.py --evaluate-models
```

### Notification Configuration
Configure multiple notification channels:

```yaml
notifications:
  email:
    enabled: true
    smtp_server: "smtp.example.com"
    smtp_port: 587
    username: "nids@example.com"
    password: "password"
    to_addresses: ["admin@example.com"]

  webhook:
    enabled: true
    url: "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines
- Follow the existing code style and patterns
- Add unit tests for new features
- Update documentation for new functionality
- Ensure all tests pass before submitting

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

### Troubleshooting

**Packet Capture Issues**
```bash
# Check network interface permissions
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)

# Verify interface availability
ip link show
```

**Performance Issues**
- Increase buffer size in configuration
- Adjust confidence thresholds
- Monitor system resources

**Docker Issues**
```bash
# Check container logs
docker-compose logs nids

# Restart services
docker-compose restart nids
```

### Getting Help

- 📖 [Documentation](https://docs.example.com/nids)
- 🐛 [Issues](https://github.com/yourorg/ai-based-nids/issues)
- 💬 [Discussions](https://github.com/yourorg/ai-based-nids/discussions)
- 📧 [Email Support](mailto:support@example.com)

## Acknowledgments

- Based on concepts from [vicky60629/Network-Intrusion-Detection-System](https://github.com/vicky60629/Network-Intrusion-Detection-System)
- Built with Scapy, Scikit-learn, Flask, and modern web technologies
- Inspired by modern cybersecurity best practices

---

**🚨 Disclaimer**: This tool is designed for defensive security purposes only. Users are responsible for ensuring compliance with applicable laws and regulations when deploying this system.
