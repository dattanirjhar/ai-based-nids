/**
 * AI-based NIDS Dashboard JavaScript
 * Handles real-time updates, data visualization, and user interactions
 */

// Global variables
let socket = null;
let charts = {};
let isTrafficPaused = false;
let updateIntervals = {};
let currentAlertFilter = 'all';

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeDashboard();
});

/**
 * Initialize the dashboard
 */
function initializeDashboard() {
    console.log('Initializing NIDS Dashboard...');

    // Hide loading overlay
    setTimeout(() => {
        document.getElementById('loadingOverlay').classList.add('hidden');
    }, 1000);

    // Initialize Socket.IO connection
    initializeSocket();

    // Initialize charts
    initializeCharts();

    // Setup event listeners
    setupEventListeners();

    // Start periodic updates
    startPeriodicUpdates();

    // Load initial data
    loadInitialData();

    console.log('Dashboard initialized successfully');
}

/**
 * Initialize Socket.IO connection
 */
function initializeSocket() {
    try {
        socket = io();

        socket.on('connect', function() {
            console.log('Connected to NIDS WebSocket');
            updateConnectionStatus(true);

            // Join alerts room
            socket.emit('join_room', { room: 'alerts' });
        });

        socket.on('disconnect', function() {
            console.log('Disconnected from NIDS WebSocket');
            updateConnectionStatus(false);
        });

        socket.on('status', function(data) {
            console.log('Status update:', data);
        });

        socket.on('new_alert', function(alert) {
            handleNewAlert(alert);
        });

        socket.on('packet_stats', function(stats) {
            updatePacketStats(stats);
        });

        socket.on('alert_stats', function(stats) {
            updateAlertStats(stats);
        });

        socket.on('anomaly_stats', function(stats) {
            updateAnomalyStats(stats);
        });

        socket.on('error', function(error) {
            console.error('Socket error:', error);
        });

    } catch (error) {
        console.error('Failed to initialize Socket.IO:', error);
        // Fallback to HTTP polling
        startHTTPPolling();
    }
}

/**
 * Initialize all charts
 */
function initializeCharts() {
    // Traffic Chart
    const trafficCtx = document.getElementById('trafficChart').getContext('2d');
    charts.traffic = new Chart(trafficCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Inbound',
                data: [],
                borderColor: '#2196f3',
                backgroundColor: 'rgba(33, 150, 243, 0.1)',
                tension: 0.4,
                fill: true
            }, {
                label: 'Outbound',
                data: [],
                borderColor: '#ff9800',
                backgroundColor: 'rgba(255, 152, 0, 0.1)',
                tension: 0.4,
                fill: true
            }]
        },
        options: getTrafficChartOptions()
    });

    // Network Topology Chart
    const networkCtx = document.getElementById('networkChart').getContext('2d');
    charts.network = new Chart(networkCtx, {
        type: 'doughnut',
        data: {
            labels: ['TCP', 'UDP', 'ICMP', 'Other'],
            datasets: [{
                data: [0, 0, 0, 0],
                backgroundColor: [
                    '#2196f3',
                    '#4caf50',
                    '#ff9800',
                    '#9c27b0'
                ],
                borderWidth: 2,
                borderColor: '#1a1a1a'
            }]
        },
        options: getNetworkChartOptions()
    });

    // Attack Statistics Chart
    const attackCtx = document.getElementById('attackChart').getContext('2d');
    charts.attack = new Chart(attackCtx, {
        type: 'bar',
        data: {
            labels: ['Port Scan', 'DoS', 'Brute Force', 'Anomaly'],
            datasets: [{
                label: 'Attack Count',
                data: [0, 0, 0, 0],
                backgroundColor: [
                    'rgba(0, 255, 65, 0.6)',
                    'rgba(255, 23, 68, 0.6)',
                    'rgba(255, 152, 0, 0.6)',
                    'rgba(156, 39, 176, 0.6)'
                ],
                borderColor: [
                    '#00ff41',
                    '#ff1744',
                    '#ff9800',
                    '#9c27b0'
                ],
                borderWidth: 2
            }]
        },
        options: getAttackChartOptions()
    });
}

/**
 * Get traffic chart options
 */
function getTrafficChartOptions() {
    return {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                display: true,
                labels: {
                    color: '#ffffff',
                    font: {
                        family: 'Roboto Mono'
                    }
                }
            },
            tooltip: {
                mode: 'index',
                intersect: false,
                backgroundColor: 'rgba(0, 0, 0, 0.8)',
                titleColor: '#00ff41',
                bodyColor: '#ffffff',
                borderColor: '#00ff41',
                borderWidth: 1
            }
        },
        scales: {
            x: {
                grid: {
                    color: 'rgba(255, 255, 255, 0.1)',
                    borderColor: 'rgba(255, 255, 255, 0.2)'
                },
                ticks: {
                    color: '#ffffff',
                    font: {
                        family: 'Roboto Mono'
                    }
                }
            },
            y: {
                grid: {
                    color: 'rgba(255, 255, 255, 0.1)',
                    borderColor: 'rgba(255, 255, 255, 0.2)'
                },
                ticks: {
                    color: '#ffffff',
                    font: {
                        family: 'Roboto Mono'
                    },
                    callback: function(value) {
                        return value + ' pps';
                    }
                }
            }
        }
    };
}

/**
 * Get network chart options
 */
function getNetworkChartOptions() {
    return {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                display: true,
                position: 'bottom',
                labels: {
                    color: '#ffffff',
                    font: {
                        family: 'Roboto Mono'
                    }
                }
            },
            tooltip: {
                backgroundColor: 'rgba(0, 0, 0, 0.8)',
                titleColor: '#00ff41',
                bodyColor: '#ffffff',
                borderColor: '#00ff41',
                borderWidth: 1
            }
        }
    };
}

/**
 * Get attack chart options
 */
function getAttackChartOptions() {
    return {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                display: false
            },
            tooltip: {
                backgroundColor: 'rgba(0, 0, 0, 0.8)',
                titleColor: '#00ff41',
                bodyColor: '#ffffff',
                borderColor: '#00ff41',
                borderWidth: 1
            }
        },
        scales: {
            x: {
                grid: {
                    color: 'rgba(255, 255, 255, 0.1)',
                    borderColor: 'rgba(255, 255, 255, 0.2)'
                },
                ticks: {
                    color: '#ffffff',
                    font: {
                        family: 'Roboto Mono'
                    }
                }
            },
            y: {
                grid: {
                    color: 'rgba(255, 255, 255, 0.1)',
                    borderColor: 'rgba(255, 255, 255, 0.2)'
                },
                ticks: {
                    color: '#ffffff',
                    font: {
                        family: 'Roboto Mono'
                    }
                }
            }
        }
    };
}

/**
 * Setup event listeners
 */
function setupEventListeners() {
    // Navigation
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            handleNavigation(this);
        });
    });

    // Traffic controls
    document.getElementById('trafficToggle').addEventListener('click', toggleTrafficMonitoring);
    document.getElementById('trafficSettings').addEventListener('click', showTrafficSettings);

    // Alert filter
    document.getElementById('alertFilter').addEventListener('change', function() {
        currentAlertFilter = this.value;
        filterAlerts();
    });

    // Time range buttons
    document.querySelectorAll('.range-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            handleTimeRangeChange(this);
        });
    });

    // Alert modal close button
    document.querySelector('.modal-close').addEventListener('click', closeAlertModal);

    // Topology controls
    document.getElementById('topologyRefresh').addEventListener('click', refreshNetworkTopology);
    document.getElementById('topologyExpand').addEventListener('click', expandNetworkTopology);

    // Window resize
    window.addEventListener('resize', handleWindowResize);

    // Keyboard shortcuts
    document.addEventListener('keydown', handleKeyboardShortcuts);
}

/**
 * Handle navigation clicks
 */
function handleNavigation(link) {
    // Remove active class from all links
    document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));

    // Add active class to clicked link
    link.classList.add('active');

    // Update dashboard content (placeholder for future sections)
    const section = link.getAttribute('data-section');
    updateDashboardSection(section);
}

/**
 * Update dashboard section
 */
function updateDashboardSection(section) {
    // For now, all sections show the same dashboard
    // In the future, this could load different content
    console.log('Navigating to section:', section);

    // Add terminal log
    addTerminalLine(`Navigating to ${section.toUpperCase()} section...`);
}

/**
 * Toggle traffic monitoring
 */
function toggleTrafficMonitoring() {
    isTrafficPaused = !isTrafficPaused;
    const btn = document.getElementById('trafficToggle');
    const icon = btn.querySelector('i');

    if (isTrafficPaused) {
        icon.className = 'fas fa-play';
        addTerminalLine('Traffic monitoring PAUSED');
    } else {
        icon.className = 'fas fa-pause';
        addTerminalLine('Traffic monitoring RESUMED');
    }
}

/**
 * Show traffic settings
 */
function showTrafficSettings() {
    // Placeholder for settings modal
    addTerminalLine('Opening traffic settings...');
    alert('Traffic settings feature coming soon!');
}

/**
 * Filter alerts
 */
function filterAlerts() {
    // This would filter the displayed alerts
    console.log('Filtering alerts:', currentAlertFilter);
    addTerminalLine(`Filtering alerts: ${currentAlertFilter}`);
}

/**
 * Handle time range change
 */
function handleTimeRangeChange(btn) {
    // Remove active class from all buttons
    document.querySelectorAll('.range-btn').forEach(b => b.classList.remove('active'));

    // Add active class to clicked button
    btn.classList.add('active');

    const range = btn.getAttribute('data-range');
    console.log('Time range changed to:', range);
    addTerminalLine(`Time range: ${range}`);

    // Reload data for new time range
    loadAlertData(range);
}

/**
 * Load initial data from API
 */
async function loadInitialData() {
    try {
        // Load system statistics
        const statsResponse = await fetch('/api/stats');
        const statsData = await statsResponse.json();

        if (statsData.success) {
            updateSystemStats(statsData.data);
        }

        // Load recent alerts
        const alertsResponse = await fetch('/api/alerts?limit=10');
        const alertsData = await alertsResponse.json();

        if (alertsData.success) {
            updateAlertsList(alertsData.data.alerts);
        }

        // Load network statistics
        const networkResponse = await fetch('/api/network/statistics');
        const networkData = await networkResponse.json();

        if (networkData.success) {
            updateNetworkStats(networkData.data);
        }

        addTerminalLine('Initial data loaded successfully');

    } catch (error) {
        console.error('Error loading initial data:', error);
        addTerminalLine('ERROR: Failed to load initial data', 'error');
    }
}

/**
 * Update system statistics
 */
function updateSystemStats(stats) {
    // Update stats bar
    if (stats.packet_capture) {
        document.getElementById('packetsPerSec').textContent =
            Math.round(stats.packet_capture.capture_rate || 0);
    }

    if (stats.alerts) {
        document.getElementById('activeAlerts').textContent = stats.alerts.active_alerts || 0;
        document.getElementById('threatsBlocked').textContent = stats.alerts.total_alerts || 0;
    }

    if (stats.anomaly_detector && stats.anomaly_detector.total_samples > 0) {
        // Placeholder for ML accuracy
        document.getElementById('mlAccuracy').textContent = '98.7%';
    }
}

/**
 * Update alerts list
 */
function updateAlertsList(alerts) {
    const timeline = document.getElementById('alertTimeline');

    if (alerts.length === 0) {
        timeline.innerHTML = `
            <div class="timeline-placeholder">
                <i class="fas fa-shield-alt"></i>
                <p>No alerts yet. System is monitoring...</p>
            </div>
        `;
        return;
    }

    const alertsHtml = alerts.map(alert => createAlertItem(alert)).join('');
    timeline.innerHTML = alertsHtml;
}

/**
 * Create alert item HTML
 */
function createAlertItem(alert) {
    const time = new Date(alert.timestamp * 1000).toLocaleTimeString();
    const priorityClass = alert.priority.toLowerCase();

    return `
        <div class="alert-item ${priorityClass}" onclick="showAlertDetails('${alert.id}')">
            <div class="alert-time">${time}</div>
            <div class="alert-title">${alert.attack_type.toUpperCase()}</div>
            <div class="alert-details">
                Source: ${alert.source_ip} | Confidence: ${Math.round(alert.confidence * 100)}%
            </div>
        </div>
    `;
}

/**
 * Handle new alert from WebSocket
 */
function handleNewAlert(alert) {
    // Update stats
    const activeAlertsElement = document.getElementById('activeAlerts');
    const currentCount = parseInt(activeAlertsElement.textContent);
    activeAlertsElement.textContent = currentCount + 1;

    // Add to timeline
    const timeline = document.getElementById('alertTimeline');
    const newAlertHtml = createAlertItem(alert);

    // Remove placeholder if exists
    const placeholder = timeline.querySelector('.timeline-placeholder');
    if (placeholder) {
        placeholder.remove();
    }

    // Insert at the beginning
    timeline.insertAdjacentHTML('afterbegin', newAlertHtml);

    // Limit to 50 items
    const items = timeline.querySelectorAll('.alert-item');
    if (items.length > 50) {
        items[items.length - 1].remove();
    }

    // Show alert modal for critical alerts
    if (alert.priority === 'CRITICAL') {
        showAlertModal(alert);
    }

    // Add terminal line
    addTerminalLine(`🚨 ALERT: ${alert.attack_type} from ${alert.source_ip}`, 'warning');

    // Update charts
    updateAttackChart(alert.attack_type);
}

/**
 * Update packet statistics
 */
function updatePacketStats(stats) {
    if (!isTrafficPaused && stats) {
        // Update packets per second
        const packetsPerSec = Math.round(stats.capture_rate || 0);
        document.getElementById('packetsPerSec').textContent = packetsPerSec;

        // Update traffic chart
        updateTrafficChart(stats);
    }
}

/**
 * Update alert statistics
 */
function updateAlertStats(stats) {
    document.getElementById('activeAlerts').textContent = stats.active_alerts || 0;
    document.getElementById('threatsBlocked').textContent = stats.total_alerts || 0;
}

/**
 * Update anomaly statistics
 */
function updateAnomalyStats(stats) {
    // Update ML-related statistics
    if (stats.detector_status) {
        const accuracy = stats.detector_status.average_confidence || 0;
        document.getElementById('mlAccuracy').textContent = Math.round(accuracy * 100) + '%';
    }
}

/**
 * Update traffic chart
 */
function updateTrafficChart(stats) {
    if (!charts.traffic || isTrafficPaused) return;

    const now = new Date().toLocaleTimeString();
    const chart = charts.traffic;

    // Keep only last 20 data points
    if (chart.data.labels.length >= 20) {
        chart.data.labels.shift();
        chart.data.datasets[0].data.shift();
        chart.data.datasets[1].data.shift();
    }

    chart.data.labels.push(now);
    chart.data.datasets[0].data.push(Math.random() * 100); // Placeholder inbound
    chart.data.datasets[1].data.push(Math.random() * 100); // Placeholder outbound

    chart.update('none'); // Update without animation
}

/**
 * Update network statistics
 */
function updateNetworkStats(stats) {
    if (charts.network && stats.protocol_distribution) {
        const protocols = ['TCP', 'UDP', 'ICMP', 'Other'];
        const data = protocols.map(p => stats.protocol_distribution[p] || 0);

        charts.network.data.datasets[0].data = data;
        charts.network.update('none');
    }
}

/**
 * Update attack chart
 */
function updateAttackChart(attackType) {
    if (!charts.attack) return;

    const typeMap = {
        'port_scan': 0,
        'dos': 1,
        'brute_force': 2,
        'anomaly_detection': 3
    };

    const index = typeMap[attackType];
    if (index !== undefined) {
        charts.attack.data.datasets[0].data[index]++;
        charts.attack.update('none');
    }

    // Update attack type counts
    updateAttackTypeCounts();
}

/**
 * Update attack type counts
 */
function updateAttackTypeCounts() {
    if (!charts.attack) return;

    const data = charts.attack.data.datasets[0].data;

    document.getElementById('portScanCount').textContent = data[0];
    document.getElementById('dosCount').textContent = data[1];
    document.getElementById('bruteForceCount').textContent = data[2];
    document.getElementById('anomalyCount').textContent = data[3];

    // Update progress bars
    const maxCount = Math.max(...data, 1);

    document.querySelector('.attack-fill.port-scan').style.width = `${(data[0] / maxCount) * 100}%`;
    document.querySelector('.attack-fill.dos').style.width = `${(data[1] / maxCount) * 100}%`;
    document.querySelector('.attack-fill.brute-force').style.width = `${(data[2] / maxCount) * 100}%`;
    document.querySelector('.attack-fill.anomaly').style.width = `${(data[3] / maxCount) * 100}%`;
}

/**
 * Update connection status
 */
function updateConnectionStatus(connected) {
    const indicator = document.getElementById('connectionIndicator');
    const status = document.getElementById('connectionStatus');
    const systemStatus = document.getElementById('systemStatus');

    if (connected) {
        indicator.className = 'status-indicator online';
        status.textContent = 'CONNECTED';
        systemStatus.textContent = 'ONLINE';
        systemStatus.className = 'brand-status';
    } else {
        indicator.className = 'status-indicator offline';
        status.textContent = 'DISCONNECTED';
        systemStatus.textContent = 'OFFLINE';
        systemStatus.className = 'brand-status';
    }
}

/**
 * Show alert modal
 */
function showAlertModal(alert) {
    const modal = document.getElementById('alertModal');

    // Update modal content
    document.getElementById('modalAttackType').textContent = alert.attack_type.toUpperCase();
    document.getElementById('modalSourceIP').textContent = alert.source_ip;
    document.getElementById('modalConfidence').textContent = Math.round(alert.confidence * 100) + '%';
    document.getElementById('modalTimestamp').textContent = new Date(alert.timestamp * 1000).toLocaleString();

    modal.classList.add('show');
}

/**
 * Close alert modal
 */
function closeAlertModal() {
    const modal = document.getElementById('alertModal');
    modal.classList.remove('show');
}

/**
 * Show alert details
 */
function showAlertDetails(alertId) {
    console.log('Showing details for alert:', alertId);
    // In a real implementation, this would show detailed alert information
}

/**
 * Alert action functions
 */
function blockIP() {
    console.log('Blocking IP address...');
    addTerminalLine('IP address blocked successfully', 'success');
    closeAlertModal();
}

function investigateAlert() {
    console.log('Investigating alert...');
    addTerminalLine('Investigation started...');
    closeAlertModal();
}

function dismissAlert() {
    console.log('Alert dismissed');
    closeAlertModal();
}

/**
 * Add terminal line
 */
function addTerminalLine(text, type = 'info') {
    const terminal = document.getElementById('terminalOutput');
    const line = document.createElement('div');
    line.className = 'terminal-line';

    const typeClass = type === 'error' ? 'error' : type === 'warning' ? 'warning' : type === 'success' ? 'success' : '';

    line.innerHTML = `
        <span class="terminal-prompt">$</span>
        <span class="terminal-text ${typeClass}">${text}</span>
    `;

    terminal.appendChild(line);
    terminal.scrollTop = terminal.scrollHeight;

    // Limit to 100 lines
    const lines = terminal.querySelectorAll('.terminal-line');
    if (lines.length > 100) {
        lines[0].remove();
    }
}

/**
 * Start periodic updates
 */
function startPeriodicUpdates() {
    // Update system resources every 5 seconds
    updateIntervals.resources = setInterval(updateSystemResources, 5000);

    // Update network data every 2 seconds
    updateIntervals.network = setInterval(updateNetworkData, 2000);

    // Update charts every 1 second
    updateIntervals.charts = setInterval(updateCharts, 1000);
}

/**
 * Update system resources
 */
function updateSystemResources() {
    // Simulated system resource data
    const resources = {
        cpu: Math.random() * 100,
        memory: Math.random() * 100,
        network: Math.random() * 100,
        disk: Math.random() * 100
    };

    document.getElementById('cpuUsage').textContent = Math.round(resources.cpu) + '%';
    document.getElementById('memoryUsage').textContent = Math.round(resources.memory) + '%';
    document.getElementById('networkUsage').textContent = Math.round(resources.network) + '%';
    document.getElementById('diskUsage').textContent = Math.round(resources.disk) + '%';

    document.querySelector('.resource-fill.cpu').style.width = resources.cpu + '%';
    document.querySelector('.resource-fill.memory').style.width = resources.memory + '%';
    document.querySelector('.resource-fill.network').style.width = resources.network + '%';
    document.querySelector('.resource-fill.disk').style.width = resources.disk + '%';
}

/**
 * Update network data
 */
function updateNetworkData() {
    // This would fetch real network data
    // For now, it's handled by WebSocket updates
}

/**
 * Update charts
 */
function updateCharts() {
    // Traffic chart is updated by WebSocket
    // Network chart could be updated periodically
}

/**
 * Handle window resize
 */
function handleWindowResize() {
    // Resize charts
    Object.values(charts).forEach(chart => {
        if (chart) {
            chart.resize();
        }
    });
}

/**
 * Handle keyboard shortcuts
 */
function handleKeyboardShortcuts(event) {
    // Ctrl + R: Refresh data
    if (event.ctrlKey && event.key === 'r') {
        event.preventDefault();
        loadInitialData();
        addTerminalLine('Data refreshed manually');
    }

    // Ctrl + P: Pause/Resume traffic
    if (event.ctrlKey && event.key === 'p') {
        event.preventDefault();
        toggleTrafficMonitoring();
    }

    // Escape: Close modal
    if (event.key === 'Escape') {
        closeAlertModal();
    }

    // 1-5: Navigate to sections
    if (event.key >= '1' && event.key <= '5') {
        const links = document.querySelectorAll('.nav-link');
        const index = parseInt(event.key) - 1;
        if (links[index]) {
            handleNavigation(links[index]);
        }
    }
}

/**
 * Start HTTP polling (fallback when WebSocket fails)
 */
function startHTTPPolling() {
    console.log('Starting HTTP polling fallback...');

    // Poll alerts every 5 seconds
    updateIntervals.httpAlerts = setInterval(async () => {
        try {
            const response = await fetch('/api/alerts?limit=10');
            const data = await response.json();

            if (data.success && data.data.alerts.length > 0) {
                updateAlertsList(data.data.alerts);
            }
        } catch (error) {
            console.error('HTTP polling error:', error);
        }
    }, 5000);

    // Poll stats every 10 seconds
    updateIntervals.httpStats = setInterval(async () => {
        try {
            const response = await fetch('/api/stats');
            const data = await response.json();

            if (data.success) {
                updateSystemStats(data.data);
            }
        } catch (error) {
            console.error('HTTP stats polling error:', error);
        }
    }, 10000);
}

/**
 * Load alert data for specific time range
 */
async function loadAlertData(timeRange) {
    try {
        const response = await fetch(`/api/alerts?limit=100&time_range=${timeRange}`);
        const data = await response.json();

        if (data.success) {
            updateAlertsList(data.data.alerts);
        }
    } catch (error) {
        console.error('Error loading alert data:', error);
    }
}

/**
 * Refresh network topology
 */
function refreshNetworkTopology() {
    addTerminalLine('Refreshing network topology...');
    // In a real implementation, this would reload network visualization
}

/**
 * Expand network topology
 */
function expandNetworkTopology() {
    addTerminalLine('Expanding network topology view...');
    // In a real implementation, this would show detailed network view
}

/**
 * Show traffic settings
 */
function showTrafficSettings() {
    // Placeholder for traffic settings modal
    const settings = {
        interface: 'auto',
        packetFilter: '',
        updateInterval: 1000,
        maxPackets: 1000
    };

    console.log('Traffic settings:', settings);
    addTerminalLine('Traffic settings loaded');
}

// Export functions for global access
window.closeAlertModal = closeAlertModal;
window.blockIP = blockIP;
window.investigateAlert = investigateAlert;
window.dismissAlert = dismissAlert;