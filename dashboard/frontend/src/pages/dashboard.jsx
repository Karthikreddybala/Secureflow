import React from 'react';
import { useSelector } from 'react-redux';
import './css/dashboard.css';
import NetworkTrafficChart from '../charts/NetworkTrafficChart.jsx';
import ProtocolPieChart from '../charts/ProtocolPieChart.jsx';
import AttackDistributionChart from '../charts/AttackDistributionChart.jsx';
import { selectFilteredAlerts, selectAlertStats } from '../store/slices/alertsSlice';

const getSeverityClass = (severity) => {
    const severityKey = (severity || '').toLowerCase();
    if (severityKey === 'high') return 'severity-high';
    if (severityKey === 'medium') return 'severity-medium';
    if (severityKey === 'low') return 'severity-low';
    return 'severity-normal';
};

function Dashboard() {
    const filteredAlerts = useSelector((state) => selectFilteredAlerts(state));
    const networkData = useSelector((state) => state.networkData.networkData);
    const alertStats = useSelector((state) => selectAlertStats(state));

    const threatLevel =
        alertStats.high > 0 ? 'Critical' : alertStats.medium > 0 ? 'Elevated' : alertStats.attacks > 0 ? 'Guarded' : 'Stable';
    const threatLevelClass =
        threatLevel === 'Critical'
            ? 'threat-critical'
            : threatLevel === 'Elevated'
              ? 'threat-elevated'
              : threatLevel === 'Guarded'
                ? 'threat-guarded'
                : 'threat-stable';
    const attackRate = alertStats.total ? Math.round((alertStats.attacks / alertStats.total) * 100) : 0;

    return (
        <div className="dashboard-page">
            <div className="dashboard-grid">
                <div className="dashboard-col-1">
                    <div className="dashboard-row dashboard-row-1 chart-slot">
                        <NetworkTrafficChart />
                    </div>

                    <div className="dashboard-row dashboard-row-2">
                        <div className="dashboard-panel network-feed-panel">
                            <div className="panel-heading">
                                <h3>Packet Feed</h3>
                                <span className="panel-pill">{networkData.length} entries</span>
                            </div>
                            <p className="panel-subtitle">Most recent traffic activity across monitored hosts.</p>

                            {networkData.length === 0 ? (
                                <div className="panel-empty">Waiting for incoming network packets...</div>
                            ) : (
                                <div className="network-list">
                                    {networkData.slice(0, 12).map((packet, index) => {
                                        const source = packet?.src || packet?.src_ip || 'Unknown';
                                        const destination = packet?.dst || packet?.dst_ip || 'Unknown';
                                        const sourcePort = packet?.sport || '-';
                                        const destinationPort = packet?.dport || '-';
                                        const protocol = packet?.proto || packet?.protocol || 'N/A';
                                        const timestamp = packet?.timestamp
                                            ? new Date(packet.timestamp).toLocaleTimeString()
                                            : new Date().toLocaleTimeString();

                                        return (
                                            <div key={index} className="network-item">
                                                <div className="network-item-main">
                                                    <span className="network-direction">
                                                        {source}:{sourcePort} -&gt; {destination}:{destinationPort}
                                                    </span>
                                                    <span className="network-protocol">{protocol}</span>
                                                </div>
                                                <span className="network-time">{timestamp}</span>
                                            </div>
                                        );
                                    })}
                                </div>
                            )}
                        </div>

                        <div className="dashboard-panel security-status-panel">
                            <div className="panel-heading">
                                <h3>Security Posture</h3>
                                <span className={`threat-chip ${threatLevelClass}`}>{threatLevel}</span>
                            </div>
                            <p className="panel-subtitle">Live risk indicators calculated from active alerts.</p>

                            <div className="metric-grid">
                                <div className="metric-card">
                                    <span className="metric-label">Total Alerts</span>
                                    <span className="metric-value">{alertStats.total}</span>
                                </div>
                                <div className="metric-card">
                                    <span className="metric-label">Attack Alerts</span>
                                    <span className="metric-value">{alertStats.attacks}</span>
                                </div>
                                <div className="metric-card">
                                    <span className="metric-label">High Severity</span>
                                    <span className="metric-value">{alertStats.high}</span>
                                </div>
                                <div className="metric-card">
                                    <span className="metric-label">Attack Rate</span>
                                    <span className="metric-value">{attackRate}%</span>
                                </div>
                            </div>

                            <div className="threat-meter-wrap">
                                <div className="threat-meter-label">
                                    <span>Threat Intensity</span>
                                    <span>{attackRate}%</span>
                                </div>
                                <div className="threat-meter-track">
                                    <div className="threat-meter-fill" style={{ width: `${attackRate}%` }} />
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div className="dashboard-col-2">
                    <div className="dashboard-row dashboard-row-3">
                        <div className="alerts-header">
                            <h3>Live Alerts</h3>
                            <span className="panel-pill">{filteredAlerts.length} visible</span>
                        </div>

                        {filteredAlerts.length === 0 ? (
                            <div className="panel-empty">
                                No alerts match the current filter.
                                <br />
                                {alertStats.total > 0 ? 'Try changing the filter for wider results.' : 'Waiting for WebSocket alerts...'}
                            </div>
                        ) : (
                            <div className="alert-list">
                                {filteredAlerts.slice(0, 14).map((alert, index) => (
                                    <div key={alert.id || index} className="alert-item">
                                        <div className="alert-item-header">
                                            <h6>{alert.final?.attack_type || 'Unknown Attack'}</h6>
                                            <span className={`severity-pill ${getSeverityClass(alert.final?.severity)}`}>
                                                {alert.final?.severity || 'Unknown'}
                                            </span>
                                        </div>

                                        <p className="alert-meta">
                                            {alert.protocol || 'N/A'} | {alert.src_ip || 'N/A'}:{alert.sport || '-'} -&gt;{' '}
                                            {alert.dst_ip || 'N/A'}:{alert.dport || '-'}
                                        </p>

                                        <div className="alert-footer">
                                            <span className="score-pill">Score: {alert.final?.final_score || 'N/A'}</span>
                                            <small>
                                                {alert.timestamp ? new Date(alert.timestamp).toLocaleString() : 'No timestamp'}
                                            </small>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>

                    <div className="dashboard-row dashboard-row-4 chart-slot">
                        <ProtocolPieChart />
                    </div>

                    <div className="dashboard-row dashboard-row-5 chart-slot">
                        <AttackDistributionChart />
                    </div>
                </div>
            </div>
        </div>
    );
}

export default Dashboard;
