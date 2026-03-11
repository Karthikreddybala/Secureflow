import React, { useMemo } from 'react';
import { useSelector } from 'react-redux';
import './css/attack.css';
import AlertControls from '../components/AlertControls.jsx';
import ProtocolPieChart from '../charts/ProtocolPieChart.jsx';
import AttackDistributionChart from '../charts/AttackDistributionChart.jsx';
import { selectFilteredAlerts, selectAlertStats } from '../store/slices/alertsSlice';

function AttackAnalytics() {
  const filteredAlerts = useSelector((state) => selectFilteredAlerts(state));
  const alertStats = useSelector((state) => selectAlertStats(state));

  const attackTypeBreakdown = useMemo(() => {
    const attackMap = new Map();

    filteredAlerts.forEach((alert) => {
      const attackType = alert.final?.attack_type || 'Unknown';
      attackMap.set(attackType, (attackMap.get(attackType) || 0) + 1);
    });

    return Array.from(attackMap.entries())
      .map(([type, count]) => ({ type, count }))
      .sort((left, right) => right.count - left.count)
      .slice(0, 8);
  }, [filteredAlerts]);

  const criticalAlerts = useMemo(() => {
    return filteredAlerts
      .filter((alert) => {
        const severity = (alert.final?.severity || '').toLowerCase();
        return severity === 'high' || severity === 'medium';
      })
      .slice(0, 10);
  }, [filteredAlerts]);

  const threatPressure = alertStats.total ? Math.round(((alertStats.high * 2 + alertStats.medium) / alertStats.total) * 100) : 0;

  return (
    <div className="cyber-page attack-page">
      <div className="attack-layout">
        <section className="attack-controls cyber-panel">
          <div className="cyber-panel-header">
            <div>
              <h2 className="cyber-panel-title">Threat Analytics Control</h2>
              <p className="cyber-panel-subtitle">Filter and sort incoming alerts to inspect attack behavior trends.</p>
            </div>
            <span className="cyber-pill">Pressure {threatPressure}%</span>
          </div>
          <AlertControls compact />
        </section>

        <section className="attack-charts">
          <div className="attack-chart-slot">
            <AttackDistributionChart />
          </div>
          <div className="attack-chart-slot">
            <ProtocolPieChart />
          </div>
        </section>

        <section className="attack-insights">
          <article className="attack-insight-card cyber-panel">
            <div className="cyber-panel-header">
              <h3 className="cyber-panel-title">Top Attack Classes</h3>
              <span className="cyber-pill">Top 8</span>
            </div>
            {attackTypeBreakdown.length === 0 ? (
              <div className="cyber-empty">No attack entries available for current filters.</div>
            ) : (
              <ul className="cyber-list attack-insight-list">
                {attackTypeBreakdown.map((entry) => (
                  <li key={entry.type} className="cyber-list-item attack-insight-item">
                    <span>{entry.type}</span>
                    <strong>{entry.count}</strong>
                  </li>
                ))}
              </ul>
            )}
          </article>

          <article className="attack-insight-card cyber-panel">
            <div className="cyber-panel-header">
              <h3 className="cyber-panel-title">Recent Critical Alerts</h3>
              <span className="cyber-pill">{criticalAlerts.length}</span>
            </div>
            {criticalAlerts.length === 0 ? (
              <div className="cyber-empty">No medium/high alerts found in current view.</div>
            ) : (
              <ul className="cyber-list attack-timeline-list">
                {criticalAlerts.map((alert, index) => (
                  <li key={alert.id || index} className="cyber-list-item attack-timeline-item">
                    <div>
                      <p className="attack-title">{alert.final?.attack_type || 'Unknown Attack'}</p>
                      <p className="attack-meta">
                        {alert.src_ip || 'N/A'}:{alert.sport || '-'} -&gt; {alert.dst_ip || 'N/A'}:{alert.dport || '-'}
                      </p>
                    </div>
                    <div className="attack-tag-wrap">
                      <span className={`attack-tag ${(alert.final?.severity || 'low').toLowerCase()}`}>{alert.final?.severity || 'Unknown'}</span>
                      <small>{alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : 'N/A'}</small>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </article>
        </section>
      </div>
    </div>
  );
}

export default AttackAnalytics;
