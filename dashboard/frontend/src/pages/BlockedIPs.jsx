import React, { useMemo } from 'react';
import { useSelector } from 'react-redux';
import './css/blockedip.css';
import { selectFilteredAlerts, selectAlertStats } from '../store/slices/alertsSlice';

function calculateSeverityWeight(severity) {
  const key = (severity || '').toLowerCase();
  if (key === 'high') return 3;
  if (key === 'medium') return 2;
  if (key === 'low') return 1;
  return 1;
}

function BlockedIPs() {
  const filteredAlerts = useSelector((state) => selectFilteredAlerts(state));
  const alertStats = useSelector((state) => selectAlertStats(state));

  const sourceProfiles = useMemo(() => {
    const profileMap = new Map();

    filteredAlerts.forEach((alert) => {
      const sourceIp = alert.src_ip || alert.src || 'Unknown';
      const destinationIp = alert.dst_ip || alert.dst || 'Unknown';
      const severity = alert.final?.severity || 'Unknown';
      const attackType = alert.final?.attack_type || 'Unknown';
      const score = Number(alert.final?.final_score || 0);

      if (!profileMap.has(sourceIp)) {
        profileMap.set(sourceIp, {
          ip: sourceIp,
          hits: 0,
          highestSeverity: 'Low',
          severityWeight: 0,
          destinations: new Set(),
          attackTypes: new Set(),
          scoreTotal: 0,
          lastSeen: null
        });
      }

      const profile = profileMap.get(sourceIp);
      profile.hits += 1;
      profile.destinations.add(destinationIp);
      profile.attackTypes.add(attackType);
      profile.scoreTotal += score;

      const severityWeight = calculateSeverityWeight(severity);
      if (severityWeight >= profile.severityWeight) {
        profile.severityWeight = severityWeight;
        profile.highestSeverity = severity;
      }

      const timestamp = alert.timestamp ? new Date(alert.timestamp).getTime() : 0;
      if (!profile.lastSeen || timestamp > profile.lastSeen) {
        profile.lastSeen = timestamp;
      }
    });

    return Array.from(profileMap.values())
      .map((profile) => ({
        ...profile,
        destinationCount: profile.destinations.size,
        attackTypeCount: profile.attackTypes.size,
        riskScore: Math.round(profile.hits * 10 + profile.severityWeight * 14 + profile.scoreTotal),
        avgScore: profile.hits ? (profile.scoreTotal / profile.hits).toFixed(2) : '0.00'
      }))
      .sort((left, right) => right.riskScore - left.riskScore);
  }, [filteredAlerts]);

  const destinationFocus = useMemo(() => {
    const destinationMap = new Map();

    filteredAlerts.forEach((alert) => {
      const destinationIp = alert.dst_ip || alert.dst || 'Unknown';
      destinationMap.set(destinationIp, (destinationMap.get(destinationIp) || 0) + 1);
    });

    return Array.from(destinationMap.entries())
      .map(([ip, hits]) => ({ ip, hits }))
      .sort((left, right) => right.hits - left.hits)
      .slice(0, 8);
  }, [filteredAlerts]);

  const recentEvents = filteredAlerts.slice(0, 10);

  return (
    <div className="cyber-page blockedip-page">
      <div className="blocked-layout">
        <section className="blocked-overview cyber-panel">
          <div className="cyber-panel-header">
            <div>
              <h2 className="cyber-panel-title">Blocked IP Intelligence</h2>
              <p className="cyber-panel-subtitle">Hostile source profiling based on observed alert traffic.</p>
            </div>
            <span className="cyber-pill">{sourceProfiles.length} Sources</span>
          </div>

          <div className="cyber-kpi-grid blocked-kpis">
            <div className="cyber-kpi-card">
              <span className="cyber-kpi-label">Alert Volume</span>
              <span className="cyber-kpi-value">{alertStats.total}</span>
            </div>
            <div className="cyber-kpi-card">
              <span className="cyber-kpi-label">Attack Alerts</span>
              <span className="cyber-kpi-value">{alertStats.attacks}</span>
            </div>
            <div className="cyber-kpi-card">
              <span className="cyber-kpi-label">High Severity</span>
              <span className="cyber-kpi-value">{alertStats.high}</span>
            </div>
            <div className="cyber-kpi-card">
              <span className="cyber-kpi-label">Tracked Sources</span>
              <span className="cyber-kpi-value">{sourceProfiles.length}</span>
            </div>
          </div>
        </section>

        <section className="blocked-main cyber-panel">
          <div className="cyber-panel-header">
            <h3 className="cyber-panel-title">Hostile Source Ranking</h3>
            <span className="cyber-pill">Risk Ordered</span>
          </div>

          {sourceProfiles.length === 0 ? (
            <div className="cyber-empty">No suspicious source profiles available yet.</div>
          ) : (
            <div className="blocked-table-scroll">
              <table className="blocked-table">
                <thead>
                  <tr>
                    <th>Source IP</th>
                    <th>Risk Score</th>
                    <th>Hits</th>
                    <th>Severity</th>
                    <th>Targets</th>
                    <th>Attack Types</th>
                    <th>Avg Score</th>
                    <th>Last Seen</th>
                  </tr>
                </thead>
                <tbody>
                  {sourceProfiles.slice(0, 24).map((profile) => (
                    <tr key={profile.ip}>
                      <td>
                        <code>{profile.ip}</code>
                      </td>
                      <td>{profile.riskScore}</td>
                      <td>{profile.hits}</td>
                      <td>
                        <span className={`blocked-severity ${(profile.highestSeverity || 'low').toLowerCase()}`}>{profile.highestSeverity}</span>
                      </td>
                      <td>{profile.destinationCount}</td>
                      <td>{profile.attackTypeCount}</td>
                      <td>{profile.avgScore}</td>
                      <td>{profile.lastSeen ? new Date(profile.lastSeen).toLocaleTimeString() : 'N/A'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <aside className="blocked-side">
          <article className="blocked-side-card cyber-panel">
            <div className="cyber-panel-header">
              <h3 className="cyber-panel-title">Most Targeted Destinations</h3>
              <span className="cyber-pill">Top 8</span>
            </div>
            {destinationFocus.length === 0 ? (
              <div className="cyber-empty">No destination hotspots detected.</div>
            ) : (
              <ul className="cyber-list">
                {destinationFocus.map((destination) => (
                  <li key={destination.ip} className="cyber-list-item blocked-list-item">
                    <code>{destination.ip}</code>
                    <strong>{destination.hits} hits</strong>
                  </li>
                ))}
              </ul>
            )}
          </article>

          <article className="blocked-side-card cyber-panel">
            <div className="cyber-panel-header">
              <h3 className="cyber-panel-title">Recent Suspicious Events</h3>
              <span className="cyber-pill">Latest 10</span>
            </div>
            {recentEvents.length === 0 ? (
              <div className="cyber-empty">No recent suspicious events.</div>
            ) : (
              <ul className="cyber-list blocked-event-list">
                {recentEvents.map((alert, index) => (
                  <li key={alert.id || index} className="cyber-list-item blocked-event-item">
                    <div>
                      <p>{alert.final?.attack_type || 'Unknown Attack'}</p>
                      <small>
                        {alert.src_ip || 'N/A'} -&gt; {alert.dst_ip || 'N/A'}
                      </small>
                    </div>
                    <span className={`blocked-severity ${(alert.final?.severity || 'low').toLowerCase()}`}>{alert.final?.severity || 'Unknown'}</span>
                  </li>
                ))}
              </ul>
            )}
          </article>
        </aside>
      </div>
    </div>
  );
}

export default BlockedIPs;
