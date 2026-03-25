import React, { useState, useEffect } from 'react';
import chartDataManager from '../server/chartDataManager.js';

const C = 80, R = 62;
const PROTOCOLS = [
  { name: 'TCP',   color: '#20d8de' },
  { name: 'UDP',   color: '#41e28f' },
  { name: 'ICMP',  color: '#ffbf47' },
  { name: 'Other', color: '#7e9cbd' },
];

function buildSegments(data) {
  const total = data.TCP + data.UDP + data.ICMP + data.Other;
  if (!total) return [];
  let start = -Math.PI / 2;
  return PROTOCOLS.map(({ name, color }) => {
    const v = data[name] || 0;
    let a = (v / total) * 2 * Math.PI;
    if (a >= 2 * Math.PI) a = 2 * Math.PI - 0.001;
    const end = start + a;
    const x1 = C + R * Math.cos(start), y1 = C + R * Math.sin(start);
    const x2 = C + R * Math.cos(end),   y2 = C + R * Math.sin(end);
    const path = `M${C} ${C} L${x1} ${y1} A${R} ${R} 0 ${a > Math.PI ? 1 : 0} 1 ${x2} ${y2}Z`;
    start = end;
    return { name, color, value: v, path };
  });
}

function ProtocolPieChart() {
  const [data, setData] = useState(chartDataManager.getProtocolData());

  useEffect(() => {
    const tick = () => setData(chartDataManager.getProtocolData());
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  const segments = buildSegments(data);

  return (
    <div className="chart-card">
      <div className="chart-card-header">
        <h5>Protocol Distribution</h5>
        <span className="chart-pill">{data.totalCount} TOTAL</span>
      </div>

      <div className="chart-card-body" style={{ flexDirection: 'row', alignItems: 'center', gap: 14, padding: '8px 14px' }}>
        {/* Compact donut SVG */}
        <svg viewBox="0 0 160 160" style={{ width: 120, height: 120, flexShrink: 0 }}>
          {segments.length ? segments.map(s => (
            <path key={s.name} d={s.path} fill={s.color} stroke="rgba(6,20,35,0.9)" strokeWidth="1.5" opacity="0.95" />
          )) : (
            <circle cx={C} cy={C} r={R} fill="rgba(20,40,65,0.7)" />
          )}
          <circle cx={C} cy={C} r="38" fill="rgba(10,24,41,0.98)" stroke="rgba(95,139,184,0.3)" strokeWidth="1.5" />
          <text x={C} y={C - 4} textAnchor="middle" fontSize="9" fill="#90abc7">packets</text>
          <text x={C} y={C + 13} textAnchor="middle" fontSize="15" fontWeight="700" fill="#d7ecff">{data.totalCount}</text>
        </svg>

        {/* Legend */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 7 }}>
          {PROTOCOLS.map(({ name, color }) => {
            const v = data[name] || 0;
            const pct = data.totalCount ? ((v / data.totalCount) * 100).toFixed(1) : '0.0';
            return (
              <div key={name} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ width: 8, height: 8, borderRadius: '50%', background: color, flexShrink: 0 }} />
                <span style={{ fontSize: '0.76rem', color: '#90abc7', flex: 1 }}>{name}</span>
                <span style={{ fontSize: '0.76rem', fontWeight: 700, color: '#d7ecff' }}>{v}</span>
                <span style={{ fontSize: '0.7rem', color: '#7e9cbd', minWidth: 38, textAlign: 'right' }}>{pct}%</span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

export default ProtocolPieChart;
