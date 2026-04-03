import React, { useState, useEffect } from 'react';
import chartDataManager from '../server/chartDataManager.js';

const C = 80, R = 62;

function buildSegments(normal, attacks) {
  const total = normal + attacks;
  if (!total) return [];
  const items = [
    { name: 'Normal', value: normal, color: '#41e28f' },
    { name: 'Attack', value: attacks, color: '#ff5d73' },
  ];
  let start = -Math.PI / 2;
  return items.map(({ name, value, color }) => {
    let a = (value / total) * 2 * Math.PI;
    if (a >= 2 * Math.PI) a = 2 * Math.PI - 0.001;
    const end = start + a;
    const x1 = C + R * Math.cos(start), y1 = C + R * Math.sin(start);
    const x2 = C + R * Math.cos(end),   y2 = C + R * Math.sin(end);
    const path = `M${C} ${C} L${x1} ${y1} A${R} ${R} 0 ${a > Math.PI ? 1 : 0} 1 ${x2} ${y2}Z`;
    start = end;
    return { name, value, color, path };
  });
}

function AttackDistributionChart() {
  const [data, setData] = useState({ normal: 0, attacks: 0, total: 0 });

  useEffect(() => {
    const tick = () => setData(chartDataManager.getAttackData());
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  const segments = buildSegments(data.normal, data.attacks);
  const attackPct = data.total ? ((data.attacks / data.total) * 100).toFixed(1) : '0.0';
  const normalPct = data.total ? ((data.normal / data.total) * 100).toFixed(1) : '0.0';
  const isUnderAttack = data.attacks > 0;

  return (
    <div className="chart-card">
      <div className="chart-card-header">
        <h5>Attack Distribution</h5>
        <span className="chart-pill" style={{ color: isUnderAttack ? '#ff5d73' : '#41e28f', borderColor: isUnderAttack ? 'rgba(255,93,115,0.5)' : 'rgba(65,226,143,0.5)', background: isUnderAttack ? 'rgba(255,93,115,0.1)' : 'rgba(65,226,143,0.1)' }}>
          {isUnderAttack ? '⚠ ATTACK' : '✓ NORMAL'}
        </span>
      </div>

      <div className="chart-card-body" style={{ flexDirection: 'row', alignItems: 'center', gap: 14, padding: '8px 14px' }}>
        {/* Compact donut */}
        <svg viewBox="0 0 160 160" style={{ width: 120, height: 120, flexShrink: 0 }}>
          {segments.length ? segments.map(s => (
            <path key={s.name} d={s.path} fill={s.color} stroke="rgba(6,20,35,0.9)" strokeWidth="1.5" opacity="0.95" />
          )) : (
            <circle cx={C} cy={C} r={R} fill="rgba(20,40,65,0.7)" />
          )}
          <circle cx={C} cy={C} r="38" fill="rgba(10,24,41,0.98)" stroke="rgba(95,139,184,0.3)" strokeWidth="1.5" />
          <text x={C} y={C - 6} textAnchor="middle" fontSize="8" fill="#90abc7">attack ratio</text>
          <text x={C} y={C + 11} textAnchor="middle" fontSize="18" fontWeight="700" fill={isUnderAttack ? '#ff5d73' : '#41e28f'}>{attackPct}%</text>
        </svg>

        {/* Stats */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 10 }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#41e28f', flexShrink: 0 }} />
              <span style={{ fontSize: '0.76rem', color: '#90abc7', flex: 1 }}>Normal</span>
              <span style={{ fontSize: '0.76rem', fontWeight: 700, color: '#d7ecff' }}>{data.normal}</span>
              <span style={{ fontSize: '0.7rem', color: '#7e9cbd', minWidth: 38, textAlign: 'right' }}>{normalPct}%</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#ff5d73', flexShrink: 0 }} />
              <span style={{ fontSize: '0.76rem', color: '#90abc7', flex: 1 }}>Attack</span>
              <span style={{ fontSize: '0.76rem', fontWeight: 700, color: '#d7ecff' }}>{data.attacks}</span>
              <span style={{ fontSize: '0.7rem', color: '#7e9cbd', minWidth: 38, textAlign: 'right' }}>{attackPct}%</span>
            </div>
          </div>
          <div style={{ borderTop: '1px solid rgba(95,139,184,0.2)', paddingTop: 8 }}>
            <div style={{ fontSize: '0.68rem', color: '#90abc7' }}>Total analyzed</div>
            <div style={{ fontSize: '1.1rem', fontWeight: 700, color: '#d7ecff' }}>{data.total}</div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default AttackDistributionChart;
