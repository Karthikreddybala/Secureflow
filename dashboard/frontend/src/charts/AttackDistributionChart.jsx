import React, { useState, useEffect } from 'react';
import { Card, CardHeader, CardBody } from 'react-bootstrap';
import chartDataManager from '../server/chartDataManager.js';

const PIE_CENTER = 150;
const PIE_RADIUS = 118;

function AttackDistributionChart() {
    const [attackData, setAttackData] = useState({
        normal: 0,
        attacks: 0,
        total: 0
    });

    useEffect(() => {
        const updateAttackData = () => {
            const data = chartDataManager.getAttackData();
            setAttackData(data);
        };

        updateAttackData();
        const interval = setInterval(updateAttackData, 1000);

        return () => clearInterval(interval);
    }, []);

    const calculatePieSegments = () => {
        const total = attackData.normal + attackData.attacks;
        if (total === 0) return [];

        const attackTypes = [
            { name: 'Normal', value: attackData.normal, color: '#41e28f' },
            { name: 'Attack', value: attackData.attacks, color: '#ff5d73' }
        ];

        let startAngle = -Math.PI / 2;
        const segments = [];

        attackTypes.forEach((type) => {
            const percentage = type.value / total;
            let angle = percentage * 2 * Math.PI;
            if (angle >= 2 * Math.PI) {
                angle = 2 * Math.PI - 0.0001;
            }

            const endAngle = startAngle + angle;
            const x1 = PIE_CENTER + PIE_RADIUS * Math.cos(startAngle);
            const y1 = PIE_CENTER + PIE_RADIUS * Math.sin(startAngle);
            const x2 = PIE_CENTER + PIE_RADIUS * Math.cos(endAngle);
            const y2 = PIE_CENTER + PIE_RADIUS * Math.sin(endAngle);
            const largeArcFlag = angle > Math.PI ? 1 : 0;

            const pathData = [
                `M ${PIE_CENTER} ${PIE_CENTER}`,
                `L ${x1} ${y1}`,
                `A ${PIE_RADIUS} ${PIE_RADIUS} 0 ${largeArcFlag} 1 ${x2} ${y2}`,
                'Z'
            ].join(' ');

            segments.push({
                ...type,
                percentage: percentage * 100,
                pathData
            });

            startAngle = endAngle;
        });

        return segments;
    };

    const segments = calculatePieSegments();
    const attackPct = attackData.total ? ((attackData.attacks / attackData.total) * 100).toFixed(1) : '0.0';
    const normalPct = attackData.total ? ((attackData.normal / attackData.total) * 100).toFixed(1) : '0.0';

    return (
        <Card className="chart-card">
            <CardHeader className="chart-card-header">
                <h5>Attack Distribution</h5>
                <span className="chart-pill">{attackData.total} TOTAL</span>
            </CardHeader>

            <CardBody className="chart-card-body">
                <div className="pie-stage">
                    <svg className="pie-svg" viewBox="0 0 300 300" preserveAspectRatio="xMidYMid meet">
                        {segments.map((segment) => (
                            <path
                                key={segment.name}
                                d={segment.pathData}
                                fill={segment.color}
                                stroke="rgba(6, 20, 35, 0.9)"
                                strokeWidth="2"
                                opacity="0.96"
                            />
                        ))}

                        <circle cx={PIE_CENTER} cy={PIE_CENTER} r="62" fill="rgba(10, 24, 41, 0.98)" stroke="rgba(95, 139, 184, 0.45)" strokeWidth="2" />

                        <text x={PIE_CENTER} y="140" textAnchor="middle" fontSize="13" fill="#90abc7">
                            Security Signal
                        </text>
                        <text x={PIE_CENTER} y="162" textAnchor="middle" fontSize="20" fontWeight="700" fill="#d7ecff">
                            {attackData.attacks > 0 ? 'UNDER ATTACK' : 'NORMAL'}
                        </text>
                        <text x={PIE_CENTER} y="179" textAnchor="middle" fontSize="11" fill="#90abc7">
                            attack ratio {attackPct}%
                        </text>
                    </svg>
                </div>

                <div className="pie-summary-grid attack">
                    <div className="pie-summary-item" style={{ borderColor: '#41e28f66' }}>
                        <span className="name" style={{ color: '#41e28f' }}>
                            Normal
                        </span>
                        <span className="value">{attackData.normal}</span>
                        <span className="pct">{normalPct}%</span>
                    </div>
                    <div className="pie-summary-item" style={{ borderColor: '#ff5d7366' }}>
                        <span className="name" style={{ color: '#ff5d73' }}>
                            Attack
                        </span>
                        <span className="value">{attackData.attacks}</span>
                        <span className="pct">{attackPct}%</span>
                    </div>
                </div>
            </CardBody>
        </Card>
    );
}

export default AttackDistributionChart;
