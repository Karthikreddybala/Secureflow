import React, { useState, useEffect } from 'react';
import { Card, CardHeader, CardBody } from 'react-bootstrap';
import chartDataManager from '../server/chartDataManager.js';

const PIE_CENTER = 150;
const PIE_RADIUS = 118;

function ProtocolPieChart() {
    const [protocolData, setProtocolData] = useState(chartDataManager.getProtocolData());

    useEffect(() => {
        const updateProtocolData = () => {
            const data = chartDataManager.getProtocolData();
            setProtocolData(data);
        };

        updateProtocolData();
        const interval = setInterval(updateProtocolData, 1000);

        return () => clearInterval(interval);
    }, []);

    const calculatePieSegments = () => {
        const total = protocolData.TCP + protocolData.UDP + protocolData.ICMP + protocolData.Other;
        if (total === 0) return [];

        const protocols = [
            { name: 'TCP', value: protocolData.TCP, color: '#20d8de' },
            { name: 'UDP', value: protocolData.UDP, color: '#41e28f' },
            { name: 'ICMP', value: protocolData.ICMP, color: '#ffbf47' },
            { name: 'Other', value: protocolData.Other, color: '#7e9cbd' }
        ];

        let startAngle = -Math.PI / 2;
        const segments = [];

        protocols.forEach((protocol) => {
            const percentage = protocol.value / total;
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
                ...protocol,
                percentage: percentage * 100,
                pathData
            });

            startAngle = endAngle;
        });

        return segments;
    };

    const segments = calculatePieSegments();

    return (
        <Card className="chart-card">
            <CardHeader className="chart-card-header">
                <h5>Protocol Distribution</h5>
                <span className="chart-pill">{protocolData.totalCount} TOTAL</span>
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
                            Protocol Mix
                        </text>
                        <text x={PIE_CENTER} y="162" textAnchor="middle" fontSize="28" fontWeight="700" fill="#d7ecff">
                            {protocolData.totalCount}
                        </text>
                        <text x={PIE_CENTER} y="179" textAnchor="middle" fontSize="11" fill="#90abc7">
                            packets analyzed
                        </text>
                    </svg>
                </div>

                <div className="pie-summary-grid">
                    {[
                        { name: 'TCP', value: protocolData.TCP, color: '#20d8de' },
                        { name: 'UDP', value: protocolData.UDP, color: '#41e28f' },
                        { name: 'ICMP', value: protocolData.ICMP, color: '#ffbf47' },
                        { name: 'Other', value: protocolData.Other, color: '#7e9cbd' }
                    ].map((item) => {
                        const percent = protocolData.totalCount ? ((item.value / protocolData.totalCount) * 100).toFixed(1) : '0.0';
                        return (
                            <div key={item.name} className="pie-summary-item" style={{ borderColor: `${item.color}66` }}>
                                <span className="name" style={{ color: item.color }}>
                                    {item.name}
                                </span>
                                <span className="value">{item.value}</span>
                                <span className="pct">{percent}%</span>
                            </div>
                        );
                    })}
                </div>
            </CardBody>
        </Card>
    );
}

export default ProtocolPieChart;
