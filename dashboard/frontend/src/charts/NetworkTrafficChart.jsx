import React, { useState, useRef, useEffect } from 'react';
import { Card, CardHeader, CardBody } from 'react-bootstrap';
import { Line } from 'react-chartjs-2';
import chartDataManager from '../server/chartDataManager.js';
import {
    Chart as ChartJS,
    CategoryScale,
    LinearScale,
    PointElement,
    LineElement,
    Title,
    Tooltip,
    Legend,
    TimeScale
} from 'chart.js';
import 'chartjs-adapter-date-fns';

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Title, Tooltip, Legend, TimeScale);

function NetworkTrafficChart() {
    const [chartData, setChartData] = useState(chartDataManager.getNetworkTrafficData());
    const chartRef = useRef(null);

    useEffect(() => {
        const updateChartData = () => {
            const data = chartDataManager.getNetworkTrafficData();
            setChartData(data);
        };

        updateChartData();
        const interval = setInterval(updateChartData, 1000);
        return () => clearInterval(interval);
    }, []);

    const chartOptions = {
        responsive: true,
        maintainAspectRatio: false,
        interaction: {
            mode: 'index',
            intersect: false
        },
        plugins: {
            legend: {
                position: 'top',
                labels: {
                    color: '#c7ddf6',
                    usePointStyle: true,
                    pointStyle: 'circle',
                    padding: 16
                }
            },
            tooltip: {
                backgroundColor: 'rgba(6, 16, 29, 0.94)',
                borderColor: 'rgba(90, 140, 190, 0.55)',
                borderWidth: 1,
                titleColor: '#eff6ff',
                bodyColor: '#d4e7ff',
                callbacks: {
                    label: (context) => {
                        const label = context.dataset.label || '';
                        const value = context.parsed.y;
                        return `${label}: ${value} ${value === 1 ? 'event' : 'events'}`;
                    }
                }
            }
        },
        scales: {
            x: {
                ticks: {
                    color: '#9bb6d4',
                    maxRotation: 0,
                    autoSkip: true,
                    maxTicksLimit: 8
                },
                grid: {
                    color: 'rgba(79, 118, 161, 0.2)'
                },
                border: {
                    color: 'rgba(79, 118, 161, 0.35)'
                }
            },
            y: {
                beginAtZero: true,
                ticks: {
                    color: '#9bb6d4',
                    stepSize: 1
                },
                grid: {
                    color: 'rgba(79, 118, 161, 0.22)'
                },
                border: {
                    color: 'rgba(79, 118, 161, 0.35)'
                }
            }
        },
        animation: {
            duration: 550,
            easing: 'easeOutQuart'
        }
    };

    return (
        <Card className="chart-card">
            <CardHeader className="chart-card-header">
                <h5>Network Traffic Timeline</h5>
                <span className="chart-pill">LIVE</span>
            </CardHeader>
            <CardBody className="chart-card-body">
                <div className="chart-canvas-shell">
                    <Line ref={chartRef} data={chartData} options={chartOptions} />
                </div>
            </CardBody>
        </Card>
    );
}

export default NetworkTrafficChart;
