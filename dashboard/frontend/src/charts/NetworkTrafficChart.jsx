import React, { useEffect, useMemo, useRef, useState } from 'react'
import { Card, CardHeader, CardBody } from 'react-bootstrap'
import { Line } from 'react-chartjs-2'
import chartDataManager from '../server/chartDataManager.js'
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
} from 'chart.js'
import 'chartjs-adapter-date-fns'

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Title, Tooltip, Legend, TimeScale)

const MIN_TRACK_WIDTH = 860
const PIXELS_PER_POINT = 26
const RIGHT_EDGE_MARGIN = 24

function NetworkTrafficChart() {
  const [chartData, setChartData] = useState(chartDataManager.getNetworkTrafficData())
  const [followLatest, setFollowLatest] = useState(true)
  const chartRef = useRef(null)
  const scrollShellRef = useRef(null)

  useEffect(() => {
    const updateChartData = () => {
      setChartData(chartDataManager.getNetworkTrafficData())
    }

    updateChartData()
    const interval = setInterval(updateChartData, 500)
    return () => clearInterval(interval)
  }, [])

  const chartWidth = useMemo(() => {
    const points = Math.max(chartData.labels.length, 34)
    return Math.max(MIN_TRACK_WIDTH, points * PIXELS_PER_POINT)
  }, [chartData.labels.length])

  useEffect(() => {
    const shell = scrollShellRef.current
    if (!shell || !followLatest) {
      return
    }

    shell.scrollLeft = shell.scrollWidth
  }, [chartData.labels.length, followLatest])

  const handleScroll = () => {
    const shell = scrollShellRef.current
    if (!shell) return

    const distanceFromRight = shell.scrollWidth - shell.clientWidth - shell.scrollLeft
    setFollowLatest(distanceFromRight <= RIGHT_EDGE_MARGIN)
  }

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    interaction: {
      mode: 'index',
      intersect: false
    },
    elements: {
      line: {
        tension: 0,
        borderWidth: 2
      },
      point: {
        radius: 0,
        hoverRadius: 4,
        hitRadius: 10
      }
    },
    plugins: {
      legend: {
        position: 'top',
        labels: {
          color: '#c7ddf6',
          usePointStyle: true,
          pointStyle: 'line',
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
            const label = context.dataset.label || ''
            const value = context.parsed.y
            return `${label}: ${value} ${value === 1 ? 'event' : 'events'}`
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
          maxTicksLimit: 12
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
        min: 0,
        max: 100,
        ticks: {
          color: '#9bb6d4',
          stepSize: 10
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
      duration: 180,
      easing: 'linear'
    }
  }

  return (
    <Card className="chart-card">
      <CardHeader className="chart-card-header">
        <h5>Network Traffic Timeline</h5>
        <span className="chart-pill">{followLatest ? 'LIVE' : 'HISTORY'}</span>
      </CardHeader>
      <CardBody className="chart-card-body">
        <div className="chart-history-hint">Scroll left or right to browse older and newer spikes.</div>
        <div className="chart-scroll-shell" ref={scrollShellRef} onScroll={handleScroll}>
          <div className="chart-scroll-track" style={{ width: `${chartWidth}px` }}>
            <div className="chart-canvas-shell">
              <Line ref={chartRef} data={chartData} options={chartOptions} />
            </div>
          </div>
        </div>
      </CardBody>
    </Card>
  )
}

export default NetworkTrafficChart
