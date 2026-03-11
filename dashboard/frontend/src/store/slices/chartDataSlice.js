import { createSlice } from '@reduxjs/toolkit'

const MAX_CHART_POINTS = 240
const MAX_Y_VALUE = 100

const initialState = {
  networkTrafficData: {
    labels: [],
    datasets: [{
      label: 'Network Traffic',
      data: [],
      borderColor: 'rgb(75, 192, 192)',
      backgroundColor: 'rgba(75, 192, 192, 0.2)',
      tension: 0.1
    }]
  },
  protocolDistribution: {
    labels: ['TCP', 'UDP', 'ICMP', 'Other'],
    datasets: [{
      label: 'Protocol Distribution',
      data: [0, 0, 0, 0],
      backgroundColor: [
        'rgba(54, 162, 235, 0.8)',
        'rgba(75, 192, 192, 0.8)',
        'rgba(255, 159, 64, 0.8)',
        'rgba(201, 203, 207, 0.8)'
      ]
    }]
  },
  lastChartDataUpdate: null
}

export const chartDataSlice = createSlice({
  name: 'chartData',
  initialState,
  reducers: {
    updateNetworkTrafficData: (state, action) => {
      const now = new Date()
      const timeLabel = now.toLocaleTimeString()
      const count = Number(action.payload.count || 0)
      const clampedCount = Math.max(0, Math.min(MAX_Y_VALUE, count))
      
      // Add new data point
      state.networkTrafficData.labels.push(timeLabel)
      state.networkTrafficData.datasets[0].data.push(clampedCount)
      
      // Keep bounded history to avoid memory growth
      if (state.networkTrafficData.labels.length > MAX_CHART_POINTS) {
        state.networkTrafficData.labels.shift()
        state.networkTrafficData.datasets[0].data.shift()
      }
      
      state.lastChartDataUpdate = Date.now()
    },
    updateProtocolDistribution: (state, action) => {
      const { protocol, increment = 1 } = action.payload
      
      // Find protocol index
      const protocolIndex = state.protocolDistribution.labels.indexOf(protocol)
      if (protocolIndex !== -1) {
        state.protocolDistribution.datasets[0].data[protocolIndex] += increment
      } else {
        // Handle unknown protocol
        const otherIndex = state.protocolDistribution.labels.indexOf('Other')
        if (otherIndex !== -1) {
          state.protocolDistribution.datasets[0].data[otherIndex] += increment
        }
      }
      
      state.lastChartDataUpdate = Date.now()
    },
    updateProtocolDistributionBatch: (state, action) => {
      const protocolCounts = action.payload || {}

      Object.entries(protocolCounts).forEach(([protocol, count]) => {
        const protocolIndex = state.protocolDistribution.labels.indexOf(protocol)
        const targetIndex =
          protocolIndex !== -1
            ? protocolIndex
            : state.protocolDistribution.labels.indexOf('Other')

        if (targetIndex !== -1) {
          state.protocolDistribution.datasets[0].data[targetIndex] += Number(count || 0)
        }
      })

      state.lastChartDataUpdate = Date.now()
    },
    resetChartData: (state) => {
      state.networkTrafficData = initialState.networkTrafficData
      state.protocolDistribution = initialState.protocolDistribution
      state.lastChartDataUpdate = null
    },
    clearProtocolData: (state) => {
      state.protocolDistribution.datasets[0].data = [0, 0, 0, 0]
    }
  }
})

export const { 
  updateNetworkTrafficData, 
  updateProtocolDistribution, 
  updateProtocolDistributionBatch,
  resetChartData,
  clearProtocolData
} = chartDataSlice.actions

// Selectors
export const selectNetworkTrafficData = (state) => state.chartData.networkTrafficData
export const selectProtocolDistribution = (state) => state.chartData.protocolDistribution
export const selectLastChartDataUpdate = (state) => state.chartData.lastChartDataUpdate

export default chartDataSlice.reducer
