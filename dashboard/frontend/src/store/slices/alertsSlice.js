import { createSlice } from '@reduxjs/toolkit'

const initialState = {
  alerts: [],
  lastAlertTime: null,
  alertCount: 0,
  alertFilter: 'all', // 'all', 'high', 'medium', 'low', 'normal'
  alertSort: 'newest', // 'newest', 'oldest', 'severity', 'score'
  alertLimit: 50 // Maximum alerts to display
}

export const alertsSlice = createSlice({
  name: 'alerts',
  initialState,
  reducers: {
    addAlert: (state, action) => {
      // Add new alert to the beginning of the array
      state.alerts.unshift({
        ...action.payload,
        id: Date.now() + Math.random(), // Unique ID for React keys
        timestamp: action.payload.timestamp || Date.now()
      })
      
      // Keep only last 200 alerts to prevent memory issues (increased from 100)
      if (state.alerts.length > 200) {
        state.alerts = state.alerts.slice(0, 200)
      }
      
      state.lastAlertTime = Date.now()
      state.alertCount += 1
    },
    clearAlerts: (state) => {
      state.alerts = []
      state.lastAlertTime = null
      state.alertCount = 0
    },
    removeAlert: (state, action) => {
      state.alerts = state.alerts.filter(alert => alert.id !== action.payload)
    },
    setAlertFilter: (state, action) => {
      state.alertFilter = action.payload
    },
    setAlertSort: (state, action) => {
      state.alertSort = action.payload
    },
    setAlertLimit: (state, action) => {
      state.alertLimit = action.payload
    },
    clearOldAlerts: (state) => {
      // Keep only the most recent alerts based on limit
      if (state.alerts.length > state.alertLimit) {
        state.alerts = state.alerts.slice(0, state.alertLimit)
      }
    }
  }
})

export const { 
  addAlert, 
  clearAlerts, 
  removeAlert, 
  setAlertFilter, 
  setAlertSort, 
  setAlertLimit,
  clearOldAlerts 
} = alertsSlice.actions

// Helper function to get severity level for sorting
const getSeverityLevel = (severity) => {
  const level = severity?.toLowerCase()
  switch (level) {
    case 'high': return 3
    case 'medium': return 2
    case 'low': return 1
    case 'normal': return 0
    default: return 1
  }
}

// Selector for filtered and sorted alerts
export const selectFilteredAlerts = (state) => {
  const { alerts, alertFilter, alertSort, alertLimit } = state.alerts
  
  // Filter alerts based on severity
  let filteredAlerts = alerts
  if (alertFilter !== 'all') {
    filteredAlerts = alerts.filter(alert => {
      const severity = alert.final?.severity?.toLowerCase()
      const attackType = alert.final?.attack_type?.toLowerCase()
      
      switch (alertFilter) {
        case 'high':
          return severity === 'high'
        case 'medium':
          return severity === 'medium'
        case 'low':
          return severity === 'low'
        case 'normal':
          return attackType === 'normal'
        default:
          return true
      }
    })
  }
  
  // Sort alerts
  const sortedAlerts = [...filteredAlerts].sort((a, b) => {
    switch (alertSort) {
      case 'newest': {
        return (b.timestamp || 0) - (a.timestamp || 0)
      }
      case 'oldest': {
        return (a.timestamp || 0) - (b.timestamp || 0)
      }
      case 'severity': {
        const aSeverity = getSeverityLevel(a.final?.severity)
        const bSeverity = getSeverityLevel(b.final?.severity)
        if (aSeverity !== bSeverity) {
          return bSeverity - aSeverity // High severity first
        }
        return (b.timestamp || 0) - (a.timestamp || 0) // Then by time
      }
      case 'score': {
        const aScore = parseFloat(a.final?.final_score || 0)
        const bScore = parseFloat(b.final?.final_score || 0)
        if (aScore !== bScore) {
          return bScore - aScore // High score first
        }
        return (b.timestamp || 0) - (a.timestamp || 0) // Then by time
      }
      default: {
        return (b.timestamp || 0) - (a.timestamp || 0)
      }
    }
  })
  
  // Apply limit
  return sortedAlerts.slice(0, alertLimit)
}

// Selector for alert statistics
export const selectAlertStats = (state) => {
  const alerts = state.alerts.alerts
  const stats = {
    total: alerts.length,
    high: 0,
    medium: 0,
    low: 0,
    normal: 0,
    attacks: 0
  }
  
  alerts.forEach(alert => {
    const severity = alert.final?.severity?.toLowerCase()
    const attackType = alert.final?.attack_type?.toLowerCase()
    
    if (severity === 'high') stats.high++
    else if (severity === 'medium') stats.medium++
    else if (severity === 'low') stats.low++
    else if (attackType === 'normal') stats.normal++
    
    if (attackType !== 'normal') stats.attacks++
  })
  
  return stats
}

// Selectors
export const selectAlerts = (state) => state.alerts.alerts
export const selectLastAlertTime = (state) => state.alerts.lastAlertTime
export const selectAlertCount = (state) => state.alerts.alertCount
export const selectAlertFilter = (state) => state.alerts.alertFilter
export const selectAlertSort = (state) => state.alerts.alertSort
export const selectAlertLimit = (state) => state.alerts.alertLimit
export const selectHighSeverityAlerts = (state) => 
  state.alerts.alerts.filter(alert => 
    alert.final?.severity === 'High' || alert.final?.severity === 'HIGH'
  )

export default alertsSlice.reducer
