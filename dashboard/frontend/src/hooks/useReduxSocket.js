import { useEffect } from "react"
import { useDispatch, useSelector } from "react-redux"
import { socketManager } from "../server/socket"
import { 
  addAlert
} from "../store/slices/alertsSlice"
import { 
  setAlertConnected, 
  setNetworkConnected
} from "../store/slices/connectionStatusSlice"
import { 
  addNetworkData as addNetworkDataAction,
  pauseNetworkData,
  resumeNetworkData
} from "../store/slices/networkDataSlice"
import { 
  updateNetworkTrafficData as updateTrafficData,
  updateProtocolDistribution as updateProtocolData
} from "../store/slices/chartDataSlice"

export default function useReduxSocket() {
  const dispatch = useDispatch()
  const isPaused = useSelector(state => state.networkData.isPaused)

  useEffect(() => {
    // Add alert message handler
    const handleAlertMessage = (data) => {
      dispatch(addAlert(data))
    }

    // Add network message handler
    const handleNetworkMessage = (data) => {
      if (!isPaused) {
        dispatch(addNetworkDataAction(data))
        
        // Update chart data based on network data
        if (Array.isArray(data)) {
          // Batch of packets
          const packetCount = data.length
          dispatch(updateTrafficData({ count: packetCount }))
          
          // Update protocol distribution
          data.forEach(packet => {
            const protocol = String(packet.proto || 'Unknown')
            dispatch(updateProtocolData({ protocol, increment: 1 }))
          })
        } else {
          // Single packet
          dispatch(updateTrafficData({ count: 1 }))
          const protocol = String(data.proto || 'Unknown')
          dispatch(updateProtocolData({ protocol, increment: 1 }))
        }
      }
    }

    // Add connection status handlers
    const handleConnectionStatus = (status) => {
      dispatch(setAlertConnected(status.isAlertConnected))
      dispatch(setNetworkConnected(status.isNetworkConnected))
    }

    // Add handlers to socket manager
    socketManager.addAlertMessageHandler(handleAlertMessage)
    socketManager.addNetworkMessageHandler(handleNetworkMessage)
    socketManager.addConnectionStatusHandler(handleConnectionStatus)

    // Return cleanup function to remove the handlers when component unmounts
    return () => {
      socketManager.removeAlertMessageHandler(handleAlertMessage)
      socketManager.removeNetworkMessageHandler(handleNetworkMessage)
      socketManager.removeConnectionStatusHandler(handleConnectionStatus)
    }
  }, [dispatch, isPaused])

  // Expose Redux actions and selectors
  return {
    // Actions
    pauseNetworkData: () => dispatch(pauseNetworkData()),
    resumeNetworkData: () => dispatch(resumeNetworkData()),
    clearAlerts: () => dispatch({ type: 'alerts/clearAlerts' }),
    clearNetworkData: () => dispatch({ type: 'networkData/clearNetworkData' }),
    clearProtocolData: () => dispatch({ type: 'chartData/clearProtocolData' }),
    
    // Selectors
    alerts: useSelector(state => state.alerts.alerts),
    networkData: useSelector(state => state.networkData.networkData),
    isAlertConnected: useSelector(state => state.connectionStatus.isAlertConnected),
    isNetworkConnected: useSelector(state => state.connectionStatus.isNetworkConnected),
    isPaused: useSelector(state => state.networkData.isPaused),
    packetCount: useSelector(state => state.networkData.packetCount),
    alertCount: useSelector(state => state.alerts.alertCount),
    networkTrafficData: useSelector(state => state.chartData.networkTrafficData),
    protocolDistribution: useSelector(state => state.chartData.protocolDistribution),
    lastAlertTime: useSelector(state => state.alerts.lastAlertTime),
    lastNetworkTime: useSelector(state => state.networkData.lastNetworkTime)
  }
}