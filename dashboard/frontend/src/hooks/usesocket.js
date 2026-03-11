import { useEffect, useState } from "react"
import { socketManager } from "../server/socket"

export default function useSocket(onAlertMessage, onNetworkMessage) {
  const [connectionStatus, setConnectionStatus] = useState({
    isAlertConnected: socketManager.isAlertConnected,
    isNetworkConnected: socketManager.isNetworkConnected
  })

  useEffect(() => {
    // Add the alert message handler
    if (onAlertMessage) {
      socketManager.addAlertMessageHandler(onAlertMessage)
    }

    // Add the network message handler if provided
    if (onNetworkMessage) {
      socketManager.addNetworkMessageHandler(onNetworkMessage)
    }

    // Add connection status handler to update state reactively
    const handleConnectionStatus = (status) => {
      setConnectionStatus(status)
    }
    socketManager.addConnectionStatusHandler(handleConnectionStatus)

    // Return cleanup function to remove the handlers when component unmounts
    return () => {
      if (onAlertMessage) {
        socketManager.removeAlertMessageHandler(onAlertMessage)
      }
      if (onNetworkMessage) {
        socketManager.removeNetworkMessageHandler(onNetworkMessage)
      }
      socketManager.removeConnectionStatusHandler(handleConnectionStatus)
    }
  }, [onAlertMessage, onNetworkMessage])

  // Expose connection status and send functions
  return {
    isAlertConnected: connectionStatus.isAlertConnected,
    isNetworkConnected: connectionStatus.isNetworkConnected,
    sendAlert: socketManager.sendAlert,
    sendNetwork: socketManager.sendNetwork
  }
}
