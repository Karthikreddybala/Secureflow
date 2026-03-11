const WEBSOCKET_URL = "ws://localhost:8000/ws/alerts/"
const NETWORK_WEBSOCKET_URL = "ws://localhost:8000/ws/network/"
const RECONNECT_INTERVAL = 3000
const MAX_RECONNECT_ATTEMPTS = 10

class WebSocketManager {
  constructor() {
    this.alertSocket = null
    this.networkSocket = null
    this.alertReconnectAttempts = 0
    this.networkReconnectAttempts = 0
    this.isAlertConnected = false
    this.isNetworkConnected = false
    this.alertMessageHandlers = []
    this.networkMessageHandlers = []
    this.connectionStatusHandlers = [] // New: handlers for connection status changes
    this.connectAlerts()
    this.connectNetwork()
  }

  // Add connection status handler
  addConnectionStatusHandler(handler) {
    this.connectionStatusHandlers.push(handler)
  }

  // Remove connection status handler
  removeConnectionStatusHandler(handler) {
    this.connectionStatusHandlers = this.connectionStatusHandlers.filter(h => h !== handler)
  }

  // Notify connection status changes
  notifyConnectionStatus() {
    this.connectionStatusHandlers.forEach(handler => handler({
      isAlertConnected: this.isAlertConnected,
      isNetworkConnected: this.isNetworkConnected
    }))
  }

  connectAlerts() {
    try {
      this.alertSocket = new WebSocket(WEBSOCKET_URL)
      
      this.alertSocket.onopen = () => {
        console.log("Alert WebSocket Connected")
        this.isAlertConnected = true
        this.alertReconnectAttempts = 0
        this.notifyAlertConnectionStatus(true)
        this.notifyConnectionStatus() // Notify status change
      }

      this.alertSocket.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)
          this.alertMessageHandlers.forEach(handler => handler(data))
        } catch (error) {
          console.error("Error parsing Alert WebSocket message:", error)
        }
      }

      this.alertSocket.onerror = (error) => {
        console.error("Alert WebSocket Error:", error)
        this.notifyAlertConnectionStatus(false)
        // Additional error logging for debugging
        console.error("Alert WebSocket error details:", {
          type: error.type,
          message: error.message,
          target: error.target ? {
            readyState: error.target.readyState,
            url: error.target.url
          } : null
        })
      }

      this.alertSocket.onclose = (event) => {
        console.log("Alert WebSocket Closed:", event.code, event.reason)
        this.isAlertConnected = false
        this.notifyAlertConnectionStatus(false)
        
        // Attempt to reconnect if not manually closed
        if (event.code !== 1000 && this.alertReconnectAttempts < MAX_RECONNECT_ATTEMPTS) {
          this.alertReconnectAttempts++
          console.log(`Attempting to reconnect alerts (${this.alertReconnectAttempts}/${MAX_RECONNECT_ATTEMPTS})...`)
          setTimeout(() => this.connectAlerts(), RECONNECT_INTERVAL * this.alertReconnectAttempts)
        }
      }
    } catch (error) {
      console.error("Failed to create Alert WebSocket connection:", error)
    }
  }

  connectNetwork() {
    try {
      this.networkSocket = new WebSocket(NETWORK_WEBSOCKET_URL)
      
      this.networkSocket.onopen = () => {
        console.log("Network WebSocket Connected")
        this.isNetworkConnected = true
        this.networkReconnectAttempts = 0
        this.notifyNetworkConnectionStatus(true)
        this.notifyConnectionStatus() // Notify status change
      }

      this.networkSocket.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)
          this.networkMessageHandlers.forEach(handler => handler(data))
        } catch (error) {
          console.error("Error parsing Network WebSocket message:", error)
        }
      }

      this.networkSocket.onerror = (error) => {
        console.error("Network WebSocket Error:", error)
        this.notifyNetworkConnectionStatus(false)
        // Additional error logging for debugging
        console.error("Network WebSocket error details:", {
          type: error.type,
          message: error.message,
          target: error.target ? {
            readyState: error.target.readyState,
            url: error.target.url
          } : null
        })
      }

      this.networkSocket.onclose = (event) => {
        console.log("Network WebSocket Closed:", event.code, event.reason)
        this.isNetworkConnected = false
        this.notifyNetworkConnectionStatus(false)
        
        // Attempt to reconnect if not manually closed
        if (event.code !== 1000 && this.networkReconnectAttempts < MAX_RECONNECT_ATTEMPTS) {
          this.networkReconnectAttempts++
          console.log(`Attempting to reconnect network (${this.networkReconnectAttempts}/${MAX_RECONNECT_ATTEMPTS})...`)
          setTimeout(() => this.connectNetwork(), RECONNECT_INTERVAL * this.networkReconnectAttempts)
        }
      }
    } catch (error) {
      console.error("Failed to create Network WebSocket connection:", error)
    }
  }

  addAlertMessageHandler(handler) {
    this.alertMessageHandlers.push(handler)
  }

  removeAlertMessageHandler(handler) {
    this.alertMessageHandlers = this.alertMessageHandlers.filter(h => h !== handler)
  }

  addNetworkMessageHandler(handler) {
    this.networkMessageHandlers.push(handler)
  }

  removeNetworkMessageHandler(handler) {
    this.networkMessageHandlers = this.networkMessageHandlers.filter(h => h !== handler)
  }

  notifyAlertConnectionStatus(connected) {
    // You can add UI notification logic here
    console.log(`Alert WebSocket connection status: ${connected ? 'Connected' : 'Disconnected'}`)
  }

  notifyNetworkConnectionStatus(connected) {
    // You can add UI notification logic here
    console.log(`Network WebSocket connection status: ${connected ? 'Connected' : 'Disconnected'}`)
  }

  close() {
    if (this.alertSocket) {
      this.alertSocket.close(1000, "Client disconnect")
    }
    if (this.networkSocket) {
      this.networkSocket.close(1000, "Client disconnect")
    }
  }

  sendAlert(data) {
    if (this.alertSocket && this.isAlertConnected) {
      this.alertSocket.send(JSON.stringify(data))
    } else {
      console.warn("Alert WebSocket not connected, cannot send message")
    }
  }

  sendNetwork(data) {
    if (this.networkSocket && this.isNetworkConnected) {
      this.networkSocket.send(JSON.stringify(data))
    } else {
      console.warn("Network WebSocket not connected, cannot send message")
    }
  }
}

export const socketManager = new WebSocketManager()
