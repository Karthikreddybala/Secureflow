const RECONNECT_BASE_MS = 1000
const MAX_RECONNECT_DELAY_MS = 5000

const resolveBaseSocketUrl = () => {
  const envBase = import.meta?.env?.VITE_WS_BASE_URL
  if (envBase) {
    return envBase.replace(/\/$/, '')
  }

  const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws'
  const host = window.location.hostname || '127.0.0.1'
  return `${protocol}://${host}:8000`
}

const ALERTS_URL = `${resolveBaseSocketUrl()}/ws/alerts/`
const NETWORK_URL = `${resolveBaseSocketUrl()}/ws/network/`

class WebSocketManager {
  constructor() {
    this.alertSocket = null
    this.networkSocket = null

    this.alertReconnectAttempts = 0
    this.networkReconnectAttempts = 0

    this.alertReconnectTimer = null
    this.networkReconnectTimer = null

    this.isAlertConnected = false
    this.isNetworkConnected = false

    this.alertMessageHandlers = new Set()
    this.networkMessageHandlers = new Set()
    this.connectionStatusHandlers = new Set()

    this.isManuallyClosed = false
  }

  connect() {
    this.isManuallyClosed = false
    this.connectAlerts()
    this.connectNetwork()
  }

  disconnect() {
    this.isManuallyClosed = true
    this.clearReconnectTimers()

    if (this.alertSocket) {
      this.alertSocket.close(1000, 'Client disconnect')
      this.alertSocket = null
    }

    if (this.networkSocket) {
      this.networkSocket.close(1000, 'Client disconnect')
      this.networkSocket = null
    }

    this.isAlertConnected = false
    this.isNetworkConnected = false
    this.notifyConnectionStatus()
  }

  clearReconnectTimers() {
    if (this.alertReconnectTimer) {
      clearTimeout(this.alertReconnectTimer)
      this.alertReconnectTimer = null
    }

    if (this.networkReconnectTimer) {
      clearTimeout(this.networkReconnectTimer)
      this.networkReconnectTimer = null
    }
  }

  notifyConnectionStatus() {
    const payload = {
      isAlertConnected: this.isAlertConnected,
      isNetworkConnected: this.isNetworkConnected
    }

    this.connectionStatusHandlers.forEach((handler) => {
      try {
        handler(payload)
      } catch (error) {
        console.error('Connection status handler failed:', error)
      }
    })
  }

  connectAlerts() {
    if (
      this.alertSocket &&
      (this.alertSocket.readyState === WebSocket.OPEN || this.alertSocket.readyState === WebSocket.CONNECTING)
    ) {
      return
    }

    try {
      this.alertSocket = new WebSocket(ALERTS_URL)

      this.alertSocket.onopen = () => {
        this.isAlertConnected = true
        this.alertReconnectAttempts = 0
        this.notifyConnectionStatus()
      }

      this.alertSocket.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)
          this.alertMessageHandlers.forEach((handler) => handler(data))
        } catch (error) {
          console.error('Error parsing alert message:', error)
        }
      }

      this.alertSocket.onerror = (error) => {
        console.error('Alert WebSocket error:', error)
      }

      this.alertSocket.onclose = (event) => {
        this.isAlertConnected = false
        this.notifyConnectionStatus()

        if (this.isManuallyClosed || event.code === 1000) {
          return
        }

        this.alertReconnectAttempts += 1
        const retryDelay = Math.min(
          RECONNECT_BASE_MS * Math.pow(2, this.alertReconnectAttempts - 1),
          MAX_RECONNECT_DELAY_MS
        )
        this.alertReconnectTimer = setTimeout(() => this.connectAlerts(), retryDelay)
      }
    } catch (error) {
      console.error('Failed to open alerts socket:', error)
    }
  }

  connectNetwork() {
    if (
      this.networkSocket &&
      (this.networkSocket.readyState === WebSocket.OPEN || this.networkSocket.readyState === WebSocket.CONNECTING)
    ) {
      return
    }

    try {
      this.networkSocket = new WebSocket(NETWORK_URL)

      this.networkSocket.onopen = () => {
        this.isNetworkConnected = true
        this.networkReconnectAttempts = 0
        this.notifyConnectionStatus()
      }

      this.networkSocket.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)
          this.networkMessageHandlers.forEach((handler) => handler(data))
        } catch (error) {
          console.error('Error parsing network message:', error)
        }
      }

      this.networkSocket.onerror = (error) => {
        console.error('Network WebSocket error:', error)
      }

      this.networkSocket.onclose = (event) => {
        this.isNetworkConnected = false
        this.notifyConnectionStatus()

        if (this.isManuallyClosed || event.code === 1000) {
          return
        }

        this.networkReconnectAttempts += 1
        const retryDelay = Math.min(
          RECONNECT_BASE_MS * Math.pow(2, this.networkReconnectAttempts - 1),
          MAX_RECONNECT_DELAY_MS
        )
        this.networkReconnectTimer = setTimeout(() => this.connectNetwork(), retryDelay)
      }
    } catch (error) {
      console.error('Failed to open network socket:', error)
    }
  }

  addAlertMessageHandler(handler) {
    this.alertMessageHandlers.add(handler)
  }

  removeAlertMessageHandler(handler) {
    this.alertMessageHandlers.delete(handler)
  }

  addNetworkMessageHandler(handler) {
    this.networkMessageHandlers.add(handler)
  }

  removeNetworkMessageHandler(handler) {
    this.networkMessageHandlers.delete(handler)
  }

  addConnectionStatusHandler(handler) {
    this.connectionStatusHandlers.add(handler)
  }

  removeConnectionStatusHandler(handler) {
    this.connectionStatusHandlers.delete(handler)
  }

  sendAlert(data) {
    if (this.alertSocket && this.alertSocket.readyState === WebSocket.OPEN) {
      this.alertSocket.send(JSON.stringify(data))
    }
  }

  sendNetwork(data) {
    if (this.networkSocket && this.networkSocket.readyState === WebSocket.OPEN) {
      this.networkSocket.send(JSON.stringify(data))
    }
  }
}

export const socketManager = new WebSocketManager()
