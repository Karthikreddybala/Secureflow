import { socketManager } from './socket'
import chartDataManager from './chartDataManager'

const normalizeProtocolLabel = (value) => {
  const protocol = String(value ?? 'Unknown').toUpperCase()
  if (protocol === '6' || protocol === 'TCP') return 'TCP'
  if (protocol === '17' || protocol === 'UDP') return 'UDP'
  if (protocol === '1' || protocol === 'ICMP') return 'ICMP'
  return 'Other'
}

const isNormalTrafficAlert = (alert) => {
  const attackType = String(alert?.final?.attack_type ?? '').toLowerCase()
  return attackType === 'normal'
}

class GlobalSocketManager {
  constructor() {
    if (GlobalSocketManager.instance) {
      return GlobalSocketManager.instance
    }

    this.dispatch = null
    this.initialized = false
    this.connected = false

    this.handleAlertMessage = null
    this.handleNetworkMessage = null
    this.handleConnectionStatus = null

    GlobalSocketManager.instance = this
    return this
  }

  init(dispatch) {
    if (this.initialized) {
      return
    }

    this.dispatch = dispatch
    this.setupGlobalHandlers()
    this.connect()
    this.initialized = true
  }

  setupGlobalHandlers() {
    this.handleAlertMessage = (data) => {
      if (!this.dispatch) return

      this.dispatch({
        type: 'alerts/addAlert',
        payload: data
      })

      chartDataManager.updateNetworkTraffic(data, true)
      chartDataManager.updateProtocolFromAlert(data)
      chartDataManager.updateAttackData(!isNormalTrafficAlert(data))
    }

    this.handleNetworkMessage = (data) => {
      if (!this.dispatch) return

      const packets = Array.isArray(data) ? data : [data]
      if (packets.length === 0) return

      this.dispatch({
        type: 'networkData/addNetworkData',
        payload: packets
      })

      chartDataManager.updateNetworkTraffic(packets, false)
      chartDataManager.updateProtocolData(packets)

      this.dispatch({
        type: 'chartData/updateNetworkTrafficData',
        payload: { count: packets.length }
      })

      const protocolCounts = packets.reduce((accumulator, packet) => {
        const protocol = normalizeProtocolLabel(packet?.proto ?? packet?.protocol)
        accumulator[protocol] = (accumulator[protocol] || 0) + 1
        return accumulator
      }, {})

      this.dispatch({
        type: 'chartData/updateProtocolDistributionBatch',
        payload: protocolCounts
      })
    }

    this.handleConnectionStatus = (status) => {
      if (!this.dispatch) return

      this.dispatch({
        type: 'connectionStatus/setAlertConnected',
        payload: status.isAlertConnected
      })

      this.dispatch({
        type: 'connectionStatus/setNetworkConnected',
        payload: status.isNetworkConnected
      })
    }

    socketManager.addAlertMessageHandler(this.handleAlertMessage)
    socketManager.addNetworkMessageHandler(this.handleNetworkMessage)
    socketManager.addConnectionStatusHandler(this.handleConnectionStatus)
  }

  connect() {
    if (this.connected) return

    socketManager.connect()
    this.connected = true
  }

  disconnect() {
    if (this.handleAlertMessage) {
      socketManager.removeAlertMessageHandler(this.handleAlertMessage)
    }

    if (this.handleNetworkMessage) {
      socketManager.removeNetworkMessageHandler(this.handleNetworkMessage)
    }

    if (this.handleConnectionStatus) {
      socketManager.removeConnectionStatusHandler(this.handleConnectionStatus)
    }

    socketManager.disconnect()
    this.connected = false
    this.initialized = false
    this.dispatch = null
  }
}

const globalSocketManager = new GlobalSocketManager()
export default globalSocketManager
