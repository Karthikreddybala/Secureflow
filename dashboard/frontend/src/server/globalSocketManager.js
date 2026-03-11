import { socketManager } from './socket';
import chartDataManager from './chartDataManager';

// Global socket manager singleton that connects once and updates Redux globally
class GlobalSocketManager {
  constructor() {
    if (GlobalSocketManager.instance) {
      return GlobalSocketManager.instance;
    }
    
    this.isConnected = false;
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 10;
    this.reconnectInterval = 3000;
    this.dispatch = null;
    
    GlobalSocketManager.instance = this;
    return this;
  }

  // Initialize global socket connections with Redux dispatch
  init(dispatch) {
    if (this.dispatch) return; // Already initialized
    
    this.dispatch = dispatch;
    this.setupGlobalHandlers();
    this.connect();
  }

  setupGlobalHandlers() {
    // Global alert message handler
    const handleAlertMessage = (data) => {
      if (this.dispatch) {
        this.dispatch({
          type: 'alerts/addAlert',
          payload: {
            ...data,
            id: Date.now() + Math.random(),
            timestamp: data.timestamp || Date.now()
          }
        });

        // Update chart data manager for alerts
        chartDataManager.updateNetworkTraffic(data, true);
        chartDataManager.updateProtocolFromAlert(data);
        chartDataManager.updateAttackData(true); // Mark as attack
      }
    };

    // Global network message handler
    const handleNetworkMessage = (data) => {
      if (this.dispatch) {
        // Update network data
        const networkData = Array.isArray(data) ? data : [data];
        this.dispatch({
          type: 'networkData/addNetworkData',
          payload: networkData
        });

        // Update chart data manager (for persistent charts)
        chartDataManager.updateNetworkTraffic(data, false);
        chartDataManager.updateProtocolData(data);

        // Update chart data in Redux (for other components)
        const packetCount = networkData.length;
        this.dispatch({
          type: 'chartData/updateNetworkTrafficData',
          payload: { count: packetCount }
        });

        // Update protocol distribution in Redux
        networkData.forEach(packet => {
          const protocol = String(packet.proto || 'Unknown');
          this.dispatch({
            type: 'chartData/updateProtocolDistribution',
            payload: { protocol, increment: 1 }
          });
        });
      }
    };

    // Global connection status handler
    const handleConnectionStatus = (status) => {
      if (this.dispatch) {
        this.dispatch({
          type: 'connectionStatus/setAlertConnected',
          payload: status.isAlertConnected
        });
        this.dispatch({
          type: 'connectionStatus/setNetworkConnected', 
          payload: status.isNetworkConnected
        });
      }
    };

    // Add handlers to socket manager
    socketManager.addAlertMessageHandler(handleAlertMessage);
    socketManager.addNetworkMessageHandler(handleNetworkMessage);
    socketManager.addConnectionStatusHandler(handleConnectionStatus);
  }

  connect() {
    if (this.isConnected) return;

    try {
      socketManager.connect();
      this.isConnected = true;
      this.reconnectAttempts = 0;
      console.log('Global socket manager connected');
    } catch (error) {
      console.error('Global socket connection failed:', error);
      this.handleReconnection();
    }
  }

  disconnect() {
    if (this.isConnected) {
      socketManager.disconnect();
      this.isConnected = false;
      console.log('Global socket manager disconnected');
    }
  }

  handleReconnection() {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.error('Max reconnection attempts reached');
      return;
    }

    this.reconnectAttempts++;
    const delay = this.reconnectAttempts * this.reconnectInterval;
    
    console.log(`Attempting to reconnect in ${delay}ms (attempt ${this.reconnectAttempts})`);
    
    setTimeout(() => {
      this.connect();
    }, delay);
  }

  // Get connection status
  getStatus() {
    return {
      isConnected: this.isConnected,
      reconnectAttempts: this.reconnectAttempts,
      maxReconnectAttempts: this.maxReconnectAttempts
    };
  }
}

// Create singleton instance
const globalSocketManager = new GlobalSocketManager();

export default globalSocketManager;