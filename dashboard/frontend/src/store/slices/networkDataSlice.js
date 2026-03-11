import { createSlice } from '@reduxjs/toolkit'

const initialState = {
  networkData: [],
  lastNetworkTime: null,
  packetCount: 0,
  isPaused: false
}

export const networkDataSlice = createSlice({
  name: 'networkData',
  initialState,
  reducers: {
    addNetworkData: (state, action) => {
      if (state.isPaused) return // Don't add data if paused

      // Handle batch data - if data is an array, process each packet
      if (Array.isArray(action.payload)) {
        // Process each packet in the batch
        const newPackets = action.payload.map(packet => ({
          timestamp: packet.timestamp || Date.now(),
          src: packet.src || 'Unknown',
          dst: packet.dst || 'Unknown',
          sport: packet.sport || '',
          dport: packet.dport || '',
          proto: packet.proto || '',
          size: packet.size || '',
          info: packet.info || '',
          type: 'packet',
          isAlert: false
        }))
        
        // Add new packets to the beginning
        state.networkData.unshift(...newPackets)
        state.packetCount += newPackets.length
      } else {
        // Handle single packet data
        const packet = {
          timestamp: action.payload.timestamp || Date.now(),
          src: action.payload.src || 'Unknown',
          dst: action.payload.dst || 'Unknown',
          sport: action.payload.sport || '',
          dport: action.payload.dport || '',
          proto: action.payload.proto || '',
          size: action.payload.size || '',
          info: action.payload.info || '',
          type: 'packet',
          isAlert: false
        }
        
        state.networkData.unshift(packet)
        state.packetCount += 1
      }
      
      // Keep only last 200 entries to prevent performance issues
      if (state.networkData.length > 200) {
        state.networkData = state.networkData.slice(0, 200)
      }
      
      state.lastNetworkTime = Date.now()
    },
    clearNetworkData: (state) => {
      state.networkData = []
      state.lastNetworkTime = null
      state.packetCount = 0
    },
    pauseNetworkData: (state) => {
      state.isPaused = true
    },
    resumeNetworkData: (state) => {
      state.isPaused = false
    },
    setNetworkDataFilter: (state, action) => {
      // This could be used for filtering data in the future
      state.filter = action.payload
    }
  }
})

export const { 
  addNetworkData, 
  clearNetworkData, 
  pauseNetworkData, 
  resumeNetworkData,
  setNetworkDataFilter 
} = networkDataSlice.actions

// Selectors
export const selectNetworkData = (state) => state.networkData.networkData
export const selectLastNetworkTime = (state) => state.networkData.lastNetworkTime
export const selectPacketCount = (state) => state.networkData.packetCount
export const selectIsNetworkPaused = (state) => state.networkData.isPaused

export default networkDataSlice.reducer