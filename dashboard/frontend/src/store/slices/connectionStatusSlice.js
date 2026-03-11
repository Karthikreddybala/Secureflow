import { createSlice } from '@reduxjs/toolkit'

const initialState = {
  isAlertConnected: false,
  isNetworkConnected: false,
  connectionStatus: 'disconnected', // 'connected', 'connecting', 'disconnected', 'error'
  lastConnectionAttempt: null,
  connectionError: null
}

export const connectionStatusSlice = createSlice({
  name: 'connectionStatus',
  initialState,
  reducers: {
    setAlertConnected: (state, action) => {
      state.isAlertConnected = action.payload
      state.lastConnectionAttempt = Date.now()
      if (action.payload) {
        state.connectionStatus = 'connected'
        state.connectionError = null
      } else {
        state.connectionStatus = 'disconnected'
      }
    },
    setNetworkConnected: (state, action) => {
      state.isNetworkConnected = action.payload
      state.lastConnectionAttempt = Date.now()
      if (action.payload) {
        state.connectionStatus = 'connected'
        state.connectionError = null
      } else {
        state.connectionStatus = 'disconnected'
      }
    },
    setConnectionStatus: (state, action) => {
      state.connectionStatus = action.payload
      state.lastConnectionAttempt = Date.now()
    },
    setConnectionError: (state, action) => {
      state.connectionError = action.payload
      state.connectionStatus = 'error'
      state.lastConnectionAttempt = Date.now()
    },
    clearConnectionError: (state) => {
      state.connectionError = null
      if (state.isAlertConnected || state.isNetworkConnected) {
        state.connectionStatus = 'connected'
      } else {
        state.connectionStatus = 'disconnected'
      }
    },
    resetConnectionStatus: (state) => {
      state.isAlertConnected = false
      state.isNetworkConnected = false
      state.connectionStatus = 'disconnected'
      state.lastConnectionAttempt = null
      state.connectionError = null
    }
  }
})

export const { 
  setAlertConnected, 
  setNetworkConnected, 
  setConnectionStatus,
  setConnectionError,
  clearConnectionError,
  resetConnectionStatus
} = connectionStatusSlice.actions

// Selectors
export const selectIsAlertConnected = (state) => state.connectionStatus.isAlertConnected
export const selectIsNetworkConnected = (state) => state.connectionStatus.isNetworkConnected
export const selectConnectionStatus = (state) => state.connectionStatus.connectionStatus
export const selectLastConnectionAttempt = (state) => state.connectionStatus.lastConnectionAttempt
export const selectConnectionError = (state) => state.connectionStatus.connectionError

export default connectionStatusSlice.reducer