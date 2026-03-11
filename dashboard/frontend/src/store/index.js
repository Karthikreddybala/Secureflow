import { configureStore } from '@reduxjs/toolkit'
import { combineReducers } from '@reduxjs/toolkit'

// Import reducers
import alertsReducer from './slices/alertsSlice'
import networkDataReducer from './slices/networkDataSlice'
import chartDataReducer from './slices/chartDataSlice'
import connectionStatusReducer from './slices/connectionStatusSlice'

// Combine all reducers
const rootReducer = combineReducers({
  alerts: alertsReducer,
  networkData: networkDataReducer,
  chartData: chartDataReducer,
  connectionStatus: connectionStatusReducer
})

// Configure the store
export const store = configureStore({
  reducer: rootReducer,
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware({
      serializableCheck: false, // Disable serializable check for simplicity
    }),
})
