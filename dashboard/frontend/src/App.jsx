import React, { useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
import { Provider } from 'react-redux'
import './App.css'
import 'bootstrap/dist/css/bootstrap.min.css';
import 'bootstrap/dist/js/bootstrap.bundle.min';
import Header from './header.jsx'
import Home from './pages/home.jsx'
import RealTimeTraffic from './pages/RealTimeTraffic.jsx'
import BlockedIPs from './pages/BlockedIPs.jsx'
import AttackAnalytics from './pages/AttackAnalytics.jsx'
// import Profile from './pages/Profile.jsx'
// import Settings from './pages/Settings.jsx'
// import Info from './pages/Info.jsx'
import Login from './pages/login.jsx'
import Register from './pages/register.jsx'
import Dashboard from './pages/dashboard.jsx';
import { store } from './store/index.js'
import globalSocketManager from './server/globalSocketManager.js'

function App() {
  useEffect(() => {
    // Initialize global socket manager with Redux dispatch
    globalSocketManager.init(store.dispatch);
    
    // Cleanup on app unmount
    return () => {
      globalSocketManager.disconnect();
    };
  }, []);

  return (
    <Provider store={store}>
      <Router>
        <Header />
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/traffic" element={<RealTimeTraffic />} />
          <Route path="/blocked-ips" element={<BlockedIPs />} />
          <Route path="/analytics" element={<AttackAnalytics />} />
          {/* <Route path="/profile" element={<Profile />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/info" element={<Info />} /> */}
        </Routes>
      </Router>
    </Provider>
  )
}

export default App;
