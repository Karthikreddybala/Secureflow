import React, { useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { Provider } from 'react-redux';
import './App.css';
import 'bootstrap/dist/css/bootstrap.min.css';
import 'bootstrap/dist/js/bootstrap.bundle.min';
import { AuthProvider, useAuth } from './context/AuthContext';
import ProtectedRoute from './components/ProtectedRoute';
import Header from './header.jsx';
import Dashboard from './pages/dashboard.jsx';
import RealTimeTraffic from './pages/RealTimeTraffic.jsx';
import BlockedIPs from './pages/BlockedIPs.jsx';
import AttackAnalytics from './pages/AttackAnalytics.jsx';
import AlertsPage from './pages/AlertsPage.jsx';
import NetworkFlows from './pages/NetworkFlows.jsx';
import Login from './pages/login.jsx';
import Register from './pages/register.jsx';
import AdminUsers from './pages/AdminUsers.jsx';
import HotspotDevices from './pages/HotspotDevices.jsx';
import DeviceEmails from './pages/DeviceEmails.jsx';
import { store } from './store/index.js';
import globalSocketManager from './server/globalSocketManager.js';
import { setupPushNotifications } from './server/pushNotifications.js';

/** Inner wrapper that initializes websocket after auth check */
function AppInner() {
  useEffect(() => {
    globalSocketManager.init(store.dispatch);
    // Register service worker + subscribe to Web Push (silently — user sees no prompt
    // unless VAPID keys are configured in the backend .env)
    setupPushNotifications().then(res => {
      if (res.subscribed) console.info('[SecureFlow] Web push subscribed ✓');
      else if (res.reason) console.info('[SecureFlow] Push not active:', res.reason);
    });
    return () => globalSocketManager.disconnect();
  }, []);

  return (
    <Router>
      <Routes>
        {/* Public Routes */}
        <Route path="/login"    element={<Login />} />
        <Route path="/register" element={<Register />} />

        {/* Protected layout (sidebar + content) */}
        <Route path="/*" element={
          <ProtectedRoute>
            <LayoutWithSidebar />
          </ProtectedRoute>
        } />
      </Routes>
    </Router>
  );
}

function LayoutWithSidebar() {
  return (
    <div style={{ display: 'flex', minHeight: '100vh' }}>
      <Header />
      <main style={{ flex: 1, marginLeft: 'var(--sidebar-w, 220px)', minHeight: '100vh', transition: 'margin-left 0.25s cubic-bezier(0.4,0,0.2,1)', overflowX: 'hidden' }}>
        <Routes>
          <Route path="/"              element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard"     element={<Dashboard />} />
          <Route path="/traffic"       element={<RealTimeTraffic />} />
          <Route path="/blocked-ips"   element={<BlockedIPs />} />
          <Route path="/analytics"     element={<AttackAnalytics />} />
          <Route path="/alerts"        element={<AlertsPage />} />
          <Route path="/flows"         element={<NetworkFlows />} />
          <Route path="/hotspot"            element={<HotspotDevices />} />
          <Route path="/admin/users"        element={<ProtectedRoute adminOnly><AdminUsers /></ProtectedRoute>} />
          <Route path="/device-emails"      element={<ProtectedRoute adminOnly><DeviceEmails /></ProtectedRoute>} />
        </Routes>
      </main>
    </div>
  );
}

function App() {
  return (
    <Provider store={store}>
      <AuthProvider>
        <AppInner />
      </AuthProvider>
    </Provider>
  );
}

export default App;
