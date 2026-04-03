/* SecureFlow Service Worker — Web Push handler
   Receives push payloads from the Django backend (pywebpush / VAPID)
   and shows OS-level notifications even when the tab is in the background. */

const CACHE_NAME = 'secureflow-sw-v1';

// ── Push event: show notification ──────────────────────────────
self.addEventListener('push', (event) => {
  if (!event.data) return;

  let data;
  try {
    data = event.data.json();
  } catch {
    data = {
      title: '🚨 SecureFlow Alert',
      body: event.data.text(),
      icon: '/vite.svg',
    };
  }

  const title   = data.title || '🚨 SecureFlow Alert';
  const options = {
    body:    data.body  || 'A security alert was detected.',
    icon:    data.icon  || '/vite.svg',
    badge:   data.badge || '/vite.svg',
    tag:     data.tag   || 'secureflow-alert',
    renotify: true,
    requireInteraction: (data.data?.severity === 'High'),
    data:    data.data  || { url: '/alerts' },
    actions: [
      { action: 'view',    title: '🔍 View Alerts' },
      { action: 'dismiss', title: '✕ Dismiss' },
    ],
    vibrate: [200, 100, 200],
  };

  event.waitUntil(
    self.registration.showNotification(title, options)
  );
});

// ── Notification click: open the dashboard ────────────────────
self.addEventListener('notificationclick', (event) => {
  event.notification.close();

  if (event.action === 'dismiss') return;

  const targetUrl = event.notification.data?.url || '/alerts';

  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
      // Focus existing tab if already open
      for (const client of clientList) {
        if (client.url.includes(targetUrl) && 'focus' in client) {
          return client.focus();
        }
      }
      // Otherwise open a new tab
      if (clients.openWindow) {
        return clients.openWindow(targetUrl);
      }
    })
  );
});

// ── Install + activate (no cache needed for push-only SW) ─────
self.addEventListener('install',  () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(clients.claim()));
