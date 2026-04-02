/**
 * SecureFlow — Web Push notification manager
 * Handles service-worker registration, VAPID subscription, and
 * persisting the subscription to the Django backend.
 */

const ML_API = 'http://127.0.0.1:8000/model_app';

/** Convert base64url VAPID public key to Uint8Array (required by PushManager). */
function urlBase64ToUint8Array(base64String) {
  const padding = '='.repeat((4 - (base64String.length % 4)) % 4);
  const base64  = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
  const raw     = atob(base64);
  return Uint8Array.from([...raw].map((c) => c.charCodeAt(0)));
}

/** Fetch the VAPID public key from the backend. */
async function fetchVapidPublicKey() {
  try {
    const res  = await fetch(`${ML_API}/push/vapid_key`);
    if (!res.ok) return null;
    const data = await res.json();
    return data.public_key || null;
  } catch {
    return null;
  }
}

/**
 * Register the service worker and subscribe to Web Push.
 * Automatically sends the subscription to the backend.
 * Safe to call multiple times (idempotent).
 *
 * @returns {{ subscribed: boolean, reason?: string }}
 */
export async function setupPushNotifications() {
  // Check browser support
  if (!('serviceWorker' in navigator)) {
    return { subscribed: false, reason: 'Service workers not supported in this browser.' };
  }
  if (!('PushManager' in window)) {
    return { subscribed: false, reason: 'Web Push not supported in this browser.' };
  }

  // Fetch VAPID public key
  const vapidKey = await fetchVapidPublicKey();
  if (!vapidKey) {
    return { subscribed: false, reason: 'VAPID keys not configured on server. Add them to ml_model/.env' };
  }

  // Request notification permission
  const permission = await Notification.requestPermission();
  if (permission !== 'granted') {
    return { subscribed: false, reason: `Notification permission ${permission}.` };
  }

  try {
    // Register / retrieve the service worker
    const reg = await navigator.serviceWorker.register('/sw.js', { scope: '/' });
    await navigator.serviceWorker.ready;

    // Subscribe to push (creates or retrieves existing subscription)
    const sub = await reg.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: urlBase64ToUint8Array(vapidKey),
    });

    // Encode keys to base64 for JSON transport
    const p256dh = btoa(String.fromCharCode(...new Uint8Array(sub.getKey('p256dh'))));
    const auth   = btoa(String.fromCharCode(...new Uint8Array(sub.getKey('auth'))));

    // Save subscription to Django backend
    const res = await fetch(`${ML_API}/push/subscribe`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({
        endpoint: sub.endpoint,
        keys:     { p256dh, auth },
      }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      return { subscribed: false, reason: err.error || 'Backend rejected subscription.' };
    }

    return { subscribed: true };
  } catch (err) {
    return { subscribed: false, reason: String(err) };
  }
}

/**
 * Unsubscribe from Web Push and remove from backend.
 * @returns {{ unsubscribed: boolean }}
 */
export async function teardownPushNotifications() {
  if (!('serviceWorker' in navigator)) return { unsubscribed: false };
  try {
    const reg = await navigator.serviceWorker.getRegistration('/');
    if (!reg) return { unsubscribed: false };
    const sub = await reg.pushManager.getSubscription();
    if (!sub) return { unsubscribed: true };

    // Remove from backend first
    await fetch(`${ML_API}/push/unsubscribe`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ endpoint: sub.endpoint }),
    });
    await sub.unsubscribe();
    return { unsubscribed: true };
  } catch {
    return { unsubscribed: false };
  }
}

/**
 * Returns current push subscription status.
 * @returns {{ subscribed: boolean }}
 */
export async function getPushStatus() {
  if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
    return { subscribed: false };
  }
  try {
    const reg = await navigator.serviceWorker.getRegistration('/');
    if (!reg) return { subscribed: false };
    const sub = await reg.pushManager.getSubscription();
    return { subscribed: !!sub };
  } catch {
    return { subscribed: false };
  }
}
