/* Service worker: shows the "turn finished" notification. */
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

self.addEventListener('push', (event) => {
  let payload = {};
  try {
    payload = event.data ? event.data.json() : {};
  } catch (e) {
    payload = {};
  }
  event.waitUntil(self.registration.showNotification(payload.title || 'OpenCode', {
    body: payload.body || '',
    tag: 'opencode-session',
    renotify: true,
    data: { url: payload.url || '/' },
  }));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const url = (event.notification.data && event.notification.data.url) || '/';
  event.waitUntil((async () => {
    const windows = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const client of windows) {
      if (client.url.indexOf(self.registration.scope) === 0 && 'focus' in client) {
        return client.focus();
      }
    }
    return self.clients.openWindow(url);
  })());
});
