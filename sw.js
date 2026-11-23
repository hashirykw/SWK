/* SWK Assistant — service worker. Shows push notifications (follow-ups and Sir's replies)
   even when the chat page is closed, and opens the chat when one is tapped.
   It has to be its own file: browsers only run service workers from a separate script. */
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));

self.addEventListener('push', e => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch (_) { d = { body: e.data && e.data.text() }; }
  e.waitUntil((async () => {
    const wins = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    wins.forEach(w => w.postMessage({ type: 'swk-push' }));
    // the chat is open and in front of them: it already chimes, so skip the system popup
    if (wins.some(w => w.focused && w.visibilityState === 'visible')) return;
    await self.registration.showNotification(d.title || 'SWK Solutions', {
      body: d.body || 'You have a new message from Sir Waqas Khan\'s desk.',
      icon: 'swk-icon-192.png',
      badge: 'swk-badge.png',
      tag: d.tag || 'swk',
      renotify: true,
      vibrate: [80, 40, 80],
      data: { url: d.url || './' }
    });
  })());
});

self.addEventListener('notificationclick', e => {
  e.notification.close();
  const url = (e.notification.data && e.notification.data.url) || './';
  e.waitUntil((async () => {
    const wins = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const w of wins) { if (w.url.startsWith(self.registration.scope)) { w.postMessage({ type: 'swk-push' }); return w.focus(); } }
    return self.clients.openWindow(url);
  })());
});
