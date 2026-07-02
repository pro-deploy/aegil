// Service worker панели администратора (ADR-0033, стратегия пересмотрена в ADR-0041). Оболочку
// (навигация и корень index.html с его JS) отдаём ПО СЕТИ в первую очередь (network-first), чтобы
// после каждой выкатки браузер сразу получал свежий интерфейс, а кэш служил лишь офлайн-запасом.
// Прежняя стратегия cache-first залипала на старой версии: сервер отдавал новый код, а браузер
// продолжал крутить устаревший, отсюда «пустой ответ» и пропавшие кнопки. Диалоговые и
// динамические вызовы (/chat, /confirm, /incidents, /agent, /commands, /health) идут только по сети.
const CACHE = 'krokki-admin-v4';
const SHELL = ['/', '/icon.svg', '/manifest.webmanifest'];
// Динамические эндпоинты только по сети (свежесть важнее офлайна).
const NETWORK_ONLY = ['/chat', '/confirm', '/health', '/commands'];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).catch(() => null));
  self.skipWaiting();
});

self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys().then((keys) =>
    Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))));
  self.clients.claim();
});

function networkFirst(request) {
  return fetch(request).then((resp) => {
    const copy = resp.clone();
    caches.open(CACHE).then((c) => c.put('/', copy)).catch(() => null);
    return resp;
  }).catch(() => caches.match('/'));
}

function cacheFirst(request) {
  return caches.match(request).then((hit) => hit || fetch(request).then((resp) => {
    const copy = resp.clone();
    caches.open(CACHE).then((c) => c.put(request, copy)).catch(() => null);
    return resp;
  }).catch(() => caches.match('/')));
}

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET') return;                 // мутации мимо кэша
  // Динамика и агентные вызовы только по сети.
  if (NETWORK_ONLY.includes(url.pathname) || url.pathname.startsWith('/incidents')
      || url.pathname.startsWith('/agent')) return;
  // Оболочка (навигация или корень): network-first, чтобы всегда была свежая версия интерфейса.
  if (e.request.mode === 'navigate' || url.pathname === '/' || url.pathname === '/index.html') {
    e.respondWith(networkFirst(e.request));
    return;
  }
  // Прочая статика (иконка, манифест): cache-first, она меняется редко.
  e.respondWith(cacheFirst(e.request));
});
