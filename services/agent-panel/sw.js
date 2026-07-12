// Service worker операторской консоли kube-sentinel. Оболочку (навигация и корень index.html с
// его встроенным скриптом) отдаём ПО СЕТИ в первую очередь (network-first), чтобы после каждой
// выкатки браузер сразу получал свежий интерфейс, а кэш служил лишь офлайн-запасом. Прежняя
// стратегия cache-first залипала на старой версии: сервер отдавал новый код, а браузер продолжал
// крутить устаревший. Диалоговые и динамические вызовы идут только по сети.
//
// Имя кэша содержит версию продукта: при выпуске новой версии образа поднимайте суффикс, тогда
// старый кэш детерминированно вычищается в activate, а не остаётся жить рядом с новым.
const CACHE = 'kube-sentinel-v0.1.0';
const SHELL = ['/', '/icon.svg', '/manifest.webmanifest'];
// Динамические эндпоинты только по сети (свежесть важнее офлайна).
const NETWORK_ONLY = ['/chat', '/confirm', '/health', '/status', '/commands'];

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
