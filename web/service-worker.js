const CACHE_NAME = "ztas-console-shell-v13";
const STATIC_ASSETS = [
  "/assets/common.css",
  "/assets/common.js",
  "/assets/dashboard.css",
  "/assets/dashboard.js",
  "/assets/logs.css",
  "/assets/logs.js",
  "/assets/accounts.css",
  "/assets/accounts.js",
  "/assets/documents.css",
  "/assets/documents.js",
  "/assets/ptit-logo-white.png",
  "/manifest.webmanifest"
];

self.addEventListener("install", event => {
  event.waitUntil(caches.open(CACHE_NAME).then(cache => cache.addAll(STATIC_ASSETS)));
  self.skipWaiting();
});

self.addEventListener("activate", event => {
  event.waitUntil(caches.keys().then(keys => Promise.all(
    keys.filter(key => key !== CACHE_NAME).map(key => caches.delete(key))
  )));
  self.clients.claim();
});

self.addEventListener("fetch", event => {
  const request = event.request;
  const url = new URL(request.url);
  if (request.method !== "GET" || url.origin !== self.location.origin ||
      !STATIC_ASSETS.includes(url.pathname)) return;

  event.respondWith(caches.match(request).then(cached => cached || fetch(request).then(response => {
    const copy = response.clone();
    caches.open(CACHE_NAME).then(cache => cache.put(request, copy));
    return response;
  })));
});
