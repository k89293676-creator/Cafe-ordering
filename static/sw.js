// Cafe 11:11 — minimal offline cache (Toast/Square offline parity)
const CACHE = 'cafe-11-v2';
const CORE = ['/owner/dashboard','/owner/tables','/owner/menu','/kitchen','/manifest.json'];
self.addEventListener('install', e=>{
  e.waitUntil(caches.open(CACHE).then(c=>c.addAll(CORE).catch(()=>{})));
  self.skipWaiting();
});
self.addEventListener('activate', e=>{
  e.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(k=>k!==CACHE).map(k=>caches.delete(k)))));
  self.clients.claim();
});
self.addEventListener('fetch', e=>{
  const req=e.request;
  if(req.method!=='GET') return;
  // Network-first for API, cache-first for static
  if(req.url.includes('/api/')){
    e.respondWith(fetch(req).catch(()=>caches.match(req)));
    return;
  }
  e.respondWith(caches.match(req).then(cached=> cached || fetch(req).then(res=>{
    if(res.ok) caches.open(CACHE).then(c=>c.put(req,res.clone()));
    return res;
  }).catch(()=>cached)));
});
