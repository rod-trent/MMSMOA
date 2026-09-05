/* sw.js — offline cache for the demo site.
 *
 * The point is stage reliability. Once you have loaded the site on the venue
 * Wi-Fi, everything it needs is cached: the page, the demo sources, every baked
 * transcript, and the Pyodide runtime. If the network dies mid-session the
 * demos keep working.
 *
 * Strategy: cache-first for our own assets (they are versioned by CACHE below
 * and rebuilt on deploy), stale-while-revalidate for the Pyodide CDN.
 */

var CACHE = 'mms-midway-v1';

var CORE = [
  './',
  'index.html',
  'assets/style.css',
  'assets/app.js',
  'assets/ansi.js',
  'data/manifest.json'
];

self.addEventListener('install', function (e) {
  e.waitUntil(
    caches.open(CACHE).then(function (c) {
      // Warm the core shell, then everything the manifest references.
      return c.addAll(CORE).then(function () {
        return fetch('data/manifest.json')
          .then(function (r) { return r.json(); })
          .then(function (m) {
            var urls = [];
            m.pyAssets.forEach(function (p) { urls.push('py/' + p); });
            m.demos.forEach(function (d) {
              if (d.transcript) urls.push('transcripts/' + d.transcript + '.txt');
              (d.variants || []).forEach(function (v) {
                if (v.transcript) urls.push('transcripts/' + v.transcript + '.txt');
              });
            });
            // Individually, so one 404 does not fail the whole install.
            return Promise.all(urls.map(function (u) {
              return c.add(u).catch(function () {});
            }));
          })
          .catch(function () {});
      });
    }).then(function () { return self.skipWaiting(); })
  );
});

self.addEventListener('activate', function (e) {
  e.waitUntil(
    caches.keys().then(function (keys) {
      return Promise.all(keys.map(function (k) {
        return k === CACHE ? null : caches.delete(k);
      }));
    }).then(function () { return self.clients.claim(); })
  );
});

self.addEventListener('fetch', function (e) {
  var req = e.request;
  if (req.method !== 'GET') return;

  var url = new URL(req.url);
  var isPyodide = url.hostname === 'cdn.jsdelivr.net';
  var isOurs = url.origin === self.location.origin;

  if (!isOurs && !isPyodide) return;

  e.respondWith(
    caches.match(req).then(function (hit) {
      var net = fetch(req).then(function (res) {
        if (res && (res.ok || res.type === 'opaque')) {
          var copy = res.clone();
          caches.open(CACHE).then(function (c) { c.put(req, copy); });
        }
        return res;
      }).catch(function () { return hit; });

      // Pyodide is big and immutable-per-version: serve from cache, refresh
      // in the background. Our own assets: cache-first, same idea.
      return hit || net;
    })
  );
});
