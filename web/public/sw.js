/* sw.js — offline cache for the demo site.
 *
 * The point is stage reliability. Once you have loaded the site on the venue
 * Wi-Fi, everything it needs is cached: the page, the demo sources, every baked
 * transcript, and the Pyodide runtime. If the network dies mid-session the
 * demos keep working.
 *
 * Strategy: network-first with a short timeout for our own assets, falling
 * back to cache; cache-first for the Pyodide CDN.
 *
 * Our assets change on every deploy, and the cache-first version this used
 * to run handed a returning visitor the PREVIOUS build unless CACHE was
 * bumped by hand - which was forgotten, and is exactly the wrong failure
 * when you open the site in the room. Network-first removes the footgun:
 * whatever is deployed is what you get. The timeout keeps bad venue Wi-Fi
 * from costing more than NET_TIMEOUT per asset, and a dead network falls
 * straight through to the cache, so the offline guarantee is unchanged.
 */

var CACHE = 'mms-midway-v3';   // bumped: evicts the stale v2 caches
var NET_TIMEOUT = 1500;        // ms before we stop waiting and use the cache

var CORE = [
  './',
  'index.html',
  'assets/style.css',
  'assets/app.js',
  'assets/ansi.js',
  'assets/mms-logo.png',
  'assets/mms-midway-dark.webp',
  'assets/mms-midway-dark.jpg',
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

function keep(req, res) {
  if (res && (res.ok || res.type === 'opaque')) {
    var copy = res.clone();
    caches.open(CACHE).then(function (c) { c.put(req, copy); });
  }
  return res;
}

/* Resolve from the network, but give up waiting after `ms`. A response that
 * arrives late is still cached - it just does not hold up the page. */
function fromNetwork(req, ms) {
  return new Promise(function (resolve, reject) {
    var settled = false;
    var timer = setTimeout(function () {
      if (!settled) { settled = true; reject(new Error('slow')); }
    }, ms);

    fetch(req).then(function (res) {
      keep(req, res);
      if (settled) return;                 // too late to be used, now cached
      settled = true;
      clearTimeout(timer);
      resolve(res);
    }).catch(function (err) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(err);
    });
  });
}

self.addEventListener('fetch', function (e) {
  var req = e.request;
  if (req.method !== 'GET') return;

  var url = new URL(req.url);
  var isPyodide = url.hostname === 'cdn.jsdelivr.net';
  var isOurs = url.origin === self.location.origin;

  if (!isOurs && !isPyodide) return;

  // Pyodide is big and immutable per version: serve from cache, refresh in
  // the background.
  if (isPyodide) {
    e.respondWith(
      caches.match(req).then(function (hit) {
        var net = fetch(req)
          .then(function (res) { return keep(req, res); })
          .catch(function () { return hit; });
        return hit || net;
      })
    );
    return;
  }

  // Ours: whatever is deployed wins, with the cache as the safety net.
  e.respondWith(
    fromNetwork(req, NET_TIMEOUT).catch(function () {
      return caches.match(req).then(function (hit) {
        return hit || Response.error();
      });
    })
  );
});
