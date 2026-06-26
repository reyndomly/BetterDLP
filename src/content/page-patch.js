/**
 * BetterDLP - Page World Patch
 * Runs in MAIN world to intercept the page's actual fetch() and XHR.
 * Content scripts run in an isolated JS context — patching fetch/XHR there
 * has no effect on the page's network calls. This file must run in MAIN world.
 *
 * Cannot use chrome.* APIs here. Logs are sent via CustomEvent to bridge.js.
 */
(function () {
  'use strict';

  // JSZip is loaded before this script in MAIN world via manifest.json

  // ─── Detection ───────────────────────────────────────────────────────────────

  const MAGIC = {
    ZIP:      [0x50, 0x4B, 0x03, 0x04],
    OLE2:     [0xD0, 0xCF, 0x11, 0xE0],
    PDF:      [0x25, 0x50, 0x44, 0x46],
    RTF:      [0x7B, 0x5C, 0x72, 0x74],
    RAR4:     [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00],
    RAR5:     [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01],
    SEVENZIP: [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C],
    GZIP:     [0x1F, 0x8B],
  };

  const OFFICE_PATHS = [
    'word/document.xml', 'xl/workbook.xml', 'ppt/presentation.xml',
    'content.xml', 'META-INF/manifest.xml',
  ];

  const MAX_DEPTH = 3;
  const MAX_UNCOMP = 100 * 1024 * 1024;

  function match(bytes, magic) {
    return magic.every(function (b, i) { return bytes[i] === b; });
  }

  function isZipEncrypted(bytes) {
    return match(bytes, MAGIC.ZIP) && ((bytes[6] | (bytes[7] << 8)) & 0x01) !== 0;
  }

  function inspectZip(buf, depth) {
    if (depth > MAX_DEPTH)
      return Promise.resolve({ blocked: true, reason: 'Archive nested too deep' });

    return JSZip.loadAsync(buf).then(function (zip) {
      var names = Object.keys(zip.files);

      for (var i = 0; i < OFFICE_PATHS.length; i++) {
        var op = OFFICE_PATHS[i];
        if (names.some(function (n) { return n === op || n.endsWith('/' + op); }))
          return { blocked: true, reason: 'Office document detected (contains ' + op + ')' };
      }

      var checks = names.map(function (name) {
        var entry = zip.files[name];
        if (entry.dir) return Promise.resolve({ blocked: false });
        if (entry._data && entry._data.uncompressedSize > MAX_UNCOMP)
          return Promise.resolve({ blocked: true, reason: 'Possible zip bomb' });

        return entry.async('arraybuffer').then(function (entryBuf) {
          return detectType(new Uint8Array(entryBuf), entryBuf, depth + 1);
        }).then(function (r) {
          return r.blocked ? { blocked: true, reason: r.reason + ' (inside: ' + name + ')' } : { blocked: false };
        }).catch(function () {
          return { blocked: true, reason: 'Encrypted entry: ' + name };
        });
      });

      return Promise.all(checks).then(function (results) {
        var hit = results.find(function (r) { return r.blocked; });
        return hit || { blocked: true, reason: 'ZIP archive — all archives blocked by policy' };
      });

    }).catch(function (err) {
      var msg = (err.message || '').toLowerCase();
      if (msg.includes('encrypt') || msg.includes('password'))
        return { blocked: true, reason: 'Password-protected archive' };
      return { blocked: true, reason: 'Unreadable archive' };
    });
  }

  function detectType(bytes, buf, depth) {
    if (match(bytes, MAGIC.OLE2))     return Promise.resolve({ blocked: true, reason: 'Legacy Office document (DOC/XLS/PPT)' });
    if (match(bytes, MAGIC.PDF))      return Promise.resolve({ blocked: true, reason: 'PDF document' });
    if (match(bytes, MAGIC.RTF))      return Promise.resolve({ blocked: true, reason: 'RTF document' });
    if (match(bytes, MAGIC.RAR4) ||
        match(bytes, MAGIC.RAR5))     return Promise.resolve({ blocked: true, reason: 'RAR archive — cannot inspect' });
    if (match(bytes, MAGIC.SEVENZIP)) return Promise.resolve({ blocked: true, reason: '7-Zip archive — cannot inspect' });
    if (match(bytes, MAGIC.GZIP))     return Promise.resolve({ blocked: true, reason: 'GZIP archive — cannot inspect' });

    if (match(bytes, MAGIC.ZIP)) {
      if (isZipEncrypted(bytes)) return Promise.resolve({ blocked: true, reason: 'Password-protected ZIP' });
      if (!buf) return Promise.resolve({ blocked: true, reason: 'ZIP — buffer required' });
      return inspectZip(buf, depth || 0);
    }

    return Promise.resolve({ blocked: false, reason: 'File type allowed' });
  }

  var NO_MAGIC_EXT = { csv: 1, tsv: 1, txt: 1 };

  function inspectFile(file) {
    var ext = (file.name || '').split('.').pop().toLowerCase();
    if (NO_MAGIC_EXT[ext]) {
      return Promise.resolve({ blocked: true, reason: ext.toUpperCase() + ' file — no magic bytes, blocked by extension' });
    }
    return file.arrayBuffer().then(function (buf) {
      return detectType(new Uint8Array(buf), buf, 0);
    });
  }

  // ─── Block Modal ─────────────────────────────────────────────────────────────

  function showBlockModal(filename, reason, vector) {
    var existing = document.getElementById('betterdlp-host');
    if (existing) existing.remove();

    var host = document.createElement('div');
    host.id = 'betterdlp-host';
    host.style.cssText = 'all:initial;position:fixed;top:0;left:0;width:100%;height:100%;z-index:2147483647;pointer-events:all;';

    var shadow = host.attachShadow({ mode: 'closed' });
    shadow.innerHTML = '<style>*{box-sizing:border-box;margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.o{position:fixed;inset:0;background:rgba(0,0,0,.65);display:flex;align-items:center;justify-content:center}.m{background:#fff;border-radius:12px;padding:32px;max-width:460px;width:90%;box-shadow:0 20px 60px rgba(0,0,0,.3)}.h{display:flex;align-items:center;gap:12px;margin-bottom:20px}.ic{width:44px;height:44px;border-radius:10px;background:#fee2e2;display:flex;align-items:center;justify-content:center;font-size:22px;flex-shrink:0}.t{font-size:18px;font-weight:700;color:#111}.st{font-size:13px;color:#ef4444;font-weight:500;margin-top:2px}.db{background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px;padding:14px 16px;margin-bottom:20px}.dr{display:flex;gap:8px;margin-bottom:6px;font-size:13px}.dl{color:#6b7280;width:70px;flex-shrink:0}.dv{color:#111;font-weight:500;word-break:break-all}.rb{background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:12px 14px;margin-bottom:24px;font-size:13px;color:#991b1b;line-height:1.5}.ac{display:flex;gap:10px;justify-content:flex-end}.btn{padding:9px 18px;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;border:none}.b1{background:#f3f4f6;color:#374151}.b2{background:#ef4444;color:#fff}.ft{margin-top:16px;font-size:11px;color:#9ca3af;text-align:center}</style><div class="o"><div class="m"><div class="h"><div class="ic">🚫</div><div><div class="t">Upload Blocked</div><div class="st">BetterDLP Policy Violation</div></div></div><div class="db"><div class="dr"><span class="dl">File</span><span class="dv" id="fn"></span></div><div class="dr"><span class="dl">Vector</span><span class="dv" id="vc"></span></div></div><div class="rb" id="rs"></div><div class="ac"><button class="btn b2" id="ok">Understood</button></div><div class="ft">BetterDLP is protecting your data</div></div></div>';

    shadow.getElementById('fn').textContent = filename || 'Unknown';
    shadow.getElementById('vc').textContent = vector || 'unknown';
    shadow.getElementById('rs').textContent = reason || 'Blocked by policy';
    shadow.getElementById('ok').addEventListener('click', function () { host.remove(); });

    document.documentElement.appendChild(host);
  }

  // ─── Log bridge ──────────────────────────────────────────────────────────────

  function emitLog(entry) {
    window.dispatchEvent(new CustomEvent('betterdlp-log', { detail: entry }));
  }

  // ─── File extraction ─────────────────────────────────────────────────────────

  function extractFiles(body) {
    if (body instanceof File) return Promise.resolve([body]);
    if (body instanceof Blob) return Promise.resolve([new File([body], 'upload.bin', { type: body.type })]);
    if (body instanceof FormData) {
      var files = [];
      body.forEach(function (value) {
        if (value instanceof File) files.push(value);
        else if (value instanceof Blob) files.push(new File([value], 'upload.bin', { type: value.type }));
      });
      return Promise.resolve(files);
    }
    return Promise.resolve([]);
  }

  function hasFileBody(body) {
    return body instanceof FormData || body instanceof File || body instanceof Blob;
  }

  function handleFiles(files, vector) {
    if (!files.length) return Promise.resolve(false);

    var queue = files.slice();

    function next() {
      if (!queue.length) return Promise.resolve(false);
      var file = queue.shift();
      return inspectFile(file).then(function (result) {
        if (result.blocked) {
          showBlockModal(file.name, result.reason, vector);
          emitLog({ filename: file.name, size: file.size, reason: result.reason, vector: vector, action: 'BLOCKED', site: location.hostname });
          return true;
        }
        emitLog({ filename: file.name, size: file.size, reason: result.reason, vector: vector, action: 'ALLOWED', site: location.hostname });
        return next();
      });
    }

    return next();
  }

  // ─── Patch fetch ─────────────────────────────────────────────────────────────

  var _fetch = window.fetch;
  window.fetch = function (input, init) {
    var body = init && init.body;
    if (!hasFileBody(body)) return _fetch.apply(this, arguments);

    var self = this;
    var args = arguments;
    return extractFiles(body).then(function (files) {
      if (!files.length) return _fetch.apply(self, args);
      return handleFiles(files, 'fetch').then(function (blocked) {
        if (blocked) return new Response('{"error":"Blocked by BetterDLP"}', { status: 403, headers: { 'Content-Type': 'application/json' } });
        return _fetch.apply(self, args);
      });
    }).catch(function () { return _fetch.apply(self, args); });
  };

  // ─── Patch XHR ───────────────────────────────────────────────────────────────

  var _send = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.send = function (body) {
    if (!hasFileBody(body)) return _send.apply(this, arguments);

    var self = this;
    var args = arguments;
    extractFiles(body).then(function (files) {
      if (!files.length) { _send.apply(self, args); return; }
      handleFiles(files, 'XHR').then(function (blocked) {
        if (!blocked) _send.apply(self, args);
      });
    }).catch(function () { _send.apply(self, args); });
  };

})();
