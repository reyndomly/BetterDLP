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

  var BLOCKED_MAGIC = [
    { sig: [0xD0, 0xCF, 0x11, 0xE0],                         label: 'Legacy Office document (DOC/XLS/PPT)' },
    { sig: [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00],       label: 'RAR archive'       },
    { sig: [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01],       label: 'RAR5 archive'      },
    { sig: [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C],             label: '7-Zip archive'     },
    { sig: [0x1F, 0x8B, 0x08],                               label: 'GZIP archive'      },
    { sig: [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00],             label: 'XZ archive'        },
    { sig: [0x28, 0xB5, 0x2F, 0xFD],                         label: 'Zstandard archive' },
    { sig: [0x42, 0x5A, 0x68],                               label: 'BZIP2 archive'     },
    { sig: [0x04, 0x22, 0x4D, 0x18],                         label: 'LZ4 archive'       },
    { sig: [0x4D, 0x53, 0x43, 0x46],                         label: 'Cabinet archive'   },
  ];

  var PDF_SIG   = [0x25, 0x50, 0x44, 0x46];
  var RTF_SIG   = [0x7B, 0x5C, 0x72, 0x74];
  var TAR_SIG   = [0x75, 0x73, 0x74, 0x61, 0x72];
  var TAR_OFF   = 257;
  var PDF_SCAN  = 1024;
  var RTF_SCAN  = 64;
  var ZIP_LOCAL = [0x50, 0x4B, 0x03, 0x04];
  var ZIP_EOCD  = [0x50, 0x4B, 0x05, 0x06];
  var ZIP_SCAN  = 64 * 1024;

  var OFFICE_PATHS = [
    'word/document.xml', 'xl/workbook.xml', 'ppt/presentation.xml',
    'content.xml', 'META-INF/manifest.xml',
  ];

  var MAX_DEPTH  = 3;
  var MAX_UNCOMP = 100 * 1024 * 1024;

  function matchesAt(bytes, sig, offset) {
    if (bytes.length < offset + sig.length) return false;
    return sig.every(function (b, i) { return bytes[offset + i] === b; });
  }

  function matchesMagic(bytes, sig) { return matchesAt(bytes, sig, 0); }

  function indexOfSig(bytes, sig, maxScan) {
    var limit = Math.min(bytes.length, maxScan) - sig.length;
    for (var i = 0; i <= limit; i++) {
      if (sig.every(function (b, j) { return bytes[i + j] === b; })) return i;
    }
    return -1;
  }

  function findZipStart(bytes) {
    if (matchesMagic(bytes, ZIP_LOCAL)) return 0;
    if (indexOfSig(bytes, ZIP_EOCD, bytes.length) === -1) return -1;
    return indexOfSig(bytes, ZIP_LOCAL, ZIP_SCAN);
  }

  function isZipEncrypted(bytes, offset) {
    if (!matchesAt(bytes, ZIP_LOCAL, offset)) return false;
    return ((bytes[offset + 6] | (bytes[offset + 7] << 8)) & 0x01) !== 0;
  }

  function isPlainText(bytes) {
    var sample = bytes.length > 512 ? bytes.subarray(0, 512) : bytes;
    for (var i = 0; i < sample.length; i++) {
      var b = sample[i];
      if (b === 0x09 || b === 0x0A || b === 0x0D) continue;
      if (b >= 0x20 && b <= 0x7E) continue;
      if (b === 0x00 || b < 0x09) return false;
    }
    return true;
  }

  function inspectZip(buf, depth) {
    if (depth > MAX_DEPTH)
      return Promise.resolve({ blocked: true, reason: 'Archive nested too deep' });

    return JSZip.loadAsync(buf).then(function (zip) {
      var names = Object.keys(zip.files);

      for (var i = 0; i < OFFICE_PATHS.length; i++) {
        var op = OFFICE_PATHS[i];
        if (names.some(function (n) { return n === op || n.endsWith('/' + op); }))
          return { blocked: true, reason: 'Office document detected (' + op + ')' };
      }

      var checks = names.map(function (name) {
        var entry = zip.files[name];
        if (entry.dir) return Promise.resolve({ blocked: false });
        if (entry._data && entry._data.uncompressedSize > MAX_UNCOMP)
          return Promise.resolve({ blocked: true, reason: 'Possible zip bomb' });

        return entry.async('arraybuffer').then(function (entryBuf) {
          return detectType(new Uint8Array(entryBuf), entryBuf);
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
      var msg = (err && err.message || '').toLowerCase();
      if (msg.includes('encrypt') || msg.includes('password'))
        return { blocked: true, reason: 'Password-protected archive' };
      return { blocked: true, reason: 'Unreadable archive' };
    });
  }

  function detectType(bytes, buf) {
    for (var i = 0; i < BLOCKED_MAGIC.length; i++) {
      if (matchesMagic(bytes, BLOCKED_MAGIC[i].sig))
        return Promise.resolve({ blocked: true, reason: BLOCKED_MAGIC[i].label });
    }

    if (indexOfSig(bytes, PDF_SIG, PDF_SCAN) !== -1)
      return Promise.resolve({ blocked: true, reason: 'PDF document' });
    if (indexOfSig(bytes, RTF_SIG, RTF_SCAN) !== -1)
      return Promise.resolve({ blocked: true, reason: 'RTF document' });
    if (matchesAt(bytes, TAR_SIG, TAR_OFF))
      return Promise.resolve({ blocked: true, reason: 'TAR archive' });

    var zipStart = findZipStart(bytes);
    if (zipStart !== -1) {
      if (isZipEncrypted(bytes, zipStart))
        return Promise.resolve({ blocked: true, reason: 'Password-protected ZIP archive' });
      if (!buf)
        return Promise.resolve({ blocked: true, reason: 'ZIP archive — blocked by policy' });
      var slice = zipStart > 0 ? buf.slice(zipStart) : buf;
      return inspectZip(slice, 0);
    }

    if (isPlainText(bytes))
      return Promise.resolve({ blocked: true, reason: 'Text/data file — blocked by policy' });

    return Promise.resolve({ blocked: false, reason: 'File type allowed' });
  }

  function inspectFile(file) {
    return file.arrayBuffer().then(function (buf) {
      return detectType(new Uint8Array(buf), buf);
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
    if (body instanceof FormData) {
      var files = [];
      body.forEach(function (value) { if (value instanceof File) files.push(value); });
      return Promise.resolve(files);
    }
    return Promise.resolve([]);
  }

  function hasFileBody(body) {
    if (body instanceof File) return true;
    if (body instanceof FormData) {
      var has = false;
      body.forEach(function (v) { if (v instanceof File) has = true; });
      return has;
    }
    return false;
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
