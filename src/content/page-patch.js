/**
 * BetterDLP - Page World Patch (MAIN world)
 *
 * Intercepts the page's real network egress so file/data uploads are inspected
 * before they leave the browser. Content scripts run in an isolated JS context;
 * patching here (MAIN world) is the only way to hook the page's actual
 * fetch/XHR/WebSocket/etc.
 *
 * Detection logic is shared via globalThis.BetterDLPCore (src/lib/detection-core.js,
 * injected before this file). JSZip is loaded before this file too.
 *
 * Two inspection contexts:
 *   - FILE uploads (File / Blob / FormData file parts): block ALL document/data
 *     uploads (Core.inspectFileBytes) — that is the extension's core intent.
 *   - RAW request bodies (ArrayBuffer / TypedArray / string / URLSearchParams /
 *     stream): these include legitimate JSON/API traffic, so block selectively —
 *     only document/archive signatures or positive PII (Core.inspectNetworkBytes).
 *
 * Cannot use chrome.* here. Logs are sent via CustomEvent to bridge.js.
 *
 * NOTE: Separate JS realms (Web/Service Workers) are only partially covered by
 * the Worker wrap below; the authoritative cross-realm control is the
 * webRequest backstop in the service worker.
 */
(function () {
  'use strict';

  var Core = globalThis.BetterDLPCore;
  if (!Core) return; // detection-core failed to load; fail open rather than break the page

  // ─── Deep (async) ZIP-aware file inspection ──────────────────────────────────

  function inspectZip(bytes, zipStart, depth) {
    if (depth > Core.MAX_ZIP_DEPTH)
      return Promise.resolve({ blocked: true, reason: 'Archive nested too deep' });

    var slice = zipStart > 0 ? bytes.subarray(zipStart) : bytes;

    return JSZip.loadAsync(slice).then(function (zip) {
      var names = Object.keys(zip.files);

      for (var i = 0; i < Core.OFFICE_ZIP_PATHS.length; i++) {
        var op = Core.OFFICE_ZIP_PATHS[i];
        if (names.some(function (n) { return n === op || n.endsWith('/' + op); }))
          return { blocked: true, reason: 'Office document detected (contains ' + op + ')' };
      }

      var checks = names.map(function (name) {
        var entry = zip.files[name];
        if (entry.dir) return Promise.resolve({ blocked: false });
        if (entry._data && entry._data.uncompressedSize > Core.MAX_UNCOMPRESSED_BYTES)
          return Promise.resolve({ blocked: true, reason: 'Possible zip bomb (inside: ' + name + ')' });

        return entry.async('arraybuffer').then(function (entryBuf) {
          var eb = new Uint8Array(entryBuf);
          var nestedStart = Core.findZipStart(eb);
          if (nestedStart !== -1) {
            return inspectZip(eb, nestedStart, depth + 1).then(function (r) {
              return r.blocked ? { blocked: true, reason: r.reason + ' (inside: ' + name + ')' } : { blocked: false };
            });
          }
          var sig = Core.sniffBinarySignature(eb);
          if (sig) return { blocked: true, reason: sig.reason + ' (inside: ' + name + ')' };
          if (Core.isPlainText(eb)) {
            var pii = Core.scanTextContent(Core.bytesToText(eb, 256 * 1024));
            if (pii) return { blocked: true, reason: pii.reason + ' (inside: ' + name + ')' };
          }
          return { blocked: false };
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
      return { blocked: true, reason: 'Archive — all archives blocked by policy' };
    });
  }

  // Inspect raw bytes as a FILE (block all document/data uploads).
  function inspectFileBytes(bytes, filename) {
    var zipStart = Core.findZipStart(bytes);
    if (zipStart !== -1) {
      if (Core.isZipEncrypted(bytes, zipStart))
        return Promise.resolve({ blocked: true, reason: 'Password-protected ZIP archive' });
      return inspectZip(bytes, zipStart, 0);
    }
    return Promise.resolve(Core.inspectFileBytes(bytes, filename));
  }

  function inspectFileObj(file) {
    return file.arrayBuffer().then(function (buf) {
      return inspectFileBytes(new Uint8Array(buf), file.name || 'upload.bin');
    });
  }

  // Inspect raw bytes as a NETWORK body (selective: signatures + PII only).
  function inspectNetworkBytes(bytes) {
    var zipStart = Core.findZipStart(bytes);
    if (zipStart !== -1) {
      // Archive uploaded as a raw body — block (deep reason if possible).
      return inspectZip(bytes, zipStart, 0);
    }
    return Promise.resolve(Core.inspectNetworkBytes(bytes));
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

  function reportBlocked(filename, reason, vector, size) {
    showBlockModal(filename, reason, vector);
    emitLog({ filename: filename, size: size || 0, reason: reason, vector: vector, action: 'BLOCKED', site: location.hostname });
  }

  // ─── Body extraction / classification ────────────────────────────────────────

  function toBytes(body) {
    if (body instanceof ArrayBuffer) return new Uint8Array(body);
    if (ArrayBuffer.isView(body)) return new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
    if (typeof body === 'string') return new TextEncoder().encode(body);
    if (typeof URLSearchParams !== 'undefined' && body instanceof URLSearchParams)
      return new TextEncoder().encode(body.toString());
    return null;
  }

  function withName(promise, name) {
    return promise.then(function (r) { return Object.assign({ filename: name }, r); });
  }

  // Inspect a request/transport body. ALL network transports (fetch, XHR,
  // sendBeacon, WebSocket) use the SELECTIVE network context — document/archive
  // signatures and text-only PII — NOT the file-context "block all data" rule.
  // Web apps constantly send binary/JSON bodies as normal operation; blocking
  // all unrecognized binary here would break them. Genuine user file uploads are
  // caught upstream at the file-input / drag / paste / File System Access layer.
  //
  // Returns a Promise<{blocked, reason, filename}>, or null synchronously if the
  // body type carries no inspectable payload.
  function inspectBody(body, vector) {
    if (body instanceof File)
      return body.arrayBuffer().then(function (buf) {
        return withName(inspectNetworkBytes(new Uint8Array(buf)), body.name || 'file');
      });

    if (typeof Blob !== 'undefined' && body instanceof Blob)
      return body.arrayBuffer().then(function (buf) {
        return withName(inspectNetworkBytes(new Uint8Array(buf)), 'request body');
      });

    if (typeof FormData !== 'undefined' && body instanceof FormData) {
      var parts = [];
      body.forEach(function (value) { if (value instanceof File || value instanceof Blob) parts.push(value); });
      if (!parts.length) return null;
      return inspectPartsNet(parts);
    }

    var bytes = toBytes(body);
    if (bytes)
      return withName(inspectNetworkBytes(bytes), 'request body');

    if (typeof ReadableStream !== 'undefined' && body instanceof ReadableStream)
      return inspectStreamPrefix(body);

    return null;
  }

  // Sequentially inspect FormData file/blob parts in the network context.
  function inspectPartsNet(parts) {
    var idx = 0;
    function next() {
      if (idx >= parts.length) return Promise.resolve({ blocked: false });
      var p = parts[idx++];
      return p.arrayBuffer().then(function (b) {
        return inspectNetworkBytes(new Uint8Array(b));
      }).then(function (r) {
        if (r.blocked) return Object.assign({ filename: p.name || 'request body' }, r);
        return next();
      });
    }
    return next();
  }

  // File-context sequence — used ONLY by the File System Access picker, where the
  // user is genuinely selecting files to upload (block all document/data).
  function inspectFileSequence(files) {
    var idx = 0;
    function next() {
      if (idx >= files.length) return Promise.resolve({ blocked: false });
      var f = files[idx++];
      var p = (f instanceof File)
        ? inspectFileObj(f)
        : f.arrayBuffer().then(function (b) { return inspectFileBytes(new Uint8Array(b), 'upload.bin'); });
      return p.then(function (r) {
        if (r.blocked) return Object.assign({ filename: f.name || 'upload.bin' }, r);
        return next();
      });
    }
    return next();
  }

  function inspectStreamPrefix(stream) {
    // Caller is responsible for substituting a tee'd stream; here we just read
    // a bounded prefix for inspection.
    var reader = stream.getReader();
    var chunks = [];
    var total = 0;
    var CAP = 256 * 1024;
    function pump() {
      return reader.read().then(function (res) {
        if (res.done || total >= CAP) { try { reader.releaseLock(); } catch (_) {} return finish(); }
        if (res.value) { chunks.push(res.value); total += res.value.length; }
        return pump();
      });
    }
    function finish() {
      var buf = new Uint8Array(total), off = 0;
      chunks.forEach(function (c) { buf.set(c, off); off += c.length; });
      return inspectNetworkBytes(buf).then(function (r) { return Object.assign({ filename: 'stream body' }, r); });
    }
    return pump();
  }

  // ─── Patch fetch ─────────────────────────────────────────────────────────────

  var _fetch = window.fetch;
  window.fetch = function (input, init) {
    var body = init && init.body;
    var result = body != null ? inspectBody(body, 'fetch') : null;
    if (!result) return _fetch.apply(this, arguments);

    var self = this, args = arguments;
    return result.then(function (r) {
      if (r && r.blocked) {
        reportBlocked(r.filename, r.reason, 'fetch');
        return new Response('{"error":"Blocked by BetterDLP"}', { status: 403, headers: { 'Content-Type': 'application/json' } });
      }
      return _fetch.apply(self, args);
    }).catch(function () { return _fetch.apply(self, args); });
  };

  // ─── Patch XHR ───────────────────────────────────────────────────────────────

  var _send = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.send = function (body) {
    var result = body != null ? inspectBody(body, 'XHR') : null;
    if (!result) return _send.apply(this, arguments);

    var self = this, args = arguments;
    result.then(function (r) {
      if (r && r.blocked) { reportBlocked(r.filename, r.reason, 'XHR'); return; }
      _send.apply(self, args);
    }).catch(function () { _send.apply(self, args); });
  };

  // ─── Patch navigator.sendBeacon ──────────────────────────────────────────────

  if (navigator.sendBeacon) {
    var _beacon = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = function (url, data) {
      var result = data != null ? inspectBody(data, 'sendBeacon') : null;
      if (!result) return _beacon(url, data);
      // sendBeacon is synchronous-return; inspect async and only forward if clean.
      result.then(function (r) {
        if (r && r.blocked) { reportBlocked(r.filename, r.reason, 'sendBeacon'); return; }
        _beacon(url, data);
      }).catch(function () { _beacon(url, data); });
      return true; // optimistic; the real send happens after inspection
    };
  }

  // ─── Patch WebSocket.send / RTCDataChannel.send ──────────────────────────────
  // These are synchronous and return void. For payloads we can read synchronously
  // (string / ArrayBuffer / typed array) we block inline. Blob payloads are
  // inspected asynchronously and forwarded only if clean (may reorder frames —
  // acceptable for a security control).

  function wrapChannelSend(proto, label) {
    if (!proto || !proto.send) return;
    var _origSend = proto.send;
    proto.send = function (data) {
      var self = this, origArgs = arguments;
      var bytes = toBytes(data);
      if (bytes) {
        var verdict = Core.inspectNetworkBytes(bytes);
        if (verdict.blocked) { reportBlocked(label + ' frame', verdict.reason, label); return; }
        return _origSend.apply(self, origArgs);
      }
      if (typeof Blob !== 'undefined' && data instanceof Blob) {
        data.arrayBuffer().then(function (buf) {
          var v = Core.inspectNetworkBytes(new Uint8Array(buf));
          if (v.blocked) { reportBlocked(label + ' frame', v.reason, label); return; }
          _origSend.apply(self, origArgs);
        }).catch(function () { _origSend.apply(self, origArgs); });
        return;
      }
      return _origSend.apply(self, origArgs);
    };
  }

  if (typeof WebSocket !== 'undefined') wrapChannelSend(WebSocket.prototype, 'WebSocket');
  if (typeof RTCDataChannel !== 'undefined') wrapChannelSend(RTCDataChannel.prototype, 'WebRTC');

  // ─── Best-effort Worker instrumentation (belt-and-suspenders) ────────────────
  // A separate JS realm has its own un-patched fetch/XHR. We prepend a small
  // guard to same-origin / blob worker scripts so their fetch is also checked.
  // The authoritative cross-realm control is the webRequest backstop in the SW;
  // this only raises the bar and must NEVER break worker construction.

  function buildWorkerBootstrap() {
    // Inlined minimal guard: blocks fetch/XHR bodies with document/archive magic.
    // (Kept intentionally small; full detection lives at the network backstop.)
    return [
      '(function(){',
      'function sig(b){b=new Uint8Array(b);',
      'function at(s,o){for(var i=0;i<s.length;i++)if(b[(o||0)+i]!==s[i])return false;return true;}',
      'function find(s,m){var L=Math.min(b.length,m||b.length)-s.length;for(var i=0;i<=L;i++){var k=true;for(var j=0;j<s.length;j++)if(b[i+j]!==s[j]){k=false;break;}if(k)return i;}return -1;}',
      'if(at([0x50,0x4B,0x03,0x04])||find([0x50,0x4B,0x05,0x06])!==-1)return "ZIP/Office archive";',
      'if(at([0xD0,0xCF,0x11,0xE0]))return "Legacy Office document";',
      'if(find([0x25,0x50,0x44,0x46],1024)!==-1)return "PDF document";',
      'if(at([0x52,0x61,0x72,0x21])||at([0x37,0x7A,0xBC,0xAF])||at([0x1F,0x8B])||at([0xFD,0x37,0x7A,0x58,0x5A,0x00])||at([0x28,0xB5,0x2F,0xFD]))return "archive";',
      'return null;}',
      'function tb(x){return x instanceof ArrayBuffer?x:(ArrayBuffer.isView(x)?x.buffer:null);}',
      'var _f=self.fetch;if(_f)self.fetch=function(i,n){var b=n&&n.body,buf=tb(b);if(buf){var r=sig(buf);if(r)return Promise.resolve(new Response("{\\"error\\":\\"Blocked by BetterDLP\\"}",{status:403}));}return _f.apply(self,arguments);};',
      '})();'
    ].join('\n');
  }

  function instrumentWorker(NativeWorker) {
    function GuardedWorker(scriptURL, options) {
      try {
        var url = String(scriptURL);
        // Only instrument module-less blob: workers — the common exfil vector
        // (page-generated blob script). Wrapping served URLs would change the
        // worker base URL and break relative fetch/importScripts in real apps,
        // so we leave those to the webRequest backstop.
        if (url.indexOf('blob:') === 0 && (!options || options.type !== 'module')) {
          var boot = buildWorkerBootstrap();
          var wrapped = 'importScripts(' + JSON.stringify(url) + ');';
          // If importScripts of the original fails (e.g. CORS), fall back below.
          var blob = new Blob([boot + '\ntry{' + wrapped + '}catch(e){}'], { type: 'application/javascript' });
          return new NativeWorker(URL.createObjectURL(blob), options);
        }
      } catch (_) { /* fall through to native */ }
      return new NativeWorker(scriptURL, options);
    }
    GuardedWorker.prototype = NativeWorker.prototype;
    return GuardedWorker;
  }

  try {
    if (typeof Worker !== 'undefined') window.Worker = instrumentWorker(Worker);
  } catch (_) { /* never break the page */ }

  // ─── File System Access API (closes the no-change-event gap, #9) ─────────────
  // showOpenFilePicker() yields file handles with no input element / change
  // event, bypassing the isolated-world interceptor. Inspect the chosen files at
  // pick time; if any is blocked, show the modal and abort the pick so the page
  // never receives the handle.

  if (window.showOpenFilePicker) {
    var _openPicker = window.showOpenFilePicker.bind(window);
    window.showOpenFilePicker = function () {
      var args = arguments;
      return _openPicker.apply(null, args).then(function (handles) {
        return Promise.all(handles.map(function (h) {
          return h.getFile().then(function (file) { return { handle: h, file: file }; });
        })).then(function (pairs) {
          return inspectFileSequence(pairs.map(function (p) { return p.file; })).then(function (r) {
            if (r && r.blocked) {
              reportBlocked(r.filename, r.reason, 'file system access');
              var err = new DOMException('The user aborted a request.', 'AbortError');
              throw err;
            }
            return handles;
          });
        });
      });
    };
  }

})();
