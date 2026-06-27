/**
 * BetterDLP - Upload Interceptor (isolated world)
 * Handles: input[type=file], drag & drop, clipboard paste.
 * fetch/XHR are handled by page-patch.js in MAIN world.
 */
(function () {
  'use strict';

  // After the extension is reloaded/updated, content scripts already running in
  // open tabs are orphaned: chrome.* calls throw "Extension context invalidated".
  // Guard every chrome.* entry point with this check.
  function extValid() {
    try { return !!(chrome.runtime && chrome.runtime.id); } catch (_) { return false; }
  }

  function getConfig() {
    return new Promise(function (resolve) {
      // Fail closed-but-inert if the extension context is gone: report inactive
      // so we neither throw nor block the page while the extension reloads.
      if (!extValid()) { resolve({ enabled: false, mode: 'block_everywhere', domains: [], isManaged: false }); return; }
      try {
        chrome.storage.managed.get(null, function (managed) {
          var hasManagedPolicy = !chrome.runtime.lastError && managed && Object.keys(managed).length > 0;
          if (hasManagedPolicy) {
            resolve({
              enabled:      managed.enabled      !== undefined ? managed.enabled      : true,
              mode:         managed.mode         || 'block_everywhere',
              domains:      managed.domains      || [],
              lockSettings: managed.lockSettings !== undefined ? managed.lockSettings : true,
              isManaged:    true,
            });
          } else {
            chrome.storage.sync.get({ enabled: true, mode: 'block_everywhere', domains: [] }, function (sync) {
              resolve(Object.assign({ isManaged: false, lockSettings: false }, sync));
            });
          }
        });
      } catch (_) {
        resolve({ enabled: false, mode: 'block_everywhere', domains: [], isManaged: false });
      }
    });
  }

  function shouldBeActive(config) {
    if (!config.enabled) return false;
    var host = window.location.hostname;
    if (config.mode === 'block_everywhere') return true;
    if (config.mode === 'blocklist')
      return config.domains.some(function (d) { return host === d || host.endsWith('.' + d); });
    if (config.mode === 'allowlist') {
      var allowed = config.domains.some(function (d) { return host === d || host.endsWith('.' + d); });
      return !allowed;
    }
    return true;
  }

  function logEvent(entry) {
    if (!extValid()) return;
    var record = Object.assign({
      timestamp: new Date().toISOString(),
      site: window.location.hostname,
      url: window.location.href,
    }, entry);
    try {
      chrome.storage.local.get({ logs: [] }, function (data) {
        if (chrome.runtime.lastError) return;
        var logs = data.logs;
        logs.unshift(record);
        chrome.storage.local.set({ logs: logs.slice(0, 500) });
      });
      chrome.runtime.sendMessage({ type: 'DLP_BLOCKED', record: record }, function () {
        void chrome.runtime.lastError; // swallow "no receiver" / invalidated
      });
    } catch (_) { /* context invalidated mid-call */ }
  }

  window.BetterDLP = window.BetterDLP || {};
  window.BetterDLP.logEvent = logEvent;

  function notifyBlocked(file, result, vector) {
    // Log and show the modal independently so a failure in one never suppresses
    // the other (and never throws back into handleFiles).
    try {
      logEvent({ filename: file.name, size: file.size, reason: result.reason, vector: vector, action: 'BLOCKED' });
    } catch (e) { try { console.error('[BetterDLP] log error:', e); } catch (_) {} }
    try {
      if (window.BetterDLP && typeof window.BetterDLP.showBlockModal === 'function') {
        window.BetterDLP.showBlockModal({ filename: file.name, reason: result.reason, vector: vector });
      }
    } catch (e) { try { console.error('[BetterDLP] modal error:', e); } catch (_) {} }
  }

  async function handleFiles(files, vector) {
    var config = await getConfig();
    if (!shouldBeActive(config)) return false;

    for (var i = 0; i < files.length; i++) {
      var file = files[i];
      var result;
      try {
        result = (window.BetterDLP && typeof window.BetterDLP.inspectFile === 'function')
          ? await window.BetterDLP.inspectFile(file)
          : { blocked: true, reason: 'Inspector unavailable — blocked by policy' };
      } catch (err) {
        // Fail closed: an inspection error must block WITH feedback, never let
        // the file through silently or leave the user with no modal/log.
        try { console.error('[BetterDLP] inspection error:', err); } catch (_) {}
        result = { blocked: true, reason: 'Inspection error — blocked by policy' };
      }

      if (result && result.blocked) {
        notifyBlocked(file, result, vector);
        return true;
      }
      try {
        logEvent({ filename: file.name, size: file.size, reason: result.reason, vector: vector, action: 'ALLOWED' });
      } catch (_) {}
    }
    return false;
  }

  // ─── input[type=file] — document-level capture listener ──────────────────────
  // Stop ALL file input events synchronously — prevents the app from ever seeing
  // the file and showing a preview, regardless of extension or disguise.
  // After async inspection:
  //   blocked → show modal, clear input
  //   allowed → re-dispatch a synthetic change event so the app processes normally
  // isTrusted check avoids infinite loop on the re-dispatched event.

  document.addEventListener('change', function (e) {
    var target = e.target;
    if (!target || target.type !== 'file' || !target.files || target.files.length === 0) return;

    // Ignore our own re-dispatched synthetic events
    if (!e.isTrusted) return;

    var files = Array.from(target.files);

    // Stop propagation synchronously — app never sees this event, no preview shown
    e.stopImmediatePropagation();
    e.preventDefault();

    handleFiles(files, 'file input').then(function (blocked) {
      if (blocked) {
        target.value = '';
      } else {
        // File is clean — re-dispatch so the app handles it normally
        target.dispatchEvent(new Event('change', { bubbles: true, cancelable: true }));
      }
    }).catch(function (err) {
      // Fail closed: keep the file blocked (event already stopped) and tell the user.
      try { console.error('[BetterDLP] file-input handler error:', err); } catch (_) {}
      target.value = '';
      notifyBlocked({ name: (files[0] && files[0].name) || 'file', size: 0 },
        { reason: 'Inspection error — blocked by policy' }, 'file input');
    });
  }, true);

  // ─── Drag & Drop ─────────────────────────────────────────────────────────────

  document.addEventListener('dragover', function (e) {
    if (e.dataTransfer && e.dataTransfer.types && e.dataTransfer.types.includes('Files')) {
      e.preventDefault();
    }
  }, true);

  // Collect dropped files from BOTH dataTransfer.files and dataTransfer.items.
  // Some sources populate items (kind === 'file') without files; enumerate both
  // and de-duplicate so disguised drops can't slip through the .files-only path.
  function collectDropFiles(dt) {
    var out = [];
    var seen = new Set();
    function add(f) {
      if (!f) return;
      var key = (f.name || '') + ':' + f.size + ':' + (f.lastModified || 0);
      if (seen.has(key)) return;
      seen.add(key);
      out.push(f);
    }
    if (dt.files) for (var i = 0; i < dt.files.length; i++) add(dt.files[i]);
    if (dt.items) {
      for (var j = 0; j < dt.items.length; j++) {
        var it = dt.items[j];
        if (it && it.kind === 'file' && typeof it.getAsFile === 'function') add(it.getAsFile());
      }
    }
    return out;
  }

  document.addEventListener('drop', function (e) {
    if (!e.dataTransfer) return;
    if (!e.isTrusted) return;

    var files = collectDropFiles(e.dataTransfer);
    if (files.length === 0) return;
    var target = e.target;

    // Stop synchronously — prevents preview before async inspection completes
    e.stopImmediatePropagation();
    e.preventDefault();

    handleFiles(files, 'drag & drop').then(function (blocked) {
      if (!blocked) {
        // File is clean — re-dispatch so the app handles it normally
        try {
          var dt = new DataTransfer();
          files.forEach(function (f) { dt.items.add(f); });
          var syntheticDrop = new DragEvent('drop', {
            bubbles: true,
            cancelable: true,
            dataTransfer: dt,
          });
          (target || document.body).dispatchEvent(syntheticDrop);
        } catch (_) {
          // DragEvent re-dispatch not supported
        }
      }
    }).catch(function (err) {
      try { console.error('[BetterDLP] drop handler error:', err); } catch (_) {}
      notifyBlocked({ name: (files[0] && files[0].name) || 'file', size: 0 },
        { reason: 'Inspection error — blocked by policy' }, 'drag & drop');
    });
  }, true);

  // ─── Clipboard Paste ─────────────────────────────────────────────────────────
  // Mirror the same fix as input[type=file]: stop synchronously so the app never
  // sees the event and cannot show a preview, then re-dispatch with a synthetic
  // (non-trusted) ClipboardEvent if the file turns out to be clean.

  document.addEventListener('paste', function (e) {
    if (!e.clipboardData || !e.clipboardData.files || e.clipboardData.files.length === 0) return;

    // Ignore our own re-dispatched synthetic events
    if (!e.isTrusted) return;

    var files = Array.from(e.clipboardData.files);
    var target = e.target;

    // Stop synchronously — app never sees this event, no preview shown
    e.stopImmediatePropagation();
    e.preventDefault();

    handleFiles(files, 'clipboard paste').then(function (blocked) {
      if (!blocked) {
        // File is clean — re-dispatch so the app handles it normally
        try {
          var dt = new DataTransfer();
          files.forEach(function (f) { dt.items.add(f); });
          var syntheticPaste = new ClipboardEvent('paste', {
            bubbles: true,
            cancelable: true,
            clipboardData: dt,
          });
          (target || document.activeElement || document.body).dispatchEvent(syntheticPaste);
        } catch (_) {
          // DataTransfer construction not supported; clean file won't be re-delivered
        }
      }
    }).catch(function (err) {
      try { console.error('[BetterDLP] paste handler error:', err); } catch (_) {}
      notifyBlocked({ name: (files[0] && files[0].name) || 'file', size: 0 },
        { reason: 'Inspection error — blocked by policy' }, 'clipboard paste');
    });
  }, true);

})();
