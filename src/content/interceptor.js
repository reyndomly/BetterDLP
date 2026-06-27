/**
 * BetterDLP - Upload Interceptor (isolated world)
 * Handles: input[type=file], drag & drop, clipboard paste.
 * fetch/XHR are handled by page-patch.js in MAIN world.
 */
(function () {
  'use strict';

  function getConfig() {
    return new Promise(function (resolve) {
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
    var record = Object.assign({
      timestamp: new Date().toISOString(),
      site: window.location.hostname,
      url: window.location.href,
    }, entry);
    chrome.storage.local.get({ logs: [] }, function (data) {
      var logs = data.logs;
      logs.unshift(record);
      chrome.storage.local.set({ logs: logs.slice(0, 500) });
    });
    chrome.runtime.sendMessage({ type: 'DLP_BLOCKED', record: record });
  }

  window.BetterDLP = window.BetterDLP || {};
  window.BetterDLP.logEvent = logEvent;

  async function handleFiles(files, vector) {
    var config = await getConfig();
    if (!shouldBeActive(config)) return false;

    for (var i = 0; i < files.length; i++) {
      var file = files[i];
      var result = await window.BetterDLP.inspectFile(file);
      if (result.blocked) {
        logEvent({ filename: file.name, size: file.size, reason: result.reason, vector: vector, action: 'BLOCKED' });
        window.BetterDLP.showBlockModal({ filename: file.name, reason: result.reason, vector: vector });
        return true;
      }
      logEvent({ filename: file.name, size: file.size, reason: result.reason, vector: vector, action: 'ALLOWED' });
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
    });
  }, true);

  // ─── Drag & Drop ─────────────────────────────────────────────────────────────

  document.addEventListener('dragover', function (e) {
    if (e.dataTransfer && e.dataTransfer.types && e.dataTransfer.types.includes('Files')) {
      e.preventDefault();
    }
  }, true);

  document.addEventListener('drop', function (e) {
    if (!e.dataTransfer || !e.dataTransfer.files || e.dataTransfer.files.length === 0) return;
    if (!e.isTrusted) return;

    var files = Array.from(e.dataTransfer.files);
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
    });
  }, true);

})();
