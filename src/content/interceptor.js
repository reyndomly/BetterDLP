/**
 * BetterDLP - Upload Interceptor
 * Intercepts all file upload vectors:
 *   1. <input type="file"> change events
 *   2. Drag & drop
 *   3. Clipboard paste
 *   4. XHR and fetch (monkey-patched at document_start)
 */

(function () {
  'use strict';

  // ─── Config ──────────────────────────────────────────────────────────────────

  function getConfig() {
    return new Promise((resolve) => {
      chrome.storage.sync.get({ enabled: true, mode: 'block_everywhere', domains: [] }, resolve);
    });
  }

  function shouldBeActive(config) {
    if (!config.enabled) return false;
    const host = window.location.hostname;

    if (config.mode === 'block_everywhere') return true;

    if (config.mode === 'blocklist') {
      return config.domains.some(d => host === d || host.endsWith('.' + d));
    }

    if (config.mode === 'allowlist') {
      const isAllowed = config.domains.some(d => host === d || host.endsWith('.' + d));
      return !isAllowed;
    }

    return true;
  }

  // ─── Audit Log ───────────────────────────────────────────────────────────────

  function logEvent(entry) {
    const record = {
      timestamp: new Date().toISOString(),
      site: window.location.hostname,
      url: window.location.href,
      ...entry,
    };
    chrome.storage.local.get({ logs: [] }, (data) => {
      const logs = data.logs;
      logs.unshift(record);
      // Keep last 500 entries
      chrome.storage.local.set({ logs: logs.slice(0, 500) });
    });
    // Also notify background for badge update
    chrome.runtime.sendMessage({ type: 'DLP_BLOCKED', record });
  }

  window.BetterDLP = window.BetterDLP || {};
  window.BetterDLP.logEvent = logEvent;

  // ─── Core inspect + block ────────────────────────────────────────────────────

  async function handleFiles(files, vector) {
    const config = await getConfig();
    if (!shouldBeActive(config)) return;

    for (const file of Array.from(files)) {
      const result = await window.BetterDLP.inspectFile(file);
      if (result.blocked) {
        logEvent({
          filename: file.name,
          size: file.size,
          reason: result.reason,
          vector,
          action: 'BLOCKED',
        });
        window.BetterDLP.showBlockModal({
          filename: file.name,
          reason: result.reason,
          vector,
        });
        return true; // blocked
      } else {
        logEvent({
          filename: file.name,
          size: file.size,
          reason: 'Passed all checks',
          vector,
          action: 'ALLOWED',
        });
      }
    }
    return false; // allowed
  }

  // ─── Vector 1: <input type="file"> ───────────────────────────────────────────

  function attachToInput(input) {
    if (input._dlpAttached) return;
    input._dlpAttached = true;
    input.addEventListener('change', async (e) => {
      const blocked = await handleFiles(e.target.files, 'file input');
      if (blocked) {
        // Reset the input so the file is not queued for upload
        e.target.value = '';
      }
    }, true);
  }

  // Attach to existing inputs
  document.querySelectorAll('input[type="file"]').forEach(attachToInput);

  // Watch for dynamically added inputs
  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node.nodeType !== 1) continue;
        if (node.matches && node.matches('input[type="file"]')) attachToInput(node);
        node.querySelectorAll && node.querySelectorAll('input[type="file"]').forEach(attachToInput);
      }
    }
  });
  observer.observe(document.documentElement, { childList: true, subtree: true });

  // ─── Vector 2: Drag & Drop ───────────────────────────────────────────────────

  document.addEventListener('dragover', (e) => e.preventDefault(), true);
  document.addEventListener('drop', async (e) => {
    if (!e.dataTransfer || !e.dataTransfer.files || e.dataTransfer.files.length === 0) return;
    const blocked = await handleFiles(e.dataTransfer.files, 'drag & drop');
    if (blocked) {
      e.preventDefault();
      e.stopImmediatePropagation();
    }
  }, true);

  // ─── Vector 3: Clipboard Paste ───────────────────────────────────────────────

  document.addEventListener('paste', async (e) => {
    if (!e.clipboardData || !e.clipboardData.files || e.clipboardData.files.length === 0) return;
    const blocked = await handleFiles(e.clipboardData.files, 'clipboard paste');
    if (blocked) {
      e.preventDefault();
      e.stopImmediatePropagation();
    }
  }, true);

  // ─── Vector 4: XHR / Fetch monkey-patch ──────────────────────────────────────
  // Injected at document_start so it runs before page scripts initialize.

  async function extractFilesFromBody(body) {
    if (body instanceof FormData) {
      const files = [];
      for (const [, value] of body.entries()) {
        if (value instanceof File) files.push(value);
        if (value instanceof Blob && !(value instanceof File)) {
          // Wrap blob as a pseudo-file for inspection
          files.push(new File([value], 'upload.bin', { type: value.type }));
        }
      }
      return files;
    }
    if (body instanceof File) return [body];
    if (body instanceof Blob) return [new File([body], 'upload.bin', { type: body.type })];
    return [];
  }

  // Patch fetch
  const _originalFetch = window.fetch;
  window.fetch = async function (input, init = {}) {
    const files = await extractFilesFromBody(init.body);
    if (files.length > 0) {
      const blocked = await handleFiles(files, 'fetch API');
      if (blocked) {
        return new Response(JSON.stringify({ error: 'Blocked by BetterDLP' }), {
          status: 403,
          headers: { 'Content-Type': 'application/json' },
        });
      }
    }
    return _originalFetch.apply(this, arguments);
  };

  // Patch XMLHttpRequest
  const _originalXHRSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.send = async function (body) {
    const files = await extractFilesFromBody(body);
    if (files.length > 0) {
      const blocked = await handleFiles(files, 'XHR');
      if (blocked) {
        // Abort the request silently — modal already shown
        this.abort();
        return;
      }
    }
    _originalXHRSend.apply(this, arguments);
  };

})();
