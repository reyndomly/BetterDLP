/**
 * BetterDLP - Service Worker (Manifest V3 background)
 *
 * Responsibilities:
 *   - Badge updates and inter-component messaging.
 *   - NETWORK BACKSTOP: a blocking webRequest handler that inspects request
 *     bodies for document/archive signatures and PII. This sits below the JS
 *     layer in the network stack, so it catches uploads issued from ANY realm —
 *     Web Workers, Service Workers, dynamically-created iframes, raw ArrayBuffer
 *     bodies — that escape the content-script patches.
 *
 * Constraints:
 *   - Blocking webRequest handlers MUST return synchronously. We therefore keep
 *     the policy config in a cached module variable (refreshed via
 *     storage.onChanged) instead of awaiting chrome.storage inside the handler,
 *     and we do only synchronous byte/text analysis (no JSZip) at this layer.
 *   - webRequestBlocking is only granted to POLICY-INSTALLED extensions in MV3.
 *     The backstop is active only when BetterDLP is force-installed (see
 *     docs/gpo-deployment.md). Content-script enforcement still works otherwise.
 */

importScripts('../lib/detection-core.js');
const Core = self.BetterDLPCore;

// ─── Config cache (kept fresh so the blocking handler stays synchronous) ──────

let CONFIG = { enabled: true, mode: 'block_everywhere', domains: [], networkEnforcement: true, isManaged: false };

function loadConfig() {
  chrome.storage.managed.get(null, function (managed) {
    const hasManaged = !chrome.runtime.lastError && managed && Object.keys(managed).length > 0;
    if (hasManaged) {
      CONFIG = {
        enabled:            managed.enabled            !== undefined ? managed.enabled            : true,
        mode:               managed.mode               || 'block_everywhere',
        domains:            managed.domains            || [],
        networkEnforcement: managed.networkEnforcement !== undefined ? managed.networkEnforcement : true,
        isManaged:          true,
      };
    } else {
      chrome.storage.sync.get(
        { enabled: true, mode: 'block_everywhere', domains: [], networkEnforcement: true },
        function (sync) { CONFIG = Object.assign({ isManaged: false }, sync); }
      );
    }
  });
}

loadConfig();
chrome.storage.onChanged.addListener(loadConfig);

function hostFromUrl(url) {
  try { return new URL(url).hostname; } catch (_) { return ''; }
}

function shouldEnforce(host) {
  if (!CONFIG.enabled || !CONFIG.networkEnforcement) return false;
  if (CONFIG.mode === 'block_everywhere') return true;
  const inList = (CONFIG.domains || []).some(function (d) { return host === d || host.endsWith('.' + d); });
  if (CONFIG.mode === 'blocklist') return inList;
  if (CONFIG.mode === 'allowlist') return !inList;
  return true;
}

// ─── Body inspection (synchronous) ───────────────────────────────────────────

const NET_BODY_CAP = 1024 * 1024; // 1MB cap on bytes concatenated for inspection

function inspectRequestBody(requestBody) {
  if (!requestBody) return { blocked: false };

  // Raw bytes (covers fetch/XHR ArrayBuffer + multipart file parts).
  if (requestBody.raw && requestBody.raw.length) {
    let total = 0;
    for (const part of requestBody.raw) if (part.bytes) total += part.bytes.byteLength;
    total = Math.min(total, NET_BODY_CAP);
    const buf = new Uint8Array(total);
    let off = 0;
    for (const part of requestBody.raw) {
      if (!part.bytes || off >= total) break;
      const chunk = new Uint8Array(part.bytes, 0, Math.min(part.bytes.byteLength, total - off));
      buf.set(chunk, off);
      off += chunk.length;
    }
    const verdict = Core.inspectNetworkBytes(buf);
    if (verdict.blocked) return verdict;
  }

  // URL-encoded / multipart string fields → PII scan only.
  if (requestBody.formData) {
    let text = '';
    for (const key in requestBody.formData) {
      const vals = requestBody.formData[key];
      if (Array.isArray(vals)) text += key + '=' + vals.join(' ') + '\n';
    }
    if (text) {
      const pii = Core.scanTextContent(text);
      if (pii) return pii;
    }
  }

  return { blocked: false };
}

// ─── webRequest backstop ──────────────────────────────────────────────────────

function onBeforeRequest(details) {
  const method = (details.method || 'GET').toUpperCase();
  if (method !== 'POST' && method !== 'PUT' && method !== 'PATCH') return {};

  const host = hostFromUrl(details.url) || hostFromUrl(details.initiator || details.documentUrl || '');
  if (!shouldEnforce(host)) return {};

  let verdict;
  try { verdict = inspectRequestBody(details.requestBody); }
  catch (_) { return {}; } // never break traffic on an inspection error

  if (verdict && verdict.blocked) {
    recordNetworkBlock(host, details.url, verdict.reason);
    return { cancel: true };
  }
  return {};
}

function registerBackstop() {
  if (!chrome.webRequest || !chrome.webRequest.onBeforeRequest) return;
  try {
    chrome.webRequest.onBeforeRequest.addListener(
      onBeforeRequest,
      { urls: ['<all_urls>'], types: ['xmlhttprequest', 'ping', 'other', 'sub_frame', 'main_frame'] },
      ['blocking', 'requestBody']
    );
  } catch (e) {
    // webRequestBlocking not granted (extension not policy-installed). The
    // content-script layer still enforces; the network backstop is inactive.
    console.warn('BetterDLP: network backstop unavailable —', e && e.message);
  }
}

registerBackstop();

// ─── Logging / notification for network-layer blocks ─────────────────────────

function recordNetworkBlock(host, url, reason) {
  const record = {
    timestamp: new Date().toISOString(),
    site: host,
    url: url,
    filename: 'network upload',
    reason: reason,
    vector: 'network (webRequest)',
    action: 'BLOCKED',
  };
  chrome.storage.local.get({ logs: [] }, function (data) {
    const logs = data.logs;
    logs.unshift(record);
    chrome.storage.local.set({ logs: logs.slice(0, 500) });
  });
  bumpBadge();
  try {
    chrome.notifications.create({
      type: 'basic',
      iconUrl: '../../icons/icon128.png',
      title: 'Upload Blocked — BetterDLP',
      message: reason + '\n' + host,
    });
  } catch (_) { /* notifications optional */ }
}

function bumpBadge() {
  chrome.action.getBadgeText({}, function (text) {
    const count = (parseInt(text, 10) || 0) + 1;
    chrome.action.setBadgeText({ text: String(count) });
  });
}

// ─── Install / messaging ──────────────────────────────────────────────────────

chrome.runtime.onInstalled.addListener(() => {
  chrome.action.setBadgeBackgroundColor({ color: '#EF4444' });
  chrome.storage.local.set({ logs: [] });
  chrome.storage.sync.set({ enabled: true, mode: 'block_everywhere', domains: [], networkEnforcement: true });
});

chrome.runtime.onMessage.addListener((message) => {
  if (message.type === 'DLP_BLOCKED') {
    bumpBadge();
  }
  if (message.type === 'CLEAR_BADGE') {
    chrome.action.setBadgeText({ text: '' });
  }
});
