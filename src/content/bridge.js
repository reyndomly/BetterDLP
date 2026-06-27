/**
 * BetterDLP - Bridge
 * Runs in isolated world. Listens for log events dispatched by page-patch.js
 * (MAIN world) via CustomEvent and persists them to chrome.storage.
 */
window.addEventListener('betterdlp-log', function (e) {
  var entry = e.detail;
  if (!entry) return;

  // Skip if the extension was reloaded and this content script is orphaned —
  // otherwise chrome.* throws "Extension context invalidated".
  try {
    if (!chrome.runtime || !chrome.runtime.id) return;
  } catch (_) { return; }

  var record = Object.assign({
    timestamp: new Date().toISOString(),
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
});
