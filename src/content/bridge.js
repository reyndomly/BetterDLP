/**
 * BetterDLP - Bridge
 * Runs in isolated world. Listens for log events dispatched by page-patch.js
 * (MAIN world) via CustomEvent and persists them to chrome.storage.
 */
window.addEventListener('betterdlp-log', function (e) {
  var entry = e.detail;
  if (!entry) return;

  var record = Object.assign({
    timestamp: new Date().toISOString(),
    url: window.location.href,
  }, entry);

  chrome.storage.local.get({ logs: [] }, function (data) {
    var logs = data.logs;
    logs.unshift(record);
    chrome.storage.local.set({ logs: logs.slice(0, 500) });
  });

  chrome.runtime.sendMessage({ type: 'DLP_BLOCKED', record: record });
});
