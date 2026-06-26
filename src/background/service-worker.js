/**
 * BetterDLP - Service Worker (Manifest V3 background)
 * Handles badge updates and inter-component messaging.
 */

chrome.runtime.onInstalled.addListener(() => {
  chrome.action.setBadgeBackgroundColor({ color: '#EF4444' });
  chrome.storage.local.set({ logs: [] });
  chrome.storage.sync.set({ enabled: true, mode: 'block_everywhere', domains: [] });
});

chrome.runtime.onMessage.addListener((message) => {
  if (message.type === 'DLP_BLOCKED') {
    // Bump badge count
    chrome.action.getBadgeText({}, (text) => {
      const count = (parseInt(text, 10) || 0) + 1;
      chrome.action.setBadgeText({ text: String(count) });
    });
  }

  if (message.type === 'CLEAR_BADGE') {
    chrome.action.setBadgeText({ text: '' });
  }
});
