/**
 * BetterDLP - Popup Logic
 */

// ─── Tabs ─────────────────────────────────────────────────────────────────────

document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById('tab-' + tab.dataset.tab).classList.add('active');
  });
});

// ─── Toggle ───────────────────────────────────────────────────────────────────

const toggle = document.getElementById('main-toggle');
const toggleText = document.getElementById('toggle-text');

chrome.storage.managed.get(null, function (managed) {
  const hasManagedPolicy = !chrome.runtime.lastError && managed && Object.keys(managed).length > 0;
  if (hasManagedPolicy && managed.enabled !== undefined) {
    setToggle(managed.enabled);
    if (managed.lockSettings !== false) {
      toggle.style.pointerEvents = 'none';
      toggle.style.opacity = '0.6';
    }
  } else {
    chrome.storage.sync.get({ enabled: true }, ({ enabled }) => setToggle(enabled));
  }
});

toggle.addEventListener('click', () => {
  if (settingsLocked) return;
  const isOn = toggle.classList.contains('on');
  chrome.storage.sync.set({ enabled: !isOn });
  setToggle(!isOn);
});

function setToggle(enabled) {
  toggle.classList.toggle('on', enabled);
  toggleText.textContent = enabled ? 'ON' : 'OFF';
}

// ─── Log Rendering ────────────────────────────────────────────────────────────

function renderEntry(entry) {
  const div = document.createElement('div');
  const actionClass = entry.action === 'BLOCKED' ? 'blocked'
    : entry.action === 'FALSE_POSITIVE_REPORTED' ? 'false-positive'
    : 'allowed';
  div.className = `log-entry ${actionClass}`;
  div.innerHTML = `
    <div class="log-top">
      <span class="log-filename" title="${entry.filename}">${entry.filename || 'Unknown'}</span>
      <span class="log-action ${entry.action}">${entry.action}</span>
    </div>
    <div class="log-reason">${entry.reason || ''}</div>
    <div class="log-meta">${entry.site || ''} · ${entry.vector || ''} · ${formatTime(entry.timestamp)}</div>
  `;
  return div;
}

function formatTime(iso) {
  if (!iso) return '';
  try {
    const d = new Date(iso);
    return d.toLocaleString();
  } catch { return iso; }
}

function isToday(iso) {
  if (!iso) return false;
  const d = new Date(iso);
  const now = new Date();
  return d.getFullYear() === now.getFullYear()
    && d.getMonth() === now.getMonth()
    && d.getDate() === now.getDate();
}

function loadLogs() {
  chrome.storage.local.get({ logs: [] }, ({ logs }) => {
    // Dashboard stats
    const todayLogs = logs.filter(l => isToday(l.timestamp));
    document.getElementById('stat-blocked').textContent = todayLogs.filter(l => l.action === 'BLOCKED').length;
    document.getElementById('stat-allowed').textContent = todayLogs.filter(l => l.action === 'ALLOWED').length;

    // Dashboard recent (last 5)
    const recentEl = document.getElementById('dashboard-recent');
    recentEl.innerHTML = '';
    if (logs.length === 0) {
      recentEl.innerHTML = '<div class="empty-state">No activity yet</div>';
    } else {
      logs.slice(0, 5).forEach(e => recentEl.appendChild(renderEntry(e)));
    }

    // Full log
    const fullEl = document.getElementById('full-log-list');
    fullEl.innerHTML = '';
    if (logs.length === 0) {
      fullEl.innerHTML = '<div class="empty-state">No logs yet</div>';
    } else {
      logs.forEach(e => fullEl.appendChild(renderEntry(e)));
    }

    // Clear badge
    chrome.runtime.sendMessage({ type: 'CLEAR_BADGE' });
  });
}

document.getElementById('btn-clear-logs').addEventListener('click', () => {
  chrome.storage.local.set({ logs: [] }, loadLogs);
});

document.getElementById('btn-export').addEventListener('click', () => {
  chrome.storage.local.get({ logs: [] }, ({ logs }) => {
    const blob = new Blob([JSON.stringify(logs, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `betterdlp-logs-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  });
});

// ─── Settings ─────────────────────────────────────────────────────────────────

const modeSelect = document.getElementById('mode-select');
const domainSection = document.getElementById('domain-section');
const domainLabel = document.getElementById('domain-label');
const domainList = document.getElementById('domain-list');
const domainInput = document.getElementById('domain-input');

let settingsLocked = false;

function applyManagedLock(locked) {
  settingsLocked = locked;
  document.getElementById('managed-banner').style.display = locked ? 'flex' : 'none';
  document.getElementById('mode-locked-badge').style.display = locked ? 'inline-block' : 'none';
  document.getElementById('domains-locked-badge').style.display = locked ? 'inline-block' : 'none';
  document.getElementById('mode-group').classList.toggle('setting-locked', locked);
  document.getElementById('domain-add-row').style.display = locked ? 'none' : 'flex';
  // Remove delete buttons on existing domain items when locked
  document.querySelectorAll('.domain-remove').forEach(el => {
    el.style.display = locked ? 'none' : '';
  });
}

function renderDomains(domains, locked) {
  domainList.innerHTML = '';
  if (domains.length === 0) {
    domainList.innerHTML = '<div style="font-size:12px;color:#9CA3AF;padding:4px 0;">No domains added</div>';
    return;
  }
  domains.forEach(domain => {
    const item = document.createElement('div');
    item.className = 'domain-item';
    item.innerHTML = `<span>${domain}</span><span class="domain-remove" data-domain="${domain}" style="display:${locked ? 'none' : ''}">×</span>`;
    if (!locked) {
      item.querySelector('.domain-remove').addEventListener('click', () => {
        chrome.storage.sync.get({ domains: [] }, ({ domains: d }) => {
          const updated = d.filter(x => x !== domain);
          chrome.storage.sync.set({ domains: updated });
          renderDomains(updated, false);
        });
      });
    }
    domainList.appendChild(item);
  });
}

function updateDomainLabel(mode) {
  const labels = {
    block_everywhere: 'Domains (not applicable in this mode)',
    blocklist: 'Block on these domains',
    allowlist: 'Allow on these domains (block everywhere else)',
  };
  // Preserve the MANAGED badge by only updating the text node
  const badge = document.getElementById('domains-locked-badge');
  domainLabel.textContent = labels[mode] || 'Domains';
  domainLabel.appendChild(badge);
  domainSection.style.opacity = mode === 'block_everywhere' ? '0.4' : '1';
  domainSection.style.pointerEvents = (!settingsLocked && mode === 'block_everywhere') ? 'none' : '';
}

function loadSettings() {
  chrome.storage.managed.get(null, function (managed) {
    const hasManagedPolicy = !chrome.runtime.lastError && managed && Object.keys(managed).length > 0;
    if (hasManagedPolicy) {
      const locked = managed.lockSettings !== false;
      const mode = managed.mode || 'block_everywhere';
      const domains = managed.domains || [];
      modeSelect.value = mode;
      updateDomainLabel(mode);
      renderDomains(domains, locked);
      applyManagedLock(locked);
    } else {
      chrome.storage.sync.get({ mode: 'block_everywhere', domains: [] }, ({ mode, domains }) => {
        modeSelect.value = mode;
        updateDomainLabel(mode);
        renderDomains(domains, false);
        applyManagedLock(false);
      });
    }
  });
}

loadSettings();

modeSelect.addEventListener('change', () => {
  if (settingsLocked) return;
  const mode = modeSelect.value;
  chrome.storage.sync.set({ mode });
  updateDomainLabel(mode);
});

document.getElementById('btn-add-domain').addEventListener('click', () => {
  if (settingsLocked) return;
  const val = domainInput.value.trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  if (!val) return;
  chrome.storage.sync.get({ domains: [] }, ({ domains }) => {
    if (domains.includes(val)) return;
    const updated = [...domains, val];
    chrome.storage.sync.set({ domains: updated });
    renderDomains(updated, false);
    domainInput.value = '';
  });
});

domainInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') document.getElementById('btn-add-domain').click();
});

// ─── Init ─────────────────────────────────────────────────────────────────────

loadLogs();
