/**
 * BetterDLP - Block UI
 * Injects a Shadow DOM modal that cannot be removed or overridden by page scripts.
 */

function showBlockModal({ filename, reason, vector }) {
  // Remove any existing modal
  const existing = document.getElementById('betterdlp-host');
  if (existing) existing.remove();

  const host = document.createElement('div');
  host.id = 'betterdlp-host';
  host.style.cssText = 'all:initial;position:fixed;top:0;left:0;width:100%;height:100%;z-index:2147483647;';

  // Closed shadow root — page JS cannot access or remove this
  const shadow = host.attachShadow({ mode: 'closed' });

  shadow.innerHTML = `
    <style>
      * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; }
      .overlay {
        position: fixed; inset: 0;
        background: rgba(0,0,0,0.65);
        display: flex; align-items: center; justify-content: center;
        animation: fadeIn 0.15s ease;
      }
      @keyframes fadeIn { from { opacity: 0 } to { opacity: 1 } }
      .modal {
        background: #fff;
        border-radius: 12px;
        padding: 32px;
        max-width: 460px;
        width: 90%;
        box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        animation: slideUp 0.2s ease;
      }
      @keyframes slideUp { from { transform: translateY(16px); opacity: 0 } to { transform: translateY(0); opacity: 1 } }
      .header {
        display: flex; align-items: center; gap: 12px;
        margin-bottom: 20px;
      }
      .icon {
        width: 44px; height: 44px; border-radius: 10px;
        background: #FEE2E2; display: flex; align-items: center; justify-content: center;
        font-size: 22px; flex-shrink: 0;
      }
      .title { font-size: 18px; font-weight: 700; color: #111; }
      .subtitle { font-size: 13px; color: #EF4444; font-weight: 500; margin-top: 2px; }
      .detail-box {
        background: #F9FAFB; border: 1px solid #E5E7EB;
        border-radius: 8px; padding: 14px 16px; margin-bottom: 20px;
      }
      .detail-row { display: flex; gap: 8px; margin-bottom: 6px; font-size: 13px; }
      .detail-row:last-child { margin-bottom: 0; }
      .detail-label { color: #6B7280; width: 70px; flex-shrink: 0; }
      .detail-value { color: #111; font-weight: 500; word-break: break-all; }
      .reason-box {
        background: #FEF2F2; border: 1px solid #FECACA;
        border-radius: 8px; padding: 12px 14px; margin-bottom: 24px;
        font-size: 13px; color: #991B1B; line-height: 1.5;
      }
      .actions { display: flex; gap: 10px; justify-content: flex-end; }
      .btn {
        padding: 9px 18px; border-radius: 8px; font-size: 13px;
        font-weight: 600; cursor: pointer; border: none; transition: opacity 0.15s;
      }
      .btn:hover { opacity: 0.85; }
      .btn-report {
        background: #F3F4F6; color: #374151;
      }
      .btn-ok {
        background: #EF4444; color: #fff;
      }
      .footer {
        margin-top: 16px; font-size: 11px; color: #9CA3AF; text-align: center;
      }
    </style>
    <div class="overlay">
      <div class="modal">
        <div class="header">
          <div class="icon">🚫</div>
          <div>
            <div class="title">Upload Blocked</div>
            <div class="subtitle">BetterDLP Policy Violation</div>
          </div>
        </div>
        <div class="detail-box">
          <div class="detail-row">
            <span class="detail-label">File</span>
            <span class="detail-value" id="dlp-filename"></span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Vector</span>
            <span class="detail-value" id="dlp-vector"></span>
          </div>
        </div>
        <div class="reason-box" id="dlp-reason"></div>
        <div class="actions">
          <button class="btn btn-report" id="dlp-btn-report">Report False Positive</button>
          <button class="btn btn-ok" id="dlp-btn-ok">Understood</button>
        </div>
        <div class="footer">BetterDLP is protecting your organization's data</div>
      </div>
    </div>
  `;

  shadow.getElementById('dlp-filename').textContent = filename || 'Unknown';
  shadow.getElementById('dlp-vector').textContent = vector || 'file input';
  shadow.getElementById('dlp-reason').textContent = reason || 'Blocked by policy';

  shadow.getElementById('dlp-btn-ok').addEventListener('click', () => host.remove());
  shadow.getElementById('dlp-btn-report').addEventListener('click', () => {
    window.BetterDLP.logEvent({ filename, reason, vector, action: 'FALSE_POSITIVE_REPORTED' });
    host.remove();
  });

  document.documentElement.appendChild(host);
}

window.BetterDLP = window.BetterDLP || {};
window.BetterDLP.showBlockModal = showBlockModal;
