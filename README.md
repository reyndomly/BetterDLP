# BetterDLP

![Tests](https://github.com/reyndomly/BetterDLP/actions/workflows/test.yml/badge.svg)

Chrome extension that enforces Data Loss Prevention by blocking document uploads based on actual file content — not filename or extension.

---

## How it works

BetterDLP intercepts uploads before they reach the network and inspects the real file content — not the filename or extension. A DOCX renamed to `.jpg` is still a ZIP containing `word/document.xml`, and a spreadsheet renamed to `report.md` is still tabular data — BetterDLP catches both.

Enforcement runs in layers: a shared detection core ([src/lib/detection-core.js](src/lib/detection-core.js)) provides the signature, content, and PII rules; content scripts apply them at every page-side upload vector; and a service-worker `webRequest` backstop re-checks upload bodies at the network layer so uploads from other JS realms (Web/Service Workers) can't slip past.

**Policy intent:** uploads of documents and *data* are blocked; only verified-safe binary
assets (images/video matching their real magic bytes) pass. Any file whose bytes are plain
text/data is blocked regardless of its extension — a CSV renamed to `report.md` is still data.

**Blocked formats:** DOCX, XLSX, PPTX, DOC, XLS, PPT, PDF, RTF, any plain-text/data file
(CSV, TSV, JSON, XML, SVG, source, …) regardless of extension, ZIP/Office (located even when
disguised by prepended bytes or a polyglot header), and the archive containers RAR, 7z, GZIP,
XZ, Zstandard, BZIP2, LZ4, CAB, and TAR.

**Upload vectors covered:**
- `<input type="file">` — file picker, including dynamically injected inputs
- Drag and drop (`dataTransfer.files` **and** `dataTransfer.items`)
- Clipboard paste
- File System Access API (`showOpenFilePicker`)
- `fetch()` and `XMLHttpRequest` — including raw `ArrayBuffer`/`TypedArray`/string/stream bodies
- `navigator.sendBeacon`, `WebSocket.send`, `RTCDataChannel.send`
- **Network backstop:** a blocking `webRequest` handler in the service worker inspects upload
  bodies from *any* JS realm (Web/Service Workers, dynamically-created frames) that escape the
  content-script patches. Active only when the extension is force-installed (MV3 grants
  `webRequestBlocking` to policy-installed extensions only).

---

## Detection

| Technique | What it catches |
|-----------|----------------|
| Offset-tolerant magic | Real file type even when the signature is hidden by prepended bytes or a polyglot header |
| Block-all-text | Any plain-text/data file, regardless of extension (closes the rename bypass) |
| Archive signatures | RAR, 7z, GZIP, XZ, Zstandard, BZIP2, LZ4, CAB, TAR |
| ZIP inspection | Office documents (DOCX/XLSX/PPTX) disguised as other files |
| Recursive ZIP | Documents buried inside nested archives (up to 3 levels) |
| Encrypted ZIP | Blocked — contents cannot be verified |
| Zip bomb | Blocked — uncompressed size > 100MB |
| Content / PII scan | SSNs, Luhn-valid card numbers, private keys, AWS keys, secrets, and structured data tables — caught by content even inside allowed binaries and archive entries |

---

## Enterprise Policy

Administrators can lock settings via **Chrome Managed Policy** (Group Policy / MDM) so users cannot modify the protection mode or domain list.

Policy keys (`managed_schema.json`):

| Key | Type | Description |
|-----|------|-------------|
| `enabled` | boolean | Master on/off switch |
| `mode` | string | `block_everywhere` / `blocklist` / `allowlist` |
| `domains` | array | Domain list for the selected mode |
| `lockSettings` | boolean | Prevent users from editing settings |
| `networkEnforcement` | boolean | Enable the webRequest network backstop (default `true`; requires force-install) |

When a managed policy is active, the Settings tab displays a **"Managed by your organization"** banner and all controls are read-only.

**Example — allow internal mail, block everywhere else:**
```json
{
  "mode": "allowlist",
  "domains": ["outlook.office.com", "outlook.office365.com"],
  "lockSettings": true
}
```

For full deployment instructions (GPO, PowerShell, registry), see [docs/gpo-deployment.md](docs/gpo-deployment.md).

---

## Install

1. Clone the repo
2. Go to `chrome://extensions`
3. Enable Developer mode
4. Click **Load unpacked** → select this folder

---

## Structure

```
src/
  content/
    detector.js        deep async ZIP inspection (file picker / drag / paste path)
    interceptor.js     hooks file input, drag & drop, clipboard paste; reads managed policy
    page-patch.js      MAIN-world egress patch: fetch/XHR/sendBeacon/WebSocket/RTCDataChannel,
                       File System Access API, blob Worker instrumentation
    ui.js              block modal (shadow DOM, closed mode)
    bridge.js          CustomEvent → chrome.storage log bridge
  background/
    service-worker.js  badge counter + webRequest network backstop
  popup/
    popup.html / popup.js   dashboard, audit log, settings
  lib/
    jszip.min.js
    detection-core.js  shared detection signatures + content/PII scanning (all realms)
  managed_schema.json  Chrome enterprise policy schema
tests/
  run-tests.mjs        Node.js test runner (31 test cases)
  fixtures/            real binary test files
```

---

## Tests

```bash
node tests/run-tests.mjs
```

31 test cases using real binary files. Covers document formats, rename bypass attempts (any-extension text, prepended-byte and polyglot disguises), the extra archive containers (TAR/XZ/Zstandard/BZIP2), nested archives, encrypted ZIPs, zip bombs, embedded-PII detection, and clean files.

---

## Roadmap

- [x] Regex-based sensitive data patterns (SSNs, Luhn-valid card numbers, keys/secrets)
- [x] Content-based handling of plain-text data files (block-all-text rule)
- [x] Network-layer enforcement backstop (`webRequest`)
- [ ] Default-deny allowlist mode (verified-safe types only)
- [ ] Recursive inspection of TAR / GZIP contents (currently blocked outright)
- [ ] Firefox support
