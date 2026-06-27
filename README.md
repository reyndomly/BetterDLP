# BetterDLP

![Tests](https://github.com/reyndomly/BetterDLP/actions/workflows/test.yml/badge.svg)

Chrome extension that enforces Data Loss Prevention by blocking document uploads based on actual file content — not filename or extension.

---

## How it works

BetterDLP intercepts uploads before they reach the network and inspects the real file type using magic bytes. A DOCX renamed to `.jpg` is still a ZIP containing `word/document.xml` — BetterDLP catches it either way.

**Blocked formats:** DOCX, XLSX, PPTX, DOC, XLS, PPT, PDF, RTF, CSV/TSV/TXT, RAR, 7z, GZIP, XZ, Zstandard, BZIP2, LZ4, Cabinet, TAR, and any ZIP containing a document.

**Upload vectors covered:**
- `<input type="file">` — file picker, including dynamically injected inputs
- Drag and drop
- Clipboard paste
- `fetch()` and `XMLHttpRequest` — patched at page load before any page script runs

---

## Detection

| Technique | What it catches |
|-----------|----------------|
| Magic bytes (offset 0) | Real file type regardless of extension — OLE2, RAR, 7z, GZIP, XZ, Zstd, BZIP2, LZ4, CAB |
| Offset-tolerant scan | PDF with junk/comment prefix, RTF with preamble, TAR (ustar at offset 257) |
| Polyglot ZIP | ZIP header not at byte 0 — scans first 64KB, requires valid EOCD signature |
| ZIP inspection | Office documents (DOCX/XLSX/PPTX) disguised as other file types |
| Recursive ZIP | Documents buried inside nested archives (up to 3 levels) |
| Encrypted ZIP | Blocked — contents cannot be verified |
| Zip bomb | Blocked — uncompressed size > 100MB |
| Plain text content | CSV, TSV, TXT, and data files detected by byte content — not extension |

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
    detector.js        magic bytes + ZIP inspection
    interceptor.js     hooks all upload vectors, reads managed policy
    page-patch.js      fetch/XHR patch (MAIN world)
    ui.js              block modal (shadow DOM, closed mode)
    bridge.js          CustomEvent → chrome.storage log bridge
  background/
    service-worker.js  badge counter
  popup/
    popup.html / popup.js   dashboard, audit log, settings
  lib/
    jszip.min.js
  managed_schema.json  Chrome enterprise policy schema
tests/
  run-tests.mjs        Node.js test runner (27 test cases)
  fixtures/            real binary test files
```

---

## Tests

```bash
node tests/run-tests.mjs
```

27 test cases using real binary files. Covers document formats, rename bypass attempts, nested archives, encrypted ZIPs, zip bombs, polyglot ZIPs, offset-tolerant headers, new archive formats, and clean files.

---

## Contributors

| Contributor | What they did |
|-------------|--------------|
| [@andreihansel](https://github.com/andreihansel) | Identified offset-tolerant detection gaps (polyglot/prepend bypass); proposed XZ, Zstd, BZIP2, LZ4, CAB, and TAR signatures; plain text content blocking idea; GZIP signature fix |

---

## Roadmap

- [ ] Regex-based sensitive data patterns (ID numbers, card numbers)
- [ ] Content-based classifier for plain text data files
- [ ] Firefox support
- [ ] TAR/GZIP recursive inspection
