# BetterDLP 🛡️

A browser extension for **Data Loss Prevention (DLP)** — blocks sensitive document uploads before they leave your organization.

Built as a security research/educational project demonstrating real-world DLP concepts in a browser extension context.

---

## What It Does

BetterDLP intercepts file uploads **before** they reach any server and blocks documents based on their **real file type** (magic bytes), not their filename or extension.

### Blocked File Types

| Format | Detection Method |
|---|---|
| DOCX / XLSX / PPTX | ZIP magic bytes + internal Office XML structure |
| DOC / XLS / PPT (legacy) | OLE2 magic bytes (`D0 CF 11 E0`) |
| PDF | Magic bytes (`%PDF`) |
| RTF | Magic bytes (`{\rt`) |
| ZIP containing documents | JSZip inspection of internal paths |
| Password-protected ZIP | Encryption flag in ZIP header (bit 0 of general purpose flags) |
| RAR / 7-Zip | Magic bytes — cannot inspect, blocked by default |
| GZIP | Magic bytes — cannot inspect, blocked by default |
| Nested archives | Recursive inspection up to depth 3 |
| Zip bombs | Uncompressed size threshold (100MB) |

### Intercepted Upload Vectors

- `<input type="file">` — standard file picker (including dynamically added inputs via `MutationObserver`)
- Drag & drop — `drop` event at document level
- Clipboard paste — `paste` event (`Ctrl+V` a file)
- `fetch()` API — monkey-patched at `document_start`
- `XMLHttpRequest.send()` — monkey-patched at `document_start`

---

## Features

- **Real file type detection** — rename `report.docx` to `photo.jpg`, it still gets blocked
- **Office-in-ZIP detection** — detects DOCX/XLSX/PPTX even when renamed to `.zip`
- **Encrypted archive blocking** — password-protected files are blocked since contents can't be verified
- **Shadow DOM modal** — block UI uses `mode: 'closed'` shadow root, immune to page JS interference
- **Audit log** — all block/allow events stored in `chrome.storage.local` with timestamp, site, vector, and reason
- **Domain scope config** — block everywhere, block on specific domains, or allow on specific domains
- **Export logs** — download audit log as JSON
- **Badge counter** — extension icon shows number of blocked attempts

---

## Installation (Development Mode)

1. Clone this repo
2. Open Chrome → `chrome://extensions`
3. Enable **Developer mode** (top right)
4. Click **Load unpacked** → select the `BetterDLP` folder
5. The extension is now active on all sites

---

## Project Structure

```
BetterDLP/
├── src/
│   ├── content/
│   │   ├── detector.js       Magic bytes detection + ZIP inspection
│   │   ├── interceptor.js    Upload vector interception (input/drop/paste/XHR/fetch)
│   │   └── ui.js             Shadow DOM block modal
│   ├── background/
│   │   └── service-worker.js Badge updates, storage init
│   ├── popup/
│   │   ├── popup.html        Extension popup UI
│   │   └── popup.js          Dashboard, logs, settings
│   └── lib/
│       └── jszip.min.js      ZIP inspection library
├── icons/
├── manifest.json             Manifest V3
└── README.md
```

---

## Known Limitations

These are **by design** — client-side DLP is one layer of a defense-in-depth strategy:

| Limitation | Why |
|---|---|
| User can disable the extension | Requires enterprise MDM/policy to force-install |
| Incognito mode disables extensions by default | Enable via `chrome://extensions` or enterprise policy |
| Direct API calls (curl, Postman) bypass the browser | Requires server-side DLP validation |
| WebSocket file transfers | Protocol-specific, not inspectable generically |
| Images of documents (screenshots) | Requires ML/OCR — out of scope for MVP |
| Encrypted DOCX (password-protected Word files) | Cannot inspect content — flagged as unknown |
| Split file uploads (chunked) | Partial-file magic bytes may be undetectable |

BetterDLP is designed to **prevent accidental and low-effort leaks**. It is not a substitute for network-level DLP, endpoint agents, or server-side validation.

---

## Tech Stack

| Component | Technology |
|---|---|
| Extension platform | Chrome Manifest V3 |
| File inspection | JavaScript `FileReader` API + magic bytes |
| ZIP/Office inspection | [JSZip](https://stuk.github.io/jszip/) |
| Storage | `chrome.storage.local` / `chrome.storage.sync` |
| Block UI | Shadow DOM (`mode: 'closed'`) |

---

## Roadmap

- [ ] V2: ML-based content classification (TensorFlow.js)
- [ ] V2: TAR/GZIP recursive inspection (pako.js + js-untar)
- [ ] V2: Indonesian-specific sensitive patterns (NIK, NPWP, BPJS)
- [ ] V2: Firefox support
- [ ] V3: Enterprise policy deployment guide
- [ ] V3: Central reporting endpoint (optional)

---

## Disclaimer

This project is built for **educational and security research purposes**. It demonstrates browser-based DLP concepts and known bypass mitigations. It is not a production-grade enterprise DLP solution.
