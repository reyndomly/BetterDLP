# BetterDLP

Chrome extension that blocks document uploads based on actual file content, not the filename.

Tired of DLP tools that get bypassed by just renaming `report.docx` to `photo.jpg`. This checks magic bytes instead.

---

## How it works

Intercepts file uploads before they hit the network and reads the first few bytes of the file to identify the real format. A DOCX is a ZIP under the hood — so it also unpacks ZIPs and checks what's inside.

Blocked formats: DOCX, XLSX, PPTX, DOC, XLS, PPT, PDF, RTF, RAR, 7z, GZIP, and any ZIP that contains one of the above.

Upload vectors covered:
- `<input type="file">` (including dynamically injected ones)
- Drag and drop
- Clipboard paste
- `fetch()` and `XMLHttpRequest` (patched before page scripts load)

---

## Why not just check the extension?

Because it's trivially bypassed. Rename the file, done. Magic bytes can't be faked without a hex editor — and even then, a renamed DOCX is still a ZIP with `word/document.xml` inside, which this catches too.

Edge cases handled:
- ZIP containing a document → blocked
- Password-protected ZIP → blocked (can't verify contents)
- Nested ZIP (ZIP inside ZIP) → recursive inspection up to 3 levels
- RAR / 7z → blocked by default (no reliable JS parser)
- Zip bombs → blocked if uncompressed size > 100MB

---

## Install

1. Clone the repo
2. Go to `chrome://extensions`
3. Turn on Developer mode
4. Load unpacked → select this folder

---

## Structure

```
src/
  content/
    detector.js      magic bytes + ZIP inspection
    interceptor.js   hooks all upload vectors
    ui.js            block modal (shadow DOM, closed mode)
  background/
    service-worker.js
  popup/
    popup.html / popup.js   dashboard, audit log, settings
  lib/
    jszip.min.js
tests/
  run-tests.mjs      node-based test runner
  fixtures/          real binary test files
```

---

## Tests

```bash
node tests/run-tests.mjs
```

10 test cases using real binary files — not mocked magic bytes. Covers the rename bypass, nested ZIPs, encrypted archives, clean files (no false positives), etc.

---

## Limitations

This runs in the browser so it only catches what goes through the browser. Direct API calls (curl, Postman, scripts) bypass it completely. Real DLP needs a network proxy or endpoint agent on top of this — this is just the browser layer.

Other known gaps:
- User can disable the extension
- Incognito disables extensions by default
- Screenshots of documents (needs OCR, out of scope)
- Chunked/split uploads

---

## Roadmap

- [ ] Indonesian ID patterns (NIK, NPWP)
- [ ] TensorFlow.js classifier for content-based detection
- [ ] Firefox support
- [ ] TAR/GZIP recursive inspection
