# Changelog

## [0.1.1] — 2026-06-27

### Fixed
- Clipboard paste: blocked files could briefly appear in app preview before being stopped — events are now intercepted synchronously, with a synthetic re-dispatch for clean files
- Drag and drop: same race condition fixed with the same synchronous-stop + re-dispatch pattern

## [0.1.0] — 2026-06-26

### Added
- Magic bytes detection for DOCX, XLSX, PPTX, DOC, XLS, PPT, PDF, RTF
- ZIP inspection — detects Office documents disguised as other file types
- Recursive ZIP inspection up to 3 levels deep
- Password-protected ZIP blocking
- Zip bomb protection (uncompressed size > 100MB)
- RAR, 7z, GZIP blocking
- Extension fallback detection for CSV, TSV, TXT
- File type mismatch detection — plain text files disguised as images (JPG, PNG, GIF, etc.)
- Upload vector coverage: file picker, drag and drop, clipboard paste, fetch(), XHR
- fetch() and XHR patched in MAIN world to intercept browser app uploads
- Block modal with Shadow DOM (closed mode) for tamper resistance
- Audit log stored in chrome.storage.local (last 500 entries)
- Dashboard with daily blocked/allowed stats
- JSON log export
- Domain allowlist/blocklist with three protection modes
- Enterprise managed policy support via chrome.storage.managed
- Settings lockdown via Group Policy / MDM (lockSettings flag)
- GPO deployment guide for endpoint teams
- GitHub Actions CI — runs 19 test cases on every push
- MIT license
