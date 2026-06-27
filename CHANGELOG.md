# Changelog

## [0.2.0] — 2026-06-27

### Added
- XZ, Zstandard, BZIP2, LZ4, Cabinet, and TAR archive detection
- Offset-tolerant PDF detection — scans first 1KB (catches PDFs with comment headers before `%PDF`)
- Offset-tolerant RTF detection — scans first 64 bytes
- Offset-tolerant ZIP detection — scans up to 64KB to catch prepended-byte polyglot attacks
- Plain text content blocking — detects CSV, TSV, TXT, and data files by content regardless of extension
- `indexOfSig` / `findZipStart` helper functions for offset-tolerant scanning

### Fixed
- GZIP signature extended to 3 bytes (`0x1F 0x8B 0x08`) to reduce false positives on binary traffic
- Raw `Blob` bodies no longer intercepted in fetch/XHR — only `File` and `FormData` with `File` parts, fixing WhatsApp and Telegram

### Changed
- Extension-based CSV/TSV/TXT fallback replaced by content-based plain text detection
- Test suite updated to mirror new detection logic; 8 new test cases (27 total)

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
