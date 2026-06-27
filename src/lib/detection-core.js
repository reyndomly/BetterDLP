/**
 * BetterDLP - Shared Detection Core
 *
 * Pure, dependency-free detection primitives shared by every realm:
 *   - src/content/detector.js        (isolated world, deep async + JSZip)
 *   - src/content/page-patch.js       (MAIN world fetch/XHR + transports)
 *   - src/background/service-worker.js (network backstop, synchronous)
 *   - tests/run-tests.mjs             (single source of truth)
 *
 * No chrome.*, no DOM, no JSZip. Deep ZIP decompression stays with the
 * callers that ship JSZip; this module only provides synchronous byte/text
 * analysis plus the helpers (findZipStart) those callers need.
 *
 * Exposed as `globalThis.BetterDLPCore` (content scripts / importScripts) and
 * as `module.exports` (Node tests).
 */
(function (root) {
  'use strict';

  // ─── Signatures ──────────────────────────────────────────────────────────────
  // Offset-0 signatures unless noted. Multi-byte sequences are matched exactly.

  // Document formats
  const DOC_MAGIC = {
    OLE2: [0xD0, 0xCF, 0x11, 0xE0], // DOC/XLS/PPT — must be at offset 0
  };

  // Archive / container formats that we cannot (or will not) inspect → block.
  // RAR/7z/GZIP are the originals; the rest close the container bypass (#3).
  const ARCHIVE_MAGIC = {
    RAR4:     { bytes: [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00], offset: 0,   label: 'RAR' },
    RAR5:     { bytes: [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01], offset: 0,   label: 'RAR5' },
    SEVENZIP: { bytes: [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C],       offset: 0,   label: '7-Zip' },
    GZIP:     { bytes: [0x1F, 0x8B, 0x08],                         offset: 0,   label: 'GZIP' }, // +CM=deflate to cut FPs on binary traffic
    XZ:       { bytes: [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00],       offset: 0,   label: 'XZ' },
    ZSTD:     { bytes: [0x28, 0xB5, 0x2F, 0xFD],                   offset: 0,   label: 'Zstandard' },
    BZIP2:    { bytes: [0x42, 0x5A, 0x68],                         offset: 0,   label: 'BZIP2' },
    LZ4:      { bytes: [0x04, 0x22, 0x4D, 0x18],                   offset: 0,   label: 'LZ4' },
    CAB:      { bytes: [0x4D, 0x53, 0x43, 0x46],                   offset: 0,   label: 'CAB' },
    TAR:      { bytes: [0x75, 0x73, 0x74, 0x61, 0x72],             offset: 257, label: 'TAR' }, // "ustar"
  };

  const ZIP_LOCAL_HEADER = [0x50, 0x4B, 0x03, 0x04]; // PK\x03\x04
  const ZIP_EOCD         = [0x50, 0x4B, 0x05, 0x06]; // PK\x05\x06
  const PDF_SIG          = [0x25, 0x50, 0x44, 0x46]; // %PDF
  const RTF_SIG          = [0x7B, 0x5C, 0x72, 0x74]; // {\rt

  // How far into a file we scan for a non-offset-0 signature (prepend/polyglot).
  const PDF_SCAN_WINDOW  = 1024;
  const RTF_SCAN_WINDOW  = 64;
  const ZIP_SCAN_WINDOW  = 64 * 1024;

  // Internal paths that confirm a ZIP is actually an Office document.
  const OFFICE_ZIP_PATHS = [
    'word/document.xml',      // DOCX
    'xl/workbook.xml',        // XLSX
    'ppt/presentation.xml',   // PPTX
    'content.xml',            // ODT / ODS
    'META-INF/manifest.xml',  // ODF generic
  ];

  const MAX_ZIP_DEPTH = 3;
  const MAX_UNCOMPRESSED_BYTES = 100 * 1024 * 1024; // 100MB zip bomb guard

  // Real binary assets — the only class allowed to pass. Verified by magic.
  const BINARY_EXT_MAGIC = {
    jpg:  [0xFF, 0xD8, 0xFF],
    jpeg: [0xFF, 0xD8, 0xFF],
    png:  [0x89, 0x50, 0x4E, 0x47],
    gif:  [0x47, 0x49, 0x46, 0x38],
    bmp:  [0x42, 0x4D],
    ico:  [0x00, 0x00, 0x01, 0x00],
    mp4:  [0x00, 0x00, 0x00],
    webp: [0x52, 0x49, 0x46, 0x46],
  };

  // ─── Byte helpers ────────────────────────────────────────────────────────────

  function matchesAt(bytes, sig, offset) {
    offset = offset || 0;
    if (bytes.length < offset + sig.length) return false;
    for (let i = 0; i < sig.length; i++) {
      if (bytes[offset + i] !== sig[i]) return false;
    }
    return true;
  }

  function matchesMagic(bytes, sig) {
    return matchesAt(bytes, sig, 0);
  }

  // Find a byte sequence within the first `maxScan` bytes. Returns offset or -1.
  function indexOfSig(bytes, sig, maxScan) {
    const limit = Math.min(bytes.length, (maxScan || bytes.length)) - sig.length;
    for (let i = 0; i <= limit; i++) {
      let ok = true;
      for (let j = 0; j < sig.length; j++) {
        if (bytes[i + j] !== sig[j]) { ok = false; break; }
      }
      if (ok) return i;
    }
    return -1;
  }

  // Offset of the first ZIP local file header (PK\x03\x04), or -1.
  // Tolerates prepended bytes / PNG-ZIP polyglots that hide the header (#2).
  function findZipStart(bytes) {
    if (matchesMagic(bytes, ZIP_LOCAL_HEADER)) return 0;
    // Only treat it as a ZIP-based file if an EOCD is also present somewhere,
    // to avoid flagging arbitrary binaries that happen to contain "PK\x03\x04".
    if (indexOfSig(bytes, ZIP_EOCD, bytes.length) === -1) {
      // EOCD may be absent in a truncated prefix; still honour an offset-0 match
      // (handled above). Otherwise require a non-trivial local header.
      return -1;
    }
    return indexOfSig(bytes, ZIP_LOCAL_HEADER, ZIP_SCAN_WINDOW);
  }

  // Encryption bit (GP flag bit 0) of the local file header at `offset`.
  function isZipEncrypted(bytes, offset) {
    offset = offset || 0;
    if (!matchesAt(bytes, ZIP_LOCAL_HEADER, offset)) return false;
    const flags = bytes[offset + 6] | (bytes[offset + 7] << 8);
    return (flags & 0x01) !== 0;
  }

  // Heuristic: does the start of the buffer look like plain text?
  function isPlainText(bytes) {
    const sample = bytes.subarray ? bytes.subarray(0, 512) : bytes.slice(0, 512);
    if (sample.length === 0) return false;
    for (let i = 0; i < sample.length; i++) {
      const b = sample[i];
      if (b === 0x09 || b === 0x0A || b === 0x0D) continue; // tab/LF/CR
      if (b >= 0x20 && b <= 0x7E) continue;                 // printable ASCII
      if (b === 0x00) return false;                         // NUL → binary
      if (b < 0x09) return false;                           // control → binary
      // bytes >= 0x7F are tolerated (UTF-8 multibyte); a NUL/control rules it out
    }
    return true;
  }

  // Decode a byte prefix to text for content scanning (UTF-8, with UTF-16 BOM).
  function bytesToText(bytes, maxBytes) {
    const slice = bytes.subarray
      ? bytes.subarray(0, maxBytes || bytes.length)
      : bytes.slice(0, maxBytes || bytes.length);
    if (typeof TextDecoder !== 'undefined') {
      try {
        if (slice[0] === 0xFF && slice[1] === 0xFE) return new TextDecoder('utf-16le').decode(slice);
        if (slice[0] === 0xFE && slice[1] === 0xFF) return new TextDecoder('utf-16be').decode(slice);
        return new TextDecoder('utf-8').decode(slice);
      } catch (_) { /* fall through */ }
    }
    let s = '';
    for (let i = 0; i < slice.length; i++) s += String.fromCharCode(slice[i]);
    return s;
  }

  // ─── Synchronous binary-signature verdict (documents + archives) ─────────────
  // Returns { blocked, reason } when a document/archive signature is found,
  // otherwise null. Used by BOTH the file-inspection path and the network
  // backstop. Does NOT decide on plain text (that is a file-context rule).

  function sniffBinarySignature(bytes) {
    if (matchesMagic(bytes, DOC_MAGIC.OLE2))
      return { blocked: true, reason: 'Legacy Office document detected (DOC/XLS/PPT)' };

    if (indexOfSig(bytes, PDF_SIG, PDF_SCAN_WINDOW) !== -1)
      return { blocked: true, reason: 'PDF document detected' };

    if (indexOfSig(bytes, RTF_SIG, RTF_SCAN_WINDOW) !== -1)
      return { blocked: true, reason: 'RTF document detected' };

    for (const key in ARCHIVE_MAGIC) {
      const a = ARCHIVE_MAGIC[key];
      if (matchesAt(bytes, a.bytes, a.offset))
        return { blocked: true, reason: a.label + ' archive — cannot inspect contents' };
    }

    // ZIP-based (Office OOXML, ODF, or plain ZIP) — all archives blocked by policy.
    // Located offset-tolerantly so prepend/polyglot disguises are caught.
    const off = findZipStart(bytes);
    if (off !== -1) {
      if (isZipEncrypted(bytes, off))
        return { blocked: true, reason: 'Password-protected ZIP archive' };
      return { blocked: true, reason: 'ZIP archive — all archives blocked by policy', zip: true, zipStart: off };
    }

    return null;
  }

  // ─── Content / PII scanning (additive) ───────────────────────────────────────
  // Catches sensitive data hiding inside otherwise-allowed binaries / archive
  // entries / network bodies. Never re-permits a file blocked by type.

  function luhnValid(digits) {
    let sum = 0, alt = false;
    for (let i = digits.length - 1; i >= 0; i--) {
      let d = digits.charCodeAt(i) - 48;
      if (alt) { d *= 2; if (d > 9) d -= 9; }
      sum += d;
      alt = !alt;
    }
    return sum % 10 === 0;
  }

  // Issuer Identification Number prefixes for the major card networks. Requiring
  // a real IIN (in addition to Luhn) avoids flagging ordinary large numeric IDs
  // (e.g. Snowflake IDs, timestamps) that coincidentally pass the Luhn check.
  function isCardIIN(d) {
    return /^4/.test(d) ||                 // Visa
           /^(5[1-5]|2[2-7])/.test(d) ||   // Mastercard
           /^3[47]/.test(d) ||             // American Express
           /^(6011|65|64[4-9])/.test(d) || // Discover
           /^3(0[0-5]|[68])/.test(d) ||    // Diners Club
           /^35(2[89]|[3-8])/.test(d);     // JCB
  }

  const SSN_RE      = /\b\d{3}-\d{2}-\d{4}\b/;
  const CARD_RE     = /\b(?:\d[ -]?){12,18}\d\b/g;
  const PRIVKEY_RE  = /-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----/;
  const AWS_KEY_RE  = /\bAKIA[0-9A-Z]{16}\b/;
  const SECRET_RE   = /\b(?:api[_-]?key|secret|password|passwd|token)\b\s*[:=]\s*['"]?[A-Za-z0-9/+_\-]{12,}/i;

  function scanTextContent(text) {
    if (!text) return null;

    if (SSN_RE.test(text))
      return { blocked: true, reason: 'Sensitive data detected — US SSN pattern', matchType: 'ssn' };

    if (PRIVKEY_RE.test(text))
      return { blocked: true, reason: 'Sensitive data detected — private key material', matchType: 'private_key' };

    if (AWS_KEY_RE.test(text))
      return { blocked: true, reason: 'Sensitive data detected — AWS access key', matchType: 'aws_key' };

    if (SECRET_RE.test(text))
      return { blocked: true, reason: 'Sensitive data detected — credential/secret assignment', matchType: 'secret' };

    let m;
    CARD_RE.lastIndex = 0;
    while ((m = CARD_RE.exec(text)) !== null) {
      const digits = m[0].replace(/[ -]/g, '');
      if (digits.length >= 13 && digits.length <= 19 && isCardIIN(digits) && luhnValid(digits))
        return { blocked: true, reason: 'Sensitive data detected — payment card number (Luhn-valid)', matchType: 'card' };
    }

    // Structured-data heuristic: many rows with a consistent delimiter count.
    const struct = looksLikeStructuredData(text);
    if (struct)
      return { blocked: true, reason: 'Structured data table detected (' + struct + ')', matchType: 'structured' };

    return null;
  }

  // Returns a label (e.g. "CSV, 4 columns") if the text looks like a delimited
  // data table, else null. Conservative: needs several consistent rows.
  function looksLikeStructuredData(text) {
    const lines = text.split(/\r?\n/).filter(function (l) { return l.trim().length > 0; }).slice(0, 50);
    if (lines.length < 4) return null;
    const delimiters = [[',', 'CSV'], ['\t', 'TSV'], [';', 'delimited'], ['|', 'delimited']];
    for (let d = 0; d < delimiters.length; d++) {
      const ch = delimiters[d][0];
      const counts = lines.map(function (l) { return l.split(ch).length; });
      const cols = counts[0];
      if (cols < 2) continue;
      const consistent = counts.filter(function (c) { return c === cols; }).length;
      if (consistent >= Math.max(4, Math.floor(lines.length * 0.8)))
        return delimiters[d][1] + ', ' + cols + ' columns';
    }
    return null;
  }

  // ─── File-context verdict (synchronous) ──────────────────────────────────────
  // The "block all document/data uploads" rule. Used when we know the bytes are
  // a FILE the user is uploading (not arbitrary network JSON). ZIP-based files
  // return blocked here too; callers with JSZip may deep-inspect for a richer
  // reason, but the verdict is always blocked.
  //
  // Returns { blocked, reason }.
  function inspectFileBytes(bytes, filename) {
    const ext = (filename || '').split('.').pop().toLowerCase();

    // 1. Known document / archive signatures (offset-tolerant).
    const sig = sniffBinarySignature(bytes);
    if (sig) return { blocked: true, reason: sig.reason };

    // 2. Verified-safe binary assets are the only allowed class. If the bytes
    //    match the declared binary extension's magic, allow (still PII-scan any
    //    trailing text region in case of appended data / polyglot remnants).
    const expected = BINARY_EXT_MAGIC[ext];
    if (expected && matchesMagic(bytes, expected)) {
      const pii = scanTextContent(bytesToText(bytes, 256 * 1024));
      if (pii) return { blocked: true, reason: pii.reason + ' (embedded in ' + ext.toUpperCase() + ')' };
      return { blocked: false, reason: 'Verified ' + ext.toUpperCase() + ' image' };
    }

    // 3. Plain text / data — blocked regardless of extension (core intent:
    //    no document/data uploads). PII scan only enriches the reason.
    if (isPlainText(bytes)) {
      const pii = scanTextContent(bytesToText(bytes, 256 * 1024));
      if (pii) return { blocked: true, reason: pii.reason };
      return { blocked: true, reason: 'Text/data file — uploads of data files are blocked by policy' };
    }

    // 4. Unrecognized binary with a binary extension but mismatched magic —
    //    treat as a disguise attempt and block.
    if (expected)
      return { blocked: true, reason: 'File type mismatch — claims to be ' + ext.toUpperCase() + ' but content does not match' };

    // 5. Unknown binary, no claimed safe type. Scan any decodable text, then
    //    block by default (unknown content during a data-exfiltration check).
    const pii = scanTextContent(bytesToText(bytes, 256 * 1024));
    if (pii) return { blocked: true, reason: pii.reason };
    return { blocked: true, reason: 'Unrecognized binary content — blocked by policy' };
  }

  // ─── Network-context verdict (synchronous) ───────────────────────────────────
  // Used by the webRequest backstop where bodies include legitimate JSON/API
  // traffic. We must NOT block all text here — only document/archive signatures
  // and positive PII/secret matches.
  //
  // Returns { blocked, reason } or { blocked: false }.
  function inspectNetworkBytes(bytes) {
    const sig = sniffBinarySignature(bytes);
    if (sig) return { blocked: true, reason: sig.reason };
    // Only PII-scan bodies that actually look like text. Web apps send large
    // volumes of binary XHR/WebSocket traffic (encrypted protocol data,
    // protobuf, media); running SSN/Luhn regexes over those bytes produces
    // false positives (a random digit run can satisfy Luhn). Binary bodies are
    // covered by signature detection above; they are not text-scanned.
    if (isPlainText(bytes)) {
      const pii = scanTextContent(bytesToText(bytes, 256 * 1024));
      if (pii) return { blocked: true, reason: pii.reason };
    }
    return { blocked: false, reason: 'No sensitive content detected' };
  }

  // ─── Exports ─────────────────────────────────────────────────────────────────

  const api = {
    // constants
    OFFICE_ZIP_PATHS: OFFICE_ZIP_PATHS,
    BINARY_EXT_MAGIC: BINARY_EXT_MAGIC,
    MAX_ZIP_DEPTH: MAX_ZIP_DEPTH,
    MAX_UNCOMPRESSED_BYTES: MAX_UNCOMPRESSED_BYTES,
    // primitives
    matchesMagic: matchesMagic,
    matchesAt: matchesAt,
    indexOfSig: indexOfSig,
    findZipStart: findZipStart,
    isZipEncrypted: isZipEncrypted,
    isPlainText: isPlainText,
    bytesToText: bytesToText,
    // verdicts
    sniffBinarySignature: sniffBinarySignature,
    scanTextContent: scanTextContent,
    inspectFileBytes: inspectFileBytes,
    inspectNetworkBytes: inspectNetworkBytes,
  };

  root.BetterDLPCore = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;

})(typeof globalThis !== 'undefined' ? globalThis : (typeof self !== 'undefined' ? self : this));
