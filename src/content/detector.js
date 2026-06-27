/**
 * BetterDLP - File Type Detector
 * Identifies real file types via magic bytes, independent of filename/extension.
 */

// ─── Signatures ───────────────────────────────────────────────────────────────

// Offset-0 blocked formats (documents + archives)
const BLOCKED_MAGIC = [
  { sig: [0xD0, 0xCF, 0x11, 0xE0],                         label: 'Legacy Office document (DOC/XLS/PPT)' },
  { sig: [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00],       label: 'RAR archive'       },
  { sig: [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01],       label: 'RAR5 archive'      },
  { sig: [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C],             label: '7-Zip archive'     },
  { sig: [0x1F, 0x8B, 0x08],                               label: 'GZIP archive'      }, // +CM byte reduces FP on binary traffic
  { sig: [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00],             label: 'XZ archive'        },
  { sig: [0x28, 0xB5, 0x2F, 0xFD],                         label: 'Zstandard archive' },
  { sig: [0x42, 0x5A, 0x68],                               label: 'BZIP2 archive'     },
  { sig: [0x04, 0x22, 0x4D, 0x18],                         label: 'LZ4 archive'       },
  { sig: [0x4D, 0x53, 0x43, 0x46],                         label: 'Cabinet archive'   },
];

const PDF_SIG  = [0x25, 0x50, 0x44, 0x46]; // %PDF — may not be at byte 0
const RTF_SIG  = [0x7B, 0x5C, 0x72, 0x74]; // {\rt — may not be at byte 0
const TAR_SIG  = [0x75, 0x73, 0x74, 0x61, 0x72]; // "ustar" at offset 257
const TAR_OFF  = 257;
const PDF_SCAN = 1024; // scan first 1KB for %PDF
const RTF_SCAN = 64;   // scan first 64B for {\rt

const ZIP_LOCAL = [0x50, 0x4B, 0x03, 0x04];
const ZIP_EOCD  = [0x50, 0x4B, 0x05, 0x06];
const ZIP_SCAN  = 64 * 1024; // scan first 64KB for prepended-byte / polyglot ZIPs

const OFFICE_ZIP_PATHS = [
  'word/document.xml',     // DOCX
  'xl/workbook.xml',       // XLSX
  'ppt/presentation.xml',  // PPTX
  'content.xml',           // ODT / ODS
  'META-INF/manifest.xml', // ODF generic
];

const MAX_ZIP_DEPTH = 3;
const MAX_UNCOMPRESSED_BYTES = 100 * 1024 * 1024;

// ─── Byte helpers ─────────────────────────────────────────────────────────────

function matchesAt(bytes, sig, offset) {
  if (bytes.length < offset + sig.length) return false;
  return sig.every((b, i) => bytes[offset + i] === b);
}

function matchesMagic(bytes, sig) { return matchesAt(bytes, sig, 0); }

function indexOfSig(bytes, sig, maxScan) {
  const limit = Math.min(bytes.length, maxScan) - sig.length;
  for (let i = 0; i <= limit; i++) {
    if (sig.every((b, j) => bytes[i + j] === b)) return i;
  }
  return -1;
}

// Returns offset of the ZIP local file header, or -1.
// Scans up to ZIP_SCAN bytes to catch prepended-byte / polyglot attacks.
function findZipStart(bytes) {
  if (matchesMagic(bytes, ZIP_LOCAL)) return 0;
  if (indexOfSig(bytes, ZIP_EOCD, bytes.length) === -1) return -1;
  return indexOfSig(bytes, ZIP_LOCAL, ZIP_SCAN);
}

function isZipEncrypted(bytes, offset) {
  if (!matchesAt(bytes, ZIP_LOCAL, offset)) return false;
  return ((bytes[offset + 6] | (bytes[offset + 7] << 8)) & 0x01) !== 0;
}

function isPlainText(bytes) {
  const sample = bytes.length > 512 ? bytes.subarray(0, 512) : bytes;
  for (const b of sample) {
    if (b === 0x09 || b === 0x0A || b === 0x0D) continue;
    if (b >= 0x20 && b <= 0x7E) continue;
    if (b === 0x00 || b < 0x09) return false;
  }
  return true;
}

function readAsArrayBuffer(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = (e) => resolve(e.target.result);
    reader.onerror = reject;
    reader.readAsArrayBuffer(file);
  });
}

// ─── ZIP deep inspection ──────────────────────────────────────────────────────

async function inspectZip(arrayBuffer, depth) {
  if (depth > MAX_ZIP_DEPTH)
    return { blocked: true, reason: `Archive nested too deep (limit: ${MAX_ZIP_DEPTH})` };

  let zip;
  try {
    zip = await JSZip.loadAsync(arrayBuffer);
  } catch (err) {
    const msg = (err && err.message || '').toLowerCase();
    if (msg.includes('encrypt') || msg.includes('password'))
      return { blocked: true, reason: 'Password-protected archive — cannot inspect contents' };
    return { blocked: true, reason: 'Unreadable archive format' };
  }

  const fileNames = Object.keys(zip.files);

  for (const op of OFFICE_ZIP_PATHS) {
    if (fileNames.some(f => f === op || f.endsWith('/' + op)))
      return { blocked: true, reason: `Office document detected (${op})` };
  }

  for (const fileName of fileNames) {
    const entry = zip.files[fileName];
    if (entry.dir) continue;
    if (entry._data && entry._data.uncompressedSize > MAX_UNCOMPRESSED_BYTES)
      return { blocked: true, reason: 'Archive entry too large — possible zip bomb' };

    let entryBytes, entryBuffer;
    try {
      entryBuffer = await entry.async('arraybuffer');
      entryBytes = new Uint8Array(entryBuffer);
    } catch (err) {
      return { blocked: true, reason: `Encrypted entry: ${fileName}` };
    }

    const r = await detectFileType(entryBytes, entryBuffer);
    if (r.blocked) return { blocked: true, reason: `${r.reason} (inside: ${fileName})` };
  }

  return { blocked: true, reason: 'ZIP archive — all archives blocked by policy' };
}

// ─── Core detection ───────────────────────────────────────────────────────────

async function detectFileType(bytes, arrayBuffer) {
  // 1. Offset-0 binary signatures
  for (const { sig, label } of BLOCKED_MAGIC) {
    if (matchesMagic(bytes, sig)) return { blocked: true, reason: label };
  }

  // 2. Offset-tolerant signatures
  if (indexOfSig(bytes, PDF_SIG, PDF_SCAN) !== -1)
    return { blocked: true, reason: 'PDF document' };
  if (indexOfSig(bytes, RTF_SIG, RTF_SCAN) !== -1)
    return { blocked: true, reason: 'RTF document' };
  if (matchesAt(bytes, TAR_SIG, TAR_OFF))
    return { blocked: true, reason: 'TAR archive' };

  // 3. Offset-tolerant ZIP (catches prepended-byte / polyglot attacks)
  const zipStart = findZipStart(bytes);
  if (zipStart !== -1) {
    if (isZipEncrypted(bytes, zipStart))
      return { blocked: true, reason: 'Password-protected ZIP archive' };
    if (!arrayBuffer)
      return { blocked: true, reason: 'ZIP archive — blocked by policy' };
    const slice = zipStart > 0 ? arrayBuffer.slice(zipStart) : arrayBuffer;
    return await inspectZip(slice, 0);
  }

  // 4. Plain text / data — blocked regardless of extension
  if (isPlainText(bytes))
    return { blocked: true, reason: 'Text/data file — blocked by policy' };

  return { blocked: false, reason: 'File type allowed' };
}

async function inspectFile(file) {
  let arrayBuffer;
  try {
    arrayBuffer = await readAsArrayBuffer(file);
  } catch (err) {
    return { blocked: true, reason: 'Unable to read file for inspection — blocked by policy' };
  }
  const bytes = new Uint8Array(arrayBuffer);
  return detectFileType(bytes, arrayBuffer);
}

window.BetterDLP = window.BetterDLP || {};
window.BetterDLP.inspectFile = inspectFile;
