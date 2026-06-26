/**
 * BetterDLP - File Type Detector
 * Identifies real file types via magic bytes, independent of filename/extension.
 */

const MAGIC_BYTES = {
  // Office Open XML (DOCX, XLSX, PPTX, ODT, ODS) — all are ZIP-based
  ZIP: { bytes: [0x50, 0x4B, 0x03, 0x04], label: 'ZIP/Office' },

  // Legacy Office (DOC, XLS, PPT) — OLE2 Compound Document
  OLE2: { bytes: [0xD0, 0xCF, 0x11, 0xE0], label: 'Legacy Office (DOC/XLS/PPT)' },

  // PDF
  PDF: { bytes: [0x25, 0x50, 0x44, 0x46], label: 'PDF' },

  // RTF
  RTF: { bytes: [0x7B, 0x5C, 0x72, 0x74], label: 'RTF' },

  // RAR4
  RAR4: { bytes: [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00], label: 'RAR' },

  // RAR5
  RAR5: { bytes: [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01], label: 'RAR5' },

  // 7ZIP
  SEVENZIP: { bytes: [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C], label: '7-Zip' },

  // GZIP
  GZIP: { bytes: [0x1F, 0x8B], label: 'GZIP' },
};

// Internal paths that confirm a ZIP is actually an Office document
const OFFICE_ZIP_PATHS = [
  'word/document.xml',      // DOCX
  'xl/workbook.xml',        // XLSX
  'ppt/presentation.xml',   // PPTX
  'content.xml',            // ODT / ODS
  'META-INF/manifest.xml',  // ODF generic
];

const MAX_ZIP_DEPTH = 3;
const MAX_UNCOMPRESSED_BYTES = 100 * 1024 * 1024; // 100MB zip bomb guard

function matchesMagic(bytes, magic) {
  return magic.every((b, i) => bytes[i] === b);
}

function readFirstBytes(file, count = 8) {
  return new Promise((resolve) => {
    const reader = new FileReader();
    reader.onload = (e) => resolve(new Uint8Array(e.target.result));
    reader.readAsArrayBuffer(file.slice(0, count));
  });
}

function readAsArrayBuffer(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = (e) => resolve(e.target.result);
    reader.onerror = reject;
    reader.readAsArrayBuffer(file);
  });
}

function isZipEncrypted(bytes) {
  // ZIP local file header: offset 6-7 = general purpose bit flag, bit 0 = encrypted
  if (bytes[0] === 0x50 && bytes[1] === 0x4B && bytes[2] === 0x03 && bytes[3] === 0x04) {
    const flags = bytes[6] | (bytes[7] << 8);
    return (flags & 0x01) !== 0;
  }
  return false;
}

async function inspectZip(arrayBuffer, depth = 0) {
  if (depth > MAX_ZIP_DEPTH) {
    return { blocked: true, reason: `Archive nested too deep (limit: ${MAX_ZIP_DEPTH})` };
  }

  let zip;
  try {
    zip = await JSZip.loadAsync(arrayBuffer);
  } catch (err) {
    if (err.message && err.message.toLowerCase().includes('encrypt')) {
      return { blocked: true, reason: 'Password-protected archive — cannot inspect contents' };
    }
    return { blocked: true, reason: 'Unreadable archive format' };
  }

  const fileNames = Object.keys(zip.files);

  // Check if this ZIP is actually an Office document
  for (const officePath of OFFICE_ZIP_PATHS) {
    if (fileNames.some(f => f === officePath || f.endsWith('/' + officePath))) {
      return { blocked: true, reason: 'Office document detected inside archive' };
    }
  }

  // Inspect each file inside the ZIP
  for (const fileName of fileNames) {
    const entry = zip.files[fileName];
    if (entry.dir) continue;

    // Zip bomb guard
    if (entry._data && entry._data.uncompressedSize > MAX_UNCOMPRESSED_BYTES) {
      return { blocked: true, reason: 'Archive entry too large — possible zip bomb' };
    }

    let entryBytes;
    try {
      const entryBuffer = await entry.async('arraybuffer');
      entryBytes = new Uint8Array(entryBuffer);
    } catch (err) {
      return { blocked: true, reason: `Encrypted entry detected: ${fileName}` };
    }

    const entryResult = await detectFileType(entryBytes, entryBuffer, depth + 1);
    if (entryResult.blocked) {
      return { blocked: true, reason: `${entryResult.reason} (inside: ${fileName})` };
    }
  }

  return { blocked: true, reason: 'ZIP archive — all archives blocked by policy' };
}

async function detectFileType(bytes, arrayBuffer = null, depth = 0) {
  // Direct document formats — block immediately
  if (matchesMagic(bytes, MAGIC_BYTES.OLE2.bytes)) {
    return { blocked: true, reason: `Legacy Office document detected (DOC/XLS/PPT)` };
  }
  if (matchesMagic(bytes, MAGIC_BYTES.PDF.bytes)) {
    return { blocked: true, reason: 'PDF document detected' };
  }
  if (matchesMagic(bytes, MAGIC_BYTES.RTF.bytes)) {
    return { blocked: true, reason: 'RTF document detected' };
  }

  // RAR and 7ZIP — can't inspect, block immediately
  if (matchesMagic(bytes, MAGIC_BYTES.RAR4.bytes) || matchesMagic(bytes, MAGIC_BYTES.RAR5.bytes)) {
    return { blocked: true, reason: 'RAR archive — cannot inspect contents' };
  }
  if (matchesMagic(bytes, MAGIC_BYTES.SEVENZIP.bytes)) {
    return { blocked: true, reason: '7-Zip archive — cannot inspect contents' };
  }

  // GZIP — block, too risky to inspect without native decompressor
  if (matchesMagic(bytes, MAGIC_BYTES.GZIP.bytes)) {
    return { blocked: true, reason: 'GZIP archive — cannot inspect contents' };
  }

  // ZIP-based (includes DOCX, XLSX, PPTX, ODT, plain ZIP)
  if (matchesMagic(bytes, MAGIC_BYTES.ZIP.bytes)) {
    // Check encryption flag in raw bytes
    if (isZipEncrypted(bytes)) {
      return { blocked: true, reason: 'Password-protected ZIP archive' };
    }

    // Need full buffer to inspect contents
    if (!arrayBuffer) {
      return { blocked: true, reason: 'ZIP file — full content required for inspection' };
    }

    return await inspectZip(arrayBuffer, depth);
  }

  return { blocked: false, reason: 'File type allowed' };
}

// Formats with no magic bytes — detection falls back to extension only.
const NO_MAGIC_EXTENSIONS = new Set(['csv', 'tsv', 'txt']);

// Expected magic bytes for common binary formats used as disguise targets.
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

function isPlainText(bytes) {
  const sample = bytes.slice(0, 512);
  for (const b of sample) {
    if (b === 0x09 || b === 0x0A || b === 0x0D) continue;
    if (b >= 0x20 && b <= 0x7E) continue;
    if (b === 0x00) return false;
    if (b < 0x09) return false;
  }
  return true;
}

async function inspectFile(file) {
  const ext = (file.name || '').split('.').pop().toLowerCase();
  if (NO_MAGIC_EXTENSIONS.has(ext)) {
    return { blocked: true, reason: `${ext.toUpperCase()} file — no magic bytes, blocked by extension` };
  }

  const headerBytes = await readFirstBytes(file, 8);

  // For ZIP-based files we need the full buffer
  if (matchesMagic(headerBytes, MAGIC_BYTES.ZIP.bytes)) {
    const arrayBuffer = await readAsArrayBuffer(file);
    const fullBytes = new Uint8Array(arrayBuffer);
    return await detectFileType(fullBytes, arrayBuffer, 0);
  }

  const result = await detectFileType(headerBytes, null, 0);
  if (result.blocked) return result;

  // File passed all magic byte checks — verify it matches its claimed extension.
  // A plain text file claiming to be an image is a data disguise attempt.
  const expectedMagic = BINARY_EXT_MAGIC[ext];
  if (expectedMagic && !matchesMagic(headerBytes, expectedMagic) && isPlainText(headerBytes)) {
    return { blocked: true, reason: `File type mismatch — claims to be ${ext.toUpperCase()} but contains plain text` };
  }

  return result;
}

window.BetterDLP = window.BetterDLP || {};
window.BetterDLP.inspectFile = inspectFile;
