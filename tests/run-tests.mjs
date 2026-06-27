import { readFileSync } from 'fs';

// ─── JSZip shim ───────────────────────────────────────────────────────────────
const jszipCode = readFileSync(new URL('../src/lib/jszip.min.js', import.meta.url).pathname, 'utf8');
const mod = { exports: {} };
(new Function('module', 'exports', jszipCode))(mod, mod.exports);
const JSZip = mod.exports;

// ─── FileReader shim ──────────────────────────────────────────────────────────
class FileReader {
  readAsArrayBuffer(blob) {
    Promise.resolve(blob._buf ? blob._buf : blob.arrayBuffer())
      .then(buf => this.onload({ target: { result: buf } }))
      .catch(err => this.onerror && this.onerror(err));
  }
}

// ─── Detection (mirrors src/content/detector.js) ─────────────────────────────

const BLOCKED_MAGIC = [
  { sig: [0xD0, 0xCF, 0x11, 0xE0],                         label: 'Legacy Office document (DOC/XLS/PPT)' },
  { sig: [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00],       label: 'RAR archive'       },
  { sig: [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01],       label: 'RAR5 archive'      },
  { sig: [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C],             label: '7-Zip archive'     },
  { sig: [0x1F, 0x8B, 0x08],                               label: 'GZIP archive'      },
  { sig: [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00],             label: 'XZ archive'        },
  { sig: [0x28, 0xB5, 0x2F, 0xFD],                         label: 'Zstandard archive' },
  { sig: [0x42, 0x5A, 0x68],                               label: 'BZIP2 archive'     },
  { sig: [0x04, 0x22, 0x4D, 0x18],                         label: 'LZ4 archive'       },
  { sig: [0x4D, 0x53, 0x43, 0x46],                         label: 'Cabinet archive'   },
];

const PDF_SIG   = [0x25, 0x50, 0x44, 0x46];
const RTF_SIG   = [0x7B, 0x5C, 0x72, 0x74];
const TAR_SIG   = [0x75, 0x73, 0x74, 0x61, 0x72];
const TAR_OFF   = 257;
const PDF_SCAN  = 1024;
const RTF_SCAN  = 64;
const ZIP_LOCAL = [0x50, 0x4B, 0x03, 0x04];
const ZIP_EOCD  = [0x50, 0x4B, 0x05, 0x06];
const ZIP_SCAN  = 64 * 1024;

const OFFICE_PATHS = [
  'word/document.xml', 'xl/workbook.xml', 'ppt/presentation.xml',
  'content.xml', 'META-INF/manifest.xml',
];

const MAX_DEPTH  = 3;
const MAX_UNCOMP = 100 * 1024 * 1024;

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

async function inspectZip(buf, depth = 0) {
  if (depth > MAX_DEPTH)
    return { blocked: true, reason: `Archive nested too deep (limit: ${MAX_DEPTH})` };

  let zip;
  try {
    zip = await JSZip.loadAsync(buf);
  } catch (err) {
    const msg = (err && err.message || '').toLowerCase();
    if (msg.includes('encrypt') || msg.includes('password'))
      return { blocked: true, reason: 'Password-protected archive — cannot inspect contents' };
    return { blocked: true, reason: 'Unreadable archive format' };
  }

  const names = Object.keys(zip.files);

  for (const op of OFFICE_PATHS) {
    if (names.some(n => n === op || n.endsWith('/' + op)))
      return { blocked: true, reason: `Office document detected (${op})` };
  }

  for (const name of names) {
    const entry = zip.files[name];
    if (entry.dir) continue;
    if (entry._data && entry._data.uncompressedSize > MAX_UNCOMP)
      return { blocked: true, reason: 'Archive entry too large — possible zip bomb' };

    let entryBuf;
    try { entryBuf = await entry.async('arraybuffer'); }
    catch { return { blocked: true, reason: `Encrypted entry: ${name}` }; }

    const r = await detectFileType(new Uint8Array(entryBuf), entryBuf);
    if (r.blocked) return { blocked: true, reason: `${r.reason} (inside: ${name})` };
  }

  return { blocked: true, reason: 'ZIP archive — all archives blocked by policy' };
}

async function detectFileType(bytes, buf = null) {
  for (const { sig, label } of BLOCKED_MAGIC) {
    if (matchesMagic(bytes, sig)) return { blocked: true, reason: label };
  }

  if (indexOfSig(bytes, PDF_SIG, PDF_SCAN) !== -1)
    return { blocked: true, reason: 'PDF document' };
  if (indexOfSig(bytes, RTF_SIG, RTF_SCAN) !== -1)
    return { blocked: true, reason: 'RTF document' };
  if (matchesAt(bytes, TAR_SIG, TAR_OFF))
    return { blocked: true, reason: 'TAR archive' };

  const zipStart = findZipStart(bytes);
  if (zipStart !== -1) {
    if (isZipEncrypted(bytes, zipStart))
      return { blocked: true, reason: 'Password-protected ZIP archive' };
    if (!buf)
      return { blocked: true, reason: 'ZIP archive — blocked by policy' };
    const slice = zipStart > 0 ? buf.slice(zipStart) : buf;
    return await inspectZip(slice, 0);
  }

  if (isPlainText(bytes))
    return { blocked: true, reason: 'Text/data file — blocked by policy' };

  return { blocked: false, reason: 'File type allowed' };
}

async function inspectFile(blob) {
  const buf = await blob.arrayBuffer();
  return detectFileType(new Uint8Array(buf), buf);
}

// ─── File helper ──────────────────────────────────────────────────────────────
function makeBlob(filename) {
  const raw = readFileSync(new URL(`fixtures/${filename}`, import.meta.url).pathname);
  return {
    name: filename,
    arrayBuffer: () => Promise.resolve(raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.byteLength)),
  };
}

// ─── Tests ────────────────────────────────────────────────────────────────────
const TESTS = [
  // Core document formats
  { name: 'Real DOCX',                  file: 'real.docx',              expect: 'BLOCKED' },
  { name: 'Real XLSX',                  file: 'real.xlsx',              expect: 'BLOCKED' },
  { name: 'Real PPTX',                  file: 'real.pptx',              expect: 'BLOCKED' },
  { name: 'Legacy DOC (OLE2)',          file: 'legacy.doc',             expect: 'BLOCKED' },
  { name: 'PDF',                        file: 'document.pdf',           expect: 'BLOCKED' },
  { name: 'PDF (offset header)',        file: 'offset_header.pdf',      expect: 'BLOCKED' },
  { name: 'RTF',                        file: 'real.rtf',               expect: 'BLOCKED' },
  // Archive formats
  { name: 'RAR Archive',                file: 'archive.rar',            expect: 'BLOCKED' },
  { name: '7-Zip Archive',              file: 'archive.7z',             expect: 'BLOCKED' },
  { name: 'GZIP Archive',              file: 'archive.gz',             expect: 'BLOCKED' },
  { name: 'XZ Archive',                file: 'archive.xz',             expect: 'BLOCKED' },
  { name: 'Zstandard Archive',          file: 'archive.zst',            expect: 'BLOCKED' },
  { name: 'BZIP2 Archive',              file: 'archive.bz2',            expect: 'BLOCKED' },
  { name: 'LZ4 Archive',                file: 'archive.lz4',            expect: 'BLOCKED' },
  { name: 'Cabinet Archive',            file: 'archive.cab',            expect: 'BLOCKED' },
  { name: 'TAR Archive',                file: 'archive.tar',            expect: 'BLOCKED' },
  // Bypass attempts
  { name: 'DOCX renamed to .jpg',       file: 'photo_disguised.jpg',    expect: 'BLOCKED' },
  { name: 'ZIP with DOCX inside',       file: 'archive_with_doc.zip',   expect: 'BLOCKED' },
  { name: 'Encrypted ZIP',              file: 'encrypted.zip',          expect: 'BLOCKED' },
  { name: 'Zip Bomb (200MB declared)',  file: 'zipbomb.zip',            expect: 'BLOCKED' },
  { name: 'Nested ZIP (2 levels)',      file: 'nested.zip',             expect: 'BLOCKED' },
  { name: 'Nested ZIP (3 levels)',      file: 'triple_nested.zip',      expect: 'BLOCKED' },
  { name: 'Polyglot ZIP (prepend)',     file: 'polyglot_docx.zip',      expect: 'BLOCKED' },
  // Plain text detection (content-based, extension-agnostic)
  { name: 'CSV file',                   file: 'data.csv',               expect: 'BLOCKED' },
  { name: 'CSV renamed to .jpg',        file: 'csv_as_image.jpg',       expect: 'BLOCKED' },
  // Should pass
  { name: 'Clean ZIP (images only)',    file: 'clean_photos.zip',       expect: 'BLOCKED' },
  { name: 'Real PNG Image',             file: 'real_image.png',         expect: 'ALLOWED' },
];

const G = '\x1b[32m', R = '\x1b[31m', Y = '\x1b[33m', D = '\x1b[2m', B = '\x1b[1m', X = '\x1b[0m';

console.log(`\n${B}🛡️  BetterDLP Test Suite${X}\n${'─'.repeat(62)}`);

let passed = 0, failed = 0, failures = [];

for (const t of TESTS) {
  try {
    const blob = makeBlob(t.file);
    const result = await inspectFile(blob);
    const actual = result.blocked ? 'BLOCKED' : 'ALLOWED';
    const ok = actual === t.expect;
    if (ok) passed++; else { failed++; failures.push({ ...t, actual, reason: result.reason }); }
    const icon = ok ? `${G}✓${X}` : `${R}✗${X}`;
    const col  = actual === 'BLOCKED' ? R : G;
    console.log(`  ${icon} ${t.name.padEnd(28)} ${col}${actual.padEnd(8)}${X} ${D}${result.reason}${X}`);
  } catch (err) {
    failed++;
    failures.push({ ...t, actual: 'ERROR', reason: err.message });
    console.log(`  ${Y}!${X} ${t.name.padEnd(28)} ${Y}ERROR${X}    ${err.message}`);
  }
}

console.log(`\n${'─'.repeat(62)}`);
console.log(`  ${B}Results:${X}  ${G}${passed} passed${X}  ${failed > 0 ? R : D}${failed} failed${X}  / ${TESTS.length} total\n`);

if (failures.length) {
  console.log(`${R}${B}Failures:${X}`);
  failures.forEach(f => console.log(`  ${R}✗${X} ${f.name} — expected ${f.expect}, got ${f.actual}\n    ${D}${f.reason}${X}`));
  console.log('');
}

process.exit(failed > 0 ? 1 : 0);
