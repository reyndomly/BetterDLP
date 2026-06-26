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

// ─── Detector (inlined, no chrome.* deps) ────────────────────────────────────
const MAGIC = {
  ZIP:      [0x50, 0x4B, 0x03, 0x04],
  OLE2:     [0xD0, 0xCF, 0x11, 0xE0],
  PDF:      [0x25, 0x50, 0x44, 0x46],
  RTF:      [0x7B, 0x5C, 0x72, 0x74],
  RAR4:     [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00],
  RAR5:     [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01],
  SEVENZIP: [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C],
  GZIP:     [0x1F, 0x8B],
};

const OFFICE_PATHS = [
  'word/document.xml', 'xl/workbook.xml', 'ppt/presentation.xml',
  'content.xml', 'META-INF/manifest.xml',
];

const MAX_DEPTH = 3;
const MAX_UNCOMP = 100 * 1024 * 1024;

function match(bytes, magic) { return magic.every((b, i) => bytes[i] === b); }

function readBytes(blob, count = 8) {
  return new Promise((resolve, reject) => {
    const fr = new FileReader();
    fr.onload = e => resolve(new Uint8Array(e.target.result));
    fr.onerror = reject;
    fr.readAsArrayBuffer({ arrayBuffer: () => blob.arrayBuffer().then(b => b.slice(0, count)), _buf: null });
  });
}

function readAll(blob) {
  return new Promise((resolve, reject) => {
    const fr = new FileReader();
    fr.onload = e => resolve(e.target.result);
    fr.onerror = reject;
    fr.readAsArrayBuffer(blob);
  });
}

function isZipEncrypted(bytes) {
  if (match(bytes, MAGIC.ZIP)) {
    return (bytes[6] | (bytes[7] << 8)) & 0x01;
  }
  return false;
}

async function inspectZip(buf, depth = 0) {
  if (depth > MAX_DEPTH)
    return { blocked: true, reason: `Archive nested too deep (limit: ${MAX_DEPTH})` };

  let zip;
  try {
    zip = await JSZip.loadAsync(buf);
  } catch (err) {
    const msg = err.message || '';
    if (msg.toLowerCase().includes('encrypt') || msg.toLowerCase().includes('password'))
      return { blocked: true, reason: 'Password-protected archive — cannot inspect contents' };
    return { blocked: true, reason: 'Unreadable archive: ' + msg };
  }

  const names = Object.keys(zip.files);

  for (const op of OFFICE_PATHS) {
    if (names.some(n => n === op || n.endsWith('/' + op)))
      return { blocked: true, reason: `Office document detected (contains ${op})` };
  }

  for (const name of names) {
    const entry = zip.files[name];
    if (entry.dir) continue;
    if (entry._data && entry._data.uncompressedSize > MAX_UNCOMP)
      return { blocked: true, reason: 'Archive entry too large — possible zip bomb' };

    let entryBuf;
    try { entryBuf = await entry.async('arraybuffer'); }
    catch { return { blocked: true, reason: `Encrypted entry: ${name}` }; }

    const r = await detectType(new Uint8Array(entryBuf), entryBuf, depth + 1);
    if (r.blocked) return { blocked: true, reason: `${r.reason} (inside: ${name})` };
  }

  return { blocked: true, reason: 'ZIP archive — all archives blocked by policy' };
}

async function detectType(bytes, buf = null, depth = 0) {
  if (match(bytes, MAGIC.OLE2))     return { blocked: true, reason: 'Legacy Office document (DOC/XLS/PPT)' };
  if (match(bytes, MAGIC.PDF))      return { blocked: true, reason: 'PDF document' };
  if (match(bytes, MAGIC.RTF))      return { blocked: true, reason: 'RTF document' };
  if (match(bytes, MAGIC.RAR4) ||
      match(bytes, MAGIC.RAR5))     return { blocked: true, reason: 'RAR archive — cannot inspect' };
  if (match(bytes, MAGIC.SEVENZIP)) return { blocked: true, reason: '7-Zip archive — cannot inspect' };
  if (match(bytes, MAGIC.GZIP))     return { blocked: true, reason: 'GZIP archive — cannot inspect' };

  if (match(bytes, MAGIC.ZIP)) {
    if (isZipEncrypted(bytes))      return { blocked: true, reason: 'Password-protected ZIP' };
    if (!buf)                        return { blocked: true, reason: 'ZIP — full buffer required' };
    return await inspectZip(buf, depth);
  }

  return { blocked: false, reason: 'File type allowed' };
}

const NO_MAGIC_EXT = new Set(['csv', 'tsv', 'txt']);

async function inspectFile(blob) {
  const ext = (blob.name || '').split('.').pop().toLowerCase();
  if (NO_MAGIC_EXT.has(ext)) {
    return { blocked: true, reason: `${ext.toUpperCase()} file — no magic bytes, blocked by extension` };
  }
  const buf = await blob.arrayBuffer();
  const bytes = new Uint8Array(buf);
  return await detectType(bytes, buf, 0);
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
  { name: 'Real DOCX',                  file: 'real.docx',            expect: 'BLOCKED' },
  { name: 'Real XLSX',                  file: 'real.xlsx',            expect: 'BLOCKED' },
  { name: 'Real PPTX',                  file: 'real.pptx',            expect: 'BLOCKED' },
  { name: 'Legacy DOC (OLE2)',          file: 'legacy.doc',           expect: 'BLOCKED' },
  { name: 'PDF',                        file: 'document.pdf',         expect: 'BLOCKED' },
  { name: 'RTF',                        file: 'real.rtf',             expect: 'BLOCKED' },
  // Bypass attempts
  { name: 'DOCX renamed to .jpg',       file: 'photo_disguised.jpg',  expect: 'BLOCKED' },
  { name: 'ZIP with DOCX inside',       file: 'archive_with_doc.zip', expect: 'BLOCKED' },
  { name: 'Encrypted ZIP',              file: 'encrypted.zip',        expect: 'BLOCKED' },
  { name: 'RAR Archive',                file: 'archive.rar',          expect: 'BLOCKED' },
  { name: '7-Zip Archive',              file: 'archive.7z',           expect: 'BLOCKED' },
  { name: 'GZIP Archive',               file: 'archive.gz',           expect: 'BLOCKED' },
  { name: 'Zip Bomb (200MB declared)',   file: 'zipbomb.zip',          expect: 'BLOCKED' },
  { name: 'Nested ZIP (2 levels)',       file: 'nested.zip',           expect: 'BLOCKED' },
  { name: 'Nested ZIP (3 levels)',       file: 'triple_nested.zip',    expect: 'BLOCKED' },
  // No-magic-bytes formats (extension-based detection)
  { name: 'CSV file',                   file: 'data.csv',             expect: 'BLOCKED' },
  // Should pass
  { name: 'Clean ZIP (images only)',    file: 'clean_photos.zip',     expect: 'BLOCKED' },
  { name: 'Real PNG Image',             file: 'real_image.png',       expect: 'ALLOWED' },
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
    console.log(`  ${icon} ${t.name.padEnd(26)} ${col}${actual.padEnd(8)}${X} ${D}${result.reason}${X}`);
  } catch (err) {
    failed++;
    failures.push({ ...t, actual: 'ERROR', reason: err.message });
    console.log(`  ${Y}!${X} ${t.name.padEnd(26)} ${Y}ERROR${X}    ${err.message}`);
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
