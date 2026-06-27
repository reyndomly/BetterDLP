import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';

const resolve = (rel) => fileURLToPath(new URL(rel, import.meta.url));

// ─── Load shipped JSZip ───────────────────────────────────────────────────────
const jszipCode = readFileSync(resolve('../src/lib/jszip.min.js'), 'utf8');
const jmod = { exports: {} };
(new Function('module', 'exports', jszipCode))(jmod, jmod.exports);
const JSZip = jmod.exports;

// ─── Load the shared detection core (single source of truth) ──────────────────
const coreCode = readFileSync(resolve('../src/lib/detection-core.js'), 'utf8');
const cmod = { exports: {} };
(new Function('module', 'exports', coreCode))(cmod, cmod.exports);
const Core = cmod.exports;

// ─── Async inspectFile — mirrors src/content/detector.js exactly ──────────────
// (Deep JSZip inspection here; the synchronous rules live in detection-core.js.)
async function inspectZip(bytes, zipStart, depth) {
  if (depth > Core.MAX_ZIP_DEPTH)
    return { blocked: true, reason: `Archive nested too deep (limit: ${Core.MAX_ZIP_DEPTH})` };

  const slice = zipStart > 0 ? bytes.subarray(zipStart) : bytes;

  let zip;
  try { zip = await JSZip.loadAsync(slice); }
  catch (err) {
    const msg = (err && err.message || '').toLowerCase();
    if (msg.includes('encrypt') || msg.includes('password'))
      return { blocked: true, reason: 'Password-protected archive — cannot inspect contents' };
    return { blocked: true, reason: 'Archive — all archives blocked by policy' };
  }

  const names = Object.keys(zip.files);

  for (const op of Core.OFFICE_ZIP_PATHS) {
    if (names.some(n => n === op || n.endsWith('/' + op)))
      return { blocked: true, reason: 'Office document detected inside archive' };
  }

  for (const name of names) {
    const entry = zip.files[name];
    if (entry.dir) continue;
    if (entry._data && entry._data.uncompressedSize > Core.MAX_UNCOMPRESSED_BYTES)
      return { blocked: true, reason: 'Archive entry too large — possible zip bomb' };

    let eb;
    try { eb = new Uint8Array(await entry.async('arraybuffer')); }
    catch { return { blocked: true, reason: `Encrypted entry detected: ${name}` }; }

    const nestedStart = Core.findZipStart(eb);
    if (nestedStart !== -1) {
      const nested = await inspectZip(eb, nestedStart, depth + 1);
      if (nested.blocked) return { blocked: true, reason: `${nested.reason} (inside: ${name})` };
      continue;
    }
    const sig = Core.sniffBinarySignature(eb);
    if (sig) return { blocked: true, reason: `${sig.reason} (inside: ${name})` };
    if (Core.isPlainText(eb)) {
      const pii = Core.scanTextContent(Core.bytesToText(eb, 256 * 1024));
      if (pii) return { blocked: true, reason: `${pii.reason} (inside: ${name})` };
    }
  }

  return { blocked: true, reason: 'ZIP archive — all archives blocked by policy' };
}

async function inspectFile(blob) {
  const bytes = new Uint8Array(await blob.arrayBuffer());
  const zipStart = Core.findZipStart(bytes);
  if (zipStart !== -1) {
    if (Core.isZipEncrypted(bytes, zipStart))
      return { blocked: true, reason: 'Password-protected ZIP archive' };
    return await inspectZip(bytes, zipStart, 0);
  }
  return Core.inspectFileBytes(bytes, blob.name);
}

// ─── Fixture / blob helpers ───────────────────────────────────────────────────
function fixtureBytes(filename) {
  const raw = readFileSync(resolve(`fixtures/${filename}`));
  return new Uint8Array(raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.byteLength));
}
function makeBlob(filename) {
  const u8 = fixtureBytes(filename);
  return { name: filename, arrayBuffer: () => Promise.resolve(u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength)) };
}
function blobFrom(name, u8) {
  return { name, arrayBuffer: () => Promise.resolve(u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength)) };
}
const enc = (s) => new TextEncoder().encode(s);
function concat(...arrs) {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}

// ─── Synthetic bypass payloads (built from real fixtures) ─────────────────────
const DOCX = fixtureBytes('real.docx');
const PNG  = fixtureBytes('real_image.png');
const CSV  = 'employee_id,ssn,salary\n1001,123-45-6789,250000\n1002,987-65-4321,310000\n1003,111-22-3333,90000\n';
const PROSE = '# Project Notes\n\nThis is an ordinary readme describing the build steps.\nNothing sensitive lives in this file at all.\nIt is just prose for humans to read.\n';

function tarBytes() {
  const h = new Uint8Array(512);
  h.set(enc('ustar'), 257);
  return concat(h, enc(CSV));
}

// ─── Tests ────────────────────────────────────────────────────────────────────
const TESTS = [
  // Core document formats
  { name: 'Real DOCX',                  blob: makeBlob('real.docx'),            expect: 'BLOCKED' },
  { name: 'Real XLSX',                  blob: makeBlob('real.xlsx'),            expect: 'BLOCKED' },
  { name: 'Real PPTX',                  blob: makeBlob('real.pptx'),            expect: 'BLOCKED' },
  { name: 'Legacy DOC (OLE2)',          blob: makeBlob('legacy.doc'),           expect: 'BLOCKED' },
  { name: 'PDF',                        blob: makeBlob('document.pdf'),         expect: 'BLOCKED' },
  { name: 'RTF',                        blob: makeBlob('real.rtf'),             expect: 'BLOCKED' },
  // Original bypass attempts
  { name: 'DOCX renamed to .jpg',       blob: makeBlob('photo_disguised.jpg'),  expect: 'BLOCKED' },
  { name: 'ZIP with DOCX inside',       blob: makeBlob('archive_with_doc.zip'), expect: 'BLOCKED' },
  { name: 'Encrypted ZIP',              blob: makeBlob('encrypted.zip'),        expect: 'BLOCKED' },
  { name: 'RAR Archive',                blob: makeBlob('archive.rar'),          expect: 'BLOCKED' },
  { name: '7-Zip Archive',              blob: makeBlob('archive.7z'),           expect: 'BLOCKED' },
  { name: 'GZIP Archive',               blob: makeBlob('archive.gz'),           expect: 'BLOCKED' },
  { name: 'Zip Bomb (200MB declared)',  blob: makeBlob('zipbomb.zip'),          expect: 'BLOCKED' },
  { name: 'Nested ZIP (2 levels)',      blob: makeBlob('nested.zip'),           expect: 'BLOCKED' },
  { name: 'Nested ZIP (3 levels)',      blob: makeBlob('triple_nested.zip'),    expect: 'BLOCKED' },
  { name: 'CSV file',                   blob: makeBlob('data.csv'),             expect: 'BLOCKED' },
  { name: 'CSV renamed to .jpg',        blob: makeBlob('csv_as_image.jpg'),     expect: 'BLOCKED' },
  { name: 'Clean ZIP (images only)',    blob: makeBlob('clean_photos.zip'),     expect: 'BLOCKED' },
  { name: 'Real PNG Image',             blob: makeBlob('real_image.png'),       expect: 'ALLOWED' },

  // ── New: bypasses found in the red-team analysis ──
  { name: 'DOCX w/ prepended junk',     blob: blobFrom('prepend.docx', concat(enc('JUNK'), DOCX)),                 expect: 'BLOCKED' },
  { name: 'PNG-header DOCX polyglot',   blob: blobFrom('poly.png', concat(new Uint8Array([0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A]), DOCX)), expect: 'BLOCKED' },
  { name: 'CSV renamed to .md',         blob: blobFrom('data.md', enc(CSV)),                                       expect: 'BLOCKED' },
  { name: 'CSV renamed to .dat',        blob: blobFrom('data.dat', enc(CSV)),                                      expect: 'BLOCKED' },
  { name: 'CSV with no extension',      blob: blobFrom('EXPORT', enc(CSV)),                                        expect: 'BLOCKED' },
  { name: 'PII text as .json',          blob: blobFrom('export.json', enc(JSON.stringify({ ssn: '123-45-6789' }))), expect: 'BLOCKED' },
  { name: 'TAR container of CSV',        blob: blobFrom('data.tar', tarBytes()),                                    expect: 'BLOCKED' },
  { name: 'XZ container',               blob: blobFrom('data.xz', concat(new Uint8Array([0xFD,0x37,0x7A,0x58,0x5A,0x00]), enc(CSV))), expect: 'BLOCKED' },
  { name: 'Zstandard container',        blob: blobFrom('data.zst', concat(new Uint8Array([0x28,0xB5,0x2F,0xFD]), enc(CSV))), expect: 'BLOCKED' },
  { name: 'BZIP2 container',            blob: blobFrom('data.bz2', concat(enc('BZh91AY&SY'), enc(CSV))),            expect: 'BLOCKED' },
  { name: 'PII embedded in real PNG',   blob: blobFrom('shot.png', concat(PNG, enc('\nSSN 123-45-6789\n'))),       expect: 'BLOCKED' },
  { name: 'Plain prose README.md',      blob: blobFrom('README.md', enc(PROSE)),                                   expect: 'BLOCKED' },
];

const G = '\x1b[32m', R = '\x1b[31m', Y = '\x1b[33m', D = '\x1b[2m', B = '\x1b[1m', X = '\x1b[0m';

console.log(`\n${B}🛡️  BetterDLP Test Suite${X}\n${'─'.repeat(72)}`);

let passed = 0, failed = 0, failures = [];

for (const t of TESTS) {
  try {
    const result = await inspectFile(t.blob);
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

// ─── Network-context tests (Core.inspectNetworkBytes) ─────────────────────────
// These guard against false positives on ordinary app traffic: binary XHR/WS
// bodies and JSON must NOT be blocked just for being non-image binary or for
// containing a coincidental Luhn-valid digit run. Real document/archive
// signatures and PII *in text* must still be blocked.
function randomBinary(n, seed = 1) {
  const out = new Uint8Array(n);
  let s = seed;
  for (let i = 0; i < n; i++) { s = (s * 1103515245 + 12345) & 0x7fffffff; out[i] = s & 0xff; }
  return out;
}
const NET_TESTS = [
  { name: 'Binary XHR blob (encrypted-like)',  bytes: randomBinary(2048, 7),                              expect: 'ALLOWED' },
  { name: 'Binary blob w/ card digit run',     bytes: concat(randomBinary(64, 3), enc('4111111111111111'), randomBinary(64, 9)), expect: 'ALLOWED' },
  { name: 'JSON w/ big numeric ID (snowflake)', bytes: enc(JSON.stringify({ id: '1719300000123456789', msg: 'hi', ts: 1719300000 })), expect: 'ALLOWED' },
  { name: 'JSON body with real card number',   bytes: enc(JSON.stringify({ card: '4111 1111 1111 1111' })), expect: 'BLOCKED' },
  { name: 'JSON body with real SSN',           bytes: enc(JSON.stringify({ ssn: '123-45-6789' })),        expect: 'BLOCKED' },
  { name: 'PDF uploaded as raw body',          bytes: enc('%PDF-1.7\n...'),                                expect: 'BLOCKED' },
  { name: 'DOCX uploaded as raw body',         bytes: DOCX,                                                expect: 'BLOCKED' },
];
for (const t of NET_TESTS) {
  try {
    const result = Core.inspectNetworkBytes(t.bytes);
    const actual = result.blocked ? 'BLOCKED' : 'ALLOWED';
    const ok = actual === t.expect;
    if (ok) passed++; else { failed++; failures.push({ ...t, actual, reason: result.reason }); }
    const icon = ok ? `${G}✓${X}` : `${R}✗${X}`;
    const col  = actual === 'BLOCKED' ? R : G;
    console.log(`  ${icon} ${('[net] ' + t.name).padEnd(28)} ${col}${actual.padEnd(8)}${X} ${D}${result.reason}${X}`);
  } catch (err) {
    failed++;
    failures.push({ ...t, actual: 'ERROR', reason: err.message });
    console.log(`  ${Y}!${X} ${('[net] ' + t.name).padEnd(28)} ${Y}ERROR${X}    ${err.message}`);
  }
}
const TOTAL = TESTS.length + NET_TESTS.length;

console.log(`\n${'─'.repeat(72)}`);
console.log(`  ${B}Results:${X}  ${G}${passed} passed${X}  ${failed > 0 ? R : D}${failed} failed${X}  / ${TOTAL} total\n`);

if (failures.length) {
  console.log(`${R}${B}Failures:${X}`);
  failures.forEach(f => console.log(`  ${R}✗${X} ${f.name} — expected ${f.expect}, got ${f.actual}\n    ${D}${f.reason}${X}`));
  console.log('');
}

process.exit(failed > 0 ? 1 : 0);
