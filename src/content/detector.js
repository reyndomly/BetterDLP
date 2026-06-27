/**
 * BetterDLP - File Type Detector (isolated world)
 *
 * Identifies real file types independent of filename/extension and enforces the
 * "no document/data uploads" policy. Synchronous detection logic lives in the
 * shared module (src/lib/detection-core.js → globalThis.BetterDLPCore); this
 * file adds async, JSZip-backed deep inspection of ZIP-based archives so blocked
 * archives get a specific reason (Office doc / nested archive / zip bomb).
 *
 * The verdict for any archive is ALWAYS "blocked"; deep inspection only enriches
 * the reason string shown to the user and audit log.
 */

function readAsArrayBuffer(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = (e) => resolve(e.target.result);
    reader.onerror = reject;
    reader.readAsArrayBuffer(file);
  });
}

// Deep-inspect a ZIP (located at `zipStart` inside `bytes`) for a richer reason.
// Always returns a blocked verdict.
async function inspectZip(bytes, zipStart, depth) {
  const Core = globalThis.BetterDLPCore;
  if (depth > Core.MAX_ZIP_DEPTH) {
    return { blocked: true, reason: `Archive nested too deep (limit: ${Core.MAX_ZIP_DEPTH})` };
  }

  const slice = zipStart > 0 ? bytes.subarray(zipStart) : bytes;

  let zip;
  try {
    zip = await JSZip.loadAsync(slice);
  } catch (err) {
    const msg = (err && err.message || '').toLowerCase();
    if (msg.includes('encrypt') || msg.includes('password')) {
      return { blocked: true, reason: 'Password-protected archive — cannot inspect contents' };
    }
    // Unreadable by JSZip but the signature was present → still blocked.
    return { blocked: true, reason: 'Archive — all archives blocked by policy' };
  }

  const fileNames = Object.keys(zip.files);

  // Office document?
  for (const officePath of Core.OFFICE_ZIP_PATHS) {
    if (fileNames.some(f => f === officePath || f.endsWith('/' + officePath))) {
      return { blocked: true, reason: 'Office document detected inside archive' };
    }
  }

  // Inspect each entry for a more specific reason.
  for (const fileName of fileNames) {
    const entry = zip.files[fileName];
    if (entry.dir) continue;

    if (entry._data && entry._data.uncompressedSize > Core.MAX_UNCOMPRESSED_BYTES) {
      return { blocked: true, reason: 'Archive entry too large — possible zip bomb' };
    }

    let entryBytes;
    try {
      const entryBuffer = await entry.async('arraybuffer');
      entryBytes = new Uint8Array(entryBuffer);
    } catch (err) {
      return { blocked: true, reason: `Encrypted entry detected: ${fileName}` };
    }

    // Nested archive → recurse for a deeper reason.
    const nestedStart = Core.findZipStart(entryBytes);
    if (nestedStart !== -1) {
      const nested = await inspectZip(entryBytes, nestedStart, depth + 1);
      if (nested.blocked) return { blocked: true, reason: `${nested.reason} (inside: ${fileName})` };
      continue;
    }

    // Document/archive signature inside the entry.
    const sig = Core.sniffBinarySignature(entryBytes);
    if (sig) return { blocked: true, reason: `${sig.reason} (inside: ${fileName})` };

    // Sensitive text/data inside the entry.
    if (Core.isPlainText(entryBytes)) {
      const pii = Core.scanTextContent(Core.bytesToText(entryBytes, 256 * 1024));
      if (pii) return { blocked: true, reason: `${pii.reason} (inside: ${fileName})` };
    }
  }

  return { blocked: true, reason: 'ZIP archive — all archives blocked by policy' };
}

async function inspectFile(file) {
  // This function must NEVER reject: a rejected promise would let the caller's
  // event stay stopped (file blocked) with no modal/log. Any error fails closed
  // with a verdict and is surfaced to the console for diagnosis.
  try {
    // Resolve the core at call time (not load time) so a load-order hiccup
    // degrades gracefully instead of throwing an uncaught TypeError.
    const core = globalThis.BetterDLPCore;
    if (!core) {
      console.error('[BetterDLP] detection-core not loaded — blocking file as a precaution');
      return { blocked: true, reason: 'Inspector unavailable — blocked by policy' };
    }

    let arrayBuffer;
    try {
      arrayBuffer = await readAsArrayBuffer(file);
    } catch (err) {
      return { blocked: true, reason: 'Unable to read file for inspection — blocked by policy' };
    }
    const bytes = new Uint8Array(arrayBuffer);

    // ZIP-based files (incl. prepend / polyglot disguises) → deep inspection.
    const zipStart = core.findZipStart(bytes);
    if (zipStart !== -1) {
      if (core.isZipEncrypted(bytes, zipStart)) {
        return { blocked: true, reason: 'Password-protected ZIP archive' };
      }
      return await inspectZip(bytes, zipStart, 0);
    }

    // Everything else: synchronous file-context verdict (block all document/data).
    return core.inspectFileBytes(bytes, file.name);
  } catch (err) {
    console.error('[BetterDLP] inspection error — blocking file as a precaution:', err);
    return { blocked: true, reason: 'Inspection error — blocked by policy (' + ((err && err.message) || err) + ')' };
  }
}

window.BetterDLP = window.BetterDLP || {};
window.BetterDLP.inspectFile = inspectFile;
