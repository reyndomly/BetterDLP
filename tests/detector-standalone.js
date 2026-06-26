/**
 * BetterDLP detector — standalone version for testing (no chrome.* APIs)
 */
const BetterDLPDetector = (() => {
  const MAGIC_BYTES = {
    ZIP:      { bytes: [0x50, 0x4B, 0x03, 0x04] },
    OLE2:     { bytes: [0xD0, 0xCF, 0x11, 0xE0] },
    PDF:      { bytes: [0x25, 0x50, 0x44, 0x46] },
    RTF:      { bytes: [0x7B, 0x5C, 0x72, 0x74] },
    RAR4:     { bytes: [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00] },
    RAR5:     { bytes: [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01] },
    SEVENZIP: { bytes: [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C] },
    GZIP:     { bytes: [0x1F, 0x8B] },
  };

  const OFFICE_ZIP_PATHS = [
    'word/document.xml',
    'xl/workbook.xml',
    'ppt/presentation.xml',
    'content.xml',
    'META-INF/manifest.xml',
  ];

  const MAX_ZIP_DEPTH = 3;
  const MAX_UNCOMPRESSED_BYTES = 100 * 1024 * 1024;

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

    for (const officePath of OFFICE_ZIP_PATHS) {
      if (fileNames.some(f => f === officePath || f.endsWith('/' + officePath))) {
        return { blocked: true, reason: `Office document detected (contains ${officePath})` };
      }
    }

    for (const fileName of fileNames) {
      const entry = zip.files[fileName];
      if (entry.dir) continue;

      if (entry._data && entry._data.uncompressedSize > MAX_UNCOMPRESSED_BYTES) {
        return { blocked: true, reason: 'Archive entry too large — possible zip bomb' };
      }

      let entryBuffer;
      try {
        entryBuffer = await entry.async('arraybuffer');
      } catch (err) {
        return { blocked: true, reason: `Encrypted entry detected: ${fileName}` };
      }

      const entryBytes = new Uint8Array(entryBuffer);
      const entryResult = await detectFileType(entryBytes, entryBuffer, depth + 1);
      if (entryResult.blocked) {
        return { blocked: true, reason: `${entryResult.reason} (inside: ${fileName})` };
      }
    }

    return { blocked: false, reason: 'ZIP contents are clean' };
  }

  async function detectFileType(bytes, arrayBuffer = null, depth = 0) {
    if (matchesMagic(bytes, MAGIC_BYTES.OLE2.bytes))
      return { blocked: true, reason: 'Legacy Office document detected (DOC/XLS/PPT)' };
    if (matchesMagic(bytes, MAGIC_BYTES.PDF.bytes))
      return { blocked: true, reason: 'PDF document detected' };
    if (matchesMagic(bytes, MAGIC_BYTES.RTF.bytes))
      return { blocked: true, reason: 'RTF document detected' };
    if (matchesMagic(bytes, MAGIC_BYTES.RAR4.bytes) || matchesMagic(bytes, MAGIC_BYTES.RAR5.bytes))
      return { blocked: true, reason: 'RAR archive — cannot inspect contents' };
    if (matchesMagic(bytes, MAGIC_BYTES.SEVENZIP.bytes))
      return { blocked: true, reason: '7-Zip archive — cannot inspect contents' };
    if (matchesMagic(bytes, MAGIC_BYTES.GZIP.bytes))
      return { blocked: true, reason: 'GZIP archive — cannot inspect contents' };

    if (matchesMagic(bytes, MAGIC_BYTES.ZIP.bytes)) {
      if (isZipEncrypted(bytes))
        return { blocked: true, reason: 'Password-protected ZIP archive' };
      if (!arrayBuffer)
        return { blocked: true, reason: 'ZIP file — full content required for inspection' };
      return await inspectZip(arrayBuffer, depth);
    }

    return { blocked: false, reason: 'File type is allowed' };
  }

  async function inspectFile(file) {
    const headerBytes = await readFirstBytes(file, 8);

    if (matchesMagic(headerBytes, MAGIC_BYTES.ZIP.bytes)) {
      const arrayBuffer = await readAsArrayBuffer(file);
      const fullBytes = new Uint8Array(arrayBuffer);
      return await detectFileType(fullBytes, arrayBuffer, 0);
    }

    return await detectFileType(headerBytes, null, 0);
  }

  return { inspectFile };
})();
