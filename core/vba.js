// Creato da anvex2012
'use strict';
/**
 * MS-OVBA decompression (VBA macro compression, as used by olevba).
 * Finds the compressed source modules by locating the "Attribut" signature.
 */
function decompress(buf, start) {
  if (buf[start] !== 1) return null;
  let pos = start + 1;
  const out = [];
  while (pos + 2 <= buf.length) {
    const header = buf.readUInt16LE(pos);
    if (((header >> 12) & 7) !== 3) break;
    const chunkEnd = Math.min(buf.length, pos + (header & 0x0fff) + 3);
    const compressed = header & 0x8000;
    pos += 2;
    const decStart = out.length;
    if (!compressed) {
      for (let i = 0; i < 4096 && pos < buf.length; i++) out.push(buf[pos++]);
      continue;
    }
    while (pos < chunkEnd) {
      const flags = buf[pos++];
      for (let bit = 0; bit < 8 && pos < chunkEnd; bit++) {
        if (!((flags >> bit) & 1)) { out.push(buf[pos++]); continue; }
        if (pos + 2 > buf.length) return Buffer.from(out);
        const token = buf.readUInt16LE(pos); pos += 2;
        const dpos = out.length - decStart;
        const bitCount = Math.max(Math.ceil(Math.log2(Math.max(dpos, 1))), 4);
        const lengthMask = 0xffff >> bitCount;
        const length = (token & lengthMask) + 3;
        const offset = ((token & (~lengthMask & 0xffff)) >> (16 - bitCount)) + 1;
        const from = out.length - offset;
        if (from < 0) return Buffer.from(out);
        for (let k = 0; k < length; k++) out.push(out[from + k]);
      }
    }
    if (out.length > 16 * 1024 * 1024) break;
  }
  return Buffer.from(out);
}

function extractMacros(buf) {
  const sources = [];
  const sig = Buffer.from('Attribut');
  let i = buf.indexOf(sig);
  while (i !== -1 && sources.length < 50) {
    if (i >= 4 && buf[i - 4] === 1 && buf[i - 1] === 0) {
      try {
        const d = decompress(buf, i - 4);
        if (d && d.length > 20) {
          const s = d.toString('latin1');
          if (/Attribute VB_/i.test(s)) sources.push(s);
        }
      } catch { /* ignore */ }
    }
    i = buf.indexOf(sig, i + 1);
  }
  return sources;
}

module.exports = { extractMacros };
