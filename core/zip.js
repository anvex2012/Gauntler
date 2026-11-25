// Creato da anvex2012
'use strict';
const zlib = require('zlib');
const limits = require('./limits');

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; }
  return t;
})();
const crcUpd = (crc, b) => (CRC_TABLE[(crc ^ b) & 0xff] ^ (crc >>> 8)) >>> 0;
function crc32(buf) { let c = 0xffffffff; for (let i = 0; i < buf.length; i++) c = crcUpd(c, buf[i]); return (c ^ 0xffffffff) >>> 0; }

/** Reads the ZIP central directory (also ZIP64 for sizes/offsets) */
function readZip(buf, { maxEntries = Infinity } = {}) {
  const entries = [];
  let truncated = false;
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) { const l = scanLocalHeaders(buf, maxEntries); return { entries: l.entries, broken: true, truncated: l.truncated }; }
  let count = buf.readUInt16LE(eocd + 10);
  let off = buf.readUInt32LE(eocd + 16);
  // ZIP64
  if ((count === 0xffff || off === 0xffffffff) && eocd >= 20 && buf.readUInt32LE(eocd - 20) === 0x07064b50) {
    const z64 = Number(buf.readBigUInt64LE(eocd - 20 + 8));
    if (z64 + 56 <= buf.length && buf.readUInt32LE(z64) === 0x06064b50) {
      count = Number(buf.readBigUInt64LE(z64 + 32));
      off = Number(buf.readBigUInt64LE(z64 + 48));
    }
  }
  for (let n = 0; n < count && off + 46 <= buf.length; n++) {
    if (buf.readUInt32LE(off) !== 0x02014b50) break;
    if (entries.length >= maxEntries) { truncated = true; break; }
    const flags = buf.readUInt16LE(off + 8);
    const method = buf.readUInt16LE(off + 10);
    const modTime = buf.readUInt16LE(off + 12);
    const crc = buf.readUInt32LE(off + 16);
    let csize = buf.readUInt32LE(off + 20);
    let usize = buf.readUInt32LE(off + 24);
    const nlen = buf.readUInt16LE(off + 28), xlen = buf.readUInt16LE(off + 30), clen = buf.readUInt16LE(off + 32);
    let local = buf.readUInt32LE(off + 42);
    const name = buf.toString(flags & 0x800 ? 'utf8' : 'latin1', off + 46, off + 46 + nlen);
    // ZIP64 extra field
    let x = off + 46 + nlen;
    const xend = x + xlen;
    while (x + 4 <= xend) {
      const id = buf.readUInt16LE(x), sz = buf.readUInt16LE(x + 2);
      if (id === 0x0001) {
        let p = x + 4;
        if (usize === 0xffffffff) { usize = Number(buf.readBigUInt64LE(p)); p += 8; }
        if (csize === 0xffffffff) { csize = Number(buf.readBigUInt64LE(p)); p += 8; }
        if (local === 0xffffffff) { local = Number(buf.readBigUInt64LE(p)); }
      }
      x += 4 + sz;
    }
    const comment = clen ? buf.toString('utf8', xend, xend + clen) : '';
    entries.push({ name, method, csize, usize, encrypted: !!(flags & 1), aes: method === 99, flags, crc, modTime, local, comment });
    off += 46 + nlen + xlen + clen;
  }
  return { entries, broken: false, truncated, declaredCount: count };
}

/**
 * Entries whose compressed data overlap or share the same local header: the "non-recursive" ZIP bomb
 * (many central-directory entries pointing at the same highly compressed kernel). Returns the names.
 */
function overlappingEntries(buf, entries) {
  const spans = [];
  for (const e of entries) {
    if (e.local + 30 > buf.length) continue;
    const nlen = buf.readUInt16LE(e.local + 26), xlen = buf.readUInt16LE(e.local + 28);
    spans.push({ a: e.local, b: e.local + 30 + nlen + xlen + e.csize, name: e.name });
  }
  spans.sort((x, y) => x.a - y.a || x.b - y.b);
  const out = new Set();
  for (let i = 1; i < spans.length; i++) {
    const p = spans[i - 1], c = spans[i];
    if (c.a < p.b) { out.add(p.name); out.add(c.name); }
  }
  return [...out];
}

/** Damaged ZIP: reconstructs the entries from the local headers */
function scanLocalHeaders(buf, maxEntries = Infinity) {
  const out = [];
  let truncated = false;
  let i = 0;
  const sig = Buffer.from([0x50, 0x4b, 0x03, 0x04]);
  while ((i = buf.indexOf(sig, i)) !== -1 && i + 30 <= buf.length) {
    if (out.length >= maxEntries) { truncated = true; break; }
    const flags = buf.readUInt16LE(i + 6), method = buf.readUInt16LE(i + 8), modTime = buf.readUInt16LE(i + 10);
    const crc = buf.readUInt32LE(i + 14), csize = buf.readUInt32LE(i + 18), usize = buf.readUInt32LE(i + 22);
    const nlen = buf.readUInt16LE(i + 26);
    out.push({ name: buf.toString('utf8', i + 30, i + 30 + nlen), method, csize, usize, encrypted: !!(flags & 1), aes: method === 99, flags, crc, modTime, local: i });
    i += 30 + nlen + Math.max(csize, 0);
  }
  return { entries: out, truncated };
}

/** ZipCrypto (legacy PKWARE encryption) */
function zipCryptoDecrypt(data, password, check) {
  let k0 = 0x12345678, k1 = 0x23456789, k2 = 0x34567890;
  const upd = (c) => {
    k0 = crcUpd(k0, c);
    k1 = (Math.imul((k1 + (k0 & 0xff)) | 0, 134775813) + 1) >>> 0;
    k2 = crcUpd(k2, k1 >>> 24);
  };
  for (const c of Buffer.from(password, 'utf8')) upd(c);
  const out = Buffer.allocUnsafe(data.length);
  for (let i = 0; i < data.length; i++) {
    const t = (k2 | 2) & 0xffff;
    const p = data[i] ^ (((t * (t ^ 1)) >>> 8) & 0xff);
    out[i] = p;
    upd(p);
    if (i === 11 && p !== check) return null;
  }
  return out.subarray(12);
}

function rawData(buf, e) {
  if (e.local + 30 > buf.length) return null;
  const nlen = buf.readUInt16LE(e.local + 26), xlen = buf.readUInt16LE(e.local + 28);
  const start = e.local + 30 + nlen + xlen;
  return buf.subarray(start, start + e.csize);
}

/** Decompresses an entry within the budget. Returns { data } | { limit: true } | { error } */
function inflate(e, data, budget, where) {
  if (e.method === 0) {
    if (budget.tripped) return { limit: true };
    if (!budget.consume(data.length, where)) return { limit: true };
    return { data: Buffer.from(data) };
  }
  if (e.method === 8) {
    const r = limits.inflateRaw(budget, data, where);
    return r.error ? { error: r.error } : r;
  }
  return { error: new Error('metodo non supportato') };
}

/**
 * Extracts an entry. For encrypted entries it tries the given passwords.
 * Every decompression is bounded by a Budget (limits.js): output cap per entry, compression ratio,
 * total bytes. Pass opts.budget to share it across a whole analysis; otherwise a fresh one is used.
 * Returns { data, password } | { error } | { error, limit: true } (budget exceeded: stop extracting)
 */
function extract(buf, e, passwords = [], opts = {}) {
  const budget = opts.budget || limits.standalone(opts.limits);
  const where = e.name;
  const data = rawData(buf, e);
  if (!data) return { error: 'intestazione non valida' };
  if (e.aes) return { error: 'cifratura AES non supportata' };
  if (budget.tripped) return { error: 'limite di decompressione superato', limit: true };
  if (!e.encrypted) {
    const r = inflate(e, data, budget, where);
    if (r.limit) return { error: 'limite di decompressione superato', limit: true };
    return r.data ? { data: r.data } : { error: e.method === 8 || e.method === 0 ? 'dati corrotti' : `metodo di compressione ${e.method} non supportato` };
  }
  const check = e.flags & 0x8 ? (e.modTime >> 8) & 0xff : (e.crc >>> 24) & 0xff;
  for (const pw of passwords) {
    const dec = zipCryptoDecrypt(data, pw, check);
    if (!dec) continue;
    // A wrong password that passes the 1-byte check produces garbage: decompress with a scratch budget
    // (same caps, nothing charged) and charge the real budget only for the verified plaintext
    const trial = new limits.Budget(budget.limits);
    trial.totalBytes = budget.totalBytes;
    const r = inflate(e, dec, trial, where);
    if (r.limit) {
      // With a wrong password the stream is almost always invalid long before the cap: a stream that
      // really expands past it is a bomb hidden behind a password.
      budget.trip(trial.exceeded.reason, trial.exceeded.detail, where);
      return { error: 'limite di decompressione superato', limit: true };
    }
    if (r.data && crc32(r.data) === e.crc) {
      if (!budget.consume(r.data.length, where, data.length)) return { error: 'limite di decompressione superato', limit: true };
      return { data: r.data, password: pw };
    }
  }
  return { error: 'protetto da password sconosciuta' };
}

/** TAR reader (ustar, GNU long names, PAX) */
function readTar(buf, { maxEntries = Infinity } = {}) {
  const out = [];
  let off = 0, longName = null;
  const str = (a, b) => buf.toString('utf8', a, b).replace(/\0[\s\S]*$/, '');
  while (off + 512 <= buf.length) {
    let empty = true;
    for (let i = off; i < off + 512; i++) if (buf[i]) { empty = false; break; }
    if (empty) break;
    if (out.length >= maxEntries) { out.truncated = true; break; }
    let name = str(off, off + 100);
    const prefix = buf.toString('latin1', off + 257, off + 262) === 'ustar' ? str(off + 345, off + 500) : '';
    if (prefix) name = prefix + '/' + name;
    const sizeField = buf.subarray(off + 124, off + 136);
    const size = sizeField[0] & 0x80 ? Number(sizeField.readBigUInt64BE(4)) : parseInt(str(off + 124, off + 136).trim() || '0', 8) || 0;
    const type = String.fromCharCode(buf[off + 156] || 48);
    const ds = off + 512;
    const data = buf.subarray(ds, ds + size);
    if (type === 'L') longName = data.toString('utf8').replace(/\0[\s\S]*$/, '');
    else if (type === 'x') { const m = data.toString('utf8').match(/\d+ path=([^\n]+)\n/); if (m) longName = m[1]; }
    else if (type !== 'g') {
      if (longName) { name = longName; longName = null; }
      if (type === '0' || type === '\0' || type === '7') out.push({ name, size, data });
      else out.push({ name, size: 0, data: null, special: { 1: 'hardlink', 2: 'symlink', 3: 'char device', 4: 'block device', 5: 'directory', 6: 'fifo' }[type] || type, link: str(off + 157, off + 257) });
    }
    off = ds + Math.ceil(size / 512) * 512;
  }
  return out;
}

/**
 * Writes a ZIP archive (deflate, UTF-8 names, fixed timestamp so the output is reproducible).
 * entries: [{ name, data, store? }]
 */
function writeZip(entries) {
  const locals = [], centrals = [];
  let off = 0;
  const DOS_TIME = 0, DOS_DATE = (0 << 9) | (1 << 5) | 1; // 1980-01-01 00:00
  for (const e of entries) {
    const data = Buffer.isBuffer(e.data) ? e.data : Buffer.from(e.data);
    const store = e.store || data.length < 64;
    const comp = store ? data : zlib.deflateRawSync(data, { level: 9 });
    const method = store ? 0 : 8;
    const nb = Buffer.from(e.name, 'utf8');
    const crc = crc32(data);
    if (data.length >= 0xffffffff || off >= 0xffffffff) throw new Error('ZIP64 in scrittura non supportato');
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(0x800, 6); lh.writeUInt16LE(method, 8);
    lh.writeUInt16LE(DOS_TIME, 10); lh.writeUInt16LE(DOS_DATE, 12);
    lh.writeUInt32LE(crc, 14); lh.writeUInt32LE(comp.length, 18); lh.writeUInt32LE(data.length, 22); lh.writeUInt16LE(nb.length, 26);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(0x800, 8); ch.writeUInt16LE(method, 10);
    ch.writeUInt16LE(DOS_TIME, 12); ch.writeUInt16LE(DOS_DATE, 14);
    ch.writeUInt32LE(crc, 16); ch.writeUInt32LE(comp.length, 20); ch.writeUInt32LE(data.length, 24); ch.writeUInt16LE(nb.length, 28);
    ch.writeUInt32LE(e.name.endsWith('/') ? 0x10 : 0, 38); ch.writeUInt32LE(off, 42);
    locals.push(lh, nb, comp); centrals.push(ch, nb);
    off += 30 + nb.length + comp.length;
  }
  const cd = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(entries.length, 8); end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(off, 16);
  return Buffer.concat([...locals, cd, end]);
}

module.exports = { readZip, extract, readTar, crc32, writeZip, overlappingEntries };
