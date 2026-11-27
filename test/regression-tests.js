// Created by anvex2012
'use strict';
/*
 * Regression tests for:
 *  1. decompression bombs (ZIP, nested ZIP, overlapping entries, GZIP, PDF FlateDecode, encoded payloads,
 *     7-Zip/xz) → strict limits on single entry, total, ratio, file count and memory; analysis stops;
 *  2. quarantine → unique UUID ids, full SHA-256, atomic metadata, exact restore of every file;
 *  3. disassembler false positives → coverage without padding, entropy gate, function-start tables,
 *     prologue seeds, no-return calls, strict API-hashing loop, universal (fat) binaries.
 * Every sample is generated on the fly and harmless.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

process.env.GAUNTLER_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'gauntler-reg-home-'));
process.env.GAUNTLER_LANG = 'it'; // the checks match Italian texts
const { scanBuffer, scanFile } = require('../core');
const { writeZip, readZip, extract, crc32 } = require('../core/zip');
const limits = require('../core/limits');
const X = require('../core/extract');
const quarantine = require('../core/quarantine');
const paths = require('../core/paths');
const D = require('../core/disasm');
const { Detector, scanRange } = require('../core/disasm/heuristics');
const shellcode = require('../core/disasm/shellcode');
const { sanitizeBuffer } = require('../core/sanitize');

let fail = 0, total = 0;
const check = (name, cond, extra = '') => { total++; console.log(`${cond ? '✔' : '✘'} ${name}${cond ? '' : '  ' + extra}`); if (!cond) fail++; };
const work = fs.mkdtempSync(path.join(os.tmpdir(), 'gauntler-reg-'));
const MiB = 1024 * 1024;
const OPT = { useConfig: false, cache: false };
const archiveCritical = (r) => r.findings.filter((f) => f.categoryId === 'archive' && f.severity === 'critical').map((f) => f.title);

/* ------------------------------------------------------------------ ZIP builders */
/** ZIP with full control over the declared sizes, local offsets and encryption */
function rawZip(entries) {
  const locals = [], centrals = [];
  let off = 0;
  for (const e of entries) {
    const nb = Buffer.from(e.name);
    const comp = e.comp;
    const local = e.sameAs != null ? entries[e.sameAs]._off : off;
    e._off = local;
    if (e.sameAs == null) {
      const lh = Buffer.alloc(30); lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(e.flags || 0, 6); lh.writeUInt16LE(e.method ?? 8, 8);
      lh.writeUInt32LE(e.crc >>> 0, 14); lh.writeUInt32LE(comp.length, 18); lh.writeUInt32LE(e.usize >>> 0, 22); lh.writeUInt16LE(nb.length, 26);
      locals.push(lh, nb, comp);
      off += 30 + nb.length + comp.length;
    }
    const ch = Buffer.alloc(46); ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(e.flags || 0, 8); ch.writeUInt16LE(e.method ?? 8, 10);
    ch.writeUInt32LE(e.crc >>> 0, 16); ch.writeUInt32LE(comp.length, 20); ch.writeUInt32LE(e.usize >>> 0, 24); ch.writeUInt16LE(nb.length, 28); ch.writeUInt32LE(local, 42);
    centrals.push(ch, nb);
  }
  const cd = Buffer.concat(centrals);
  const end = Buffer.alloc(22); end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(entries.length, 8); end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(off, 16);
  return Buffer.concat([...locals, cd, end]);
}
function zipCryptoEncrypt(data, password, crc) {
  const T = []; for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; T[n] = c >>> 0; }
  const cu = (c, b) => (T[(c ^ b) & 0xff] ^ (c >>> 8)) >>> 0;
  let k0 = 0x12345678, k1 = 0x23456789, k2 = 0x34567890;
  const upd = (c) => { k0 = cu(k0, c); k1 = (Math.imul((k1 + (k0 & 0xff)) | 0, 134775813) + 1) >>> 0; k2 = cu(k2, k1 >>> 24); };
  for (const c of Buffer.from(password)) upd(c);
  const plain = Buffer.concat([crypto.randomBytes(11), Buffer.from([crc >>> 24]), data]);
  const out = Buffer.alloc(plain.length);
  for (let i = 0; i < plain.length; i++) { const t = (k2 | 2) & 0xffff; out[i] = plain[i] ^ (((t * (t ^ 1)) >>> 8) & 0xff); upd(plain[i]); }
  return out;
}
const ZEROS_64M = Buffer.alloc(64 * MiB);
const DEFLATED_ZEROS = zlib.deflateRawSync(ZEROS_64M, { level: 9 });
const CRC_ZEROS = crc32(ZEROS_64M);

/* ------------------------------------------------------------------ ELF / Mach-O builders */
/**
 * Minimal ELF64 x86-64: sections .text (+ optional .eh_frame_hdr and .symtab/.strtab).
 * text: Buffer, entry: offset in text, fdes: offsets of function starts for .eh_frame_hdr,
 * syms: [{ name, off }] FUNC symbols.
 */
function makeELF(text, { entry = 0, fdes = null, syms = [] } = {}) {
  const TEXT_VA = 0x401000;
  const shstr = ['', '.text', '.eh_frame_hdr', '.symtab', '.strtab', '.shstrtab'];
  const shstrBuf = Buffer.from(shstr.join('\0') + '\0');
  const nameOff = (n) => shstr.slice(0, shstr.indexOf(n)).reduce((a, s) => a + s.length + 1, 0);
  const parts = [];
  let cur = 64;
  const place = (buf, align = 16) => { cur = Math.ceil(cur / align) * align; const o = cur; parts.push([o, buf]); cur += buf.length; return o; };
  const textOff = place(text, 4096);
  let ehOff = 0, ehBuf = null;
  const EH_VA = 0x600000;
  if (fdes) {
    ehBuf = Buffer.alloc(12 + fdes.length * 8);
    ehBuf[0] = 1; ehBuf[1] = 0x1b; ehBuf[2] = 0x03; ehBuf[3] = 0x3b;
    ehBuf.writeInt32LE(0, 4); ehBuf.writeUInt32LE(fdes.length, 8);
    fdes.forEach((f, i) => { ehBuf.writeInt32LE(TEXT_VA + f - EH_VA, 12 + i * 8); ehBuf.writeInt32LE(0, 16 + i * 8); });
    ehOff = place(ehBuf, 4);
  }
  const strtab = Buffer.from('\0' + syms.map((s) => s.name + '\0').join(''));
  const symtab = Buffer.alloc(24 * (syms.length + 1));
  let so = 1;
  syms.forEach((s, i) => { const o = 24 * (i + 1); symtab.writeUInt32LE(so, o); symtab[o + 4] = 0x12; symtab.writeUInt16LE(1, o + 6); symtab.writeBigUInt64LE(BigInt(TEXT_VA + s.off), o + 8); so += s.name.length + 1; });
  const symOff = place(symtab, 8), strOff = place(strtab, 1), shstrOff = place(shstrBuf, 1);
  const shOff = Math.ceil(cur / 8) * 8;
  const sh = Buffer.alloc(64 * 6);
  const sec = (i, name, type, flags, addr, off, size, link = 0, entsize = 0) => {
    const o = i * 64; sh.writeUInt32LE(name, o); sh.writeUInt32LE(type, o + 4); sh.writeBigUInt64LE(BigInt(flags), o + 8); sh.writeBigUInt64LE(BigInt(addr), o + 16);
    sh.writeBigUInt64LE(BigInt(off), o + 24); sh.writeBigUInt64LE(BigInt(size), o + 32); sh.writeUInt32LE(link, o + 40); sh.writeBigUInt64LE(BigInt(entsize), o + 56);
  };
  sec(1, nameOff('.text'), 1, 6, TEXT_VA, textOff, text.length);
  if (fdes) sec(2, nameOff('.eh_frame_hdr'), 1, 2, EH_VA, ehOff, ehBuf.length); else sec(2, nameOff('.eh_frame_hdr'), 0, 0, 0, 0, 0);
  sec(3, nameOff('.symtab'), 2, 0, 0, symOff, symtab.length, 4, 24);
  sec(4, nameOff('.strtab'), 3, 0, 0, strOff, strtab.length);
  sec(5, nameOff('.shstrtab'), 3, 0, 0, shstrOff, shstrBuf.length);
  const out = Buffer.alloc(shOff + sh.length);
  out.write('\x7fELF', 0, 'latin1'); out[4] = 2; out[5] = 1; out[6] = 1;
  out.writeUInt16LE(2, 16); out.writeUInt16LE(62, 18); out.writeUInt32LE(1, 20); out.writeBigUInt64LE(BigInt(TEXT_VA + entry), 24);
  out.writeBigUInt64LE(0n, 32); out.writeBigUInt64LE(BigInt(shOff), 40); out.writeUInt16LE(64, 52); out.writeUInt16LE(56, 54); out.writeUInt16LE(0, 56);
  out.writeUInt16LE(64, 58); out.writeUInt16LE(6, 60); out.writeUInt16LE(5, 62);
  for (const [o, b] of parts) b.copy(out, o);
  sh.copy(out, shOff);
  return out;
}
/** Thin Mach-O 64 with a single __TEXT,__text section */
function makeMachO(cputype, code) {
  const ncmds = 2, segSize = 72 + 80, mainSize = 24;
  const hdr = 32, textOff = 0x1000;
  const b = Buffer.alloc(textOff + code.length);
  b.writeUInt32LE(0xfeedfacf, 0); b.writeUInt32LE(cputype, 4); b.writeUInt32LE(cputype === 0x0100000c ? 0 : 3, 8); b.writeUInt32LE(2, 12);
  b.writeUInt32LE(ncmds, 16); b.writeUInt32LE(segSize + mainSize, 20);
  let o = hdr;
  b.writeUInt32LE(0x19, o); b.writeUInt32LE(segSize, o + 4); b.write('__TEXT', o + 8, 'latin1');
  b.writeBigUInt64LE(0x100000000n, o + 24); b.writeBigUInt64LE(BigInt(b.length), o + 32); b.writeBigUInt64LE(0n, o + 40); b.writeBigUInt64LE(BigInt(b.length), o + 48);
  b.writeUInt32LE(5, o + 56); b.writeUInt32LE(5, o + 60); b.writeUInt32LE(1, o + 64);
  const s = o + 72;
  b.write('__text', s, 'latin1'); b.write('__TEXT', s + 16, 'latin1');
  b.writeBigUInt64LE(BigInt(0x100000000 + textOff), s + 32); b.writeBigUInt64LE(BigInt(code.length), s + 40); b.writeUInt32LE(textOff, s + 48); b.writeUInt32LE(0x80000400, s + 64);
  o += segSize;
  b.writeUInt32LE(0x80000028, o); b.writeUInt32LE(mainSize, o + 4); b.writeBigUInt64LE(BigInt(textOff), o + 8);
  code.copy(b, textOff);
  return b;
}
function makeFat(slices) {
  let off = 0x4000;
  const hdr = Buffer.alloc(8 + slices.length * 20);
  hdr.writeUInt32BE(0xcafebabe, 0); hdr.writeUInt32BE(slices.length, 4);
  const bodies = [];
  slices.forEach((s, i) => {
    const o = 8 + i * 20;
    hdr.writeUInt32BE(s.cpu >>> 0, o); hdr.writeUInt32BE(0, o + 4); hdr.writeUInt32BE(off, o + 8); hdr.writeUInt32BE(s.buf.length, o + 12); hdr.writeUInt32BE(14, o + 16);
    bodies.push([off, s.buf]); off = Math.ceil((off + s.buf.length) / 0x4000) * 0x4000;
  });
  const out = Buffer.alloc(off);
  hdr.copy(out, 0);
  for (const [o, b] of bodies) b.copy(out, o);
  return out;
}
/** Low-entropy compiled-looking x86-64 functions (no frame-pointer prologue), each padded with int3 to 16 bytes */
function leafFunctions(n, { prologue = false } = {}) {
  const fns = [];
  for (let i = 0; i < n; i++) {
    const k = (i * 7 + 3) & 0xff;
    const body = Buffer.from([
      ...(prologue ? [0x55, 0x48, 0x89, 0xe5] : []),
      0x89, 0xf8, 0x69, 0xc0, k, 0, 0, 0, 0x01, 0xf0, 0x8d, 0x0c, 0x78, 0x31, 0xc8, 0x83, 0xc0, i & 0x7f,
      ...(prologue ? [0x5d] : []), 0xc3,
    ]);
    const pad = (16 - (body.length % 16)) % 16;
    fns.push(Buffer.concat([body, Buffer.alloc(pad, 0xcc)]));
  }
  return fns;
}
/** entry: call <first function>; ret — followed by the functions */
function withEntry(fns) {
  const entry = Buffer.from([0xe8, 0, 0, 0, 0, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc]);
  entry.writeInt32LE(16 - 5, 1);
  const offs = []; let o = 16;
  for (const f of fns) { offs.push(o); o += f.length; }
  return { text: Buffer.concat([entry, ...fns]), offs };
}
const mcOf = (r) => r.categories.find((c) => c.id === 'machinecode');
const mcBad = (r) => (mcOf(r)?.findings || []).filter((f) => f.severity !== 'info');

(async () => {
  /* ==================================================================== 1. DECOMPRESSION BOMBS */
  console.log('\n— Zip bomb e limiti di decompressione —');
  {
    // 64 MiB of zeros in 64 KB (≈1000:1): the declared ratio alone stops it before inflating anything
    const bomb = writeZip([{ name: 'zeros.bin', data: ZEROS_64M }]);
    const t0 = Date.now();
    const r = await scanBuffer(bomb, 'bomba.zip', OPT);
    check('ZIP 1000:1 → critico, limite "ratio", nessun file interno analizzato', r.limitExceeded?.reason === 'ratio' && archiveCritical(r).some((t) => /Zip bomb/.test(t)) && r.children.length === 0 && r.overall.score <= 25, JSON.stringify(r.limitExceeded) + ' ' + r.overall.score);
    check('ZIP 1000:1 → interrotta in fretta (< 5 s)', Date.now() - t0 < 5000, `${Date.now() - t0} ms`);
  }
  {
    // Lying header: declares 1 KB but expands to 64 MiB → the REAL output is capped while inflating
    const z = rawZip([{ name: 'innocuo.txt', comp: DEFLATED_ZEROS, crc: CRC_ZEROS, usize: 1024 }]);
    const before = process.memoryUsage().arrayBuffers;
    const r = await scanBuffer(z, 'bugiardo.zip', OPT);
    const grew = process.memoryUsage().arrayBuffers - before;
    check('ZIP con dimensione dichiarata falsa → fermata durante la decompressione', r.limitExceeded?.reason === 'ratio' && r.children.length === 0, JSON.stringify(r.limitExceeded));
    check('ZIP con dimensione falsa → memoria non esplosa (< 48 MB trattenuti)', grew < 48 * MiB, `${Math.round(grew / MiB)} MB`);
  }
  {
    // Direct API: extract() with a fresh budget never allocates past the cap
    const z = rawZip([{ name: 'x', comp: DEFLATED_ZEROS, crc: CRC_ZEROS, usize: 10 }]);
    const e = readZip(z).entries[0];
    const res = extract(z, e, [], { limits: { maxEntryBytes: 4 * MiB, ratioMinBytes: 1 * MiB } });
    check('extract(): limite per voce rispettato anche fuori dall\'analisi', res.limit === true && !res.data, JSON.stringify(res));
  }
  {
    // Boundary on the single-entry limit (random data: ratio ≈ 1, only the size counts)
    const L = { maxEntryBytes: 1 * MiB, ratioMinBytes: 1 * MiB };
    const ok = await scanBuffer(writeZip([{ name: 'a.bin', data: crypto.randomBytes(1 * MiB) }]), 'giusto.zip', { ...OPT, limits: L });
    const over = await scanBuffer(writeZip([{ name: 'a.bin', data: crypto.randomBytes(1 * MiB + 1) }]), 'oltre.zip', { ...OPT, limits: L });
    check('limite per voce: esattamente al limite → accettato', !ok.limitExceeded && ok.children.length === 1, JSON.stringify(ok.limitExceeded));
    check('limite per voce: 1 byte oltre → interrotto ("entry")', over.limitExceeded?.reason === 'entry' || over.limitExceeded?.reason === 'total', JSON.stringify(over.limitExceeded));
  }
  {
    // Boundary on the number of files
    const mk = (n) => writeZip(Array.from({ length: n }, (_, i) => ({ name: `f${i}.txt`, data: `file ${i}\n` })));
    const L = { maxFiles: 50 };
    const ok = await scanBuffer(mk(50), 'cinquanta.zip', { ...OPT, limits: L });
    const over = await scanBuffer(mk(51), 'cinquantuno.zip', { ...OPT, limits: L });
    check('numero di file: 50 con limite 50 → accettato', !ok.limitExceeded && ok.children.length === 50, `${JSON.stringify(ok.limitExceeded)} ${ok.children.length}`);
    check('numero di file: 51 con limite 50 → interrotto ("files") prima di estrarre', over.limitExceeded?.reason === 'files' && over.children.length === 0, `${JSON.stringify(over.limitExceeded)} ${over.children.length}`);
  }
  {
    // Recursive bomb: the TOTAL is shared across nesting levels (each level alone is small)
    const inner = () => writeZip([{ name: 'dati.bin', data: crypto.randomBytes(1 * MiB) }]);
    const outer = writeZip([{ name: 'a.zip', data: inner(), store: true }, { name: 'b.zip', data: inner(), store: true }, { name: 'c.zip', data: inner(), store: true }]);
    const r = await scanBuffer(outer, 'annidato.zip', { ...OPT, limits: { maxTotalBytes: 4 * MiB } });
    check('archivi annidati: totale condiviso tra i livelli → interrotto ("total")', r.limitExceeded?.reason === 'total' && archiveCritical(r).length > 0, JSON.stringify(r.limitExceeded));
    const r2 = await scanBuffer(outer, 'annidato.zip', { ...OPT, limits: { maxTotalBytes: 8 * MiB } });
    check('archivi annidati sotto il limite totale → analizzati tutti', !r2.limitExceeded && r2.children.length === 3 && r2.children.every((c) => c.children.length === 1), JSON.stringify(r2.limitExceeded));
  }
  {
    // Non-recursive bomb (overlapping entries pointing at the same compressed kernel)
    const comp = zlib.deflateRawSync(Buffer.alloc(1 * MiB));
    const crc = crc32(Buffer.alloc(1 * MiB));
    const entries = [{ name: 'k0', comp, crc, usize: MiB }];
    for (let i = 1; i < 20; i++) entries.push({ name: `k${i}`, comp, crc, usize: MiB, sameAs: 0 });
    const r = await scanBuffer(rawZip(entries), 'sovrapposto.zip', OPT);
    check('voci ZIP sovrapposte (zip bomb non ricorsiva) → critico, nulla estratto', archiveCritical(r).some((t) => /sovrapposte/.test(t)) && r.children.length === 0, archiveCritical(r).join(' | '));
  }
  {
    // Encrypted bomb: password "infected" is tried automatically; its output must be capped too
    const enc = zipCryptoEncrypt(DEFLATED_ZEROS, 'infected', CRC_ZEROS);
    const z = rawZip([{ name: 'cifrato.bin', comp: enc, crc: CRC_ZEROS, usize: 100, flags: 1 }]);
    const r = await scanBuffer(z, 'cifrato.zip', OPT);
    check('ZIP cifrato con password nota: bomba fermata dopo la decifratura', !!r.limitExceeded && r.children.length === 0, JSON.stringify(r.limitExceeded));
  }
  {
    // Small but very compressible file: high ratio but below ratioMinBytes → legitimate
    const text = Buffer.from('riga di log ripetuta\n'.repeat(100000)); // ~2 MB, ratio > 100:1
    const r = await scanBuffer(writeZip([{ name: 'log.txt', data: text }]), 'log.zip', OPT);
    check('file piccolo molto comprimibile (> 100:1 ma < 16 MB) → nessun falso allarme', !r.limitExceeded && r.children.length === 1 && !archiveCritical(r).length, JSON.stringify(r.limitExceeded));
  }
  {
    const r = await scanBuffer(zlib.gzipSync(ZEROS_64M), 'zeri.gz', OPT);
    check('GZIP bomb → interrotta', !!r.limitExceeded && archiveCritical(r).length > 0 && r.children.length === 0, JSON.stringify(r.limitExceeded));
    const ok = await scanBuffer(zlib.gzipSync(Buffer.from('ciao mondo\n'.repeat(1000))), 'ok.txt.gz', OPT);
    check('GZIP normale → analizzato', !ok.limitExceeded && ok.children.length === 1);
  }
  {
    const stream = zlib.deflateSync(ZEROS_64M);
    const pdf = Buffer.concat([Buffer.from(`%PDF-1.7\n1 0 obj << /Type /Catalog >> endobj\n2 0 obj << /Length ${stream.length} /Filter /FlateDecode >>\nstream\n`, 'latin1'), stream, Buffer.from('\nendstream\nendobj\ntrailer << /Root 1 0 R >>\n%%EOF\n', 'latin1')]);
    const r = await scanBuffer(pdf, 'bomba.pdf', OPT);
    check('PDF con flusso FlateDecode bomba → interrotto e segnalato', !!r.limitExceeded && archiveCritical(r).length > 0, JSON.stringify(r.limitExceeded));
  }
  {
    // gzip bomb hidden as base64 in a text file (recursive decoder)
    const b64 = zlib.gzipSync(ZEROS_64M).toString('base64');
    const r = await scanBuffer(Buffer.from(`payload = "${b64}"\n`), 'script.py', OPT);
    check('payload base64+gzip bomba in un testo → interrotto', !!r.limitExceeded && archiveCritical(r).length > 0, JSON.stringify(r.limitExceeded));
  }
  {
    const r = await scanBuffer(writeZip([{ name: 'a.bin', data: crypto.randomBytes(2 * MiB) }]), 'mem.zip', { ...OPT, limits: { maxMemoryBytes: 1 } });
    check('limite di memoria → interrotto ("memory")', r.limitExceeded?.reason === 'memory', JSON.stringify(r.limitExceeded));
  }
  {
    // One budget per analysis: a bomb does not poison the next file scanned with the same options
    const opts = { ...OPT, limits: { maxFiles: 5 } };
    await scanBuffer(writeZip(Array.from({ length: 6 }, (_, i) => ({ name: `f${i}`, data: 'x' }))), 'uno.zip', opts);
    const r = await scanBuffer(writeZip([{ name: 'a.txt', data: 'ciao' }]), 'due.zip', opts);
    check('budget separato per ogni file analizzato', !r.limitExceeded && r.children.length === 1);
  }
  {
    const r = await sanitizeBuffer(writeZip([{ name: 'zeros.bin', data: ZEROS_64M }]), 'bomba.zip', {});
    check('CDR (sanitize) di una zip bomb → bloccato', r.status === 'blocked' && /bomb/i.test(r.reason || ''), `${r.status} ${r.reason}`);
  }
  {
    const b = new limits.Budget({ maxTotalBytes: 100 });
    check('Budget: consume oltre il totale → false e motivo "total"', b.consume(60, 'a') && !b.consume(41, 'b') && b.exceeded.reason === 'total' && b.totalBytes === 60);
    check('Budget: dopo lo scatto ogni operazione è rifiutata', !b.consume(1, 'c') && !b.admitFile('d') && X.decodeBlobs('A'.repeat(10), b).length === 0);
  }
  const t = X.tools();
  if (t.xz) {
    const xzBomb = spawnSync(t.xz, ['-z', '-c', '-9'], { input: ZEROS_64M, maxBuffer: 64 * MiB }).stdout;
    const r = await scanBuffer(xzBomb, 'zeri.xz', OPT);
    check('XZ bomb (strumento di sistema) → uscita limitata e interrotta', !!r.limitExceeded && r.children.length === 0, JSON.stringify(r.limitExceeded));
  } else console.log('… xz non installato: test XZ saltato');
  if (t.sevenZip) {
    const src = path.join(work, 'zeri.bin'); fs.writeFileSync(src, ZEROS_64M);
    const out = path.join(work, 'bomba.7z');
    spawnSync(t.sevenZip, ['a', '-mx=9', out, src], { stdio: 'ignore' });
    fs.rmSync(src);
    if (fs.existsSync(out)) {
      const r = await scanFile(out, OPT);
      check('7z bomb → rifiutata dall\'elenco prima dell\'estrazione', !!r.limitExceeded && r.children.length === 0, JSON.stringify(r.limitExceeded));
    }
  } else console.log('… 7-Zip non installato: test 7z saltato');
  if (t.bsdtar) {
    // Without 7-Zip the bsdtar fallback used to extract everything to disk and check the size only
    // afterwards: a 224 KB .7z wrote 1.5 GB to the temporary folder before being stopped.
    const dir = path.join(work, 'bsd'); fs.mkdirSync(dir);
    fs.writeFileSync(path.join(dir, 'zeri.bin'), ZEROS_64M);
    const out = path.join(work, 'bomba-bsdtar.7z');
    spawnSync(t.bsdtar, ['--format', '7zip', '-cf', out, '-C', dir, 'zeri.bin'], { stdio: 'ignore' });
    fs.rmSync(dir, { recursive: true, force: true });
    if (fs.existsSync(out)) {
      const saved = t.sevenZip; t.sevenZip = null; // force the bsdtar path even where 7-Zip is installed
      const tmpBefore = fs.readdirSync(os.tmpdir()).filter((f) => f.startsWith('gauntler-x-')).length;
      try {
        const budget = new limits.Budget();
        const r = await X.systemExtract(fs.readFileSync(out), '7z', out, [], budget);
        check(`7z bomb senza 7-Zip (bsdtar, ${Math.round(fs.statSync(out).size / 1024)} KB → 64 MB) → interrotta`, r.limit === true && budget.tripped && !r.files.length, JSON.stringify({ limit: r.limit, ex: budget.exceeded, n: r.files.length }));
        check('… nessun byte decompresso scritto su disco (flusso in memoria con tetto esatto)', r.diskBytes === 0, String(r.diskBytes));
        check('… tetto rispettato: letti al massimo 16 MB di dati + spazio intestazioni (non 64 MB)', r.producedBytes != null && r.producedBytes <= 32 * MiB, String(r.producedBytes));
        const rs = await scanFile(out, OPT);
        check('… anche dall\'analisi completa: limite segnalato, nessun file interno', !!rs.limitExceeded && rs.children.length === 0, JSON.stringify(rs.limitExceeded));
        const ok = path.join(work, 'normale.7z');
        fs.mkdirSync(path.join(work, 'n')); fs.writeFileSync(path.join(work, 'n', 'a.txt'), 'ciao'); fs.mkdirSync(path.join(work, 'n', 'sub')); fs.writeFileSync(path.join(work, 'n', 'sub', 'b.txt'), 'mondo');
        fs.symlinkSync('/etc/passwd', path.join(work, 'n', 'link'));
        spawnSync(t.bsdtar, ['--format', '7zip', '-cf', ok, '-C', path.join(work, 'n'), '.'], { stdio: 'ignore' });
        const rn = await X.systemExtract(fs.readFileSync(ok), '7z', ok, []);
        const names = rn.files.map((f) => f.name.replace(/^\.\//, '')).sort();
        check('bsdtar: archivio normale estratto (nomi e contenuti, collegamenti simbolici esclusi)', names.join(',') === 'a.txt,sub/b.txt' && rn.files.find((f) => /a\.txt$/.test(f.name)).data.toString() === 'ciao', names.join(','));
      } finally { t.sevenZip = saved; }
      const tmpAfter = fs.readdirSync(os.tmpdir()).filter((f) => f.startsWith('gauntler-x-')).length;
      check('… nessuna cartella temporanea lasciata', tmpAfter <= tmpBefore, `${tmpBefore} → ${tmpAfter}`);
    }
  } else console.log('… bsdtar non installato: test bsdtar saltato');
  {
    // Disk-writing extractors (7-Zip, unar) are watched while they run and killed past the cap
    const fake = path.join(work, 'estrattore-finto.js');
    fs.writeFileSync(fake, "const fs=require('fs'),p=require('path');const o=process.argv[2];const b=Buffer.alloc(1<<20);let i=0;const t=setInterval(()=>{fs.appendFileSync(p.join(o,'f.bin'),b);if(++i>=400)clearInterval(t)},1);");
    const outDir = fs.mkdtempSync(path.join(work, 'watch-'));
    const w = await X.runWatched(process.execPath, [fake, outDir], outDir, { maxBytes: 8 * MiB, maxFiles: 100, timeoutMs: 60000 });
    const left = fs.existsSync(path.join(outDir, 'f.bin')) ? fs.statSync(path.join(outDir, 'f.bin')).size : 0;
    check('estrazione su disco sorvegliata: processo fermato oltre il limite', w.over && w.over.kind === 'bytes' && left < 64 * MiB, JSON.stringify({ over: w.over, left }));
  }

  /* ==================================================================== 2. QUARANTINE */
  console.log('\n— Quarantena —');
  const qdir = paths.dir('quarantine');
  {
    // 20 identical files quarantined back to back (same second, same hash): the old id scheme
    // (timestamp + 8 hex of the hash) gave them the same id and each overwrote the previous one
    const content = Buffer.from('stesso contenuto malevolo\n');
    const files = Array.from({ length: 20 }, (_, i) => { const d = path.join(work, `copia${i}`); fs.mkdirSync(d); const p = path.join(d, 'virus.ps1'); fs.writeFileSync(p, content, { mode: 0o640 }); return p; });
    const metas = files.map((f) => quarantine.add(f, { reason: 'test' }));
    const ids = new Set(metas.map((m) => m.id));
    check('quarantena: 20 file identici nello stesso istante → 20 id distinti', ids.size === 20, `${ids.size}`);
    check('quarantena: id = UUID v4, SHA-256 completo (64 hex)', metas.every((m) => quarantine.UUID_RE.test(m.id) && /^[0-9a-f]{64}$/.test(m.sha256)), metas[0].id + ' ' + metas[0].sha256);
    check('quarantena: 20 elementi elencati, originali rimossi', quarantine.list().length === 20 && files.every((f) => !fs.existsSync(f)));
    check('quarantena: nessun file temporaneo rimasto', !fs.readdirSync(qdir).some((f) => f.endsWith('.tmp')), fs.readdirSync(qdir).join(','));
    check('quarantena: copia resa inoffensiva (byte trasformati, sola lettura)', !fs.readFileSync(path.join(qdir, metas[0].id + '.quar')).equals(content) && (fs.statSync(path.join(qdir, metas[0].id + '.quar')).mode & 0o222) === 0);
    let restored = 0;
    for (const m of metas) { quarantine.restore(m.id); if (fs.readFileSync(m.originalPath).equals(content) && (fs.statSync(m.originalPath).mode & 0o777) === 0o640) restored++; }
    check('quarantena: ogni file ripristinato nel SUO percorso, contenuto e permessi identici', restored === 20, `${restored}/20`);
    check('quarantena: vuota dopo i ripristini', quarantine.list().length === 0 && fs.readdirSync(qdir).length === 0, fs.readdirSync(qdir).join(','));
  }
  {
    // Every byte value, empty file, large file
    const cases = { 'tutti-i-byte.bin': Buffer.from(Array.from({ length: 256 * 4 }, (_, i) => i & 255)), 'vuoto.txt': Buffer.alloc(0), 'grande.bin': crypto.randomBytes(5 * MiB + 3) };
    let ok = 0;
    for (const [name, data] of Object.entries(cases)) {
      const p = path.join(work, name); fs.writeFileSync(p, data);
      const m = quarantine.add(p); quarantine.restore(m.id);
      if (fs.readFileSync(p).equals(data)) ok++;
    }
    check('quarantena: ripristino byte per byte (tutti i valori, file vuoto, 5 MB)', ok === 3, `${ok}/3`);
  }
  {
    const p = path.join(work, 'meta.txt'); fs.writeFileSync(p, 'x');
    const m = quarantine.add(p);
    const raw = fs.readFileSync(path.join(qdir, m.id + '.json'), 'utf8');
    check('quarantena: metadati JSON completi e coerenti', JSON.parse(raw).id === m.id && JSON.parse(raw).sha256 === crypto.createHash('sha256').update('x').digest('hex') && JSON.parse(raw).size === 1);
    // Crash simulation: leftovers of an interrupted write / restore are never listed
    fs.writeFileSync(path.join(qdir, `.${m.id}.json.${crypto.randomUUID()}.tmp`), '{"id":"mezzo');
    fs.writeFileSync(path.join(qdir, `.altro.json.restoring-1-${crypto.randomUUID()}`), '{}');
    fs.writeFileSync(path.join(qdir, 'rotto.json'), '{non json');
    check('quarantena: file temporanei/danneggiati ignorati dall\'elenco', quarantine.list().length === 1 && quarantine.list()[0].id === m.id, JSON.stringify(quarantine.list().map((x) => x.id)));
    for (const f of fs.readdirSync(qdir)) if (f.startsWith('.') || f === 'rotto.json') fs.rmSync(path.join(qdir, f));
    // Destination exists: refused without --force, replaced atomically with --force
    fs.writeFileSync(p, 'nuovo');
    let refused = false; try { quarantine.restore(m.id); } catch { refused = true; }
    check('quarantena: destinazione esistente → rifiutato senza --force (originale intatto)', refused && fs.readFileSync(p, 'utf8') === 'nuovo' && quarantine.list().length === 1);
    quarantine.restore(m.id, { force: true });
    check('quarantena: --force sovrascrive con il contenuto originale', fs.readFileSync(p, 'utf8') === 'x' && quarantine.list().length === 0);
  }
  {
    // Corrupted quarantine copy: restore refused, nothing written, item kept
    const p = path.join(work, 'corrotto.txt'); fs.writeFileSync(p, 'contenuto importante');
    const m = quarantine.add(p);
    const bin = path.join(qdir, m.id + '.quar');
    fs.chmodSync(bin, 0o600); const b = fs.readFileSync(bin); b[3] ^= 0xff; fs.writeFileSync(bin, b);
    let err = ''; try { quarantine.restore(m.id); } catch (e) { err = e.message; }
    check('quarantena: copia danneggiata → ripristino rifiutato, nulla scritto, elemento conservato', /danneggiata/.test(err) && !fs.existsSync(p) && quarantine.list().some((x) => x.id === m.id), err);
    quarantine.remove(m.id);
  }
  {
    // Ids: exact match wins, short / ambiguous prefixes are refused, a claimed item cannot be restored twice
    const a = path.join(work, 'a1.txt'), b2 = path.join(work, 'a2.txt');
    fs.writeFileSync(a, 'uguale'); fs.writeFileSync(b2, 'uguale');
    const m1 = quarantine.add(a), m2 = quarantine.add(b2);
    let amb = ''; try { quarantine.find(m1.sha256.slice(0, 12)); } catch (e) { amb = e.message; }
    check('quarantena: prefisso SHA-256 condiviso → errore "ambiguo" (nessun ripristino sbagliato)', /ambiguo/.test(amb), amb);
    let short = ''; try { quarantine.find('a'); } catch (e) { short = e.message; }
    check('quarantena: prefisso troppo corto rifiutato', /corto/.test(short), short);
    check('quarantena: id esatto e prefisso univoco trovano l\'elemento giusto', quarantine.find(m2.id).id === m2.id && quarantine.find(m1.id.slice(0, 13)).id === m1.id);
    fs.renameSync(path.join(qdir, m1.id + '.json'), path.join(qdir, `.${m1.id}.json.restoring-999-x`)); // another process claimed it
    let twice = ''; try { quarantine.restore(m1.id); } catch (e) { twice = e.message; }
    check('quarantena: elemento già in ripristino da un altro processo → non ripristinato due volte', /Nessun elemento|già/.test(twice) && !fs.existsSync(a), twice);
    fs.renameSync(path.join(qdir, `.${m1.id}.json.restoring-999-x`), path.join(qdir, m1.id + '.json'));
    quarantine.restore(m1.id); quarantine.restore(m2.id);
    check('quarantena: entrambi i file identici ripristinati', fs.readFileSync(a, 'utf8') === 'uguale' && fs.readFileSync(b2, 'utf8') === 'uguale');
  }
  {
    // Item written by the previous version (id = timestamp-hash8) is still restorable
    const p = path.join(work, 'vecchio.bin'); const data = crypto.randomBytes(1000); fs.writeFileSync(p, data);
    const m = quarantine.add(p);
    const legacy = '20250101120000-' + m.sha256.slice(0, 8);
    fs.renameSync(path.join(qdir, m.id + '.quar'), path.join(qdir, legacy + '.quar'));
    const meta = JSON.parse(fs.readFileSync(path.join(qdir, m.id + '.json'), 'utf8'));
    fs.rmSync(path.join(qdir, m.id + '.json'));
    delete meta.format; meta.id = legacy;
    fs.writeFileSync(path.join(qdir, legacy + '.json'), JSON.stringify(meta));
    quarantine.restore(legacy);
    check('quarantena: elementi del vecchio formato ancora ripristinabili', fs.readFileSync(p).equals(data));
  }
  {
    // Symbolic link: the real file is neutralized (before, the link was removed and the file left in place)
    const real = path.join(work, 'reale.sh'); fs.writeFileSync(real, 'echo x');
    const link = path.join(work, 'collegamento.sh'); fs.symlinkSync(real, link);
    const m = quarantine.add(link);
    check('quarantena: collegamento simbolico → messo in quarantena il file reale', !fs.existsSync(real) && m.originalPath === fs.realpathSync(work) + path.sep + 'reale.sh', m.originalPath);
    quarantine.restore(m.id);
    check('quarantena: file reale ripristinato', fs.readFileSync(real, 'utf8') === 'echo x');
  }

  /* ==================================================================== 3. DISASSEMBLER FALSE POSITIVES */
  console.log('\n— Disassemblatore: falsi positivi —');
  {
    // Many functions reached only through pointers (no prologue, no symbols): low coverage but normal code
    const { text } = withEntry(leafFunctions(5000));
    const r = await scanBuffer(makeELF(text), 'servizio', OPT);
    const mc = r.machineCode;
    check('codice raggiunto solo tramite puntatori (entropia da codice) → nessuna penalità', mc?.stats && mc.stats.coverage < 0.05 && !mcBad(r).length && mcOf(r).score >= 90, `${mc?.stats?.coverage} ${mcBad(r).map((f) => f.title)}`);
    check('… e segnalato solo come informazione', mcOf(r).findings.some((f) => f.severity === 'info' && /puntatori/.test(f.title)));
  }
  {
    // Same code but compressed/encrypted after the loader stub: still flagged (true positive kept)
    const stub = Buffer.from([0x31, 0xc0, 0xc3]);
    const r = await scanBuffer(makeELF(Buffer.concat([stub, crypto.randomBytes(200 * 1024)])), 'impacchettato', OPT);
    check('codice irraggiungibile con entropia ~8 (packer) → ancora segnalato', mcBad(r).some((f) => /irraggiungibile/.test(f.title)), mcOf(r)?.findings.map((f) => f.title).join(' | '));
  }
  {
    // Alignment padding is not "unreachable code"
    const code = Buffer.from([0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x5d, 0xc3]);
    const text = Buffer.concat([code, Buffer.alloc(120 * 1024, 0xcc), Buffer.alloc(60 * 1024, 0x00), Buffer.from('660f1f840000000000'.repeat(2000), 'hex')]);
    const r = await scanBuffer(makeELF(text), 'padding', OPT);
    check('padding int3/zero/nop multi-byte escluso dalla copertura', r.machineCode.stats.coverage === 1 && r.machineCode.stats.padding >= 180 * 1024 && !mcBad(r).length, JSON.stringify(r.machineCode.stats));
  }
  {
    // Function prologues as seeds
    const { text } = withEntry(leafFunctions(3000, { prologue: true }));
    const r = await scanBuffer(makeELF(text), 'prologhi', OPT);
    check('prologhi push rbp/mov rbp,rsp riconosciuti → copertura alta', r.machineCode.stats.coverage > 0.9 && r.machineCode.stats.functions >= 3000, JSON.stringify(r.machineCode.stats));
  }
  {
    // .eh_frame_hdr function table (stripped ELF without prologues)
    const { text, offs } = withEntry(leafFunctions(3000));
    const elf = makeELF(text, { fdes: offs });
    const img = D.load(elf, 'elf');
    check('ELF: funzioni lette da .eh_frame_hdr', offs.every((o) => img.functions.includes(0x401000 + o)), `${img.functions.length}`);
    const r = await scanBuffer(elf, 'strippato', OPT);
    check('ELF strippato con .eh_frame_hdr → copertura alta', r.machineCode.stats.coverage > 0.9, JSON.stringify(r.machineCode.stats));
  }
  {
    // Call to a no-return function followed by data that decodes as in/out/int1
    const fn = Buffer.from([0x0f, 0x0b, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc]); // __stack_chk_fail: ud2
    const entry = Buffer.from([0x55, 0x48, 0x89, 0xe5, 0xe8, 0, 0, 0, 0, 0xe4, 0x71, 0xe6, 0x71, 0xf1, 0xfa, 0xfb, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc]);
    entry.writeInt32LE(entry.length - 9, 5);
    const elf = makeELF(Buffer.concat([entry, fn]), { syms: [{ name: 'main', off: 0 }, { name: '__stack_chk_fail', off: entry.length }] });
    const r = await scanBuffer(elf, 'noreturn', OPT);
    const h = r.machineCode.behaviours || {};
    check('dopo call __stack_chk_fail i dati non sono disassemblati (niente in/out/int1)', !h.privileged && !h.antidebug && !mcBad(r).length, JSON.stringify(Object.keys(h)));
    // Unknown callee followed by filler + trap: same treatment (stripped binaries)
    const e2 = Buffer.from([0xe8, 0, 0, 0, 0, 0x66, 0x90, 0xf1, 0xe4, 0x71, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x31, 0xc0, 0xc3]);
    e2.writeInt32LE(16 - 5, 1);
    const r2 = await scanBuffer(makeELF(e2), 'trap', OPT);
    check('call seguita da nop + trap → nessun falso "anti-debug"', !(r2.machineCode.behaviours || {}).antidebug, JSON.stringify(Object.keys(r2.machineCode.behaviours || {})));
  }
  {
    const arm = (words) => { const b = Buffer.alloc(words.length * 4); words.forEach((w, i) => b.writeUInt32LE(w >>> 0, i * 4)); return b; };
    const dec = D.decoder('arm64');
    // /usr/bin/openssl: division by a constant (ror #2) in a loop with ldrb and calls to printf
    const div = arm([0x1b1c5d09, 0x13890929, 0x6b13013f, 0x54000088, 0xaa1903e0, 0x94009eda, 0xb9403be8, 0x3868cac8, 0xf90003e8, 0xaa1a03e0, 0x94009ed5, 0xb9403be8, 0x11000508, 0xb9003be8, 0x6b18011f, 0x54fffe2b]);
    check('ARM64: "ror #2" del compilatore (divisione per costante) → non è hashing', !scanRange(div, 0, div.length, 'arm64', 0x10000f9b0, dec).finish().hashloop);
    const hashArm = arm([0x3840140a, 0x13883508, 0x0b0a0108, 0x35ffffaa]);
    check('ARM64: vero ciclo ldrb + ror #13 + add → ancora riconosciuto', !!scanRange(hashArm, 0, hashArm.length, 'arm64', 0x1000, dec).finish().hashloop);
    const x64 = D.decoder('x64');
    const sha = Buffer.from('8b0689c1c1c90789c2c1ca1231d1c1e80331c801c34883c604ffcf75e5', 'hex');
    check('x86-64: round SHA-256 (più rotazioni, nessun byte letto) → non è hashing di API', !scanRange(sha, 0, sha.length, 'x64', 0x1000, x64).finish().hashloop);
    const word = Buffer.from('8b06c1c80d01c34883c604ffcf75f2', 'hex');
    check('x86-64: rotazione 13 su dword (non su caratteri) → non è hashing di API', !scanRange(word, 0, word.length, 'x64', 0x1000, x64).finish().hashloop);
    const api = Buffer.from('31ffacc1cf0d01c784c075f6c3', 'hex');
    check('x86: vero hashing ROR13 (lodsb; ror edi,13; add edi,eax) → ancora riconosciuto', !!scanRange(api, 0, api.length, 'x86', 0x1000, D.decoder('x86')).finish().hashloop);
  }
  {
    // Universal binary: the x86-64 slice contains bytes that look like shellcode. They are code of
    // another architecture, not "shellcode hidden in the data".
    const SC = Buffer.from('fce8000000005d31c0648b50308b520c8b52148b722831ffacc1cf0d01c784c075f681ff318b6f8768f0b5a256682e6578656863616c63c3', 'hex');
    const armCode = Buffer.alloc(64); armCode.writeUInt32LE(0xd65f03c0, 0);
    const fat = makeFat([{ cpu: 0x0100000c, buf: makeMachO(0x0100000c, armCode) }, { cpu: 0x01000007, buf: makeMachO(0x01000007, Buffer.concat([Buffer.from([0xc3]), SC])) }]);
    check('Mach-O universale: i byte "sospetti" sono davvero rilevabili come shellcode', shellcode.find(fat).length > 0);
    const r = await scanBuffer(fat, 'universale', OPT);
    check('Mach-O universale: codice delle altre architetture non scambiato per shellcode nei dati', !mcOf(r).findings.some((f) => /Shellcode/.test(f.title)), mcOf(r).findings.map((f) => f.title).join(' | '));
  }
  for (const bin of ['/bin/ls', '/usr/bin/openssl', '/bin/bash', '/usr/bin/ssh', '/bin/cat']) {
    if (!fs.existsSync(bin)) continue;
    let r; try { r = await scanFile(bin, { ...OPT, only: ['machinecode'] }); } catch { continue; }
    const mc = mcOf(r);
    if (!mc || !mc.applicable) continue;
    check(`programma di sistema ${bin}: codice macchina ≥ 95, nessuna segnalazione`, mc.score >= 95 && !mcBad(r).length, `${mc.score} ${mcBad(r).map((f) => f.title).join(' | ')}`);
  }

  fs.rmSync(work, { recursive: true, force: true });
  fs.rmSync(process.env.GAUNTLER_HOME, { recursive: true, force: true });
  console.log(fail ? `\n${fail}/${total} test di regressione FALLITI` : `\nTutti i ${total} test di regressione superati`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
