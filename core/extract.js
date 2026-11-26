// Created by anvex2012
'use strict';
const { m: msg } = require('./i18n');
/**
 * Deep extraction of hidden content:
 *  - printable strings (ASCII + UTF-16) from binaries
 *  - decompression of every PDF stream (Flate, ASCIIHex, ASCII85, LZW not supported) + PDF text
 *  - XML parts and text of Office/OpenDocument documents
 *  - objects embedded in RTF
 *  - recursive decoding of base64 / hex / charcode / gzip / zlib / PowerShell -enc / MIME email
 *  - system extraction (bsdtar / 7z / unar / xz / bzip2) for RAR, 7z, ISO, CAB, XAR/PKG…
 */
const zlib = require('zlib');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn, spawnSync } = require('child_process');
const { readZip, readTar, extract: zipExtract } = require('./zip');
const limits = require('./limits');

/* ---------------- Strings ---------------- */
function strings(buf, base = 0, min = 4) {
  const out = [];
  // ASCII
  let s = -1;
  for (let i = 0; i <= buf.length; i++) {
    const c = i < buf.length ? buf[i] : 0;
    const ok = (c >= 32 && c < 127) || c === 9;
    if (ok) { if (s < 0) s = i; }
    else if (s >= 0) { if (i - s >= min) out.push({ o: base + s, e: 'a', s: buf.toString('latin1', s, i) }); s = -1; }
  }
  // UTF-16LE (two alignments)
  for (let align = 0; align < 2; align++) {
    s = -1;
    for (let i = align; i + 1 <= buf.length; i += 2) {
      const c = i + 1 < buf.length ? buf[i] : 0, hi = i + 1 < buf.length ? buf[i + 1] : 1;
      const ok = hi === 0 && ((c >= 32 && c < 127) || c === 9);
      if (ok) { if (s < 0) s = i; }
      else if (s >= 0) { if ((i - s) / 2 >= min) out.push({ o: base + s, e: 'u', s: buf.toString('utf16le', s, i) }); s = -1; }
    }
  }
  out.sort((a, b) => a.o - b.o);
  return out;
}

const printableRatio = (b) => { let p = 0; const n = Math.min(b.length, 8192); for (let i = 0; i < n; i++) { const c = b[i]; if ((c >= 32 && c < 127) || c === 9 || c === 10 || c === 13 || c >= 160) p++; } return n ? p / n : 0; };

function magicName(b) {
  if (b.length < 4) return null;
  const h = b.toString('latin1', 0, 8);
  if (h.startsWith('MZ')) return 'exe';
  if (h.startsWith('\x7fELF')) return 'elf';
  if (h.startsWith('PK\x03\x04')) return 'zip';
  if (h.startsWith('%PDF')) return 'pdf';
  if (h.startsWith('\xd0\xcf\x11\xe0')) return 'ole';
  if (h.startsWith('Rar!')) return 'rar';
  if (h.startsWith('7z\xbc\xaf')) return '7z';
  if (h.startsWith('\x1f\x8b')) return 'gz';
  if (h.startsWith('{\\rt')) return 'rtf';
  if ([0xcafebabe, 0xfeedfacf, 0xcffaedfe, 0xfeedface, 0xcefaedfe].includes(b.readUInt32BE(0))) return 'macho';
  if (h.startsWith('\x89PNG')) return 'png';
  if (h.startsWith('\xff\xd8\xff')) return 'jpg';
  if (h.startsWith('L\x00\x00\x00\x01\x14\x02')) return 'lnk';
  if (h.startsWith('dex\n')) return 'dex';
  if (h.startsWith('\x00asm')) return 'wasm';
  return null;
}

/* ---------------- PDF ---------------- */
function ascii85(s) {
  s = s.replace(/\s/g, '').replace(/^<~/, '').replace(/~>.*$/, '');
  const out = [];
  let tuple = 0, cnt = 0;
  for (const ch of s) {
    if (ch === 'z' && cnt === 0) { out.push(0, 0, 0, 0); continue; }
    const c = ch.charCodeAt(0) - 33;
    if (c < 0 || c > 84) continue;
    tuple = tuple * 85 + c; cnt++;
    if (cnt === 5) { out.push((tuple >>> 24) & 255, (tuple >>> 16) & 255, (tuple >>> 8) & 255, tuple & 255); tuple = 0; cnt = 0; }
  }
  if (cnt > 1) { for (let i = cnt; i < 5; i++) tuple = tuple * 85 + 84; for (let i = 0; i < cnt - 1; i++) out.push((tuple >>> (24 - 8 * i)) & 255); }
  return Buffer.from(out);
}

/** FlateDecode within the budget: returns a Buffer, null (corrupt) or false (limit exceeded) */
function flate(data, budget, where) {
  const sync = { finishFlush: zlib.constants.Z_SYNC_FLUSH };
  for (const [fn, o] of [[zlib.inflateSync, {}], [zlib.inflateSync, sync], [zlib.inflateRawSync, sync]]) {
    const r = budget.inflate(fn, data, where, o);
    if (r.data) return r.data;
    if (r.limit) return false;
  }
  return null;
}

/** Decompresses every PDF stream. Returns { texts:[{label,text}], embedded:[{name,buffer}], stats } */
function pdf(buf, budget = limits.standalone()) {
  const texts = [], embedded = [];
  const stats = { streams: 0, decoded: 0, failed: 0, js: 0, images: 0 };
  const S = Buffer.from('stream'), E = Buffer.from('endstream');
  const whole0 = buf.toString('latin1');
  // Objects referenced as JavaScript (/JS 12 0 R) and as attachments (/EmbeddedFile)
  const jsRefs = new Set([...whole0.matchAll(/\/JS\s+(\d+)\s+\d+\s+R/g)].map((m) => m[1]));
  let i = 0;
  const docText = [];
  while ((i = buf.indexOf(S, i)) !== -1) {
    if (budget.tripped) { stats.limit = true; break; }
    if (i > 2 && buf[i - 1] === 0x64 && buf[i - 2] === 0x6e) { i += 6; continue; } // "endstream"
    let start = i + 6;
    if (buf[start] === 0x0d) start++;
    if (buf[start] === 0x0a) start++;
    const end = buf.indexOf(E, start);
    if (end < 0) break;
    stats.streams++;
    const dict = buf.toString('latin1', Math.max(0, i - 1500), i);
    const objs = [...dict.matchAll(/(\d+)\s+(\d+)\s+obj\b/g)];
    const objNum = objs.length ? objs[objs.length - 1][1] : '?';
    const d = dict.slice(objs.length ? objs[objs.length - 1].index : 0);
    let data = buf.subarray(start, end);
    let ok = true;
    const filters = (d.match(/\/Filter\s*(\[[^\]]*\]|\/\w+)/) || [])[1] || '';
    for (const f of filters.match(/\/\w+/g) || []) {
      if (!ok) break;
      if (/^\/(FlateDecode|Fl)$/.test(f)) { const r = flate(data, budget, `flusso PDF oggetto ${objNum}`); r ? (data = r) : (ok = false); if (r === false) stats.limit = true; }
      else if (/^\/(ASCIIHexDecode|AHx)$/.test(f)) data = Buffer.from(data.toString('latin1').replace(/[^0-9a-fA-F]/g, ''), 'hex');
      else if (/^\/(ASCII85Decode|A85)$/.test(f)) data = ascii85(data.toString('latin1'));
      else if (/^\/(DCTDecode|JPXDecode|CCITTFaxDecode|JBIG2Decode|DCT)$/.test(f)) { stats.images++; ok = false; }
      else ok = false;
    }
    if (!ok) { if (!/DCT|JPX|CCITT|JBIG2/.test(filters)) stats.failed++; i = end + 9; continue; }
    stats.decoded++;
    const isJs = /\/JS\b|\/JavaScript/.test(d) || jsRefs.has(objNum);
    if (isJs) stats.js++;
    const magic = magicName(data);
    if (magic && !['png', 'jpg'].includes(magic)) {
      embedded.push({ name: `pdf-oggetto-${objNum}.${magic}`, buffer: data, origin: `flusso PDF oggetto ${objNum}` });
    } else if (printableRatio(data) > 0.75 && data.length) {
      const t = data.toString('latin1');
      const isContent = /\bBT\b[\s\S]*\bET\b/.test(t) && /T[jJ]/.test(t);
      if (isContent) {
        // Extracts the visible text of the page (Tj / TJ operators)
        const words = [];
        for (const m of t.matchAll(/\((?:\\.|[^\\)])*\)\s*Tj|\[((?:\\.|[^\]])*)\]\s*TJ/g)) {
          const src = m[1] !== undefined ? m[1] : m[0];
          for (const p of src.matchAll(/\(((?:\\.|[^\\)])*)\)/g)) words.push(p[1].replace(/\\([nrt\\()])/g, (_, c) => ({ n: '\n', r: '', t: '\t' }[c] ?? c)));
          words.push(m[1] !== undefined ? '' : ' ');
        }
        if (words.length) docText.push(words.join(''));
      }
      if (!isContent || isJs) texts.push({ label: `Flusso PDF oggetto ${objNum}${isJs ? ' (JavaScript)' : ''}`, text: t, kind: isJs ? 'js' : 'pdf-stream' });
    }
    i = end + 9;
  }
  // JavaScript in literal strings: /JS (....)
  const whole = whole0;
  let n = 0;
  for (const m of whole.matchAll(/\/JS\s*\(((?:\\.|[^\\)]){10,})\)/g)) {
    texts.push({ label: `JavaScript PDF #${++n}`, text: m[1].replace(/\\([nrt\\()])/g, (_, c) => ({ n: '\n', r: '\r', t: '\t' }[c] ?? c)), kind: 'js' });
    stats.js++;
  }
  // /URI and /Launch actions
  if (docText.length) texts.push({ label: 'Testo visibile del PDF', text: docText.join('\n'), kind: 'doctext' });
  return { texts, embedded, stats };
}

/* ---------------- OOXML / ODF ---------------- */
function office(buf, budget = limits.standalone()) {
  const z = readZip(buf, { maxEntries: budget.limits.maxFiles + 1 });
  const texts = [], embedded = [];
  const docText = [];
  for (const e of z.entries) {
    if (e.name.endsWith('/')) continue;
    const r = zipExtract(buf, e, [], { budget });
    if (r.limit) break;
    if (!r.data) continue;
    if (/\.(xml|rels|vml|txt)$/i.test(e.name)) {
      const t = r.data.toString('utf8');
      texts.push({ label: msg('Parte del documento: {name}', { name: e.name }), text: t, kind: 'xml' });
      if (/(word\/document|word\/header\d*|word\/footer\d*|xl\/sharedStrings|ppt\/slides\/slide\d+|content)\.xml$/i.test(e.name)) {
        const words = [...t.matchAll(/<(?:w|a|text):(?:t|p|span)[^>]*>([^<]*)</g)].map((m) => m[1]).filter(Boolean);
        const xs = words.length ? words : [...t.matchAll(/<t[^>]*>([^<]*)<\/t>/g)].map((m) => m[1]);
        if (xs.length) docText.push(xs.join(' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"'));
      }
    } else if (/embeddings\/|oleObject|activeX.*\.bin$|\.(exe|dll|js|vbs|ps1|bat|hta|lnk|scr)$/i.test(e.name)) {
      embedded.push({ name: e.name.split('/').pop(), buffer: r.data, origin: msg('oggetto incorporato {name}', { name: e.name }) });
    }
  }
  if (docText.length) texts.push({ label: 'Testo visibile del documento', text: docText.join('\n'), kind: 'doctext' });
  return { texts, embedded, parts: z.entries.map((e) => e.name) };
}

/* ---------------- RTF ---------------- */
function rtf(text) {
  const embedded = [];
  let n = 0;
  for (const m of text.matchAll(/\\objdata\b([\s\S]*?)(?=\}|\\objdata|$)/g)) {
    const hex = m[1].replace(/\\[a-z]+-?\d*\s?/gi, '').replace(/[^0-9a-fA-F]/g, '');
    if (hex.length < 16) continue;
    const b = Buffer.from(hex.length % 2 ? hex.slice(0, -1) : hex, 'hex');
    // OLE1 "Package" object: look for embedded MZ/PK/OLE magic numbers
    const idx = ['MZ', 'PK\x03\x04', '\xd0\xcf\x11\xe0', '%PDF'].map((s) => b.indexOf(Buffer.from(s, 'latin1'))).filter((x) => x >= 0).sort((a, c) => a - c)[0];
    embedded.push({ name: `rtf-oggetto-${++n}.bin`, buffer: idx > 0 ? b.subarray(idx) : b, origin: 'oggetto \\objdata RTF' });
  }
  return { embedded };
}

/* ---------------- Recursive decoding of encoded blocks ---------------- */
function postDecode(b, budget) {
  if (b.length > 2 && b[0] === 0x1f && b[1] === 0x8b) { const r = limits.gunzip(budget, b, 'payload gzip codificato'); if (r.data) return { b: r.data, how: '+gzip' }; if (r.limit) return { b, how: '', limit: true }; }
  if (b.length > 2 && b[0] === 0x78 && [0x01, 0x5e, 0x9c, 0xda].includes(b[1])) { const r = limits.inflateZlib(budget, b, 'payload zlib codificato'); if (r.data) return { b: r.data, how: '+zlib' }; if (r.limit) return { b, how: '', limit: true }; }
  return { b, how: '' };
}

/** Finds and decodes encoded blocks in a text. Returns [{label, buffer, text?, at, kind}] */
function decodeBlobs(text, budget = limits.standalone()) {
  const out = [];
  const push = (kind, at, raw) => {
    if (!raw || raw.length < 16) return;
    let { b, how } = postDecode(raw, budget);
    let str = null;
    const nulls = b.subarray(0, 4096).filter((x) => x === 0).length;
    if (nulls > Math.min(b.length, 4096) * 0.3 && !magicName(b)) {
      const u = b.toString('utf16le');
      if (/^[\x09\x0a\x0d\x20-\x7e -ɏ]*$/.test(u.slice(0, 2000))) { str = u; how += '+utf16'; }
    }
    if (str === null && printableRatio(b) > 0.85 && !magicName(b)) str = b.toString('utf8');
    out.push({ kind: kind + how, at, buffer: b, text: str, magic: magicName(b) });
  };
  // Single-line base64 (also data: URIs and -EncodedCommand)
  for (const m of text.matchAll(/(?:data:[\w.+-]+\/[\w.+-]+;base64,)?([A-Za-z0-9+/]{80,}={0,2}|[A-Za-z0-9_-]{120,}={0,2})/g)) {
    const s = m[1];
    if (/^[A-Za-z]+$/.test(s) || /^[0-9a-f]+$/i.test(s)) continue; // only letters or hex: not base64
    try { push(m[0].startsWith('data:') ? 'data-URI' : 'base64', m.index, Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64')); } catch { /* */ }
  }
  // Multi-line base64 (MIME email attachments, PEM, etc.)
  for (const m of text.matchAll(/(?:^|\n)((?:[A-Za-z0-9+/]{48,100}\r?\n){4,}[A-Za-z0-9+/]*={0,2})/g)) {
    try { push('base64 MIME', m.index, Buffer.from(m[1].replace(/\s/g, ''), 'base64')); } catch { /* */ }
  }
  // Hex: \x41\x42… , 0x41,0x42… , long continuous strings
  for (const m of text.matchAll(/(?:\\x[0-9a-fA-F]{2}){24,}|(?:0x[0-9a-fA-F]{2}\s*,\s*){24,}0x[0-9a-fA-F]{2}|\b(?:[0-9a-fA-F]{2}){200,}\b/g)) {
    const hex = m[0].replace(/\\x|0x|[\s,]/g, '');
    push('hex', m.index, Buffer.from(hex.length % 2 ? hex.slice(0, -1) : hex, 'hex'));
  }
  // Numeric codes: String.fromCharCode(…), [char]…, chr(…), byte arrays
  for (const m of text.matchAll(/(?:fromCharCode\s*\(|\[byte\[\]\]\s*\(?|new\s+byte\[\]\s*\{|\[char\[\]\]\s*\(?|\bbytes\(\[)\s*((?:\d{1,3}\s*,\s*){12,}\d{1,3})/gi)) {
    const nums = m[1].split(',').map((n) => +n.trim()).filter((n) => n >= 0 && n <= 255);
    push('codici carattere', m.index, Buffer.from(nums));
  }
  // JavaScript unicode escapes used by heap sprays: unescape("%u9090%u4141…") (little-endian 16-bit units)
  for (const m of text.matchAll(/(?:%u[0-9a-fA-F]{4}){8,}/g)) {
    const units = m[0].match(/[0-9a-fA-F]{4}/g);
    const b = Buffer.alloc(units.length * 2);
    units.forEach((u, i) => b.writeUInt16LE(parseInt(u, 16), i * 2));
    push('%u (unescape)', m.index, b);
  }
  for (const m of text.matchAll(/(?:(?:\[char\]|chrw?|chr)\s*\(?\s*\d{2,3}\s*\)?\s*[+&]\s*){10,}/gi)) {
    const nums = [...m[0].matchAll(/\d{2,3}/g)].map((x) => +x[0]).filter((n) => n < 256);
    push('chr()', m.index, Buffer.from(nums));
  }
  return out;
}

/* ---------------- Extraction with system tools ---------------- */
let TOOLS = null;
let TOOLS_AT = 0;
function resetTools() { TOOLS = null; }
function tools() {
  // Tools that were missing are looked up again after a minute (they may have just been installed)
  if (TOOLS && (TOOLS.bsdtar || Date.now() - TOOLS_AT < 60000)) return TOOLS;
  TOOLS_AT = Date.now();
  const has = (cmd, args = ['--version']) => { try { const r = spawnSync(cmd, args, { encoding: 'utf8', timeout: 5000 }); return r.status === 0 || r.stdout || r.stderr ? (r.stdout || '') + (r.stderr || '') : null; } catch { return null; } };
  const tarV = has('tar') || '';
  TOOLS = {
    bsdtar: /bsdtar/.test(tarV) ? 'tar' : (has('bsdtar') ? 'bsdtar' : null),
    sevenZip: ['7zz', '7z', '7za'].find((c) => { const v = has(c, ['i']); return v && /7-Zip/i.test(v); }) || null,
    unar: has('unar', ['-v']) ? 'unar' : null,
    xz: has('xz') ? 'xz' : null,
    bzip2: has('bzip2', ['--help']) ? 'bzip2' : null,
  };
  return TOOLS;
}

/** Reads the extracted files; sizes are checked with stat BEFORE reading so a bomb never reaches memory */
function walkFiles(dir, budget, base = dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (budget.tripped) break;
    const p = path.join(dir, e.name);
    if (e.isSymbolicLink()) continue;
    if (e.isDirectory()) walkFiles(p, budget, base, out);
    else if (e.isFile()) {
      const name = path.relative(base, p);
      const size = fs.statSync(p).size;
      if (!budget.admitFile(name) || !budget.consume(size, name)) break;
      out.push({ name, data: fs.readFileSync(p) });
    }
  }
  return out;
}

/** 7-Zip listing (no extraction): number of files and declared total size */
function sevenZipList(cmd, src, pw) {
  const r = spawnSync(cmd, ['l', '-slt', '-ba', `-p${pw}`, src], { encoding: 'utf8', maxBuffer: 256 * 1024 * 1024, timeout: 120000 });
  if (r.status !== 0 || !r.stdout) return null;
  let files = 0, total = 0;
  for (const block of r.stdout.split(/\r?\n\r?\n/)) {
    if (!/^Path = /m.test(block) || /^Folder = \+/m.test(block) || /^Attributes = D/m.test(block)) continue;
    files++;
    const m = block.match(/^Size = (\d+)/m);
    if (m) total += Number(m[1]);
  }
  return { files, total };
}

/**
 * Runs an extractor that writes into outDir and watches the disk it uses while it runs: the process is
 * killed as soon as the extracted bytes or files exceed the limits (or the timeout expires), so a
 * decompression bomb can never fill the disk. Returns { status, error, over, peak }.
 */
function runWatched(cmd, args, outDir, { maxBytes, maxFiles, timeoutMs = 15 * 60 * 1000 }) {
  return new Promise((resolve) => {
    let child;
    try { child = spawn(cmd, args, { stdio: ['ignore', 'ignore', 'ignore'] }); } catch (e) { return resolve({ status: null, error: e, over: null, peak: 0 }); }
    let over = null, peak = 0, done = false, timer = null;
    const measure = () => {
      let bytes = 0, files = 0;
      const stack = [outDir];
      while (stack.length) {
        const dir = stack.pop();
        let list;
        try { list = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
        for (const e of list) {
          const p = path.join(dir, e.name);
          if (e.isDirectory()) stack.push(p);
          else { files++; try { bytes += fs.lstatSync(p).size; } catch { /* removed meanwhile */ } }
        }
      }
      return { bytes, files };
    };
    const check = () => {
      const t0 = Date.now();
      const m = measure();
      peak = Math.max(peak, m.bytes);
      if (!over && m.bytes > maxBytes) over = { kind: 'bytes', ...m };
      else if (!over && m.files > maxFiles) over = { kind: 'files', ...m };
      if (over) { try { child.kill('SIGKILL'); } catch { /* */ } }
      return Date.now() - t0;
    };
    // Adaptive polling: every 10 ms, slower only when measuring the folder itself becomes expensive
    const loop = () => { const cost = check(); if (!done && !over) timer = setTimeout(loop, Math.max(10, cost * 4)); };
    timer = setTimeout(loop, 10);
    const deadline = setTimeout(() => { if (!over) over = { kind: 'timeout' }; try { child.kill('SIGKILL'); } catch { /* */ } }, timeoutMs);
    const finish = (status, error) => {
      if (done) return;
      done = true; clearTimeout(timer); clearTimeout(deadline);
      check();
      resolve({ status, error: error || null, over, peak });
    };
    child.on('error', (e) => finish(null, e));
    child.on('close', (code) => finish(code));
  });
}

/**
 * bsdtar converts any archive it can read (7z, RAR, ISO, CAB, XAR, ZIP…) into a tar stream on stdout,
 * which is read in memory with a hard cap: nothing decompressed is ever written to disk and the
 * process is killed the moment the output exceeds the budget. Symlinks/devices stay tar metadata only.
 */
function bsdtarStream(cmd, src, budget, compressedSize) {
  const L = budget.limits;
  const ratioCap = Math.max(L.ratioMinBytes, compressedSize * L.maxRatio);
  const cap = Math.floor(Math.min(budget.remaining(), ratioCap));
  const headerRoom = Math.max(0, L.maxFiles - budget.files) * 1536 + 1024 * 1024; // pax (2 blocks) + ustar (1 block) headers per entry
  const r = spawnSync(cmd, ['-cf', '-', '--format', 'pax', '@' + src], { maxBuffer: cap + headerRoom, timeout: 15 * 60 * 1000, stdio: ['ignore', 'pipe', 'ignore'] });
  const stdout = r.stdout || Buffer.alloc(0);
  if (r.error && limits.isTooLarge(r.error)) {
    if (ratioCap <= budget.remaining()) budget.trip('ratio', msg('Rapporto di compressione oltre {max}:1 ({c} compressi → più di {cap}).', { max: L.maxRatio, c: limits.fmt(compressedSize), cap: limits.fmt(cap) }), 'archivio (bsdtar)');
    else budget.trip('total', msg('Dati decompressi oltre il limite totale di {max}.', { max: limits.fmt(L.maxTotalBytes) }), 'archivio (bsdtar)');
    return { limit: true, produced: stdout.length };
  }
  const files = [];
  let payload = 0;
  for (const e of readTar(stdout, { maxEntries: L.maxFiles + 1 })) {
    if (!e.data) continue; // directories, symlinks, hardlinks, devices: never materialized
    payload += e.data.length;
    if (!budget.admitFile(e.name) || !budget.consume(e.data.length, e.name)) return { limit: true, produced: stdout.length };
    files.push({ name: e.name.replace(/^\.\//, ''), data: e.data });
  }
  if (payload > ratioCap) { budget.trip('ratio', msg('Rapporto di compressione {r}:1 oltre il limite di {max}:1.', { r: Math.round(payload / Math.max(1, compressedSize)), max: L.maxRatio }), 'archivio (bsdtar)'); return { limit: true, produced: stdout.length }; }
  return { files, status: r.status, produced: stdout.length };
}

/** Extracts RAR/7z/ISO/CAB/XAR/XZ/BZ2 archives with the tools available on the system */
async function systemExtract(buffer, typeId, filePath, passwords = [], budget = limits.standalone()) {
  const t = tools();
  const LIMIT = (extra = {}) => ({ files: [], tool: null, error: 'limite di decompressione superato', limit: true, diskBytes: 0, ...extra });
  if (budget.tripped) return LIMIT();
  const big = { maxBuffer: 2 ** 31 - 1, timeout: 15 * 60 * 1000 };
  // Single-stream formats: the decompressor's output is capped (the child is killed past the cap)
  for (const [id, cmd] of [['xz', t.xz], ['bzip2', t.bzip2]]) {
    if (typeId !== id || !cmd) continue;
    const cap = budget.capFor(buffer.length);
    const r = spawnSync(cmd, ['-dc'], { ...big, maxBuffer: Math.max(1, cap), input: buffer });
    if (r.error && limits.isTooLarge(r.error)) { budget.explainCap(buffer.length, cap, `contenuto ${id}`); return LIMIT(); }
    if (r.status === 0) {
      if (!budget.admitFile('contenuto') || !budget.consume(r.stdout.length, `contenuto ${id}`, buffer.length)) return LIMIT();
      return { files: [{ name: 'contenuto', data: r.stdout }], tool: id, diskBytes: 0 };
    }
  }
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'gauntler-x-'));
  let src = filePath;
  try {
    if (!src) { src = path.join(tmp, 'archive.bin'); fs.writeFileSync(src, buffer); }
    const outDir = path.join(tmp, 'out');
    fs.mkdirSync(outDir);
    const L = budget.limits;
    // Pre-flight with the archive listing: a bomb is refused before anything is written to disk
    if (t.sevenZip) {
      const ls = sevenZipList(t.sevenZip, src, '');
      if (ls) {
        if (budget.files + ls.files > L.maxFiles) { budget.trip('files', msg('L\'archivio dichiara {n} file (limite {max}).', { n: ls.files, max: L.maxFiles }), msg('archivio {id}', { id: typeId })); return LIMIT(); }
        if (ls.total > budget.remaining() || (ls.total > L.ratioMinBytes && ls.total / Math.max(1, buffer.length) > L.maxRatio)) {
          budget.trip(ls.total > budget.remaining() ? 'total' : 'ratio', msg('L\'archivio dichiara {total} di dati decompressi da {size}.', { total: limits.fmt(ls.total), size: limits.fmt(buffer.length) }), msg('archivio {id}', { id: typeId }));
          return LIMIT();
        }
      }
    }
    // Disk-writing extractors are watched: the declared sizes may lie, the bytes on disk do not
    const diskCap = Math.floor(Math.min(budget.remaining(), Math.max(L.ratioMinBytes, buffer.length * L.maxRatio)));
    const attempts = [];
    if (t.sevenZip) for (const pw of ['', ...passwords]) attempts.push({ cmd: t.sevenZip, args: ['x', '-y', `-p${pw}`, `-o${outDir}`, '--', src], name: '7-Zip' + (pw ? ` (password "${pw}")` : '') });
    if (t.bsdtar) attempts.push({ name: 'bsdtar', stream: true });
    if (t.unar) attempts.push({ cmd: t.unar, args: ['-q', '-f', '-o', outDir, src], name: 'unar' });
    let peak = 0;
    for (const a of attempts) {
      if (a.stream) {
        // Each attempt is charged to a scratch budget; only the accepted one is charged for real
        const trial = new limits.Budget(L);
        trial.totalBytes = budget.totalBytes; trial.files = budget.files;
        const s = bsdtarStream(t.bsdtar, src, trial, buffer.length);
        if (s.limit) { budget.trip(trial.exceeded.reason, trial.exceeded.detail, `archivio ${typeId}`); return LIMIT({ producedBytes: s.produced, diskBytes: peak }); }
        if (s.files.length) {
          budget.totalBytes = trial.totalBytes; budget.files = trial.files;
          return { files: s.files, tool: 'bsdtar', diskBytes: peak, producedBytes: s.produced };
        }
        continue;
      }
      fs.rmSync(outDir, { recursive: true, force: true }); fs.mkdirSync(outDir);
      const w = await runWatched(a.cmd, a.args, outDir, { maxBytes: diskCap, maxFiles: L.maxFiles - budget.files, timeoutMs: big.timeout });
      peak = Math.max(peak, w.peak);
      if (w.over && w.over.kind === 'bytes') {
        budget.trip(diskCap < budget.remaining() ? 'ratio' : 'total', msg('Estrazione interrotta: oltre {cap} decompressi da {size} ({name}).', { cap: limits.fmt(diskCap), size: limits.fmt(buffer.length), name: a.name }), msg('archivio {id}', { id: typeId }));
        return LIMIT({ diskBytes: peak });
      }
      if (w.over && w.over.kind === 'files') { budget.trip('files', msg('Estrazione interrotta: oltre {n} file ({name}).', { n: L.maxFiles, name: a.name }), msg('archivio {id}', { id: typeId })); return LIMIT({ diskBytes: peak }); }
      if (w.over && w.over.kind === 'timeout') continue;
      const trial = new limits.Budget(L);
      trial.totalBytes = budget.totalBytes; trial.files = budget.files;
      const files = walkFiles(outDir, trial).filter((f) => f.name !== path.basename(src));
      if (trial.tripped) { budget.trip(trial.exceeded.reason, trial.exceeded.detail, `archivio ${typeId}`); return LIMIT({ diskBytes: peak }); }
      if (files.length && (w.status === 0 || a.name.startsWith('7-Zip'))) {
        budget.totalBytes = trial.totalBytes; budget.files = trial.files;
        return { files, tool: a.name, diskBytes: peak };
      }
    }
    return { files: [], tool: null, diskBytes: peak, error: attempts.length ? 'estrazione non riuscita (archivio cifrato o danneggiato)' : 'nessuno strumento di estrazione disponibile (installa 7-Zip: brew install sevenzip)' };
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

module.exports = { strings, pdf, office, rtf, decodeBlobs, systemExtract, runWatched, magicName, printableRatio, tools, resetTools };
