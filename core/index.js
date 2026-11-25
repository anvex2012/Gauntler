// Creato da anvex2012
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { detectType } = require('./filetype');
const U = require('./utils');
const X = require('./extract');
const { extractMacros } = require('./vba');
const { readZip, extract: zipExtract } = require('./zip');
const { StatsAccumulator } = require('./stats');
const ctph = require('./algorithms/ctph');
const shellcode = require('./disasm/shellcode');
const limits = require('./limits');

const A = {
  identity: require('./analyzers/identity'),
  signatures: require('./analyzers/signatures'),
  clamav: require('./analyzers/clamav'),
  yara: require('./analyzers/yara'),
  reputation: require('./analyzers/reputation'),
  executable: require('./analyzers/executable'),
  machinecode: require('./analyzers/machinecode'),
  documents: require('./analyzers/documents'),
  code: require('./analyzers/code'),
  lines: require('./analyzers/lines'),
  archive: require('./analyzers/archive'),
  secrets: require('./analyzers/secrets'),
  privacy: require('./analyzers/privacy'),
  social: require('./analyzers/social'),
  network: require('./analyzers/network'),
  metadata: require('./analyzers/metadata'),
  statistics: require('./analyzers/statistics'),
};
const ORDER = Object.keys(A);
const TEXTUAL = ORDER.filter((id) => A[id].textual);

const VERSION = '2.2.0';
const CHUNK = 64 * 1024 * 1024;           // analysis block (the whole file is analyzed, block by block)
const OVERLAP = 256 * 1024;               // overlap between blocks (so no match across a boundary is missed)
const IN_MEMORY_MAX = Math.min(require('buffer').constants.MAX_LENGTH, 1536 * 1024 * 1024);
const MAX_DEPTH = 12;                     // protection against self-replicating archives (zip quine)
const MAX_DECODE_DEPTH = 10;              // nested decoding layers (base64 in base64 in …)
const SOURCE_FOR_UI_MAX = 200 * 1024 * 1024;
const PENALTY = { critical: 0.75, high: 0.45, medium: 0.18, low: 0.06, info: 0 };
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const HARD_THREAT = new Set(['signatures', 'clamav', 'yara', 'reputation', 'code', 'documents', 'archive', 'social', 'machinecode']);
const THREAT = new Set(['signatures', 'clamav', 'yara', 'reputation', 'executable', 'documents', 'code', 'archive', 'machinecode']);
const config = require('./config');
const cache = require('./cache');
const { matcher } = require('./glob');

/** Merges the call options with the user configuration (~/.gauntler/config.json) */
function resolveOptions(o = {}) {
  if (o.__resolved) return o;
  const c = o.useConfig === false ? config.DEFAULTS : config.load();
  const uniq = (a) => [...new Set(a.filter(Boolean))];
  return {
    ...o,
    __resolved: true,
    passwords: uniq([...(o.passwords || []), ...(c.passwords || [])]),
    skip: uniq([...(o.skip || []), ...(c.disabled || [])]),
    only: o.only && o.only.length ? o.only : null,
    weights: { ...(c.weights || {}), ...(o.weights || {}) },
    suppress: uniq([...(o.suppress || []), ...(c.suppress || [])]),
    allowlist: uniq([...(o.allowlist || []), ...(c.allowlist || [])].map((h) => String(h).toLowerCase())),
    yara: uniq([...(o.yara || []), ...(c.yara || [])]),
    onlineKeys: { ...(c.online || {}), ...(o.onlineKeys || {}) },
    cache: o.cache !== undefined ? o.cache : c.cache,
    limits: limits.normalize({ ...(c.limits || {}), ...(o.limits || {}) }),
  };
}
const enabled = (opts, id) => !(opts.only && !opts.only.includes(id)) && !(opts.skip || []).includes(id);

/** Stable id of a finding (used to suppress it): category:title-without-numbers */
function findingId(catId, title) {
  const slug = String(title).toLowerCase().replace(/\(\d+\)|—\s*\d+.*$|\d+/g, '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/[^a-z]+/g, '-').replace(/^-|-$/g, '');
  return `${catId}:${slug}`;
}
function suppressMatcher(list) {
  const res = list.map((p) => new RegExp('^' + p.replace(/[.+^$()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$'));
  return (id) => res.some((r) => r.test(id));
}

function verdictFor(score) {
  if (score >= 90) return { verdict: 'Sicuro', level: 'safe' };
  if (score >= 70) return { verdict: 'Basso rischio', level: 'low' };
  if (score >= 40) return { verdict: 'Sospetto', level: 'medium' };
  if (score >= 15) return { verdict: 'Pericoloso', level: 'high' };
  return { verdict: 'Malevolo', level: 'critical' };
}

function categoryScore(findings) {
  let s = 100, forced = 100;
  const seen = {};
  for (const f of findings) {
    // Diminishing returns: the k-th problem of the same severity weighs 0.6^(k-1) (except critical ones)
    const k = (seen[f.severity] = (seen[f.severity] || 0) + 1);
    const factor = f.severity === 'critical' ? 1 : Math.pow(0.6, k - 1);
    s *= 1 - (PENALTY[f.severity] || 0) * factor;
    if (f.forceScore) forced = Math.min(forced, f.forceScore);
  }
  return Math.max(1, Math.min(100, Math.round(Math.min(s, forced))));
}

function overallScore(categories, findings) {
  const app = categories.filter((c) => c.applicable && c.weight > 0);
  const wsum = app.reduce((a, c) => a + c.weight, 0) || 1;
  let score = app.reduce((a, c) => a + c.weight * c.score, 0) / wsum;
  for (const c of app) score = Math.min(score, c.score + (THREAT.has(c.id) ? 5 : 20));
  if (findings.some((f) => f.severity === 'critical')) score = Math.min(score, 25);
  else if (findings.some((f) => f.severity === 'high' && HARD_THREAT.has(f.categoryId))) score = Math.min(score, 39);
  const forced = findings.filter((f) => f.forceScore).map((f) => f.forceScore);
  if (forced.length) score = Math.min(score, ...forced);
  return Math.max(1, Math.min(100, Math.round(score)));
}

function summarize(score, findings) {
  const c = (s) => findings.filter((f) => f.severity === s).length;
  const counts = { critical: c('critical'), high: c('high'), medium: c('medium'), low: c('low'), info: c('info') };
  let advice;
  if (score >= 90) advice = 'Non sono stati trovati problemi rilevanti. Il file sembra sicuro.';
  else if (score >= 70) advice = 'Qualche elemento da tenere d\'occhio, ma nessun segnale grave.';
  else if (score >= 40) advice = 'Il file presenta caratteristiche sospette. Aprilo solo se conosci e ti fidi della fonte.';
  else if (score >= 15) advice = 'Il file è pericoloso. Non aprirlo e non eseguirlo.';
  else advice = 'Il file è quasi certamente malevolo. Eliminalo o mettilo in quarantena.';
  return { counts, advice };
}

/* ---------------- Analysis units ---------------- */
function makeUnit(u) {
  let li = null;
  u.loc = (pos) => {
    if (u.kind === 'binary') return { offset: u.offset + pos };
    if (!li) li = U.buildLineIndex(u.text);
    const loc = { line: u.lineBase + U.lineOfIndex(li, pos) + 1 };
    if (u.source) loc.source = u.source;
    return loc;
  };
  u.lineText = (pos) => (u.kind === 'binary' ? U.printableAround(u.text, pos) : U.lineTextAt(u.text, pos));
  if (u.kind === 'binary') {
    const s16 = u.strings.filter((s) => s.e === 'u');
    const starts = [];
    let p = 0;
    for (const s of s16) { starts.push(p); p += s.s.length + 1; }
    u.text16 = s16.map((s) => s.s).join('\n');
    const find = (pos) => U.lineOfIndex(starts, pos);
    u.loc16 = (pos) => { const k = find(pos); return { offset: s16[k] ? s16[k].o + 2 * (pos - starts[k]) : u.offset }; };
    u.lineText16 = (pos) => (s16[find(pos)] || {}).s || '';
  }
  return u;
}

function countNewlines(buf) {
  let n = 0, i = -1;
  while ((i = buf.indexOf(10, i + 1)) !== -1) n++;
  return n;
}

/** Iterates over the whole file in blocks (from memory, or from disk for huge files) */
async function* byteChunks(ctx) {
  if (!ctx.streamPath) {
    const b = ctx.buffer;
    if (!b.length) { yield { buf: b, offset: 0, coreLen: 0 }; return; }
    for (let off = 0; off < b.length; off += CHUNK) yield { buf: b.subarray(off, Math.min(b.length, off + CHUNK + OVERLAP)), offset: off, coreLen: Math.min(CHUNK, b.length - off) };
    return;
  }
  const fd = fs.openSync(ctx.streamPath, 'r');
  try {
    for (let off = 0; off < ctx.size; off += CHUNK) {
      const len = Math.min(CHUNK + OVERLAP, ctx.size - off);
      const buf = Buffer.allocUnsafe(len);
      fs.readSync(fd, buf, 0, len, off);
      yield { buf, offset: off, coreLen: Math.min(CHUNK, ctx.size - off) };
    }
  } finally { fs.closeSync(fd); }
}

/* ---------------- Context ---------------- */
function buildContext({ buffer, name, filePath, size, streamPath, options, depth, virtual, parentChain, budget }) {
  const type = detectType(buffer, name);
  const ext = name.includes('.') ? name.split('.').pop().toLowerCase() : '';
  const isText = U.isLikelyText(buffer);
  const utf16 = isText && buffer[0] === 0xff && buffer[1] === 0xfe;
  const head = buffer.subarray(0, Math.min(buffer.length, CHUNK));
  const ctx = {
    path: filePath, name, ext, size, buffer, streamPath, type, isText, utf16, options, depth, virtual,
    parentChain: parentChain || [],
    // One decompression budget for the whole tree of nested files (ZIP-bomb protection)
    budget: budget || new limits.Budget(options.limits),
    text: isText ? head.toString(utf16 ? 'utf16le' : 'utf8') : head.toString('latin1'),
    macros: [], extracted: [], embedded: [], decoded: [], children: [],
    annotations: new Map(), seenDecoded: new Set(),
    totals: { lines: 0, strings: 0, units: 0, bytes: 0 },
    allStrings: options.detail && !isText ? [] : null,
  };
  ctx.annotate = (loc, text, tag) => {
    const key = `${loc.source || ''}|${loc.line != null ? 'L' + loc.line : 'O' + loc.offset}`;
    let a = ctx.annotations.get(key);
    if (!a) { a = { ...loc, text: U.truncate(text, 2000), tags: [] }; ctx.annotations.set(key, a); }
    if (!a.tags.some((t) => t.id === tag.id)) a.tags.push(tag);
  };
  ctx.addExtracted = (e) => { ctx.extracted.push({ depth: 0, ...e }); };
  ctx.addEmbedded = (e) => { ctx.embedded.push(e); };
  return ctx;
}

/** Content hidden in the file: macros, PDF streams, Office XML, RTF objects */
function preExtract(ctx) {
  const b = ctx.buffer, id = ctx.type.id;
  try {
    if (id === 'ole') ctx.macros = extractMacros(b);
    if (['docx', 'xlsx', 'pptx'].includes(id)) {
      for (const e of readZip(b).entries.filter((e) => /vbaProject\.bin$/i.test(e.name))) {
        const r = zipExtract(b, e, [], { budget: ctx.budget });
        if (r.data) ctx.macros.push(...extractMacros(r.data));
      }
    }
  } catch { /* */ }
  ctx.macros.forEach((m, i) => {
    const name = (m.match(/Attribute VB_Name = "([^"]+)"/) || [])[1] || `Modulo ${i + 1}`;
    ctx.addExtracted({ label: `Macro VBA: ${name}`, text: m, kind: 'macro' });
  });
  try {
    if (id === 'pdf') {
      const r = X.pdf(b, ctx.budget);
      ctx.pdfStats = r.stats;
      r.texts.forEach((t) => ctx.addExtracted(t));
      r.embedded.forEach((e) => ctx.addEmbedded(e));
    } else if (['docx', 'xlsx', 'pptx', 'odf'].includes(id)) {
      const r = X.office(b, ctx.budget);
      ctx.officeParts = r.parts;
      r.texts.forEach((t) => ctx.addExtracted(t));
      r.embedded.forEach((e) => ctx.addEmbedded(e));
    } else if (id === 'rtf') {
      X.rtf(ctx.text).embedded.forEach((e) => ctx.addEmbedded(e));
    }
  } catch (e) { ctx.extractError = e.message; }
}

/** Recursive decoding: every decoded payload is analyzed again by all the analyzers */
function decodeUnit(ctx, unit) {
  const depth = (unit.depth || 0) + 1;
  if (depth > MAX_DECODE_DEPTH) return;
  if (ctx.budget.tripped) return;
  for (const blob of X.decodeBlobs(unit.text, ctx.budget)) {
    const h = crypto.createHash('sha1').update(blob.buffer).digest('hex');
    if (ctx.seenDecoded.has(h)) continue;
    ctx.seenDecoded.add(h);
    const loc = unit.loc(blob.at);
    ctx.decodeSeq = (ctx.decodeSeq || 0) + 1;
    const label = `Payload ${ctx.decodeSeq} · ${blob.kind} decodificato${depth > 1 ? ` (livello ${depth})` : ''}`;
    const rec = { label, from: U.fmtLoc(loc) || 'inizio', kind: blob.kind, size: blob.buffer.length, magic: blob.magic, depth, preview: blob.text ? U.truncate(blob.text, 300) : null, loc };
    if (blob.text) { ctx.decoded.push(rec); ctx.addExtracted({ label, text: blob.text, kind: 'decoded', depth }); }
    else if (blob.magic) { ctx.decoded.push(rec); ctx.addEmbedded({ name: `payload-${ctx.decoded.length}.${blob.magic}`, buffer: blob.buffer, origin: label }); }
    else if (blob.buffer.length >= 32 && shellcode.find(blob.buffer).length) {
      // Binary payload that is machine code (e.g. %u9090 shellcode in PDF/HTML JavaScript)
      rec.magic = 'shellcode';
      ctx.decoded.push(rec);
      ctx.addEmbedded({ name: `shellcode-${ctx.decoded.length}.bin`, buffer: blob.buffer, origin: label });
    }
  }
}

async function textualPass(ctx, states, stats, hashers) {
  const kind = ctx.isText ? 'text' : 'binary';
  let lineBase = 0;
  const run = (unit) => {
    ctx.totals.units++;
    for (const id of TEXTUAL) {
      if (states[id] === undefined) continue;
      try { A[id].scan(unit, states[id], ctx); } catch (e) { states[id].__error = e.message; }
    }
    decodeUnit(ctx, unit);
  };
  for await (const { buf, offset, coreLen } of byteChunks(ctx)) {
    const core = buf.subarray(0, coreLen);
    stats.update(core);
    if (hashers) hashers.forEach((h) => h.update(core));
    ctx.totals.bytes += coreLen;
    const reuse = offset === 0 && !ctx.streamPath && ctx.buffer.length <= CHUNK;
    const text = reuse ? ctx.text : (kind === 'text' ? buf.toString(ctx.utf16 ? 'utf16le' : 'utf8') : buf.toString('latin1'));
    const unit = { kind, text, offset, lineBase, source: null, depth: 0 };
    if (kind === 'binary') {
      unit.strings = X.strings(buf, offset).filter((s) => s.o - offset < coreLen);
      ctx.totals.strings += unit.strings.length;
      if (ctx.allStrings) for (const s of unit.strings) ctx.allStrings.push(s);
    }
    run(makeUnit(unit));
    if (kind === 'text') lineBase += countNewlines(core);
  }
  if (kind === 'text') ctx.totals.lines = lineBase + (ctx.size && ctx.text[ctx.text.length - 1] !== '\n' ? 1 : 0);
  // Extracted / decoded content (the queue can grow while it is being analyzed)
  for (let i = 0; i < ctx.extracted.length; i++) {
    const e = ctx.extracted[i];
    run(makeUnit({ kind: 'extracted', text: e.text, offset: 0, lineBase: 0, source: e.label, depth: e.depth || 0, extractedKind: e.kind }));
  }
}

async function analyze(ctx) {
  const t0 = Date.now();
  ctx.scanChild = (buf, childName, origin) => {
    if (ctx.depth + 1 > MAX_DEPTH) return Promise.resolve(null);
    if (ctx.budget.tripped) return Promise.resolve(null);
    return analyzeBuffer(buf, childName, { ...ctx.options, noClamav: true, detail: ctx.options.detail && buf.length <= 8 * 1024 * 1024 }, ctx.depth + 1, [...ctx.parentChain, ctx.name], origin, ctx.budget);
  };
  preExtract(ctx);

  // 1) Single pass over the whole file: statistics, hashes, textual analyzers, decoding
  const states = {};
  for (const id of TEXTUAL) {
    if (!enabled(ctx.options, id)) continue;
    if (A[id].applies(ctx)) states[id] = A[id].init ? A[id].init(ctx) : {};
  }
  const stats = new StatsAccumulator(ctx.size);
  const algs = ['md5', 'sha1', 'sha256', 'sha512'];
  const hashers = algs.map((a) => crypto.createHash(a));
  await textualPass(ctx, states, stats, hashers);
  ctx.hashes = Object.fromEntries(algs.map((a, i) => [a, hashers[i].digest('hex')]));
  // Fuzzy hash (similarity between variants of the same file); needs the whole file in memory
  if (!ctx.streamPath && ctx.size >= 64 && ctx.size <= 512 * 1024 * 1024) ctx.hashes.ctph = ctph.hash(ctx.buffer);
  ctx.stats = stats.result();

  // 2) Structural analyzers + finalization of the textual ones
  const categories = [];
  const findings = [];
  const extra = {};
  const suppressed = [];
  const isSuppressed = ctx.options.suppress && ctx.options.suppress.length ? suppressMatcher(ctx.options.suppress) : null;
  // The archive analyzer runs last: it also analyzes the files found/decoded by the others
  for (const id of [...ORDER.filter((x) => x !== 'archive'), 'archive']) {
    const a = A[id];
    const base = { id, name: a.name, description: a.description };
    if (!enabled(ctx.options, id)) continue;
    const tStart = Date.now();
    let res;
    if (a.textual) {
      if (states[id] === undefined) { categories.push({ ...base, applicable: false, score: null, findings: [], checks: [] }); continue; }
      try { res = await a.finalize(states[id], ctx); } catch (e) { res = { findings: [{ severity: 'info', title: 'Errore durante l\'analisi', detail: e.message }] }; }
    } else {
      if (!a.applies(ctx)) { categories.push({ ...base, applicable: false, score: null, findings: [], checks: [] }); continue; }
      try { res = await a.run(ctx); } catch (e) { res = { findings: [{ severity: 'info', title: 'Errore durante l\'analisi', detail: String(e.message).slice(0, 300) }] }; }
    }
    if (res.skipped) { categories.push({ ...base, applicable: false, skipped: true, reason: res.reason, score: null, findings: [], checks: res.checks || [] }); continue; }
    let fs_ = (res.findings || []).map((f) => ({ ...f, id: f.id || findingId(id, f.title), category: a.name, categoryId: id, where: f.where || U.fmtLoc(f.loc) }));
    if (isSuppressed) {
      for (const f of fs_) if (isSuppressed(f.id)) suppressed.push(f);
      fs_ = fs_.filter((f) => !isSuppressed(f.id));
    }
    fs_.sort((x, y) => SEV_ORDER[x.severity] - SEV_ORDER[y.severity]);
    const score = categoryScore(fs_);
    const weight = ctx.options.weights && ctx.options.weights[id] != null ? Number(ctx.options.weights[id]) : a.weight;
    categories.push({ ...base, applicable: true, weight, score, ...verdictFor(score), findings: fs_, info: res.info || {}, checks: res.checks || [], ms: Date.now() - tStart });
    findings.push(...fs_);
    if (res.extra) Object.assign(extra, res.extra);
  }
  categories.sort((x, y) => ORDER.indexOf(x.id) - ORDER.indexOf(y.id));
  const score = overallScore(categories, findings);
  const trusted = (ctx.options.allowlist || []).includes(ctx.hashes.sha256);
  findings.sort((x, y) => SEV_ORDER[x.severity] - SEV_ORDER[y.severity]);

  const SEVS = ['critical', 'high', 'medium', 'low', 'info'];
  const lines = [...ctx.annotations.values()]
    .map((a) => ({ ...a, sev: SEVS[Math.min(...a.tags.map((t) => SEV_ORDER[t.sev] ?? 4))] }))
    .sort((a, b) => (a.source || '').localeCompare(b.source || '') || (a.line ?? a.offset) - (b.line ?? b.offset));
  const checks = categories.flatMap((c) => c.checks || []);
  const detail = !!ctx.options.detail;
  let source;
  if (detail && ctx.isText && ctx.size <= SOURCE_FOR_UI_MAX) {
    source = ctx.streamPath ? fs.readFileSync(ctx.streamPath, ctx.utf16 ? 'utf16le' : 'utf8') : ctx.buffer.length <= CHUNK ? ctx.text : ctx.buffer.toString(ctx.utf16 ? 'utf16le' : 'utf8');
  }

  return {
    scanner: { name: 'Gauntler', version: VERSION },
    file: {
      name: ctx.name, path: ctx.path, size: ctx.size, sizeHuman: U.formatBytes(ctx.size), type: ctx.type, hashes: ctx.hashes,
      encoding: ctx.isText ? (ctx.utf16 ? 'UTF-16' : 'UTF-8 / testo') : 'binario',
      head: ctx.buffer.subarray(0, 1024).toString('base64'),
      chain: ctx.parentChain, origin: ctx.origin || null, streamed: !!ctx.streamPath,
    },
    overall: trusted
      ? { score: 100, verdict: 'Attendibile', level: 'safe', ...summarize(100, findings), advice: 'Il file è nella tua lista di file attendibili (allowlist): il punteggio calcolato era ' + score + '/100.', trusted: true, computedScore: score }
      : { score, ...verdictFor(score), ...summarize(score, findings) },
    suppressed: suppressed.length ? suppressed.map((f) => ({ id: f.id, title: f.title, severity: f.severity })) : undefined,
    categories,
    findings,
    stats: ctx.stats,
    lines,
    extracted: ctx.extracted.map((e) => ({ label: e.label, kind: e.kind, depth: e.depth, size: e.text.length, lines: e.text.split('\n').length, text: detail ? e.text : undefined })),
    decoded: ctx.decoded,
    children: ctx.children,
    source,
    strings: detail && ctx.allStrings ? ctx.allStrings : undefined,
    totals: { ...ctx.totals, checks: checks.length, checksFailed: checks.filter((c) => !c.ok).length, annotatedLines: lines.length, extracted: ctx.extracted.length, decoded: ctx.decoded.length, children: ctx.children.length },
    ...extra,
    limitExceeded: ctx.budget.exceeded || undefined,
    scannedAt: new Date().toISOString(),
    durationMs: Date.now() - t0,
  };
}

async function analyzeBuffer(buffer, name, options = {}, depth = 0, parentChain = [], origin = null, budget = null) {
  options = resolveOptions(options);
  const ctx = buildContext({ buffer, name, filePath: null, size: buffer.length, options: { ...options, noClamav: true }, depth, virtual: true, parentChain, budget });
  ctx.origin = origin;
  return analyze(ctx);
}

function sha256File(p) {
  return new Promise((res, rej) => {
    const h = crypto.createHash('sha256');
    fs.createReadStream(p).on('data', (d) => h.update(d)).on('end', () => res(h.digest('hex'))).on('error', rej);
  });
}

async function scanFile(filePath, options = {}) {
  options = resolveOptions(options);
  const abs = path.resolve(filePath);
  const st = fs.statSync(abs);
  if (!st.isFile()) throw new Error('Non è un file: ' + abs);
  // Cache: an identical file already analyzed with the same options and engine is not re-analyzed
  let sha = null;
  if (options.cache) {
    sha = await sha256File(abs);
    const hit = cache.get(sha, options);
    if (hit) return { ...hit, file: { ...hit.file, path: abs, name: path.basename(abs) }, cached: true };
  }
  const r = await scanFileUncached(abs, st, options);
  if (options.cache && st.size <= 256 * 1024 * 1024) cache.put(sha || r.file.hashes.sha256, options, r);
  return r;
}

async function scanFileUncached(abs, st, options) {
  let buffer, streamPath = null;
  if (st.size <= IN_MEMORY_MAX) buffer = fs.readFileSync(abs);
  else {
    // Huge file: structure analyzed on head + tail, content block by block from disk (100% of the file)
    const fd = fs.openSync(abs, 'r');
    const head = Buffer.allocUnsafe(512 * 1024 * 1024), tail = Buffer.allocUnsafe(128 * 1024 * 1024);
    fs.readSync(fd, head, 0, head.length, 0);
    fs.readSync(fd, tail, 0, tail.length, st.size - tail.length);
    fs.closeSync(fd);
    buffer = Buffer.concat([head, tail]);
    streamPath = abs;
  }
  const ctx = buildContext({ buffer, name: path.basename(abs), filePath: abs, size: st.size, streamPath, options, depth: 0, virtual: false });
  ctx.fsStat = st;
  return analyze(ctx);
}

async function scanBuffer(buffer, name = 'buffer', options = {}) {
  return analyzeBuffer(buffer, name, options, 0);
}

/** Lists files in a folder; supports exclude/include (glob), maximum size, symlinks */
function walk(dir, opts = {}, out = [], ctx = null) {
  if (!ctx) ctx = { exclude: matcher(opts.exclude), include: opts.include && opts.include.length ? matcher(opts.include) : null, seen: new Set(), root: dir };
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (e) { if (opts.onError) opts.onError(dir, e); return out; }
  for (const e of entries) {
    const p = path.join(dir, e.name);
    const rel = path.relative(ctx.root, p);
    if (ctx.exclude(rel) || ctx.exclude(p)) continue;
    let isDir = e.isDirectory(), isFile = e.isFile();
    if (e.isSymbolicLink()) {
      if (!opts.followSymlinks) continue;
      try { const real = fs.realpathSync(p); if (ctx.seen.has(real)) continue; ctx.seen.add(real); const st = fs.statSync(real); isDir = st.isDirectory(); isFile = st.isFile(); } catch { continue; }
    }
    if (isDir) { if (opts.recursive !== false) walk(p, opts, out, ctx); }
    else if (isFile) {
      if (ctx.include && !ctx.include(rel) && !ctx.include(p)) continue;
      if (opts.maxSize) { try { if (fs.statSync(p).size > opts.maxSize) continue; } catch { continue; } }
      out.push(p);
    }
  }
  return out;
}

const analyzers = ORDER.map((id) => ({ id, name: A[id].name, description: A[id].description, weight: A[id].weight }));
const clamavAvailable = () => A.clamav.available();

const yaraAvailable = () => A.yara.available();

module.exports = { scanFile, scanBuffer, walk, analyzers, clamavAvailable, yaraAvailable, verdictFor, findingId, resolveOptions, sha256File, VERSION };
