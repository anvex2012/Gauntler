// Creato da anvex2012
'use strict';
/**
 * Gauntler CDR — Content Disarm & Reconstruction.
 *
 * A file that "passes through" Gauntler comes out as a NEW file rebuilt from its safe content only:
 *   1. the real type is detected from the bytes (never trusted from the extension)
 *   2. a type-specific disarmer rebuilds the file without active content (macros, scripts, actions,
 *      embedded objects, external loaders, hidden trailing data, metadata)
 *   3. the result is analyzed AGAIN by the whole engine (all analyzers, recursively); if anything
 *      dangerous survives the file is BLOCKED and no output is produced
 * Content that cannot be disarmed without destroying it (programs, scripts, disk images, shortcuts)
 * is released only if the analysis finds nothing (status "verified"), or always blocked in strict mode.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');
const { detectType } = require('../filetype');
const { readZip, extract, readTar, writeZip } = require('../zip');
const limits = require('../limits');
const { systemExtract } = require('../extract');
const pdf = require('./pdf');
const ooxml = require('./ooxml');
const ole = require('./ole');
const C = require('./content');

const CODE_TYPES = new Set(['pe', 'dll', 'mz', 'elf', 'macho', 'class', 'dex', 'wasm', 'pyc', 'lnk', 'chm', 'one', 'iso', 'vhd', 'dmg', 'xar', 'jar', 'apk', 'cab']);
const CODE_EXT = new Set(['exe', 'dll', 'scr', 'com', 'pif', 'cpl', 'msi', 'msp', 'bat', 'cmd', 'ps1', 'psm1', 'psd1', 'vbs', 'vbe', 'js', 'jse', 'mjs', 'cjs', 'wsf', 'wsh', 'hta', 'sct', 'reg', 'inf', 'lnk', 'url', 'scf', 'jar', 'sh', 'bash', 'zsh', 'command', 'py', 'pl', 'rb', 'php', 'applescript', 'scpt', 'workflow', 'app', 'xll', 'iqy', 'slk', 'library-ms', 'settingcontent-ms', 'appref-ms', 'gadget']);
// Findings in these categories decide whether the output is safe
const SAFETY = new Set(['signatures', 'clamav', 'yara', 'reputation', 'machinecode', 'executable', 'documents', 'code', 'archive', 'lines']);
const MAX_DEPTH = 8;

function splitName(name) {
  const base = path.basename(name);
  const i = base.lastIndexOf('.');
  return i > 0 ? { stem: base.slice(0, i), ext: base.slice(i + 1).toLowerCase() } : { stem: base, ext: '' };
}

/** Safe file name: no path, no control/bidi characters, no reserved names, no hidden double extension */
function safeName(name) {
  let n = String(name).replace(/\\/g, '/').split('/').filter((p) => p && p !== '.' && p !== '..').join('/');
  n = n.replace(/[\u0000-\u001f\u007f‪-‮⁦-⁩​-‏﻿]/g, '').replace(/[<>:"|?*]/g, '_');
  n = n.split('/').map((p) => (/^(con|prn|aux|nul|com\d|lpt\d)(\.|$)/i.test(p) ? '_' + p : p)).join('/');
  return n || 'file';
}

/** Verdict on an analysis result: is it safe to hand out? */
function judge(report) {
  const blocking = report.findings.filter((f) => SAFETY.has(f.categoryId) && (f.severity === 'critical' || f.severity === 'high'));
  const safe = !blocking.length && report.overall.score >= 40;
  return { safe, blocking, score: report.overall.score, verdict: report.overall.verdict };
}

/**
 * sanitizeBuffer(buf, name, opts) → {
 *   status: 'sanitized' | 'clean' | 'verified' | 'blocked', output: Buffer|null, outName,
 *   actions: [string], reason?, type, before?, after?, children? }
 * opts: { strict, keepMetadata, stripLinks, scanOptions, depth, verify (default true) }
 */
async function sanitizeBuffer(buf, name, opts = {}) {
  const core = require('..');
  const depth = opts.depth || 0;
  const type = detectType(buf, name);
  const { stem, ext } = splitName(name);
  const result = { name, type: type.label, typeId: type.id, actions: [], status: null, output: null, outName: null };
  const scanOpts = { ...(opts.scanOptions || {}), cache: false };
  const block = (reason, extra = {}) => Object.assign(result, { status: 'blocked', output: null, reason }, extra);
  let out = null, outExt = ext || type.id;
  try {
    if (type.id === 'pdf') {
      const r = pdf.disarm(buf, { stripLinks: opts.stripLinks }); out = r.output; result.actions.push(...r.actions); outExt = 'pdf';
    } else if (['docx', 'xlsx', 'pptx', 'odf'].includes(type.id)) {
      const r = ooxml.disarm(buf, { keepMetadata: opts.keepMetadata }); out = r.output; result.actions.push(...r.actions);
      outExt = ooxml.SAFE_EXT[ext] || ext || { docx: 'docx', xlsx: 'xlsx', pptx: 'pptx', odf: 'odt' }[type.id];
      if (outExt !== ext) result.actions.push(`Estensione cambiata da .${ext} a .${outExt} (documento senza macro)`);
    } else if (type.id === 'ole') {
      if (['msi', 'msp', 'mst'].includes(ext)) return block('Pacchetto di installazione Windows (MSI): contiene programmi, non può essere disarmato');
      const r = ole.disarm(buf); out = r.output; result.actions.push(...r.actions);
      if (r.residual.length) result.residual = r.residual;
    } else if (type.id === 'rtf') {
      const r = C.rtf(buf); out = r.output; result.actions.push(...r.actions); outExt = 'rtf';
    } else if (['html', 'svg', 'xml'].includes(type.id) && !CODE_EXT.has(ext)) {
      const r = C.markup(buf); out = r.output; result.actions.push(...r.actions);
    } else if (type.id === 'jpeg') { const r = C.jpeg(buf); out = r.output; result.actions.push(...r.actions); outExt = 'jpg'; }
    else if (type.id === 'png') { const r = C.png(buf); out = r.output; result.actions.push(...r.actions); outExt = 'png'; }
    else if (type.id === 'gif') { const r = C.gif(buf); out = r.output; result.actions.push(...r.actions); outExt = 'gif'; }
    else if (type.id === 'webp') { const r = C.webp(buf); out = r.output; result.actions.push(...r.actions); outExt = 'webp'; }
    else if (type.id === 'bmp') { const r = C.bmp(buf); out = r.output; result.actions.push(...r.actions); outExt = 'bmp'; }
    else if (['zip', 'tar', 'gzip', 'rar', '7z', 'bzip2', 'xz'].includes(type.id)) {
      if (depth >= MAX_DEPTH) return block('Troppi archivi annidati');
      const r = await sanitizeArchive(buf, type.id, name, opts, depth);
      if (!r.ok) return block(r.reason, { children: r.children });
      out = r.output; result.actions.push(...r.actions); result.children = r.children;
      outExt = type.id === 'gzip' ? (splitName(r.innerName || 'file').ext || 'bin') : 'zip';
      if (type.id === 'gzip') { result.outName = safeName(r.innerName ? `${splitName(r.innerName).stem}.safe.${outExt}` : `${stem}.safe.${outExt}`); }
    } else if (CODE_TYPES.has(type.id) || CODE_EXT.has(ext) || type.family === 'script' || type.family === 'executable') {
      // Programs and scripts: cannot be disarmed without breaking them
      if (opts.strict) return block(`${type.label}: codice eseguibile, bloccato in modalità rigorosa`);
      const rep = await core.scanBuffer(buf, name, scanOpts);
      const j = judge(rep);
      result.before = { score: rep.overall.score, verdict: rep.overall.verdict };
      if (!j.safe || rep.overall.score < 90) return block(`${type.label}: codice che non può essere disarmato e l'analisi ha trovato problemi (${rep.overall.score}/100)`, { blocking: j.blocking.slice(0, 8).map((f) => `[${f.category}] ${f.title}`) });
      return Object.assign(result, { status: 'verified', output: buf, outName: safeName(`${stem}.verified${ext ? '.' + ext : ''}`), actions: ['Codice eseguibile: nessun disarmo possibile, analisi senza minacce note'], after: { score: rep.overall.score, verdict: rep.overall.verdict } });
    } else if (type.family === 'text' || type.id === 'json' || type.id === 'eml' || type.id === 'text') {
      const r = C.text(buf, { csv: ['csv', 'tsv'].includes(ext) }); out = r.output; result.actions.push(...r.actions);
    } else {
      out = buf; // media and other data formats: no active content model, verified below
    }
  } catch (e) {
    return block(`Impossibile disarmare il file: ${e.message}`);
  }
  if (!result.outName) result.outName = safeName(`${stem}.safe.${outExt}`);
  result.output = out;
  // Verification: the whole engine analyzes the rebuilt file again
  if (opts.verify !== false) {
    const rep = await core.scanBuffer(out, result.outName, scanOpts);
    const j = judge(rep);
    result.after = { score: rep.overall.score, verdict: rep.overall.verdict };
    if (!j.safe) return block('Dopo il disarmo restano contenuti pericolosi', { blocking: j.blocking.slice(0, 8).map((f) => `[${f.category}] ${f.title}`), after: result.after });
    if (result.residual && result.residual.length) result.actions.push(...result.residual.map((r) => `Attenzione: ${r}`));
  }
  const changed = !out.equals(buf);
  result.status = changed || result.actions.length ? 'sanitized' : 'clean';
  return result;
}

/** Archives: every entry is disarmed recursively; dangerous entries are dropped; result is a ZIP */
async function sanitizeArchive(buf, typeId, name, opts, depth) {
  const files = [];
  const actions = [];
  const budget = new limits.Budget(opts.limits);
  if (typeId === 'zip') {
    const z = readZip(buf, { maxEntries: budget.limits.maxFiles + 1 });
    if (z.truncated) return { ok: false, reason: `Zip bomb (più di ${budget.limits.maxFiles} voci)` };
    for (const e of z.entries) {
      if (e.name.endsWith('/')) continue;
      if (e.encrypted) { actions.push(`Rimosso (cifrato, non ispezionabile): ${e.name}`); continue; }
      const r = extract(buf, e, opts.passwords || [], { budget });
      if (r.limit) return { ok: false, reason: `Zip bomb: ${budget.exceeded.detail}` };
      if (!r.data) { actions.push(`Rimosso (illeggibile): ${e.name}`); continue; }
      if (e.usize > 0 && r.data.length / Math.max(1, e.csize) > 1000 && r.data.length > 100 * 1024 * 1024) return { ok: false, reason: 'Zip bomb' };
      files.push({ name: e.name, data: r.data });
    }
  } else if (typeId === 'tar') {
    for (const t of readTar(buf)) {
      if (t.special) { actions.push(`Rimosso ${t.special}: ${t.name}${t.link ? ' → ' + t.link : ''}`); continue; }
      files.push({ name: t.name, data: t.data });
    }
  } else if (typeId === 'gzip') {
    let inner;
    const g = limits.gunzip(budget, buf, name);
    if (g.limit) return { ok: false, reason: `Bomba di decompressione: ${budget.exceeded.detail}` };
    if (!g.data) return { ok: false, reason: 'GZIP illeggibile: ' + (g.error && g.error.message) };
    inner = g.data;
    const innerName = (buf[3] & 8) ? buf.toString('latin1', 10, buf.indexOf(0, 10)) : name.replace(/\.(gz|tgz)$/i, (m) => (m === '.tgz' ? '.tar' : ''));
    const r = await sanitizeBuffer(inner, innerName, { ...opts, depth: depth + 1 });
    if (r.status === 'blocked') return { ok: false, reason: `Contenuto bloccato: ${r.reason}`, children: [summary(r)] };
    return { ok: true, output: r.output, actions: [`Estratto da GZIP: ${innerName}`, ...r.actions], children: [summary(r)], innerName: r.outName };
  } else {
    const r = await systemExtract(buf, typeId, null, opts.passwords || [], budget);
    if (r.limit) return { ok: false, reason: `Bomba di decompressione: ${budget.exceeded.detail}` };
    if (!r.files.length) return { ok: false, reason: `Archivio ${typeId} non estraibile (${r.error || 'serve 7-Zip'})` };
    files.push(...r.files);
  }
  const outFiles = [];
  const children = [];
  const used = new Set();
  for (const f of files) {
    const clean = safeName(f.name);
    if (clean !== f.name.replace(/\\/g, '/')) actions.push(`Nome ripulito: ${f.name} → ${clean}`);
    const r = await sanitizeBuffer(f.data, clean, { ...opts, depth: depth + 1 });
    children.push(summary(r));
    if (r.status === 'blocked') { actions.push(`Rimosso ${clean}: ${r.reason}`); continue; }
    const dir = path.posix.dirname(clean);
    let outName = (dir === '.' ? '' : dir + '/') + (r.status === 'clean' ? path.posix.basename(clean) : r.outName.split('/').pop());
    while (used.has(outName)) outName = outName.replace(/(\.[^.]*)?$/, '_1$1');
    used.add(outName);
    if (r.status === 'sanitized') actions.push(`Disarmato ${clean}: ${r.actions.length} interventi`);
    outFiles.push({ name: outName, data: r.output });
  }
  if (!outFiles.length) return { ok: false, reason: 'Nessun file sicuro nell\'archivio', children };
  return { ok: true, output: writeZip(outFiles), actions, children };
}

const summary = (r) => ({ name: r.name, status: r.status, outName: r.outName, reason: r.reason, actions: r.actions, after: r.after });

/**
 * sanitizeFile(path, { out, outDir, inPlace, ...opts }) → result (+ outPath, sha256 of the output)
 * Writes atomically, never with execute permission, and never overwrites the original unless inPlace
 * (in that case the original goes to quarantine first, so it can be restored).
 */
async function sanitizeFile(file, opts = {}) {
  const abs = path.resolve(file);
  const buf = fs.readFileSync(abs);
  const r = await sanitizeBuffer(buf, path.basename(abs), opts);
  r.path = abs;
  if (r.status === 'blocked' || !r.output || opts.dryRun) return r;
  let dest = opts.out ? path.resolve(opts.out) : path.join(opts.outDir ? path.resolve(opts.outDir) : path.dirname(abs), path.basename(r.outName));
  if (opts.inPlace) {
    const quarantine = require('../quarantine');
    const q = quarantine.add(abs, { reason: 'sostituito dalla versione disarmata', score: r.after && r.after.score });
    r.quarantineId = q.id;
    dest = path.join(path.dirname(abs), path.basename(r.outName).replace(/\.(safe|verified)\./, '.'));
  }
  if (path.resolve(dest) === abs && !opts.inPlace) throw new Error('Il file di destinazione coincide con l\'originale (usa --in-place)');
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  const tmp = dest + '.gauntler-tmp-' + process.pid;
  fs.writeFileSync(tmp, r.output, { mode: 0o644 });
  fs.renameSync(tmp, dest);
  try { fs.chmodSync(dest, 0o644); } catch { /* */ }
  r.outPath = dest;
  r.sha256 = crypto.createHash('sha256').update(r.output).digest('hex');
  return r;
}

module.exports = { sanitizeBuffer, sanitizeFile, judge, safeName };
