// Created by anvex2012
'use strict';
const { t } = require('../i18n');
/**
 * PDF Content Disarm & Reconstruction.
 *
 * 1. Parsing: every "N G obj … endobj" in the file (the LAST definition wins, as with incremental
 *    updates), plus the objects packed inside compressed object streams (/Type /ObjStm).
 *    Objects are parsed into a tree (dictionary, array, name, string, number, reference…).
 * 2. Disarm: actions that run code or touch the system are neutralized (JavaScript, Launch,
 *    SubmitForm, ImportData, GoToE/GoToR, RichMedia, Rendition, Sound/Movie, Hide), automatic triggers
 *    are removed (/OpenAction, /AA), embedded files and XFA forms are dropped, JavaScript name trees
 *    are emptied. Optional: external links (/URI).
 * 3. Reconstruction: a brand new PDF is written (no object streams, no xref streams, no previous
 *    revisions, no data hidden between objects), with a freshly computed cross-reference table.
 * Encrypted PDFs cannot be disarmed without the password and are refused.
 */
const zlib = require('zlib');
const limits = require('../limits');

/* ----------------------------- lexer / parser ----------------------------- */
const WS = new Set([0, 9, 10, 12, 13, 32]);
const DELIM = new Set([40, 41, 60, 62, 91, 93, 123, 125, 47, 37]);

class Parser {
  constructor(buf, pos = 0, end = buf.length) { this.b = buf; this.p = pos; this.end = end; }
  skip() {
    const b = this.b;
    for (;;) {
      while (this.p < this.end && WS.has(b[this.p])) this.p++;
      if (b[this.p] === 37) { while (this.p < this.end && b[this.p] !== 10 && b[this.p] !== 13) this.p++; continue; }
      break;
    }
  }
  regular() {
    const s = this.p;
    while (this.p < this.end && !WS.has(this.b[this.p]) && !DELIM.has(this.b[this.p])) this.p++;
    return this.b.toString('latin1', s, this.p);
  }
  value(depth = 0) {
    if (depth > 200) throw new Error('annidamento eccessivo');
    this.skip();
    const b = this.b, c = b[this.p];
    if (this.p >= this.end) throw new Error('fine inattesa');
    if (c === 60 && b[this.p + 1] === 60) { // << dict >>
      this.p += 2;
      const d = new Map();
      for (;;) {
        this.skip();
        if (b[this.p] === 62 && b[this.p + 1] === 62) { this.p += 2; break; }
        if (this.p >= this.end) throw new Error('dizionario non chiuso');
        const k = this.value(depth + 1);
        if (k.t !== 'name') { continue; }
        const v = this.value(depth + 1);
        d.set(k.v, v);
      }
      return { t: 'dict', v: d };
    }
    if (c === 91) { // [ array ]
      this.p++;
      const a = [];
      for (;;) {
        this.skip();
        if (b[this.p] === 93) { this.p++; break; }
        if (this.p >= this.end) throw new Error('array non chiuso');
        a.push(this.value(depth + 1));
        this.foldRef(a);
      }
      return { t: 'array', v: a };
    }
    if (c === 47) { // /Name (with #xx escapes)
      this.p++;
      const raw = this.regular();
      return { t: 'name', v: raw.replace(/#([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16))) };
    }
    if (c === 40) { // (literal string)
      let depthP = 1, i = this.p + 1;
      const out = [];
      while (i < this.end && depthP) {
        const ch = b[i];
        if (ch === 92) { out.push(ch, b[i + 1]); i += 2; continue; }
        if (ch === 40) depthP++;
        if (ch === 41) { depthP--; if (!depthP) break; }
        out.push(ch);
        i++;
      }
      this.p = i + 1;
      return { t: 'str', raw: Buffer.from(out) };
    }
    if (c === 60) { // <hex string>
      const e = b.indexOf(62, this.p);
      const raw = b.toString('latin1', this.p + 1, e < 0 ? this.end : e);
      this.p = e < 0 ? this.end : e + 1;
      return { t: 'hex', raw: raw.replace(/\s+/g, '') };
    }
    const tok = this.regular();
    if (!tok) { this.p++; return { t: 'null' }; }
    if (/^[+-]?(\d+\.?\d*|\.\d+)$/.test(tok)) {
      // n g R reference lookahead
      const save = this.p;
      this.skip();
      const g = this.regular();
      if (/^\d+$/.test(g) && /^\d+$/.test(tok)) {
        this.skip();
        if (this.b[this.p] === 82 && (this.p + 1 >= this.end || WS.has(this.b[this.p + 1]) || DELIM.has(this.b[this.p + 1]))) { this.p++; return { t: 'ref', n: +tok, g: +g }; }
      }
      this.p = save;
      return { t: 'num', v: tok };
    }
    if (tok === 'true' || tok === 'false') return { t: 'bool', v: tok === 'true' };
    if (tok === 'null') return { t: 'null' };
    return { t: 'kw', v: tok };
  }
  foldRef() { /* references are recognized with lookahead in value() */ }
}

/* ----------------------------- serializer ----------------------------- */
const nameEsc = (s) => s.replace(/[^\x21-\x7e]|[#()<>[\]{}/%]/g, (ch) => '#' + ch.charCodeAt(0).toString(16).padStart(2, '0'));
function ser(o) {
  switch (o.t) {
    case 'dict': return '<<' + [...o.v].map(([k, v]) => `/${nameEsc(k)} ${ser(v)}`).join(' ') + '>>';
    case 'array': return '[' + o.v.map(ser).join(' ') + ']';
    case 'name': return '/' + nameEsc(o.v);
    case 'str': return '(' + o.raw.toString('latin1') + ')';
    case 'hex': return '<' + o.raw + '>';
    case 'num': return o.v;
    case 'ref': return `${o.n} ${o.g} R`;
    case 'bool': return o.v ? 'true' : 'false';
    case 'null': return 'null';
    case 'kw': return o.v;
    default: return 'null';
  }
}

/* ----------------------------- reading objects ----------------------------- */
function readObjects(buf) {
  const objs = new Map(); // num → { num, gen, value, stream? }
  const trailers = [];
  const txt = buf.toString('latin1');
  const re = /(\d{1,10})\s+(\d{1,5})\s+obj\b/g;
  let m;
  while ((m = re.exec(txt))) {
    const num = +m[1], gen = +m[2];
    const p = new Parser(buf, m.index + m[0].length);
    let value;
    try { value = p.value(); } catch { continue; }
    p.skip();
    let stream = null;
    if (buf.toString('latin1', p.p, p.p + 6) === 'stream') {
      let s = p.p + 6;
      if (buf[s] === 13) s++;
      if (buf[s] === 10) s++;
      const lenObj = value.t === 'dict' ? value.v.get('Length') : null;
      let len = lenObj && lenObj.t === 'num' ? +lenObj.v : -1;
      if (!(len >= 0 && s + len <= buf.length && /^\s*endstream/.test(buf.toString('latin1', s + len, s + len + 20)))) {
        const e = buf.indexOf('endstream', s, 'latin1');
        len = (e < 0 ? buf.length : e) - s;
        while (len > 0 && (buf[s + len - 1] === 10 || buf[s + len - 1] === 13)) len--;
      }
      stream = buf.subarray(s, s + len);
      re.lastIndex = s + len;
    }
    objs.set(num, { num, gen, value, stream });
  }
  // Classic trailers (all revisions)
  for (const t of txt.matchAll(/trailer\s*<</g)) {
    try { trailers.push(new Parser(buf, t.index + 7).value()); } catch { /* */ }
  }
  return { objs, trailers };
}

function decodeStream(dict, data) {
  const f = dict.v.get('Filter');
  const filters = !f ? [] : f.t === 'array' ? f.v.map((x) => x.v) : [f.v];
  let d = data;
  for (const name of filters) {
    if (name === 'FlateDecode' || name === 'Fl') {
      // Bounded output (ratio/size caps): a FlateDecode bomb makes the stream undecodable, not the process crash
      const cap = limits.standalone().capFor(d.length);
      try { d = zlib.inflateSync(d, { maxOutputLength: cap }); } catch (e) { if (limits.isTooLarge(e)) return null; try { d = zlib.inflateSync(d, { finishFlush: zlib.constants.Z_SYNC_FLUSH, maxOutputLength: cap }); } catch { return null; } }
    } else return null;
  }
  return d;
}

/** Unpacks compressed object streams into ordinary objects */
function expandObjectStreams(objs) {
  let n = 0;
  for (const o of [...objs.values()]) {
    if (!o.stream || o.value.t !== 'dict') continue;
    const type = o.value.v.get('Type');
    if (!type || type.v !== 'ObjStm') continue;
    const data = decodeStream(o.value, o.stream);
    if (!data) throw new Error(t('object stream {n} con filtro non supportato', { n: o.num }));
    const N = +(o.value.v.get('N') || { v: 0 }).v, first = +(o.value.v.get('First') || { v: 0 }).v;
    const hp = new Parser(data, 0, first);
    const pairs = [];
    for (let i = 0; i < N; i++) { const a = hp.value(), b = hp.value(); pairs.push([+a.v, +b.v]); }
    for (const [num, off] of pairs) {
      const existing = objs.get(num);
      if (existing && !existing.fromObjStm && existing !== o) continue; // a top-level later revision wins
      try { objs.set(num, { num, gen: 0, value: new Parser(data, first + off).value(), stream: null, fromObjStm: true }); n++; } catch { /* */ }
    }
    objs.delete(o.num);
  }
  return n;
}

/* ----------------------------- disarm ----------------------------- */
const BAD_ACTIONS = new Set(['JavaScript', 'Launch', 'SubmitForm', 'ImportData', 'GoToE', 'GoToR', 'RichMediaExecute', 'Rendition', 'Sound', 'Movie', 'Hide', 'SetOCGState', 'Trans', 'GoTo3DView']);

function disarm(buf, { stripLinks = false } = {}) {
  if (!/^%PDF-/.test(buf.toString('latin1', 0, 1024).trimStart()) && buf.indexOf('%PDF-') < 0) throw new Error('non è un PDF');
  const { objs, trailers } = readObjects(buf);
  if (!objs.size) throw new Error('nessun oggetto PDF leggibile');
  const actions = [];
  const count = {};
  const note = (k) => { count[k] = (count[k] || 0) + 1; };
  const expanded = expandObjectStreams(objs);
  if (expanded) actions.push(t('Estratti {n} oggetti da object stream compressi', { n: expanded }));

  // Trailer: last classic trailer, or the dictionary of the last cross-reference stream
  let trailer = trailers.length ? trailers[trailers.length - 1] : null;
  for (const o of objs.values()) {
    if (o.value.t === 'dict' && o.value.v.get('Type')?.v === 'XRef') { if (!trailer || !trailer.v.get('Root')) trailer = o.value; objs.delete(o.num); }
  }
  if (!trailer || !trailer.v.get('Root')) {
    const cat = [...objs.values()].find((o) => o.value.t === 'dict' && o.value.v.get('Type')?.v === 'Catalog');
    if (!cat) throw new Error('catalogo del documento non trovato');
    trailer = { t: 'dict', v: new Map([['Root', { t: 'ref', n: cat.num, g: cat.gen }]]) };
  }
  if (trailer.v.get('Encrypt')) throw new Error('PDF cifrato: impossibile disarmarlo senza password');

  const isAction = (d) => d.t === 'dict' && (d.v.get('S') && d.v.get('S').t === 'name' && (d.v.has('JS') || d.v.get('Type')?.v === 'Action' || BAD_ACTIONS.has(d.v.get('S').v) || d.v.get('S').v === 'URI' || d.v.get('S').v === 'GoTo' || d.v.get('S').v === 'Named'));
  const walk = (node, ctx) => {
    if (!node) return node;
    if (node.t === 'array') { node.v = node.v.map((x) => walk(x, ctx)); return node; }
    if (node.t !== 'dict') return node;
    const d = node.v;
    // Neutralize a dangerous action dictionary entirely
    if (isAction(node)) {
      const s = d.get('S').v;
      if (BAD_ACTIONS.has(s) || d.has('JS')) { note(`azione ${s}`); return { t: 'null' }; }
      if (s === 'URI' && stripLinks) { note('collegamento esterno'); return { t: 'null' }; }
    }
    for (const k of ['OpenAction', 'AA']) if (d.has(k)) { d.delete(k); note(k === 'AA' ? 'azioni automatiche (/AA)' : 'azione all\'apertura (/OpenAction)'); }
    if (d.has('JS')) { d.delete('JS'); note('JavaScript'); }
    if (d.has('JavaScript')) { d.delete('JavaScript'); note('JavaScript nel name tree'); }
    if (d.has('EmbeddedFiles')) { d.delete('EmbeddedFiles'); note('file allegati'); }
    if (d.has('XFA')) { d.delete('XFA'); note('modulo XFA'); }
    if (d.get('Type')?.v === 'EmbeddedFile' || d.get('Type')?.v === 'Filespec' && d.has('EF')) { if (d.has('EF')) { d.delete('EF'); note('file allegati'); } }
    if (d.get('Subtype')?.v === 'FileAttachment') { d.delete('FS'); note('annotazione con allegato'); }
    if (/^(RichMedia|Screen|Movie|Sound|3D)$/.test(d.get('Subtype')?.v || '')) { for (const k of ['RichMediaContent', 'RichMediaSettings', 'A', 'MK', '3DD']) d.delete(k); note(`annotazione ${d.get('Subtype').v}`); }
    if (d.get('A')) { const a = walk(d.get('A'), ctx); if (a.t === 'null') d.delete('A'); else d.set('A', a); }
    for (const [k, v] of d) if (k !== 'A') d.set(k, walk(v, ctx));
    return node;
  };
  const dropped = [];
  for (const o of objs.values()) {
    // EmbeddedFile streams and JavaScript streams are removed entirely
    if (o.value.t === 'dict' && o.value.v.get('Type')?.v === 'EmbeddedFile') { dropped.push(o.num); note('file allegati'); continue; }
    const v = walk(o.value, {});
    o.value = v;
  }
  for (const n of dropped) objs.set(n, { num: n, gen: objs.get(n).gen, value: { t: 'null' }, stream: null });
  // JavaScript held in a stream referenced by /JS is now unreferenced: empty any stream that looks like JS
  for (const o of objs.values()) {
    if (!o.stream || o.value.t !== 'dict') continue;
    const plain = decodeStream(o.value, o.stream);
    if (plain && /\b(app\.|this\.exportDataObject|util\.printf|eval\s*\(|unescape\s*\(|getAnnots|Collab\.)/.test(plain.toString('latin1', 0, 65536)) && !/\bBT\b[\s\S]*\bET\b/.test(plain.toString('latin1', 0, 4096))) {
      o.stream = Buffer.alloc(0); o.value.v.delete('Filter'); o.value.v.delete('DecodeParms'); note('flusso JavaScript');
    }
  }
  for (const [k, n] of Object.entries(count)) actions.push(`Rimosso: ${k}${n > 1 ? ` (${n})` : ''}`);

  /* ----------------------------- rebuild ----------------------------- */
  const parts = [Buffer.from('%PDF-1.7\n%\xe2\xe3\xcf\xd3\n', 'latin1')];
  let pos = parts[0].length;
  const xref = new Map();
  const nums = [...objs.keys()].sort((a, b) => a - b);
  for (const n of nums) {
    const o = objs.get(n);
    let head;
    let body;
    if (o.stream && o.value.t === 'dict') {
      o.value.v.set('Length', { t: 'num', v: String(o.stream.length) });
      head = Buffer.from(`${n} ${o.gen} obj\n${ser(o.value)}\nstream\n`, 'latin1');
      body = Buffer.concat([head, o.stream, Buffer.from('\nendstream\nendobj\n', 'latin1')]);
    } else body = Buffer.from(`${n} ${o.gen} obj\n${ser(o.value)}\nendobj\n`, 'latin1');
    xref.set(n, { off: pos, gen: o.gen });
    parts.push(body);
    pos += body.length;
  }
  const size = (nums.length ? nums[nums.length - 1] : 0) + 1;
  const lines = ['xref', `0 ${size}`, '0000000000 65535 f '];
  for (let i = 1; i < size; i++) {
    const e = xref.get(i);
    lines.push(e ? `${String(e.off).padStart(10, '0')} ${String(e.gen).padStart(5, '0')} n ` : '0000000000 65535 f ');
  }
  const tr = new Map([['Size', { t: 'num', v: String(size) }], ['Root', trailer.v.get('Root')]]);
  if (trailer.v.get('Info')) tr.set('Info', trailer.v.get('Info'));
  parts.push(Buffer.from(lines.join('\n') + `\ntrailer\n${ser({ t: 'dict', v: tr })}\nstartxref\n${pos}\n%%EOF\n`, 'latin1'));
  const tail = buf.lastIndexOf('%%EOF');
  if (tail >= 0 && buf.length - tail > 64) actions.push(t('Eliminati {n} byte nascosti dopo la fine del documento', { n: buf.length - tail - 5 }));
  if (trailers.length > 1) actions.push(t('Unite {n} revisioni (aggiornamenti incrementali) in una sola', { n: trailers.length }));
  actions.push(t('Documento ricostruito: {n} oggetti, nuova tabella xref', { n: nums.length }));
  return { output: Buffer.concat(parts), actions, removed: Object.values(count).reduce((a, b) => a + b, 0) };
}

module.exports = { disarm, readObjects, Parser, ser };
