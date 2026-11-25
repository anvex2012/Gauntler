// Creato da anvex2012
'use strict';
/**
 * Disarm of RTF, HTML/SVG/XML markup, images and plain text.
 */
const zlib = require('zlib');
const { crc32 } = require('../zip');

/* ------------------------------------------------------------------ RTF */
const RTF_DROP = new Set(['object', 'objdata', 'objclass', 'objname', 'objemb', 'objlink', 'objautlink', 'objupdate', 'datastore', 'xmlopen', 'objocx', 'result']);
const RTF_FIELD = /\b(DDE|DDEAUTO|INCLUDETEXT|INCLUDEPICTURE|IMPORT|LINK|HYPERLINK\s+"?(file|mhtml|ms-)|QUOTE)\b/i;

/** Drops whole groups whose destination is an embedded object, and dangerous field instructions */
function rtf(buf) {
  const s = buf.toString('latin1');
  const out = [];
  const actions = new Map();
  let i = 0;
  const groupEnd = (start) => {
    let depth = 0;
    for (let k = start; k < s.length; k++) {
      const ch = s[k];
      if (ch === '\\') {
        // \binN: N raw bytes follow and must be skipped (they may contain braces)
        const m = /^\\bin(\d+) ?/.exec(s.slice(k, k + 16));
        if (m) { k += m[0].length + +m[1] - 1; continue; }
        k++; continue;
      }
      if (ch === '{') depth++;
      else if (ch === '}') { depth--; if (!depth) return k + 1; }
    }
    return s.length;
  };
  while (i < s.length) {
    const ch = s[i];
    if (ch === '{') {
      const m = /^\{(?:\\\*)?\s*\\([a-z]+)(-?\d+)? ?/i.exec(s.slice(i, i + 64));
      if (m && RTF_DROP.has(m[1].toLowerCase())) {
        const e = groupEnd(i);
        actions.set(m[1], (actions.get(m[1]) || 0) + 1);
        i = e;
        continue;
      }
      if (m && m[1].toLowerCase() === 'field') {
        const e = groupEnd(i);
        const body = s.slice(i, e);
        if (RTF_FIELD.test(body.replace(/\\[a-z]+-?\d* ?/gi, ' '))) { actions.set('campo DDE/INCLUDE', (actions.get('campo DDE/INCLUDE') || 0) + 1); i = e; continue; }
      }
    } else if (ch === '\\') {
      const m = /^\\bin(\d+) ?/.exec(s.slice(i, i + 16));
      if (m) { out.push(s.slice(i, i + m[0].length + +m[1])); i += m[0].length + +m[1]; continue; }
      const cw = /^\\([a-z]+)(-?\d+)? ?/i.exec(s.slice(i, i + 40));
      if (cw && RTF_DROP.has(cw[1].toLowerCase())) { // object keyword outside a group start: skip to the end of the enclosing group
        let depth = 1, k = i;
        for (; k < s.length && depth; k++) { if (s[k] === '\\') { k++; continue; } if (s[k] === '{') depth++; else if (s[k] === '}') depth--; }
        actions.set(cw[1], (actions.get(cw[1]) || 0) + 1);
        i = k - 1;
        continue;
      }
    }
    out.push(ch);
    i++;
  }
  // Data after the final closing brace (a common place to hide payloads)
  let txt = out.join('');
  let depth = 0, end = -1;
  for (let k = 0; k < txt.length; k++) { if (txt[k] === '\\') { k++; continue; } if (txt[k] === '{') depth++; else if (txt[k] === '}') { depth--; if (!depth) { end = k + 1; break; } } }
  const list = [...actions].map(([k, n]) => `Rimosso gruppo RTF \\${k}${n > 1 ? ` (${n})` : ''}`);
  if (end > 0 && txt.length - end > 2) { list.push(`Eliminati ${txt.length - end} byte dopo la fine del documento`); txt = txt.slice(0, end) + '\n'; }
  return { output: Buffer.from(txt, 'latin1'), actions: list };
}

/* --------------------------------------------------------------- Markup */
const DANGEROUS_TAGS = ['script', 'iframe', 'frame', 'frameset', 'object', 'embed', 'applet', 'base', 'portal', 'foreignObject', 'handler', 'listener', 'noscript', 'template', 'xml:stylesheet'];
const VOID_DANGEROUS = ['meta', 'link', 'param', 'import'];

function decodeEntities(v) {
  return v.replace(/&#x([0-9a-f]+);?/gi, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/&#(\d+);?/g, (_, d) => String.fromCharCode(+d))
    .replace(/&(colon|tab|newline);/gi, (_, n) => ({ colon: ':', tab: '\t', newline: '\n' }[n.toLowerCase()]));
}
const badUrl = (v) => /^(javascript|vbscript|livescript|data:(?!image\/(png|jpe?g|gif|webp);))/i.test(decodeEntities(v).replace(/[\s\x00-\x1f]+/g, ''));

/**
 * Tag-level sanitizer for HTML, SVG and XML. Repeated until a fixed point is reached so that nested
 * tricks such as "<scr<script>ipt>" cannot survive one pass.
 */
function markup(buf) {
  let s = buf.toString('utf8');
  const actions = new Map();
  const note = (k) => actions.set(k, (actions.get(k) || 0) + 1);
  for (let pass = 0; pass < 10; pass++) {
    const before = s;
    for (const t of DANGEROUS_TAGS) {
      const re = new RegExp(`<\\s*${t.replace(':', '\\:')}\\b[\\s\\S]*?<\\s*\\/\\s*${t.replace(':', '\\:')}\\s*>`, 'gi');
      s = s.replace(re, () => { note(`<${t}>`); return ''; });
      s = s.replace(new RegExp(`<\\s*\\/?\\s*${t.replace(':', '\\:')}\\b[^>]*>`, 'gi'), () => { note(`<${t}>`); return ''; });
    }
    // processing instructions that load code (xml-stylesheet with XSLT script, etc.)
    s = s.replace(/<\?xml-stylesheet[^>]*\?>/gi, () => { note('foglio di stile XSLT'); return ''; });
    for (const t of VOID_DANGEROUS) {
      s = s.replace(new RegExp(`<\\s*${t}\\b[^>]*>`, 'gi'), (tag) => {
        if (t === 'meta' && !/http-equiv\s*=\s*["']?\s*(refresh|set-cookie|content-security)/i.test(tag)) return tag;
        if (t === 'link' && !/rel\s*=\s*["']?[^"'>]*(import|prefetch|preload|prerender|stylesheet)/i.test(tag) && !badUrl((tag.match(/href\s*=\s*["']?([^"'\s>]+)/i) || [])[1] || '')) return tag;
        note(`<${t}>`);
        return '';
      });
    }
    // Event handlers and dangerous URLs inside any remaining tag
    s = s.replace(/<([a-zA-Z][\w:-]*)(\s[^<>]*?)?(\/?)>/g, (tag, name, attrs = '', slash) => {
      if (!attrs) return tag;
      let a = attrs.replace(/\s+on[a-z]+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/gi, () => { note('gestori di eventi (on…)'); return ''; });
      a = a.replace(/(\s(?:href|src|action|formaction|xlink:href|data|code|codebase|poster|background|lowsrc|dynsrc|values|to|from|by)\s*=\s*)("[^"]*"|'[^']*'|[^\s>]+)/gi, (m, k, v) => {
        const val = v.replace(/^["']|["']$/g, '');
        if (badUrl(val) || /javascript:/i.test(decodeEntities(val))) { note('URL javascript:/data:'); return ''; }
        return m;
      });
      a = a.replace(/\sstyle\s*=\s*("[^"]*"|'[^']*')/gi, (m, v) => (/expression\s*\(|javascript:|behavior\s*:|-moz-binding|@import/i.test(decodeEntities(v)) ? (note('CSS attivo'), '') : m));
      if (/^form$/i.test(name) && /\saction\s*=/i.test(a)) { a = a.replace(/\saction\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/gi, ''); note('destinazione dei moduli (form action)'); }
      return `<${name}${a}${slash}>`;
    });
    // <set>/<animate> that rewrite href to javascript: (SVG)
    s = s.replace(/<\s*(set|animate)\b[^>]*attributeName\s*=\s*["']?(xlink:)?href[^>]*>/gi, () => { note('animazione SVG di href'); return ''; });
    if (s === before) break;
  }
  return { output: Buffer.from(s, 'utf8'), actions: [...actions].map(([k, n]) => `Rimosso ${k}${n > 1 ? ` (${n})` : ''}`) };
}

/* --------------------------------------------------------------- Images */
function jpeg(buf) {
  const parts = [buf.subarray(0, 2)];
  const actions = new Map();
  let i = 2;
  const keep = new Set([0xdb, 0xc4, 0xdd, 0xe0, 0xee]); // DQT DHT DRI APP0(JFIF) APP14(Adobe)
  while (i + 4 <= buf.length) {
    if (buf[i] !== 0xff) throw new Error('JPEG danneggiato (marker non valido)');
    const m = buf[i + 1];
    if (m === 0xff) { i++; continue; }
    if (m === 0xd9) break;
    const len = buf.readUInt16BE(i + 2);
    const seg = buf.subarray(i, i + 2 + len);
    if (m === 0xda) {
      // Start of scan: copy entropy-coded data up to the next real marker (RSTn and stuffed 0xFF00 are data)
      let k = i + 2 + len;
      while (k + 1 < buf.length && !(buf[k] === 0xff && buf[k + 1] !== 0 && !(buf[k + 1] >= 0xd0 && buf[k + 1] <= 0xd7))) k++;
      parts.push(buf.subarray(i, k));
      i = k;
      continue;
    }
    if ((m >= 0xc0 && m <= 0xcf && m !== 0xc4 && m !== 0xc8 && m !== 0xcc) || keep.has(m) || (m === 0xe2 && seg.toString('latin1', 4, 15) === 'ICC_PROFILE')) parts.push(seg);
    else { const k = m === 0xe1 ? (seg.toString('latin1', 4, 8) === 'Exif' ? 'EXIF (anche GPS)' : 'XMP') : m === 0xfe ? 'commento' : `APP${m - 0xe0}`; actions.set(k, (actions.get(k) || 0) + 1); }
    i += 2 + len;
  }
  parts.push(Buffer.from([0xff, 0xd9]));
  const tail = buf.length - (i + 2);
  const list = [...actions].map(([k, n]) => `Rimossi metadati ${k}${n > 1 ? ` (${n})` : ''}`);
  if (tail > 0) list.push(`Eliminati ${tail} byte nascosti dopo la fine dell'immagine`);
  return { output: Buffer.concat(parts), actions: list };
}

const PNG_KEEP = new Set(['IHDR', 'PLTE', 'IDAT', 'IEND', 'tRNS', 'cHRM', 'gAMA', 'iCCP', 'sBIT', 'sRGB', 'bKGD', 'pHYs', 'acTL', 'fcTL', 'fdAT', 'cICP']);
function png(buf) {
  const parts = [buf.subarray(0, 8)];
  const actions = new Map();
  let i = 8, ended = false;
  while (i + 12 <= buf.length) {
    const len = buf.readUInt32BE(i), type = buf.toString('latin1', i + 4, i + 8);
    if (i + 12 + len > buf.length) throw new Error('PNG troncato');
    const chunk = buf.subarray(i, i + 12 + len);
    const okCrc = crc32(buf.subarray(i + 4, i + 8 + len)) === buf.readUInt32BE(i + 8 + len);
    if (!okCrc) actions.set('blocchi con CRC errato', (actions.get('blocchi con CRC errato') || 0) + 1);
    else if (PNG_KEEP.has(type)) parts.push(chunk);
    else actions.set(type, (actions.get(type) || 0) + 1);
    i += 12 + len;
    if (type === 'IEND') { ended = true; break; }
  }
  if (!ended) throw new Error('PNG senza fine (IEND)');
  const list = [...actions].map(([k, n]) => `Rimosso blocco ${k}${n > 1 ? ` (${n})` : ''}`);
  if (buf.length > i) list.push(`Eliminati ${buf.length - i} byte nascosti dopo la fine dell'immagine`);
  return { output: Buffer.concat(parts), actions: list };
}

function gif(buf) {
  const parts = [];
  const actions = new Map();
  let i = 13;
  const flags = buf[10];
  if (flags & 0x80) i += 3 * (1 << ((flags & 7) + 1));
  parts.push(buf.subarray(0, i));
  const subBlocks = (k) => { while (k < buf.length && buf[k]) k += buf[k] + 1; return k + 1; };
  while (i < buf.length) {
    const b = buf[i];
    if (b === 0x3b) { parts.push(buf.subarray(i, i + 1)); i++; break; }
    if (b === 0x21) {
      const label = buf[i + 1];
      const e = subBlocks(i + 2);
      const isLoop = label === 0xff && buf.toString('latin1', i + 3, i + 14) === 'NETSCAPE2.0';
      if (label === 0xf9 || label === 0x01 || isLoop) parts.push(buf.subarray(i, e));
      else { const k = label === 0xfe ? 'commento' : label === 0xff ? 'estensione applicativa (XMP/dati)' : `estensione 0x${label.toString(16)}`; actions.set(k, (actions.get(k) || 0) + 1); }
      i = e;
    } else if (b === 0x2c) {
      let k = i + 10;
      const f = buf[i + 9];
      if (f & 0x80) k += 3 * (1 << ((f & 7) + 1));
      k = subBlocks(k + 1);
      parts.push(buf.subarray(i, k));
      i = k;
    } else throw new Error('GIF danneggiato');
  }
  const list = [...actions].map(([k, n]) => `Rimosso ${k}${n > 1 ? ` (${n})` : ''}`);
  if (buf.length > i) list.push(`Eliminati ${buf.length - i} byte nascosti dopo la fine dell'immagine`);
  return { output: Buffer.concat(parts), actions: list };
}

function webp(buf) {
  const parts = [];
  const actions = [];
  let i = 12;
  const end = Math.min(buf.length, 8 + buf.readUInt32LE(4));
  while (i + 8 <= end) {
    const id = buf.toString('latin1', i, i + 4), len = buf.readUInt32LE(i + 4);
    const total = 8 + len + (len & 1);
    if (/^(EXIF|XMP )$/.test(id)) actions.push(`Rimossi metadati ${id.trim()}`);
    else parts.push(buf.subarray(i, i + total));
    i += total;
  }
  const body = Buffer.concat(parts);
  // VP8X flags must not announce the removed metadata
  const x = body.indexOf('VP8X');
  if (x === 0) body[8] &= ~0x0c;
  const head = Buffer.from('RIFF\0\0\0\0WEBP', 'latin1');
  head.writeUInt32LE(body.length + 4, 4);
  if (buf.length > end) actions.push(`Eliminati ${buf.length - end} byte nascosti dopo la fine dell'immagine`);
  return { output: Buffer.concat([head, body]), actions };
}

function bmp(buf) {
  const size = buf.readUInt32LE(2);
  return size < buf.length ? { output: buf.subarray(0, size), actions: [`Eliminati ${buf.length - size} byte nascosti dopo la fine dell'immagine`] } : { output: buf, actions: [] };
}

/* ----------------------------------------------------------------- Text */
const BIDI = /[‪-‮⁦-⁩‎‏؜]/g;
const INVISIBLE = /[​-‍⁠-⁤᠎]|(?!^)﻿/g;

function text(buf, { csv = false } = {}) {
  let s = buf.toString('utf8');
  const actions = [];
  const nb = (s.match(BIDI) || []).length, ni = (s.match(INVISIBLE) || []).length;
  if (nb) { s = s.replace(BIDI, ''); actions.push(`Rimossi ${nb} caratteri di controllo bidirezionale (Trojan Source)`); }
  if (ni) { s = s.replace(INVISIBLE, ''); actions.push(`Rimossi ${ni} caratteri invisibili`); }
  if (csv) {
    // CSV/formula injection: cells starting with = + - @ (or tab/CR) are executed by spreadsheets
    let n = 0;
    s = s.split(/\r?\n/).map((line) => line.split(/(,|;|\t)/).map((cell) => {
      const t = cell.replace(/^"/, '');
      if (/^[=+\-@\t\r]/.test(t) && !/^[+-]?\d[\d.,]*$/.test(t.trim())) { n++; return cell.startsWith('"') ? `"'${t}` : `'${cell}`; }
      return cell;
    }).join('')).join('\n');
    if (n) actions.push(`Neutralizzate ${n} celle con formule (CSV injection)`);
  }
  return { output: Buffer.from(s, 'utf8'), actions };
}

module.exports = { rtf, markup, jpeg, png, gif, webp, bmp, text };
