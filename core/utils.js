// Creato da anvex2012
'use strict';

/** Shannon entropy (bits per byte, 0..8) */
function shannon(buf, start = 0, end = buf.length) {
  const len = end - start;
  if (len <= 0) return 0;
  const freq = new Uint32Array(256);
  for (let i = start; i < end; i++) freq[buf[i]]++;
  let h = 0;
  for (let i = 0; i < 256; i++) {
    if (!freq[i]) continue;
    const p = freq[i] / len;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Entropy of a string (by character) */
function strEntropy(s) {
  if (!s.length) return 0;
  const m = new Map();
  for (const c of s) m.set(c, (m.get(c) || 0) + 1);
  let h = 0;
  for (const v of m.values()) { const p = v / s.length; h -= p * Math.log2(p); }
  return h;
}

function isLikelyText(buf) {
  const n = Math.min(buf.length, 65536);
  if (!n) return true;
  let printable = 0;
  for (let i = 0; i < n; i++) {
    const c = buf[i];
    if (c === 0) {
      // UTF-16 with BOM: treat as text
      return (buf[0] === 0xff && buf[1] === 0xfe) || (buf[0] === 0xfe && buf[1] === 0xff);
    }
    if (c === 9 || c === 10 || c === 13 || c === 12 || (c >= 32 && c < 127) || c >= 128) printable++;
  }
  return printable / n > 0.92;
}

/** Hides most of a secret: the report never contains it in full */
function mask(s) {
  s = String(s);
  if (s.length <= 8) return s[0] + '*'.repeat(Math.max(3, s.length - 1));
  return s.slice(0, 4) + '*'.repeat(Math.min(12, s.length - 6)) + s.slice(-2);
}

function truncate(s, n = 160) {
  s = String(s).replace(/[\x00-\x08\x0b-\x1f\x7f]/g, ' ');
  return s.length > n ? s.slice(0, n) + '…' : s;
}

function countMatches(text, re) {
  re.lastIndex = 0;
  let c = 0, m;
  while ((m = re.exec(text))) { c++; if (!m[0].length) re.lastIndex++; }
  re.lastIndex = 0;
  return c;
}

function findAll(text, re) {
  const out = [];
  re.lastIndex = 0;
  let m;
  while ((m = re.exec(text))) {
    out.push(m);
    if (m[0].length === 0) re.lastIndex++;
  }
  re.lastIndex = 0;
  return out;
}

function luhn(num) {
  let sum = 0, alt = false;
  for (let i = num.length - 1; i >= 0; i--) {
    let d = num.charCodeAt(i) - 48;
    if (alt) { d *= 2; if (d > 9) d -= 9; }
    sum += d; alt = !alt;
  }
  return sum % 10 === 0;
}

function ibanValid(iban) {
  const s = iban.replace(/\s+/g, '').toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(s)) return false;
  const r = s.slice(4) + s.slice(0, 4);
  let rem = 0;
  for (const ch of r) {
    const v = /\d/.test(ch) ? ch : String(ch.charCodeAt(0) - 55);
    for (const d of v) rem = (rem * 10 + Number(d)) % 97;
  }
  return rem === 1;
}

function formatBytes(n) {
  if (n < 1024) return n + ' B';
  const u = ['KB', 'MB', 'GB', 'TB'];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(1) + ' ' + u[i];
}

/* ---- Lines ---- */
function buildLineIndex(text) {
  const idx = [0];
  let i = -1;
  while ((i = text.indexOf('\n', i + 1)) !== -1) idx.push(i + 1);
  return idx;
}
/** 0-based index of the line that contains pos */
function lineOfIndex(idx, pos) {
  let lo = 0, hi = idx.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (idx[mid] <= pos) lo = mid; else hi = mid - 1;
  }
  return lo;
}
function lineTextAt(text, pos, max = 1000) {
  const s = text.lastIndexOf('\n', pos - 1) + 1;
  let e = text.indexOf('\n', pos);
  if (e < 0) e = text.length;
  return text.slice(s, Math.min(e, s + max)).replace(/\r$/, '');
}
/** Printable run around pos (for binaries) */
function printableAround(text, pos, max = 300) {
  let s = pos, e = pos;
  const ok = (c) => c >= 32 && c < 127;
  while (s > 0 && pos - s < max && ok(text.charCodeAt(s - 1))) s--;
  while (e < text.length && e - pos < max && ok(text.charCodeAt(e))) e++;
  return text.slice(s, e);
}

function fmtLoc(loc) {
  if (!loc) return '';
  const parts = [];
  if (loc.source) parts.push(loc.source);
  if (loc.line != null) parts.push(`riga ${loc.line}`);
  else if (loc.offset != null) parts.push(`offset 0x${loc.offset.toString(16)}`);
  return parts.join(', ');
}

/** Documentation / type definitions / licenses: they describe, they don't execute */
function isDoc(name) {
  return /\.(md|markdown|rst|txt|adoc|d\.ts|d\.mts|d\.cts)$/i.test(name) || /^(license|licence|notice|readme|changelog|authors|copying|third[_-]?party)/i.test(name) || /licen[sc]es?[\w.-]*\.html?$/i.test(name);
}

module.exports = {
  isDoc, shannon, strEntropy, isLikelyText, mask, truncate, countMatches, findAll, luhn, ibanValid, formatBytes,
  buildLineIndex, lineOfIndex, lineTextAt, printableAround, fmtLoc,
};
