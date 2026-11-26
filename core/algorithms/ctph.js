// Created by anvex2012
'use strict';
/**
 * Context-Triggered Piecewise Hashing (the spamsum / ssdeep algorithm, Kornblum 2006).
 * A rolling hash over a 7-byte window decides where to cut the file into pieces; each piece is
 * summarized with one base64 character of an FNV hash. Two files that share large parts produce
 * similar signatures even if bytes were inserted/removed, so variants of the same malware can be
 * recognized. compare() returns a 0-100 similarity score (weighted edit distance, as in ssdeep).
 */
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const SPAMSUM_LENGTH = 64, MIN_BS = 3, WIN = 7, INIT = 0x28021967, PRIME = 0x01000193;

/**
 * One pass computes the pieces for several block sizes at once (bs, bs/2, …): a trigger for
 * block size 3·2^k implies a trigger for every smaller size, so levels are checked bottom-up.
 */
function hashLevels(buf, sizes) {
  const L = sizes.length; // ascending; level L = 2 × largest (for its second piece string)
  const all = [...sizes, sizes[L - 1] * 2];
  const win = new Uint8Array(WIN);
  let h1 = 0, h2 = 0, h3 = 0, wi = 0;
  const ha = new Int32Array(L + 1).fill(INIT);
  const p = Array.from({ length: L + 1 }, () => '');
  for (let i = 0; i < buf.length; i++) {
    const c = buf[i];
    h2 = (h2 - h1 + WIN * c) | 0;
    h1 = (h1 + c - win[wi]) | 0;
    win[wi] = c;
    if (++wi === WIN) wi = 0;
    h3 = (h3 << 5) ^ c;
    const rh = (h1 + h2 + h3) >>> 0;
    for (let k = 0; k <= L; k++) ha[k] = Math.imul(ha[k], PRIME) ^ c;
    for (let k = 0; k <= L; k++) {
      const bs = all[k];
      if (rh % bs !== bs - 1) break;
      if (p[k].length < SPAMSUM_LENGTH - 1) { p[k] += B64[(ha[k] >>> 0) % 64]; ha[k] = INIT; }
    }
  }
  const rh = (h1 + h2 + h3) >>> 0;
  if (rh !== 0) for (let k = 0; k <= L; k++) p[k] += B64[(ha[k] >>> 0) % 64];
  return { all, p };
}

/** Signature "blocksize:hash1:hash2" (same result as the classic multi-pass spamsum) */
function hash(buf) {
  let top = MIN_BS;
  while (top * SPAMSUM_LENGTH < buf.length) top *= 2;
  for (;;) {
    const sizes = [];
    for (let s = top, k = 0; s >= MIN_BS && k < 6; s /= 2, k++) sizes.unshift(s);
    const { all, p } = hashLevels(buf, sizes);
    for (let k = sizes.length - 1; k >= 0; k--) {
      const s = all[k];
      if (s > MIN_BS && p[k].length < SPAMSUM_LENGTH / 2) continue;
      // the second piece string (block size 2s) is limited to 31 characters + the final one
      const raw = p[k + 1];
      const p2 = raw.length > SPAMSUM_LENGTH / 2 ? raw.slice(0, SPAMSUM_LENGTH / 2 - 1) + raw[raw.length - 1] : raw;
      return `${s}:${p[k]}:${p2}`;
    }
    top = sizes[0] / 2; // every level was too short: continue with smaller block sizes
  }
}

/** Removes runs of more than 3 identical characters (as ssdeep does before comparing) */
const squeeze = (s) => s.replace(/(.)\1{3,}/g, '$1$1$1');

function editDistance(a, b) {
  // insert/delete cost 1, substitution cost 2 (ssdeep weighting)
  let prev = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    for (let j = 1; j <= b.length; j++) cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 2));
    prev = cur;
  }
  return prev[b.length];
}

/** Common substring of length ≥ 7 (required by ssdeep to avoid random matches) */
function hasCommon(a, b) {
  if (a.length < WIN || b.length < WIN) return false;
  const set = new Set();
  for (let i = 0; i + WIN <= a.length; i++) set.add(a.slice(i, i + WIN));
  for (let i = 0; i + WIN <= b.length; i++) if (set.has(b.slice(i, i + WIN))) return true;
  return false;
}

function scoreStrings(a, b, bs) {
  if (!hasCommon(a, b)) return 0;
  let s = editDistance(a, b);
  s = (s * SPAMSUM_LENGTH) / (a.length + b.length);
  s = (100 * s) / SPAMSUM_LENGTH;
  if (s >= 100) return 0;
  s = 100 - s;
  const cap = (bs / MIN_BS) * Math.min(a.length, b.length);
  return Math.round(Math.min(s, cap));
}

function compare(sigA, sigB) {
  const [bsA, a1, a2] = sigA.split(':');
  const [bsB, b1, b2] = sigB.split(':');
  const A = +bsA, B = +bsB;
  if (A !== B && A !== B * 2 && B !== A * 2) return 0;
  const [x1, x2, y1, y2] = [a1, a2, b1, b2].map(squeeze);
  if (A === B && x1 === y1) return 100;
  if (A === B) return Math.max(scoreStrings(x1, y1, A), scoreStrings(x2, y2, A * 2));
  if (A === B * 2) return scoreStrings(x1, y2, A);
  return scoreStrings(x2, y1, B);
}

module.exports = { hash, compare };
