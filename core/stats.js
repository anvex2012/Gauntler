// Creato da anvex2012
'use strict';
const zlib = require('zlib');

/**
 * Incremental statistical analysis (works on files of any size, in blocks):
 * Shannon entropy, chi-square, Monte Carlo π, serial correlation, arithmetic mean,
 * compression ratio (sampled), entropy profile, byte histogram, printable/null ratio.
 */
class StatsAccumulator {
  constructor(total, points = 160) {
    this.total = total;
    this.freq = new Float64Array(256);
    this.n = 0;
    this.t1 = 0; this.t2 = 0; this.t3 = 0;
    this.first = -1; this.prev = -1;
    this.mcBuf = []; this.mcIn = 0; this.mcN = 0;
    this.seg = Math.max(256, Math.ceil(total / points));
    this.segFreq = new Uint32Array(256); this.segCount = 0;
    this.profile = [];
    this.compIn = 0; this.compOut = 0; this.samples = 0;
    this.maxSamples = 24;
    this.sampleEvery = Math.max(1, Math.floor(total / this.maxSamples));
    this.nextSample = 0;
  }

  _flushSeg() {
    let h = 0;
    for (let i = 0; i < 256; i++) if (this.segFreq[i]) { const p = this.segFreq[i] / this.segCount; h -= p * Math.log2(p); }
    this.profile.push(+h.toFixed(3));
    this.segFreq.fill(0); this.segCount = 0;
  }

  update(buf) {
    const freq = this.freq, segFreq = this.segFreq, seg = this.seg;
    let prev = this.prev, t1 = this.t1, t2 = this.t2, t3 = this.t3;
    if (this.first < 0 && buf.length) this.first = buf[0];
    for (let i = 0; i < buf.length; i++) {
      const b = buf[i];
      freq[b]++;
      if (prev >= 0) t1 += prev * b;
      t2 += b; t3 += b * b;
      prev = b;
      segFreq[b]++;
      if (++this.segCount === seg) this._flushSeg();
    }
    this.prev = prev; this.t1 = t1; this.t2 = t2; this.t3 = t3;
    // Monte Carlo: groups of 6 bytes (24-bit x,y coordinates)
    const mc = this.mcBuf.length ? Buffer.concat([Buffer.from(this.mcBuf), buf]) : buf;
    const groups = Math.floor(mc.length / 6);
    const max = 16777215;
    for (let g = 0; g < groups; g++) {
      const o = g * 6;
      const x = ((mc[o] << 16) | (mc[o + 1] << 8) | mc[o + 2]) / max;
      const y = ((mc[o + 3] << 16) | (mc[o + 4] << 8) | mc[o + 5]) / max;
      if (x * x + y * y <= 1) this.mcIn++;
    }
    this.mcN += groups;
    this.mcBuf = Array.from(mc.subarray(groups * 6));
    // Compression on samples spread across the file
    const start = this.n;
    this.n += buf.length;
    while (this.samples < this.maxSamples && this.nextSample < this.n) {
      const rel = this.nextSample - start;
      const s = buf.subarray(Math.max(0, rel), Math.max(0, rel) + 512 * 1024);
      if (s.length >= 64) {
        try { this.compOut += zlib.deflateRawSync(s, { level: 6 }).length; this.compIn += s.length; } catch { /* ignore */ }
      }
      this.samples++;
      this.nextSample += this.sampleEvery;
    }
  }

  result() {
    if (this.segCount) this._flushSeg();
    const n = this.n || 1;
    let h = 0, chi = 0;
    const exp = n / 256;
    let printable = 0;
    for (let i = 0; i < 256; i++) {
      const f = this.freq[i];
      if (f) { const p = f / n; h -= p * Math.log2(p); }
      chi += ((f - exp) ** 2) / exp;
      if ((i >= 32 && i < 127) || i === 9 || i === 10 || i === 13) printable += f;
    }
    // Circular serial correlation (as in `ent`)
    const t1 = this.t1 + (this.prev >= 0 && this.first >= 0 ? this.prev * this.first : 0);
    const den = n * this.t3 - this.t2 * this.t2;
    const serial = den === 0 ? 1 : (n * t1 - this.t2 * this.t2) / den;
    const pi = this.mcN >= 100 ? (4 * this.mcIn) / this.mcN : null;
    const maxF = Math.max(...this.freq) || 1;
    // chi-square p-value approximation (255 degrees of freedom, Wilson-Hilferty)
    const k = 255;
    const z = (Math.cbrt(chi / k) - (1 - 2 / (9 * k))) / Math.sqrt(2 / (9 * k));
    const chiP = 1 - normCdf(z);
    return {
      entropy: h,
      chi,
      chiP,
      mean: this.t2 / n,
      pi,
      piErr: pi ? Math.abs(pi - Math.PI) / Math.PI : null,
      serial,
      compression: this.compIn ? this.compOut / this.compIn : 1,
      printableRatio: printable / n,
      nullRatio: this.freq[0] / n,
      profile: this.profile,
      histogram: Array.from(this.freq, (f) => +(f / maxF).toFixed(4)),
      uniqueBytes: this.freq.filter((f) => f > 0).length,
    };
  }
}

function normCdf(z) {
  const t = 1 / (1 + 0.2316419 * Math.abs(z));
  const d = 0.3989423 * Math.exp(-z * z / 2);
  const p = d * t * (0.3193815 + t * (-0.3565638 + t * (1.781478 + t * (-1.821256 + t * 1.330274))));
  return z > 0 ? 1 - p : p;
}

module.exports = { StatsAccumulator };
