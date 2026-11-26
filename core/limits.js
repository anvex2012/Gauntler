// Creato da anvex2012
'use strict';
const { m: msg } = require('./i18n');
/**
 * Decompression limits (protection against ZIP bombs and every other "decompression bomb").
 *
 * A single Budget is shared by the whole recursive analysis of ONE root file: every byte produced by
 * a decompressor (ZIP, GZIP, PDF FlateDecode, zlib/gzip payloads, 7-Zip/xz/bzip2) and every file pulled
 * out of an archive is charged to it. When any limit is exceeded the budget "trips": all further
 * extraction stops, at every nesting level, and the analysis reports a critical finding.
 *
 * Limits (all overridable with options.limits or "limits" in ~/.gauntler/config.json):
 *  maxEntryBytes   largest single decompressed object
 *  maxTotalBytes   total decompressed bytes for the whole root file (all nesting levels)
 *  maxRatio        max compression ratio of a single object…
 *  ratioMinBytes   …applied only once the output exceeds this size (small, very compressible files are fine)
 *  maxFiles        total number of files extracted from archives
 *  maxMemoryBytes  growth of the process' Buffer memory since the analysis started
 */
const zlib = require('zlib');

const MiB = 1024 * 1024;
const DEFAULTS = Object.freeze({
  maxEntryBytes: 256 * MiB,
  maxTotalBytes: 1024 * MiB,
  maxRatio: 100,
  ratioMinBytes: 16 * MiB,
  maxFiles: 10000,
  maxMemoryBytes: 2048 * MiB,
});

const memNow = () => { const m = process.memoryUsage(); return m.arrayBuffers || m.external || 0; };

function normalize(limits) {
  const out = { ...DEFAULTS };
  for (const k of Object.keys(DEFAULTS)) {
    const v = limits && limits[k];
    if (v != null && Number.isFinite(Number(v)) && Number(v) > 0) out[k] = Number(v);
  }
  return out;
}

class LimitError extends Error {
  constructor(reason, detail) { super(detail); this.reason = reason; this.limit = true; }
}

class Budget {
  constructor(limits) {
    this.limits = normalize(limits);
    this.totalBytes = 0;
    this.files = 0;
    this.exceeded = null; // { reason, detail, where }
    this.memBase = memNow();
  }

  get tripped() { return !!this.exceeded; }

  trip(reason, detail, where) {
    if (!this.exceeded) this.exceeded = { reason, detail, where: where || null };
    return false;
  }

  remaining() { return Math.max(0, this.limits.maxTotalBytes - this.totalBytes); }

  /** Max bytes that may be produced by decompressing `compressedSize` bytes (0 → no ratio cap known) */
  capFor(compressedSize) {
    const L = this.limits;
    let cap = Math.min(L.maxEntryBytes, this.remaining());
    if (compressedSize > 0) cap = Math.min(cap, Math.max(L.ratioMinBytes, compressedSize * L.maxRatio));
    return Math.max(0, Math.floor(cap));
  }

  /** Explains which limit a decompression that hit `cap` exceeded */
  explainCap(compressedSize, cap, where) {
    const L = this.limits;
    const ratioCap = compressedSize > 0 ? Math.floor(Math.max(L.ratioMinBytes, compressedSize * L.maxRatio)) : Infinity;
    if (ratioCap <= cap) return this.trip('ratio', msg('Rapporto di compressione oltre {max}:1 ({c} compressi → più di {cap}).', { max: L.maxRatio, c: fmt(compressedSize), cap: fmt(cap) }), where);
    if (this.remaining() <= cap) return this.trip('total', msg('Dati decompressi oltre il limite totale di {max}.', { max: fmt(L.maxTotalBytes) }), where);
    return this.trip('entry', msg('Un singolo oggetto decompresso supera {max}.', { max: fmt(L.maxEntryBytes) }), where);
  }

  /** Registers one file extracted from an archive */
  admitFile(where) {
    if (this.exceeded) return false;
    if (this.files + 1 > this.limits.maxFiles) return this.trip('files', msg('Più di {n} file estratti dagli archivi.', { n: this.limits.maxFiles }), where);
    this.files++;
    return true;
  }

  /** Charges n decompressed bytes. Returns false (and trips) when a limit is exceeded. */
  consume(n, where, compressedSize = 0) {
    if (this.exceeded) return false;
    const L = this.limits;
    if (n > L.maxEntryBytes) return this.trip('entry', msg('Un singolo oggetto decompresso ({size}) supera {max}.', { size: fmt(n), max: fmt(L.maxEntryBytes) }), where);
    if (compressedSize > 0 && n > L.ratioMinBytes && n / compressedSize > L.maxRatio) return this.trip('ratio', msg('Rapporto di compressione {r}:1 oltre il limite di {max}:1.', { r: Math.round(n / compressedSize), max: L.maxRatio }), where);
    if (this.totalBytes + n > L.maxTotalBytes) return this.trip('total', msg('Dati decompressi oltre il limite totale di {max}.', { max: fmt(L.maxTotalBytes) }), where);
    this.totalBytes += n;
    return this.checkMemory(where);
  }

  checkMemory(where) {
    if (this.exceeded) return false;
    // Decompressed buffers stay referenced until the root analysis ends, so totalBytes is a deterministic
    // lower bound of the memory held; the process measurement also catches what the budget cannot see
    // (decoded strings, copies). The garbage collector can make the measured growth smaller, never larger.
    const used = () => Math.max(this.totalBytes, memNow() - this.memBase);
    if (used() > this.limits.maxMemoryBytes) {
      if (global.gc) global.gc();
      if (used() > this.limits.maxMemoryBytes) return this.trip('memory', msg('Memoria usata dall\'analisi oltre {max}.', { max: fmt(this.limits.maxMemoryBytes) }), where);
    }
    return true;
  }

  /**
   * Runs a zlib *Sync decompressor with a hard output cap and charges the result.
   * Returns { data } | { limit: true } | { error }
   */
  inflate(fn, data, where, opts = {}) {
    if (this.exceeded) return { limit: true };
    const cap = this.capFor(data.length);
    if (cap <= 0) { this.explainCap(data.length, cap, where); return { limit: true }; }
    let out;
    try { out = fn(data, { ...opts, maxOutputLength: cap }); } catch (e) {
      if (isTooLarge(e)) { this.explainCap(data.length, cap, where); return { limit: true }; }
      return { error: e };
    }
    if (!this.consume(out.length, where, data.length)) return { limit: true };
    return { data: out };
  }
}

const isTooLarge = (e) => e && (e.code === 'ERR_BUFFER_TOO_LARGE' || e.code === 'ENOBUFS' || e instanceof RangeError);

function fmt(n) {
  if (n >= 1024 * MiB) return `${+(n / (1024 * MiB)).toFixed(2)} GB`;
  if (n >= MiB) return `${+(n / MiB).toFixed(1)} MB`;
  if (n >= 1024) return `${+(n / 1024).toFixed(1)} KB`;
  return `${n} byte`;
}

/** Budget used when a helper is called standalone (no analysis in progress) */
const standalone = (limits) => new Budget(limits);

/** zlib helpers bound to a budget */
const inflateRaw = (budget, data, where, opts) => budget.inflate(zlib.inflateRawSync, data, where, opts);
const inflateZlib = (budget, data, where, opts) => budget.inflate(zlib.inflateSync, data, where, opts);
const gunzip = (budget, data, where, opts) => budget.inflate(zlib.gunzipSync, data, where, opts);

module.exports = { DEFAULTS, Budget, LimitError, normalize, standalone, inflateRaw, inflateZlib, gunzip, isTooLarge, fmt };
