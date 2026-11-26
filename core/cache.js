// Created by anvex2012
'use strict';
/**
 * Result cache: a file identical to one already analyzed (same SHA-256, same engine version and
 * same options) is not re-analyzed. The engine fingerprint changes automatically when
 * rules, analyzers or source code are modified.
 */
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');
const { dir } = require('./paths');

let FINGERPRINT = null;
function engineFingerprint() {
  if (FINGERPRINT) return FINGERPRINT;
  const h = crypto.createHash('sha1');
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (/\.(js|json)$/.test(e.name)) h.update(e.name).update(fs.readFileSync(p));
    }
  };
  walk(__dirname);
  FINGERPRINT = h.digest('hex').slice(0, 16);
  return FINGERPRINT;
}

/** ClamAV state: results are recomputed when ClamAV is installed or its signatures change */
function clamavStamp(options) {
  if (options.noClamav) return 'off';
  try {
    if (!require('./analyzers/clamav').available()) return 'none';
    const db = require('./setup').ownDatabase();
    if (!db) return 'system';
    return fs.readdirSync(db).filter((f) => /^(main|daily)\.c[lv]d$/.test(f)).map((f) => f + fs.statSync(path.join(db, f)).mtimeMs).join(',');
  } catch { return 'unknown'; }
}

function key(sha256, options) {
  const relevant = {
    clamav: clamavStamp(options),
    detail: !!options.detail, passwords: options.passwords || [], only: options.only || null, skip: options.skip || null,
    noClamav: !!options.noClamav, online: !!options.online, suppress: options.suppress || [], weights: options.weights || {},
    allowlist: (options.allowlist || []).includes(sha256), yara: options.yara || [], limits: options.limits || null,
  };
  return crypto.createHash('sha256').update(sha256 + engineFingerprint() + JSON.stringify(relevant)).digest('hex');
}

const fileFor = (k) => path.join(dir('cache', k.slice(0, 2)), k + '.json.gz');

function get(sha256, options) {
  try {
    const raw = fs.readFileSync(fileFor(key(sha256, options)));
    return JSON.parse(zlib.gunzipSync(raw).toString('utf8'));
  } catch { return null; }
}

function put(sha256, options, result) {
  try {
    fs.writeFileSync(fileFor(key(sha256, options)), zlib.gzipSync(JSON.stringify(result), { level: 6 }));
  } catch { /* cache not writable: ignore */ }
}

function stats() {
  let files = 0, bytes = 0;
  try {
    const root = dir('cache');
    for (const d of fs.readdirSync(root)) for (const f of fs.readdirSync(path.join(root, d))) { files++; bytes += fs.statSync(path.join(root, d, f)).size; }
  } catch { /* */ }
  return { files, bytes };
}
function clear() { fs.rmSync(dir('cache'), { recursive: true, force: true }); }

module.exports = { get, put, stats, clear, engineFingerprint };
