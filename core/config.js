// Creato da anvex2012
'use strict';
const { t } = require('./i18n');
const fs = require('fs');
const { file, dir } = require('./paths');

const DEFAULTS = {
  threshold: 40,           // below this score a file is considered a problem
  jobs: 0,                 // parallel analyses (0 = automatic, one per core)
  timeout: 900,            // maximum seconds per file
  cache: true,             // reuse the results of files already analyzed and unchanged
  passwords: [],           // extra passwords for protected archives
  exclude: [],             // glob patterns to skip (e.g. "**/node_modules/**")
  disabled: [],            // analyzers to disable (e.g. ["social"])
  weights: {},             // weight override per analyzer (e.g. {"privacy": 0.5})
  allowlist: [],           // SHA-256 of trusted files
  suppress: [],            // finding ids to ignore (e.g. "lines:eval", "secrets:*")
  yara: [],                // folders/files with YARA rules (in addition to ~/.gauntler/yara)
  online: { virustotal: '', malwarebazaar: '' }, // API keys (only the SHA-256 is sent)
  quarantineBelow: 15,     // in watch --quarantine: quarantine below this score
  language: '',            // interface language (it, en, es, fr, de); empty = ask on first use
};

let cached = null;
const PATH = () => file('config.json');

function load() {
  if (cached) return cached;
  let user = {};
  try { user = JSON.parse(fs.readFileSync(PATH(), 'utf8')); } catch { /* absent or invalid */ }
  cached = { ...DEFAULTS, ...user, online: { ...DEFAULTS.online, ...(user.online || {}) } };
  // Keys from environment variables take precedence
  if (process.env.VT_API_KEY) cached.online.virustotal = process.env.VT_API_KEY;
  if (process.env.MB_API_KEY || process.env.ABUSECH_API_KEY) cached.online.malwarebazaar = process.env.MB_API_KEY || process.env.ABUSECH_API_KEY;
  return cached;
}

function saveUser(obj) {
  dir();
  fs.writeFileSync(PATH(), JSON.stringify(obj, null, 2) + '\n', { mode: 0o600 });
  cached = null;
}
function userConfig() {
  try { return JSON.parse(fs.readFileSync(PATH(), 'utf8')); } catch { return {}; }
}

function parseValue(v) {
  if (v === undefined) return v;
  try { return JSON.parse(v); } catch { return v; }
}
function getPath(obj, key) {
  return key.split('.').reduce((o, k) => (o == null ? undefined : o[k]), obj);
}
function setPath(obj, key, value) {
  const ks = key.split('.');
  let o = obj;
  for (const k of ks.slice(0, -1)) o = o[k] = typeof o[k] === 'object' && o[k] ? o[k] : {};
  if (value === undefined) delete o[ks[ks.length - 1]];
  else o[ks[ks.length - 1]] = value;
}

function get(key) { return key ? getPath(load(), key) : load(); }
function set(key, value) {
  if (!(key.split('.')[0] in DEFAULTS)) throw new Error(t('Chiave sconosciuta: {key}. Chiavi valide: {list}', { key, list: Object.keys(DEFAULTS).join(', ') }));
  const u = userConfig();
  setPath(u, key, parseValue(value));
  saveUser(u);
}
function unset(key) { const u = userConfig(); setPath(u, key, undefined); saveUser(u); }
function add(key, value) {
  const cur = get(key);
  if (!Array.isArray(cur)) throw new Error(t('"{key}" non è una lista', { key }));
  if (cur.includes(value)) return false;
  const u = userConfig();
  setPath(u, key, [...cur, value]);
  saveUser(u);
  return true;
}
function remove(key, value) {
  const cur = get(key);
  if (!Array.isArray(cur)) throw new Error(t('"{key}" non è una lista', { key }));
  const u = userConfig();
  setPath(u, key, cur.filter((x) => x !== value));
  saveUser(u);
}

module.exports = { DEFAULTS, load, get, set, unset, add, remove, path: PATH, reset: () => { cached = null; } };
