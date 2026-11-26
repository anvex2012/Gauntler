// Created by anvex2012
'use strict';
/**
 * Translations (gettext style): the Italian text is the key, the dictionaries in ./locales
 * map it to the other languages ({ "testo italiano": [en, es, fr, de] }).
 * Placeholders: {name} → vars.name. A missing translation falls back to Italian.
 *
 * Two ways to use it:
 *  - t(text, vars)   translates immediately into the current language (CLI, reports, GUI main process)
 *  - m(text, vars)   used by the analyzers: returns the Italian text (so that finding ids and the
 *                    "suppress" rules never depend on the language) and remembers how it was built;
 *                    localize() then translates the whole result at the end of the analysis.
 */
const fs = require('fs');
const path = require('path');

const LANGUAGES = [
  { code: 'it', name: 'Italiano', locale: 'it-IT' },
  { code: 'en', name: 'English', locale: 'en-US' },
  { code: 'es', name: 'Español', locale: 'es-ES' },
  { code: 'fr', name: 'Français', locale: 'fr-FR' },
  { code: 'de', name: 'Deutsch', locale: 'de-DE' },
];
const CODES = LANGUAGES.map((l) => l.code);
const COLUMN = { en: 0, es: 1, fr: 2, de: 3 };

let DICT = null;
function dict() {
  if (DICT) return DICT;
  DICT = new Map();
  const dir = path.join(__dirname, 'locales');
  let files = [];
  try { files = fs.readdirSync(dir).filter((f) => f.endsWith('.json')).sort(); } catch { /* no dictionaries */ }
  for (const f of files) {
    try { for (const [k, v] of Object.entries(JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')))) DICT.set(k, v); } catch { /* invalid file: ignored */ }
  }
  return DICT;
}

const normalize = (code) => {
  const c = String(code || '').toLowerCase().slice(0, 2);
  return CODES.includes(c) ? c : null;
};

/** Language saved in ~/.gauntler/config.json (read directly: config.js depends on this module) */
function savedLanguage() {
  try { return normalize(JSON.parse(fs.readFileSync(require('./paths').file('config.json'), 'utf8')).language); } catch { return null; }
}
let current = normalize(process.env.GAUNTLER_LANG) || savedLanguage() || 'it';
function setLanguage(code) { const c = normalize(code); if (c) current = c; return current; }
const getLanguage = () => current;
const locale = (lang = current) => (LANGUAGES.find((l) => l.code === lang) || LANGUAGES[0]).locale;

/** Translation of a static text (no placeholders filled in) */
function lookup(text, lang = current, strict = false) {
  if (lang === 'it' || typeof text !== 'string') return text;
  const e = dict().get(text);
  if (e && e[COLUMN[lang]]) return e[COLUMN[lang]];
  // "esecuzione" → translation of "Esecuzione", with a lowercase initial (German keeps the capital)
  const c0 = text.charAt(0);
  if (!strict && c0 && c0 !== c0.toUpperCase()) {
    const u = dict().get(c0.toUpperCase() + text.slice(1));
    const tr = u && u[COLUMN[lang]];
    if (tr) return lang === 'de' ? tr : tr.charAt(0).toLowerCase() + tr.slice(1);
  }
  return text;
}

/* Registry of the messages built by m(): Italian text → [text, vars] */
const REG = new Map();
const REG_MAX = 200000;

function fill(tpl, vars, lang, pack) {
  if (!vars) return tpl;
  return tpl.replace(/\{(\w+)\}/g, (all, k) => (Object.prototype.hasOwnProperty.call(vars, k) ? value(vars[k], lang, pack) : all));
}
// A list placeholder becomes "a, b, c" (each element translated)
function value(v, lang, pack) {
  if (Array.isArray(v)) return v.map((x) => value(x, lang, pack)).join(', ');
  return String(lang === 'it' ? v : translate(v, lang, pack));
}

/** Immediate translation into the current language */
function t(text, vars) { return fill(lookup(text, current), vars, current); }
/** Immediate translation into a given language */
function tl(lang, text, vars) { const l = normalize(lang) || current; return fill(lookup(text, l), vars, l); }

/** Deferred translation (analyzers): returns Italian, translated later by localize() */
function m(text, vars) {
  const out = fill(text, vars, 'it');
  if (vars && out !== text) {
    if (REG.size > REG_MAX) REG.clear();
    REG.set(out, [text, vars]);
  }
  return out;
}

/** Translates a single value (string produced by m(), static text, or anything else unchanged) */
function translate(v, lang = current, pack = null, strict = false) {
  if (typeof v !== 'string' || lang === 'it' || !v) return v;
  const r = (pack && Object.prototype.hasOwnProperty.call(pack, v) && pack[v]) || REG.get(v);
  if (r) return fill(lookup(r[0], lang), r[1], lang, pack);
  return lookup(v, lang, strict);
}

// Fields that contain file data (never translated) or that would be too large to walk
// Objects whose keys are labels for people (the other keys are field names)
const KEYED = new Set(['info', 'metadata']);
const SKIP = new Set(['source', 'strings', 'head', 'hashes', 'text', 'preview', 'path', 'sha256', 'md5', 'sha1', 'raw', 'bytes', 'hex', 'chain', 'i18n', 'listing']);

function walkStrings(value, fn, key = '') {
  const walk = (v, k) => {
    if (typeof v === 'string') { if (v.length <= 4000) fn(v); return; }
    if (!v || typeof v !== 'object' || SKIP.has(k)) return;
    if (Array.isArray(v)) { for (const x of v) walk(x, k); return; }
    if (ArrayBuffer.isView(v)) return;
    for (const [kk, vv] of Object.entries(v)) { fn(kk); walk(vv, kk); }
  };
  walk(value, key);
}

/**
 * Translation pack of a result: how each message built by m() was composed ({ italian: [text, vars] }).
 * Stored with the result (and in the cache), so the result can be translated into any language later,
 * in any process (the desktop app translates it again when the language changes).
 */
function pack(result) {
  const out = {};
  const add = (s) => {
    if (Object.prototype.hasOwnProperty.call(out, s)) return;
    const r = REG.get(s);
    if (!r) return;
    out[s] = r;
    for (const v of Object.values(r[1])) (Array.isArray(v) ? v : [v]).forEach((x) => { if (typeof x === 'string') add(x); });
  };
  walkStrings(result, add);
  return out;
}

/** Translates a whole analysis result (deep copy); uses the result's own pack (result.i18n) */
function localize(value, lang = current, key = '') {
  const l = normalize(lang) || 'it';
  const p = (value && value.i18n) || null;
  if (l === 'it') return value;
  const walk = (v, k) => {
    if (typeof v === 'string') return v.length > 4000 ? v : translate(v, l, p, true);
    if (!v || typeof v !== 'object' || SKIP.has(k)) return v;
    if (Array.isArray(v)) return v.map((x) => walk(x, k));
    if (ArrayBuffer.isView(v)) return v;
    // File block: names, paths and hashes stay as they are, only the fields meant for people are translated
    if (k === 'file' && 'hashes' in v) {
      const f = { ...v, encoding: translate(v.encoding, l, p), origin: translate(v.origin, l, p) };
      if (v.type && typeof v.type === 'object') f.type = { ...v.type, label: translate(v.type.label, l, p) };
      return f;
    }
    const out = {};
    for (const [kk, vv] of Object.entries(v)) out[KEYED.has(k) ? translate(kk, l, p, true) : kk] = walk(vv, kk);
    return out;
  };
  return walk(value, key);
}

/** Result for people in the given language, without the translation pack */
function finish(result, lang) {
  const r = localize(result, lang);
  if (r && r.i18n) { const { i18n: _drop, ...rest } = r; return rest; }
  return r;
}

/** All the dictionary entries (for the interface and the consistency checks) */
function entries() { return dict(); }

module.exports = { savedLanguage, LANGUAGES, CODES, COLUMN, normalize, setLanguage, getLanguage, locale, lookup, t, tl, m, translate, localize, pack, finish, entries };
