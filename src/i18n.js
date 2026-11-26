// Creato da anvex2012
/**
 * Translations for the interface: same dictionaries as the engine and the terminal (core/locales),
 * same rules as core/i18n.js — the Italian text is the key, {name} placeholders, Italian as fallback.
 * Analysis results arrive in Italian with their translation pack (result.i18n) and are translated
 * here, so changing the language also translates the results already on screen.
 */
import { createContext, useContext } from 'react';

const FILES = import.meta.glob('../core/locales/*.json', { eager: true, import: 'default' });
const DICT = new Map();
for (const k of Object.keys(FILES).sort()) for (const [it, tr] of Object.entries(FILES[k])) DICT.set(it, tr);

export const LANGUAGES = [
  { code: 'it', name: 'Italiano', locale: 'it-IT' },
  { code: 'en', name: 'English', locale: 'en-US' },
  { code: 'es', name: 'Español', locale: 'es-ES' },
  { code: 'fr', name: 'Français', locale: 'fr-FR' },
  { code: 'de', name: 'Deutsch', locale: 'de-DE' },
];
const COLUMN = { en: 0, es: 1, fr: 2, de: 3 };
export const normalize = (code) => { const c = String(code || '').toLowerCase().slice(0, 2); return LANGUAGES.some((l) => l.code === c) ? c : null; };

let current = 'it';
export const getLanguage = () => current;
export function setLanguage(code) {
  const c = normalize(code);
  if (c) { current = c; document.documentElement.lang = c; }
  return current;
}
export const locale = () => (LANGUAGES.find((l) => l.code === current) || LANGUAGES[0]).locale;

function lookup(text, lang, strict = false) {
  if (lang === 'it' || typeof text !== 'string') return text;
  const e = DICT.get(text);
  if (e && e[COLUMN[lang]]) return e[COLUMN[lang]];
  const c0 = text.charAt(0);
  if (!strict && c0 && c0 !== c0.toUpperCase()) {
    const u = DICT.get(c0.toUpperCase() + text.slice(1));
    const tr = u && u[COLUMN[lang]];
    if (tr) return lang === 'de' ? tr : tr.charAt(0).toLowerCase() + tr.slice(1);
  }
  return text;
}
const has = (o, k) => !!o && Object.prototype.hasOwnProperty.call(o, k);
function fill(tpl, vars, lang, pack) {
  if (!vars) return tpl;
  return tpl.replace(/\{(\w+)\}/g, (all, k) => (has(vars, k) ? value(vars[k], lang, pack) : all));
}
function value(v, lang, pack) {
  if (Array.isArray(v)) return v.map((x) => value(x, lang, pack)).join(', ');
  return String(lang === 'it' ? v : translate(v, lang, pack));
}

/** Translation into the current language: t('Testo con {n}', { n }) */
export function t(text, vars) { return fill(lookup(text, current), vars, current); }

/** A value from the engine (static Italian text, or a message described by the result's pack) */
export function translate(v, lang = current, pack = null, strict = false) {
  if (typeof v !== 'string' || lang === 'it' || !v) return v;
  const r = has(pack, v) && pack[v];
  if (r) return fill(lookup(r[0], lang), r[1], lang, pack);
  return lookup(v, lang, strict);
}

// Objects whose keys are labels for people (the other keys are field names)
const KEYED = new Set(['info', 'metadata']);
const SKIP = new Set(['source', 'strings', 'head', 'hashes', 'text', 'preview', 'path', 'sha256', 'md5', 'sha1', 'raw', 'bytes', 'hex', 'chain', 'i18n', 'listing']);

/** Whole analysis result in the given language (deep copy, the pack is kept) */
export function localize(result, lang = current) {
  if (!result || lang === 'it') return result;
  const p = result.i18n || null;
  const walk = (v, k) => {
    if (typeof v === 'string') return v.length > 4000 ? v : translate(v, lang, p, true);
    if (!v || typeof v !== 'object' || SKIP.has(k)) return v;
    if (Array.isArray(v)) return v.map((x) => walk(x, k));
    if (ArrayBuffer.isView(v)) return v;
    if (k === 'file' && 'hashes' in v) {
      const f = { ...v, encoding: translate(v.encoding, lang, p), origin: translate(v.origin, lang, p) };
      if (v.type && typeof v.type === 'object') f.type = { ...v.type, label: translate(v.type.label, lang, p) };
      return f;
    }
    const out = {};
    for (const [kk, vv] of Object.entries(v)) out[KEYED.has(k) ? translate(kk, lang, p, true) : kk] = walk(vv, kk);
    return out;
  };
  return walk(result, '');
}

/** Current language for components (re-render when it changes) */
export const LanguageContext = createContext({ lang: 'it', setLang: () => {} });
export const useLanguage = () => useContext(LanguageContext);
