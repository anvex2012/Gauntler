// Created by anvex2012
import { createContext, useContext } from 'react';

/**
 * User preferences: appearance, analysis and report behaviour.
 * Stored in localStorage, validated on load (unknown or invalid values fall back to the default).
 */
export const OPTIONS = {
  theme: [['system', 'Sistema'], ['light', 'Chiaro'], ['dark', 'Scuro']],
  accent: [['blue', 'Blu', '#2563eb'], ['indigo', 'Indaco', '#4f46e5'], ['violet', 'Viola', '#7c3aed'], ['teal', 'Verde acqua', '#0d9488'], ['amber', 'Ambra', '#d97706'], ['graphite', 'Grafite', '#4b5563']],
  primary: [['graphite', 'Grafite'], ['accent', 'Colore d\'accento']],
  levels: [['standard', 'Standard'], ['contrast', 'Alto contrasto'], ['cvd', 'Per daltonici']],
  zoom: [[0.9, 'Piccolo'], [1, 'Normale'], [1.1, 'Grande'], [1.25, 'Molto grande']],
  density: [['comfortable', 'Comoda'], ['compact', 'Compatta']],
  font: [['system', 'Sistema'], ['rounded', 'Arrotondato'], ['inter', 'Inter']],
  mono: [['system', 'SF Mono / Consolas'], ['menlo', 'Menlo'], ['jetbrains', 'JetBrains Mono'], ['fira', 'Fira Code'], ['courier', 'Courier']],
  codeSize: [11, 12, 13, 14, 15],
  motion: [['system', 'Come il sistema'], ['reduce', 'Ridotte'], ['full', 'Complete']],
  concurrency: [1, 2, 3, 4, 6, 8],
  afterAdd: [['auto', 'Riepilogo se più file'], ['dashboard', 'Sempre il riepilogo'], ['first', 'Primo file']],
  sort: [['score', 'Per punteggio'], ['name', 'Per nome'], ['added', 'Più recenti']],
  defaultTab: [['overview', 'Panoramica'], ['issues', 'Problemi'], ['code', 'Codice']],
  exportFormat: [['html', 'HTML'], ['json', 'JSON'], ['sarif', 'SARIF'], ['csv', 'CSV'], ['md', 'Markdown']],
};

export const DEFAULTS = Object.freeze({
  theme: 'system', accent: 'blue', primary: 'graphite', levels: 'standard', zoom: 1, density: 'comfortable',
  font: 'system', mono: 'system', codeSize: 12, motion: 'system',
  concurrency: 3, afterAdd: 'auto', sort: 'score', notify: true, rememberPasswords: false, passwords: '',
  defaultTab: 'overview', showInfo: false, exportFormat: 'html',
});

const KEY = 'gauntler.settings.v1';
const allowed = (k) => (OPTIONS[k] ? OPTIONS[k].map((o) => (Array.isArray(o) ? o[0] : o)) : null);

export function sanitize(raw) {
  const out = { ...DEFAULTS };
  if (!raw || typeof raw !== 'object') return out;
  for (const k of Object.keys(DEFAULTS)) {
    const v = raw[k];
    if (v === undefined) continue;
    const list = allowed(k);
    if (list) { if (list.includes(v)) out[k] = v; }
    else if (typeof v === typeof DEFAULTS[k]) out[k] = typeof v === 'string' ? v.slice(0, 20000) : v;
  }
  return out;
}

export function load() {
  try {
    const s = sanitize(JSON.parse(localStorage.getItem(KEY) || 'null'));
    if (!s.rememberPasswords) s.passwords = '';
    return s;
  } catch { return { ...DEFAULTS }; }
}

export function save(s) {
  const stored = { ...s };
  if (!stored.rememberPasswords) stored.passwords = ''; // archive passwords stay in memory unless asked
  try { localStorage.setItem(KEY, JSON.stringify(stored)); } catch { /* storage full or disabled */ }
}

/** Applies the appearance settings to the document (CSS data attributes) and to the native window */
export function apply(s) {
  const el = document.documentElement;
  el.dataset.accent = s.accent;
  el.dataset.primary = s.primary;
  el.dataset.levels = s.levels;
  el.dataset.density = s.density;
  el.dataset.font = s.font;
  el.dataset.mono = s.mono;
  el.dataset.motion = s.motion;
  el.style.setProperty('--code-size', `${s.codeSize}px`);
  el.style.setProperty('--code-row', `${codeRow(s)}px`);
  window.gauntler?.setTheme?.(s.theme);
  window.gauntler?.setZoom?.(s.zoom);
}

/** Row height of the code/assembly viewers (virtualized lists need an exact pixel height) */
export const codeRow = (s) => Math.round((s?.codeSize || 12) * 1.65);

export const SettingsContext = createContext({ settings: DEFAULTS, set: () => {} });
export const useSettings = () => useContext(SettingsContext);
