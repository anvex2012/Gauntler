// Created by anvex2012
'use strict';
/* Language of the terminal and of the desktop app: chosen on first use, changeable with "gauntler language" */
const config = require('../core/config');
const i18n = require('../core/i18n');
const { c } = require('./ui');

const TITLE = 'Scegli la lingua · Choose your language · Elige tu idioma · Choisissez votre langue · Wähle deine Sprache';
const HINT = '↑/↓ + Invio/Enter · 1-5';

/** Language of the system (LANG, LC_ALL, Intl), used as the preselected choice */
function systemLanguage() {
  const env = process.env.LC_ALL || process.env.LC_MESSAGES || process.env.LANG || '';
  let intl = '';
  try { intl = Intl.DateTimeFormat().resolvedOptions().locale; } catch { /* */ }
  return i18n.normalize(env) || i18n.normalize(intl) || 'en';
}

/** True when the language has never been chosen (config.json has no "language") */
function needsChoice() {
  if (process.env.GAUNTLER_LANG) return false;
  try { return !i18n.normalize(JSON.parse(require('fs').readFileSync(config.path(), 'utf8')).language); } catch { return true; }
}

function save(code) {
  const norm = i18n.normalize(code);
  if (!norm) return null;
  config.set('language', norm);
  i18n.setLanguage(norm);
  return norm;
}

/** Interactive choice in the terminal (arrow keys or number). Resolves to the code, or null if cancelled */
function choose({ initial } = {}) {
  const langs = i18n.LANGUAGES;
  let sel = Math.max(0, langs.findIndex((l) => l.code === (initial || (needsChoice() ? systemLanguage() : i18n.getLanguage()))));
  const out = process.stdout;
  const draw = (first) => {
    if (!first) out.write(`\x1b[${langs.length}A`);
    langs.forEach((l, i) => {
      const on = i === sel;
      out.write(`\r\x1b[K  ${on ? c.cyan('❯') : ' '} ${c.dim(String(i + 1))} ${on ? c.bold(l.name) : l.name} ${c.dim('(' + l.code + ')')}\n`);
    });
  };
  out.write(`\n${c.bold('◆ Gauntler')}  ${TITLE}\n${c.dim('  ' + HINT)}\n\n`);
  out.write('\x1b[?25l');
  draw(true);
  return new Promise((resolve) => {
    const stdin = process.stdin;
    const wasRaw = stdin.isRaw;
    if (stdin.setRawMode) stdin.setRawMode(true);
    stdin.resume();
    const done = (code) => {
      stdin.removeListener('data', onKey);
      if (stdin.setRawMode) stdin.setRawMode(!!wasRaw);
      stdin.pause();
      out.write('\x1b[?25h\n');
      resolve(code);
    };
    const onKey = (buf) => {
      const k = buf.toString();
      if (k === '\u0003' || k === '\u001b') return done(null); // Ctrl+C / Esc
      if (k === '\r' || k === '\n' || k === ' ') return done(langs[sel].code);
      if (/^[1-9]$/.test(k) && langs[Number(k) - 1]) { sel = Number(k) - 1; draw(); return done(langs[sel].code); }
      if (k === '\u001b[A' || k === 'k') sel = (sel + langs.length - 1) % langs.length;
      else if (k === '\u001b[B' || k === 'j' || k === '\t') sel = (sel + 1) % langs.length;
      else return;
      draw();
    };
    stdin.on('data', onKey);
  });
}

/** First interactive start: asks for the language once and saves it */
async function firstRun() {
  if (!needsChoice() || !process.stdin.isTTY || !process.stdout.isTTY) return null;
  const code = await choose({ initial: systemLanguage() });
  if (!code) { i18n.setLanguage(systemLanguage()); return null; } // cancelled: asked again next time, the system language is used meanwhile
  save(code);
  console.log(`${c.green('✔')} ${i18n.t('Lingua impostata: {name}', { name: i18n.LANGUAGES.find((l) => l.code === code).name })} ${c.dim(i18n.t('(cambiala quando vuoi con: gauntler language)'))}\n`);
  return code;
}

module.exports = { choose, save, needsChoice, firstRun, systemLanguage };
