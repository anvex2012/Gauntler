// Created by anvex2012
'use strict';
const { m: msg } = require('../i18n');
const { TOKENS, GROUPS } = require('../data/tokens');
const { truncate, isDoc } = require('../utils');
const BIN_SKIP = new Set(['obf', 'web', 'social', 'deser']);

// One single regex with all the tokens (one pass over the text, every word of every line)
const COMBINED = new RegExp(TOKENS.map((t) => `(${t[1]})`).join('|'), 'gi');
const LOWER = { critical: 'high', high: 'medium', medium: 'low', low: 'info', info: 'info' };

const RTL_TEXT = /[\u0590-\u08ff\ufb1d-\ufdff\ufe70-\ufefc]/; // Hebrew, Arabic, Syriac, Thaana… letters
const BIDI = /[‪-‮⁦-⁩]/g;                       // Trojan Source (CVE-2021-42574)
const ZERO_WIDTH = /[​-‍⁠᠎](?!$)/g;
const HOMOGLYPH = /[A-Za-z][Ѐ-ӿͰ-Ͽ]|[Ѐ-ӿͰ-Ͽ][A-Za-z]/g;
const CONTROL = /[\x00-\x08\x0B\x0E-\x1F\x7F]/g;
const WORD = /[A-Za-zÀ-ÖØ-öø-ÿЀ-ӿ]{2,}/g;

function sevFor(tok, ctx, unit) {
  let sev = tok[2];
  if (sev === 'critical') return sev;
  // In binaries the strings are not executed code: one level lower (two for APIs, evaluated in context by the executable analyzer)
  if (unit.kind === 'binary') {
    sev = LOWER[sev];
    if (ctx.type.family === 'executable' && ['inject', 'crypto', 'exec', 'evasion', 'priv', 'net', 'exfil', 'fs', 'recon'].includes(tok[3])) sev = LOWER[sev];
  }
  if (isDoc(ctx.name) && unit.kind !== 'extracted') sev = LOWER[sev];
  // In prose/documentation the commands are described, not executed
  if (ctx.type.family === 'text' && unit.kind === 'text' && !['destroy', 'cred'].includes(tok[3])) sev = LOWER[sev];
  return sev;
}

module.exports = {
  id: 'lines',
  name: 'Analisi riga per riga',
  description: msg('Ogni riga e ogni parola (o, nei binari, ogni stringa estratta) viene confrontata con {n} indicatori in {g} categorie (esecuzione, rete, persistenza, elusione, credenziali, iniezione, distruzione…), con spiegazione per ogni riga segnalata. Rileva anche caratteri invisibili, omoglifi e attacchi "Trojan Source".', { n: TOKENS.length, g: Object.keys(GROUPS).length }),
  weight: 1.5,
  textual: true,
  applies: () => true,
  init: () => ({ tok: new Map(), words: 0, vocab: new Map(), special: {}, stringsChecked: 0, linesChecked: 0 }),

  scan(unit, st, ctx) {
    const hit = (tok, loc, lineText, sev) => {
      let r = st.tok.get(tok[0]);
      if (!r) { r = { tok, n: 0, locs: [], samples: [], sev }; st.tok.set(tok[0], r); }
      r.n++;
      r.locs.push(loc);
      if (r.samples.length < 5) r.samples.push(truncate(lineText.trim(), 140));
      if (sevRank(sev) < sevRank(r.sev)) r.sev = sev;
      ctx.annotate(loc, lineText, { id: 'tok:' + tok[0], sev, label: tok[4], desc: tok[5], group: GROUPS[tok[3]] });
    };
    const runOn = (text, locFn, lineFn) => {
      COMBINED.lastIndex = 0;
      let m;
      while ((m = COMBINED.exec(text))) {
        if (!m[0].length) { COMBINED.lastIndex++; continue; }
        let g = 1;
        while (g < m.length && m[g] === undefined) g++;
        const tok = TOKENS[g - 1];
        if (tok) hit(tok, locFn(m.index), lineFn(m.index), sevFor(tok, ctx, unit));
      }
    };

    if (unit.kind === 'binary') {
      // Every extracted string (ASCII and UTF-16) is analyzed on its own
      for (const s of unit.strings) {
        st.stringsChecked++;
        COMBINED.lastIndex = 0;
        let m;
        while ((m = COMBINED.exec(s.s))) {
          if (!m[0].length) { COMBINED.lastIndex++; continue; }
          let g = 1;
          while (g < m.length && m[g] === undefined) g++;
          const tok = TOKENS[g - 1];
          // A private-key header inside a program is a format constant (ssh-keygen, openssl): a key needs its base64 body
          if (tok && tok[0] === 'private_key_marker' && !/[A-Za-z0-9+/]{40}/.test(s.s.slice(m.index + m[0].length))) continue;
          if (tok && (!BIN_SKIP.has(tok[3]) || tok[2] === 'critical')) hit(tok, { offset: s.o }, (s.e === 'u' ? '[UTF-16] ' : '') + s.s, sevFor(tok, ctx, unit));
        }
      }
      return;
    }
    const t = unit.text;
    st.linesChecked += (t.match(/\n/g) || []).length + 1;
    runOn(t, (i) => unit.loc(i), (i) => unit.lineText(i));

    // Invisible and deceptive characters
    const special = (re, id, sev, label, desc) => {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(t))) {
        if (id === 'zw' && m.index === 0) continue;
        const loc = unit.loc(m.index);
        (st.special[id] ||= { label, desc, sev, locs: [], samples: [] }).locs.push(loc);
        if (st.special[id].samples.length < 4) st.special[id].samples.push(truncate(visible(unit.lineText(m.index)), 140));
        ctx.annotate(loc, visible(unit.lineText(m.index)), { id: 'char:' + id, sev, label, desc });
      }
    };
    const isCode = ctx.type.family === 'script' || ctx.type.family === 'markup' || unit.extractedKind === 'macro' || unit.extractedKind === 'js';
    // Pages in Hebrew/Arabic/Persian/Urdu use direction controls legitimately: there only code (scripts, JS) stays critical
    const rtlMarkup = ctx.type.family === 'markup' && unit.extractedKind !== 'js' && RTL_TEXT.test(t);
    special(BIDI, 'bidi', rtlMarkup ? 'info' : isCode ? 'critical' : 'medium', 'Caratteri di inversione del testo (Trojan Source)', 'Il codice mostrato è diverso da quello eseguito (CVE-2021-42574).');
    special(ZERO_WIDTH, 'zw', isCode ? 'medium' : 'low', 'Caratteri invisibili a larghezza zero', 'Caratteri che non si vedono ma cambiano il significato del testo.');
    special(HOMOGLYPH, 'homo', isCode ? 'medium' : 'low', 'Omoglifi (lettere cirilliche/greche mescolate)', 'Lettere straniere identiche a quelle latine per ingannare.');
    if (ctx.isText) special(CONTROL, 'ctrl', 'low', 'Caratteri di controllo nel testo', 'Byte non stampabili inseriti nel testo.');

    // Word analysis
    if (unit.kind === 'text' || unit.extractedKind === 'doctext') {
      WORD.lastIndex = 0;
      let m;
      while ((m = WORD.exec(t))) {
        st.words++;
        const w = m[0].toLowerCase();
        st.vocab.set(w, (st.vocab.get(w) || 0) + 1);
      }
    }
  },

  finalize(st, ctx) {
    const out = [];
    const rows = [...st.tok.values()].sort((a, b) => sevRank(a.sev) - sevRank(b.sev) || b.n - a.n);
    for (const r of rows) {
      if (r.sev === 'info') continue;
      out.push({
        severity: r.sev,
        title: msg(r.n === 1 ? '{label} — {n} riga' : '{label} — {n} righe', { label: r.tok[4], n: r.n }),
        detail: msg('{desc} [{group}]', { desc: r.tok[5], group: GROUPS[r.tok[3]] }),
        evidence: r.samples,
        loc: r.locs[0],
        locs: r.locs,
      });
    }
    for (const s of Object.values(st.special)) {
      out.push({ severity: s.sev, title: msg('{label} — {n}', { label: s.label, n: s.locs.length }), detail: s.desc, evidence: s.samples, loc: s.locs[0], locs: s.locs });
    }
    const byGroup = {};
    for (const r of rows) byGroup[r.tok[3]] = (byGroup[r.tok[3]] || 0) + (r.sev === 'info' ? 0 : r.n);
    const checks = Object.entries(GROUPS).map(([g, name]) => ({ name: msg('Indicatori di {g}', { g: name.toLowerCase() }), ok: !byGroup[g], note: msg('{n} occorrenze', { n: byGroup[g] || 0 }) }));
    checks.push(
      { name: 'Caratteri Trojan Source (bidi)', ok: !st.special.bidi },
      { name: 'Caratteri invisibili', ok: !st.special.zw },
      { name: 'Omoglifi', ok: !st.special.homo },
    );
    const top = [...st.vocab.entries()].filter(([w]) => w.length > 3).sort((a, b) => b[1] - a[1]).slice(0, 25);
    const info = {
      'Indicatori controllati': TOKENS.length,
      [ctx.isText ? 'Righe analizzate' : 'Stringhe analizzate']: ctx.isText ? st.linesChecked : st.stringsChecked,
      'Righe segnalate': ctx.annotations.size,
      'Indicatori diversi trovati': rows.length,
    };
    if (st.words) { info['Parole analizzate'] = st.words; info['Parole distinte'] = st.vocab.size; }
    return { findings: out, checks, info, extra: { wordStats: st.words ? { total: st.words, unique: st.vocab.size, top } : undefined, tokenStats: rows.map((r) => ({ id: r.tok[0], label: r.tok[4], group: GROUPS[r.tok[3]], sev: r.sev, n: r.n })) } };
  },
};

function sevRank(s) { return { critical: 0, high: 1, medium: 2, low: 3, info: 4 }[s]; }
function visible(s) {
  return s.replace(/[‪-‮⁦-⁩]/g, (c) => `⟦U+${c.charCodeAt(0).toString(16).toUpperCase()}⟧`)
    .replace(/[​-‍⁠᠎]/g, (c) => `⟦U+${c.charCodeAt(0).toString(16).toUpperCase()}⟧`);
}
