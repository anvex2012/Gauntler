// Creato da anvex2012
'use strict';
const fs = require('fs');
const path = require('path');
const os = require('os');
const RULES = require('../data/rules');
const KNOWN = require('../data/known-hashes.json');
const { truncate } = require('../utils');

/** Extra hashes: ~/.gauntler/hashes.txt (personal) + ~/.gauntler/feeds/*.txt (downloaded with `gauntler update`) */
let CUSTOM = null;
function loadCustomHashes() {
  const map = {};
  const { HOME } = require('../paths');
  const files = [path.join(HOME, 'hashes.txt')];
  try { for (const f of fs.readdirSync(path.join(HOME, 'feeds'))) if (f.endsWith('.txt')) files.push(path.join(HOME, 'feeds', f)); } catch { /* */ }
  for (const file of files) {
    try {
      for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
        if (line.startsWith('#')) continue;
        const [h, ...rest] = line.trim().split(/\s+/);
        if (/^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(h || '')) map[h.toLowerCase()] = rest.join(' ') || 'Hash malevolo (lista personale)';
      }
    } catch { /* file absent */ }
  }
  return map;
}

// Global versions of the rule strings (to find EVERY occurrence)
const COMPILED = RULES.map((r) => ({
  rule: r,
  strings: r.strings.map((s) => (s instanceof RegExp
    ? new RegExp(s.source, s.flags.includes('g') ? s.flags : s.flags + 'g')
    : { lit: r.cs ? s : s.toLowerCase() })),
  need: r.condition === 'all' ? r.strings.length : r.condition === 'any' ? 1 : r.condition,
}));

function eachMatch(cs, text, lower, cb) {
  cs.strings.forEach((s, si) => {
    if (s instanceof RegExp) {
      s.lastIndex = 0;
      let m;
      while ((m = s.exec(text))) { cb(si, m.index, m[0]); if (!m[0].length) s.lastIndex++; }
    } else {
      const hay = cs.rule.cs ? text : lower;
      const short = s.lit.length < 9 && /^\w/.test(s.lit) && /\w$/.test(s.lit);
      let i = -1;
      while ((i = hay.indexOf(s.lit, i + 1)) !== -1) {
        // Short words must be whole words (e.g. "amos" must not match "Samos")
        if (short && (/\w/.test(hay[i - 1] || '') || /\w/.test(hay[i + s.lit.length] || ''))) continue;
        cb(si, i, text.substr(i, s.lit.length));
      }
    }
  });
}

/** Plain rule matching (used elsewhere for quick checks) */
function scanText(text, family) {
  const lower = text.toLowerCase();
  const res = [];
  for (const cs of COMPILED) {
    if (cs.rule.families && family && !cs.rule.families.includes(family)) continue;
    const hit = new Set(), hits = [];
    eachMatch(cs, text, lower, (si, _i, m) => { if (!hit.has(si)) { hit.add(si); hits.push(m); } });
    if (hit.size >= cs.need) res.push({ rule: cs.rule, hits });
  }
  return res;
}

module.exports = {
  knownCount: () => Object.keys(KNOWN).length + Object.keys(CUSTOM || (CUSTOM = loadCustomHashes())).length,
  id: 'signatures',
  name: 'Firme malware',
  description: `Impronte di malware noti + ${RULES.length} regole in stile YARA (famiglie di ransomware, RAT, stealer, botnet, webshell, exploit, tecniche MITRE ATT&CK) applicate a ogni riga del file e a ogni contenuto decodificato.`,
  weight: 3,
  textual: true,
  applies: () => true,
  scanText,
  init: () => ({ rules: new Map() }),

  scan(unit, st, ctx) {
    const family = ctx.type.family;
    const passes = [[unit.text, (i) => unit.loc(i), (i) => unit.lineText(i)]];
    if (unit.text16) passes.push([unit.text16, (i) => unit.loc16(i), (i) => unit.lineText16(i)]);
    for (const [text, locFn, lineFn] of passes) {
      const lower = text.toLowerCase();
      for (const cs of COMPILED) {
        // The page rules (phishing/smuggling) only apply to pages and extracted content
        if (cs.rule.families && unit.kind !== 'extracted' && !cs.rule.families.includes(family)) continue;
        if (cs.rule.types && !cs.rule.types.includes(ctx.type.id)) continue;
        let r = st.rules.get(cs.rule.id);
        eachMatch(cs, text, lower, (si, idx, m) => {
          if (!r) { r = { cs, matched: new Set(), samples: [], occ: [] }; st.rules.set(cs.rule.id, r); }
          if (!r.matched.has(si)) { r.matched.add(si); r.samples.push(truncate(m, 100)); }
          r.occ.push({ loc: locFn(idx), text: lineFn(idx), m: truncate(m, 100), decoded: unit.kind === 'extracted' && unit.extractedKind === 'decoded' });
        });
      }
    }
  },

  finalize(st, ctx) {
    if (!CUSTOM) CUSTOM = loadCustomHashes();
    const out = [];
    const checks = [];
    const h = ctx.hashes;
    const known = KNOWN[h.sha256] || CUSTOM[h.sha256] || CUSTOM[h.sha1] || CUSTOM[h.md5];
    checks.push({ name: 'Impronta SHA-256/SHA-1/MD5 nel database dei malware noti', ok: !known, note: `${Object.keys(KNOWN).length + Object.keys(CUSTOM).length} impronte` });
    if (known) out.push({ severity: 'critical', title: 'Impronta di malware conosciuto', detail: `L'impronta del file corrisponde a: ${known}.`, forceScore: known.includes('EICAR') ? 5 : 1 });

    for (const cs of COMPILED) {
      const r = st.rules.get(cs.rule.id);
      const triggered = r && r.matched.size >= cs.need && !(cs.rule.id === 'Process_Injection_Strings' && ctx.type.family === 'executable');
      checks.push({ name: `${cs.rule.family}: ${cs.rule.id}`, ok: !triggered, note: r ? `${r.matched.size}/${cs.strings.length} indicatori (servono ${cs.need})` : `0/${cs.strings.length} indicatori` });
      if (!triggered) continue;
      const hidden = r.occ.some((o) => o.decoded) && r.occ.every((o) => o.decoded);
      let sev = cs.rule.severity;
      if (hidden && sev === 'medium') sev = 'high';
      const tag = { id: 'sig:' + cs.rule.id, sev, label: cs.rule.family, desc: cs.rule.desc, group: 'Firma ' + cs.rule.id };
      for (const o of r.occ) ctx.annotate(o.loc, o.text, tag);
      out.push({
        severity: sev,
        title: `${hidden ? 'Nascosto — ' : ''}${cs.rule.family}: ${cs.rule.id}`,
        detail: `${cs.rule.desc} ${r.occ.length} occorrenz${r.occ.length === 1 ? 'a trovata' : 'e trovate'}${hidden ? ' dentro contenuti codificati' : ''}.`,
        evidence: r.samples,
        loc: r.occ[0].loc,
        locs: r.occ.map((o) => o.loc),
        forceScore: cs.rule.id === 'EICAR_Test' ? 5 : undefined,
      });
    }
    const fired = out.length - (known ? 1 : 0);
    return { findings: out, checks, info: { 'Regole YARA-style': RULES.length, 'Regole attivate': fired, 'Impronte nel database': Object.keys(KNOWN).length + Object.keys(CUSTOM).length } };
  },
};
