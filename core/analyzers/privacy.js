// Created by anvex2012
'use strict';
const { m: msg } = require('../i18n');
const { findAll, luhn, ibanValid, mask, truncate, isDoc } = require('../utils');

const CF_MONTH = 'ABCDEHLMPRST';
function cfValid(cf) {
  const odd = { 0: 1, 1: 0, 2: 5, 3: 7, 4: 9, 5: 13, 6: 15, 7: 17, 8: 19, 9: 21, A: 1, B: 0, C: 5, D: 7, E: 9, F: 13, G: 15, H: 17, I: 19, J: 21, K: 2, L: 4, M: 18, N: 20, O: 11, P: 3, Q: 6, R: 8, S: 12, T: 14, U: 16, V: 10, W: 22, X: 25, Y: 24, Z: 23 };
  let s = 0;
  for (let i = 0; i < 15; i++) {
    const c = cf[i];
    s += i % 2 === 0 ? odd[c] : (/\d/.test(c) ? +c : c.charCodeAt(0) - 65);
  }
  return String.fromCharCode(65 + (s % 26)) === cf[15] && CF_MONTH.includes(cf[8]);
}
function pivaValid(p) {
  let s = 0;
  for (let i = 0; i < 11; i++) { let d = +p[i]; if (i % 2) { d *= 2; if (d > 9) d -= 9; } s += d; }
  return s % 10 === 0 && !/^0+$/.test(p);
}

const DETECTORS = [
  { id: 'card', name: 'Numero di carta di credito', re: /\b(?:4\d{3}|5[1-5]\d{2}|2[2-7]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[ -]?\d{4}[ -]?\d{4}[ -]?\d{1,4}\b/g, norm: (s) => s.replace(/\D/g, ''), valid: (d) => d.length >= 13 && d.length <= 19 && luhn(d), sev: (n) => (n > 3 ? 'critical' : 'high') },
  { id: 'cvv', name: 'Codice CVV/CVC', re: /\b(?:cvv2?|cvc2?|cid|codice di sicurezza)\s*[:=]?\s*(\d{3,4})\b/gi, sev: () => 'high' },
  { id: 'iban', name: 'Codice IBAN', re: /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){3,7}(?: ?[A-Z0-9]{1,3})?\b/g, norm: (s) => s.replace(/\s/g, ''), valid: ibanValid, sev: (n) => (n > 10 ? 'high' : 'medium') },
  { id: 'cf', name: 'Codice fiscale italiano', re: /\b[A-Z]{6}\d{2}[A-EHLMPR-T]\d{2}[A-Z]\d{3}[A-Z]\b/g, valid: cfValid, sev: (n) => (n > 10 ? 'high' : 'medium') },
  { id: 'piva', name: 'Partita IVA', re: /\b(?:p\.?\s?iva|partita iva|vat)\s*[:n.°]*\s*(?:IT)?\s*(\d{11})\b/gi, valid: pivaValid, sev: () => 'info' },
  { id: 'id_card', name: 'Numero carta d\'identità italiana', re: /\b(?:C[A-Z]\d{5}[A-Z]{2}|[A-Z]{2}\d{7})\b/g, ctxRe: /carta d'identit|documento|cie\b|identity card/i, sev: () => 'medium' },
  { id: 'passport', name: 'Numero di passaporto', re: /\b(?:passaporto|passport)\s*(?:n\.?|no\.?|number|numero)?\s*[:#]?\s*([A-Z0-9]{8,9})\b/gi, sev: () => 'medium' },
  { id: 'ssn', name: 'Social Security Number USA', re: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g, min: 2, sev: () => 'medium' },
  { id: 'nino', name: 'National Insurance Number UK', re: /\b[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b/g, min: 2, sev: () => 'medium' },
  { id: 'email', name: 'Indirizzo email', re: /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b/g, norm: (s) => s.toLowerCase(), valid: (e) => !/\.(png|jpe?g|gif|svg|webp|js|css)$/.test(e) && !/@(example|test|domain|email)\./.test(e), sev: (n) => (n >= 50 ? 'high' : n >= 5 ? 'low' : 'info') },
  { id: 'phone_it', name: 'Numero di cellulare', re: /(?:\+39[ .]?)?\b3[0-9]{2}[ .]?\d{6,7}\b/g, min: 10, sev: () => 'medium' },
  { id: 'phone_intl', name: 'Numero di telefono internazionale', re: /\+(?:[1-9]\d{0,2})[ .-]?\(?\d{1,4}\)?(?:[ .-]?\d{2,4}){2,4}\b/g, min: 10, sev: () => 'low' },
  { id: 'dob', name: 'Data di nascita', re: /\b(?:nato\s+il|nata\s+il|data\s+di\s+nascita|date\s+of\s+birth|dob|born\s+on)\s*[:]?\s*(\d{1,2}[\/.-]\d{1,2}[\/.-]\d{2,4})/gi, sev: () => 'medium' },
  { id: 'health', name: 'Dato sanitario', re: /\b(?:diagnosi|patologia|anamnesi|cartella clinica|referto|terapia|HIV|sieropositiv|diagnosis|medical record|prescription)\b/gi, min: 3, sev: () => 'medium' },
  { id: 'gps', name: 'Coordinate GPS', re: /\b-?(?:[1-8]?\d(?:\.\d{4,})|90\.0+)\s*,\s*-?(?:1[0-7]\d|\d{1,2})\.\d{4,}\b/g, min: 1, sev: () => 'low' },
  { id: 'ip_private', name: 'Indirizzo IP interno', re: /\b(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))(?:\.\d{1,3}){2,3}\b/g, min: 5, sev: () => 'info' },
];

module.exports = {
  id: 'privacy',
  name: 'Dati personali (privacy)',
  description: 'Rileva dati sensibili riga per riga con verifica matematica: carte di credito (Luhn), IBAN (mod-97), codici fiscali (carattere di controllo), partite IVA, documenti, SSN, email, telefoni, dati sanitari, coordinate.',
  weight: 1,
  textual: true,
  applies: (ctx) => ctx.isText || ['document', 'markup', 'text', 'data'].includes(ctx.type.family),
  init: () => ({ sets: {}, locs: {} }),
  scan(unit, st, ctx) {
    if (unit.kind === 'binary' && !['document', 'data'].includes(ctx.type.family)) return;
    const t = unit.text;
    for (const d of DETECTORS) {
      if (d.ctxRe && !d.ctxRe.test(t)) continue;
      for (const m of findAll(t, d.re)) {
        const raw = m[1] || m[0];
        const v = d.norm ? d.norm(raw) : raw;
        if (d.valid && !d.valid(v)) continue;
        (st.sets[d.id] ||= new Set()).add(v);
        const loc = unit.loc(m.index);
        (st.locs[d.id] ||= []).push(loc);
        ctx.annotate(loc, truncate(unit.lineText(m.index).split(raw).join(mask(raw)), 600), { id: 'pii:' + d.id, sev: d.id === 'email' || d.id.startsWith('phone') || d.id === 'ip_private' ? 'info' : 'medium', label: d.name, desc: 'Dato personale.' });
      }
    }
  },
  finalize(st, ctx) {
    const out = [], info = {}, checks = [];
    const doc = isDoc(ctx.name);
    for (const d of DETECTORS) {
      const set = st.sets[d.id];
      const n = set ? set.size : 0;
      checks.push({ name: msg('Ricerca: {name}', { name: d.name }), ok: n < (d.min || 1), note: `${n}` });
      if (!n) continue;
      info[d.name] = n;
      if (n < (d.min || 1)) continue;
      const sv = d.sev(n);
      out.push({ severity: doc && ['email', 'phone_intl', 'phone_it'].includes(d.id) ? 'info' : sv, title: msg('{name} ({n})', { name: d.name, n }), detail: msg(n === 1 ? (d.valid ? '{n} valore unico con verifica di validità superata, {occ} occorrenze.' : '{n} valore unico, {occ} occorrenze.') : (d.valid ? '{n} valori unici con verifica di validità superata, {occ} occorrenze.' : '{n} valori unici, {occ} occorrenze.'), { n, occ: st.locs[d.id].length }), evidence: [...set].slice(0, 5).map(mask), loc: st.locs[d.id][0], locs: st.locs[d.id] });
    }
    return { findings: out, checks, info };
  },
};
