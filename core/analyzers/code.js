// Created by anvex2012
'use strict';
const { m: msg } = require('../i18n');
const { countMatches, strEntropy, truncate } = require('../utils');

/**
 * Obfuscation analysis: measures 14 indicators over the whole code and computes an index 0-10.
 * The hidden payloads (base64, hex, charcode, gzip…) are decoded by the engine and re-analyzed by all criteria:
 * here they are reported and counted.
 */
const METRICS = [
  ['b64', 'Blocchi base64 lunghi (≥200)', /[A-Za-z0-9+/]{200,}={0,2}/g, (n) => Math.min(3, n)],
  ['eval', 'Chiamate eval / Invoke-Expression / new Function', /(?<![.\w$])(?:eval|execScript|Invoke-Expression|iex)\s*\(|new\s+Function\s*\(|\bexec\s*\(\s*(?:compile|base64|zlib|marshal|codecs|bytes)/gi, (n, c, kl) => (n >= 3 && n / kl >= 2 ? (n / kl >= 10 ? 3 : 2) : 0)],
  ['charcode', 'Conversioni da codici carattere', /fromCharCode|\[char\]\s*\d+|\bchrw?\s*\(\s*\d+\s*\)/gi, (n, c, kl) => (n >= 10 && n / kl >= 5 ? 2 : 0)],
  ['hexesc', 'Escape esadecimali/unicode', /\\x[0-9a-f]{2}|\\u[0-9a-f]{4}/gi, (n, c, kl) => (n > 200 && n / kl > 100 ? 2 : 0)],
  ['concat', 'Stringhe spezzate e ricomposte', /['"][a-z]{1,3}['"]\s*\+\s*['"][a-z]{1,3}['"]/gi, (n, c, kl) => (n > 15 && n / kl > 5 ? 2 : 0)],
  ['ticks', 'Backtick PowerShell nelle parole', /\w`\w/g, (n, ctx) => (n > 10 && /ps1|powershell/i.test(ctx.type.id + ctx.type.label) ? 2 : 0)],
  ['obfio', 'Variabili _0x (obfuscator.io)', /_0x[a-f0-9]{4,6}/g, (n) => (n > 30 ? 3 : 0)],
  ['replace', 'Catene di .replace()/-replace', /(?:\.replace\(|-replace\s)/gi, (n, c, kl) => (n > 25 && n / kl > 20 ? 1 : 0)],
  ['caret', 'Caret di offuscamento batch', /(?:\w\^){3,}/g, (n) => (n > 5 ? 2 : 0)],
  ['envslice', 'Sottostringhe di variabili d\'ambiente', /%[A-Za-z]+:~-?\d+,-?\d+%/g, (n) => (n > 3 ? 3 : 0)],
  ['jsfuck', 'Codifica JSFuck', /(?:\[\]\+\[\]|!\+\[\]){4,}/g, (n) => (n ? 4 : 0)],
  ['packer', 'Packer JavaScript (p,a,c,k,e,d)', /eval\(function\(p,a,c,k,e,[dr]\)/g, (n) => (n ? 2 : 0)],
  ['chrvba', 'Stringhe VBA da Chr()', /(?:Chr[WB]?\$?\(\s*\d+\s*\)\s*&\s*){4,}/gi, (n) => (n ? 2 : 0)],
  ['reverse', 'Stringhe invertite', /StrReverse\s*\(|\.split\(['"]{2}\)\.reverse\(\)\.join/gi, (n) => (n ? 1 : 0)],
];

module.exports = {
  id: 'code',
  name: 'Codice & offuscamento',
  description: 'Analizza script e pagine (JS, PowerShell, VBS, Python, Batch, PHP, HTML, macro…): 14 indicatori di offuscamento, entropia del codice, righe anomale, e decodifica ricorsiva dei payload nascosti.',
  weight: 2,
  textual: true,
  applies: (ctx) => (ctx.isText && ['script', 'markup', 'text'].includes(ctx.type.family)) || ['ole', 'docx', 'xlsx', 'pptx', 'pdf'].includes(ctx.type.id),
  init: () => ({ counts: {}, longest: 0, longLines: 0, entSample: '', lines: 0, units: 0 }),
  scan(unit, st, ctx) {
    if (unit.kind === 'binary') return;
    // For documents, only macros and PDF JavaScript are analyzed as code
    if (unit.kind === 'extracted' && !['macro', 'js', 'decoded'].includes(unit.extractedKind) && ctx.type.family !== 'script' && ctx.type.family !== 'markup') return;
    if (unit.kind === 'text' && !['script', 'markup', 'text'].includes(ctx.type.family)) return;
    st.units++;
    const t = unit.text;
    for (const [id, , re] of METRICS) st.counts[id] = (st.counts[id] || 0) + countMatches(t, re);
    let pos = 0;
    for (const line of t.split('\n')) {
      st.lines++;
      if (line.length > st.longest) st.longest = line.length;
      if (line.length > 5000 && (ctx.type.family !== 'text' || unit.kind === 'extracted')) {
        st.longLines++;
        ctx.annotate(unit.loc(pos), line, { id: 'code:longline', sev: 'info', label: msg('Riga di {n} caratteri', { n: line.length }), desc: 'Codice compresso in una sola riga (minificato o offuscato).' });
      }
      pos += line.length + 1;
    }
    if (st.entSample.length < 400000) st.entSample += t.slice(0, 400000 - st.entSample.length);
  },
  finalize(st, ctx) {
    const out = [];
    const checks = [];
    const scripty = ['script', 'markup'].includes(ctx.type.family) || st.units > 1;
    let obf = 0;
    const evid = [];
    const kl = Math.max(1, st.lines / 1000); // density per thousand lines: large legitimate bundles are not penalized
    for (const [id, name, , score] of METRICS) {
      const n = st.counts[id] || 0;
      const s = score(n, ctx, kl);
      obf += s;
      if (s) evid.push(`${name}: ${n}`);
      checks.push({ name: msg('Offuscamento — {name}', { name }), ok: !s, note: `${n}` });
    }
    if (st.longest > 5000 && scripty && obf >= 2) { obf += 1; evid.push(msg('riga più lunga: {n} caratteri', { n: st.longest })); }
    const ent = strEntropy(st.entSample);
    if (ent > 5.9 && scripty) { obf += 1; evid.push(msg('entropia del codice {e}', { e: ent.toFixed(2) })); }
    checks.push({ name: 'Entropia del codice nella norma (≤ 5.9)', ok: !(ent > 5.9 && scripty), note: ent.toFixed(2) });
    checks.push({ name: 'Righe lunghissime (> 5000 caratteri)', ok: !st.longLines, note: `${st.longLines}` });
    const idx = Math.min(10, obf);
    if (obf >= 6) out.push({ severity: 'high', title: msg('Codice fortemente offuscato (indice {i}/10)', { i: idx }), detail: 'Il codice è nascosto intenzionalmente: tecnica tipica dei malware.', evidence: evid });
    else if (obf >= 3) out.push({ severity: 'medium', title: msg('Codice parzialmente offuscato (indice {i}/10)', { i: idx }), detail: 'Alcune tecniche di occultamento del codice.', evidence: evid });

    const dec = ctx.decoded || [];
    if (dec.length) {
      const bin = dec.filter((d) => ['exe', 'elf', 'macho', 'lnk', 'dex', 'ole', 'rtf', 'pdf', 'zip', 'rar', '7z'].includes(d.magic));
      out.push({
        severity: bin.length ? 'high' : dec.some((d) => d.depth > 1) ? 'medium' : dec.every((d) => ['wasm', 'png', 'jpg', 'gz'].includes(d.magic)) ? 'info' : 'low',
        title: msg('Contenuti nascosti decodificati ({n})', { n: dec.length }),
        detail: msg(dec.some((d) => d.depth > 1)
          ? (bin.length ? 'Blocchi codificati sono stati decodificati su più livelli e rianalizzati da tutti i criteri. {n} contengono file eseguibili/archivi.' : 'Blocchi codificati sono stati decodificati su più livelli e rianalizzati da tutti i criteri.')
          : (bin.length ? 'Blocchi codificati sono stati decodificati e rianalizzati da tutti i criteri. {n} contengono file eseguibili/archivi.' : 'Blocchi codificati sono stati decodificati e rianalizzati da tutti i criteri.'), { n: bin.length }),
        evidence: dec.slice(0, 12).map((d) => (d.magic ? msg('{label} [da {from}]: file {magic}', { label: d.label, from: d.from, magic: d.magic }) : msg('{label} [da {from}]: {preview}', { label: d.label, from: d.from, preview: truncate(d.preview || '', 80) }))),
        loc: dec[0].loc, locs: dec.map((d) => d.loc),
      });
    }
    checks.push({ name: 'Payload codificati nascosti', ok: !dec.length, note: `${dec.length}` });
    return { findings: out, checks, info: { 'Righe di codice': st.lines, 'Riga più lunga': st.longest, 'Indice offuscamento': `${idx}/10`, 'Entropia codice': ent.toFixed(2), 'Payload decodificati': dec.length, 'Livelli di decodifica': dec.length ? Math.max(...dec.map((d) => d.depth)) : 0 } };
  },
};
