// Creato da anvex2012
'use strict';
const { t } = require('../core/i18n');
/**
 * Minimal argument parser.
 * spec: { name: { alias: 'x', type: 'bool'|'string'|'number'|'list', default } }
 * Supports --name value, --name=value, -x value, --no-name, -- (end of options), "-" as a positional argument.
 */
function parse(argv, spec) {
  const out = { _: [] };
  const byAlias = {};
  for (const [k, v] of Object.entries(spec)) {
    if (v.alias) byAlias[v.alias] = k;
    if (v.default !== undefined) out[k] = Array.isArray(v.default) ? [...v.default] : v.default;
    else if (v.type === 'list') out[k] = [];
  }
  const camel = (s) => s.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
  for (let i = 0; i < argv.length; i++) {
    let a = argv[i];
    if (a === '--') { out._.push(...argv.slice(i + 1)); break; }
    if (a === '-' || !a.startsWith('-')) { out._.push(a); continue; }
    let val;
    if (a.includes('=')) { [a, val] = [a.slice(0, a.indexOf('=')), a.slice(a.indexOf('=') + 1)]; }
    let name;
    if (a.startsWith('--')) {
      name = camel(a.slice(2));
      if (!spec[name] && name.startsWith('no') && spec[camel(name.slice(2).replace(/^./, (c) => c.toLowerCase()))]) {
        const n = camel(name.slice(2).replace(/^./, (c) => c.toLowerCase()));
        if (spec[n].type === 'bool') { out[n] = false; continue; }
      }
    } else {
      // Grouped short flags: -lqv
      const letters = a.slice(1);
      if (letters.length > 1 && !val && [...letters].every((l) => byAlias[l] && spec[byAlias[l]].type === 'bool')) {
        for (const l of letters) out[byAlias[l]] = true;
        continue;
      }
      name = byAlias[letters];
    }
    const s = spec[name];
    if (!s) throw new UsageError(t('Opzione sconosciuta: {opt}', { opt: a }));
    if (s.type === 'bool') { out[name] = val === undefined ? true : !/^(false|0|no)$/i.test(val); continue; }
    if (val === undefined) {
      val = argv[++i];
      if (val === undefined) throw new UsageError(t('Manca il valore per {opt}', { opt: a }));
    }
    if (s.type === 'number') {
      const n = Number(val);
      if (!Number.isFinite(n)) throw new UsageError(t('{opt} richiede un numero', { opt: a }));
      out[name] = n;
    } else if (s.type === 'list') out[name].push(...String(val).split(',').map((x) => x.trim()).filter(Boolean));
    else out[name] = val;
  }
  return out;
}

class UsageError extends Error {}

/** Size: "10M", "2G", "500k" → bytes */
function parseSize(v) {
  if (v == null) return null;
  const m = String(v).trim().match(/^(\d+(?:\.\d+)?)\s*([kmgt]?)b?$/i);
  if (!m) throw new UsageError(t('Dimensione non valida: {v} (esempi: 500k, 10M, 2G)', { v }));
  return Math.round(parseFloat(m[1]) * 1024 ** ' kmgt'.indexOf((m[2] || ' ').toLowerCase()));
}

module.exports = { parse, parseSize, UsageError };
