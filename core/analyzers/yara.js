// Creato da anvex2012
'use strict';
/**
 * Real YARA rules (if the `yara` binary is installed): the rules from ~/.gauntler/yara and from
 * the "yara" folders in the configuration / --yara option. Thousands of community rules can be used
 * (e.g. YARA-Forge, signature-base).
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFile, spawnSync } = require('child_process');
const { dir } = require('../paths');

let BIN;
function yaraBin() {
  if (BIN !== undefined) return BIN;
  BIN = null;
  for (const c of ['yara', '/opt/homebrew/bin/yara', '/usr/local/bin/yara', '/usr/bin/yara']) {
    try { const r = spawnSync(c, ['--version'], { encoding: 'utf8', timeout: 4000 }); if (r.status === 0) { BIN = c; break; } } catch { /* */ }
  }
  return BIN;
}

function ruleFiles(extra = []) {
  const out = [];
  const add = (p) => {
    try {
      const st = fs.statSync(p);
      if (st.isDirectory()) for (const f of fs.readdirSync(p)) add(path.join(p, f));
      else if (/\.(yar|yara|rule|rules)$/i.test(p)) out.push(p);
    } catch { /* */ }
  };
  add(dir('yara'));
  for (const e of extra) add(path.resolve(e.replace(/^~/, os.homedir())));
  return [...new Set(out)];
}

function parse(stdout) {
  const matches = [];
  let cur = null;
  for (const line of stdout.split('\n')) {
    if (!line.trim()) continue;
    const s = line.match(/^0x([0-9a-f]+):(\$\w*):\s?(.*)$/i);
    if (s && cur) { if (cur.strings.length < 20) cur.strings.push({ offset: parseInt(s[1], 16), id: s[2], data: s[3].slice(0, 120) }); continue; }
    const m = line.match(/^(\S+)\s+(?:\[([^\]]*)\]\s+)?(?:\[([^\]]*)\]\s+)?(.+)$/);
    if (m) { cur = { rule: m[1], tags: (m[2] || '').split(',').filter(Boolean), meta: m[3] || '', strings: [] }; matches.push(cur); }
  }
  return matches;
}

module.exports = {
  id: 'yara',
  name: 'Regole YARA',
  description: 'Applica regole YARA reali (motore ufficiale) dalla cartella ~/.gauntler/yara e da quelle configurate: permette di usare migliaia di regole della community (YARA-Forge, signature-base…).',
  weight: 3,
  applies: (ctx) => !ctx.options.noYara && ruleFiles(ctx.options.yara || []).length > 0,
  available: () => !!yaraBin(),
  ruleFiles,
  run(ctx) {
    const bin = yaraBin();
    const files = ruleFiles(ctx.options.yara || []);
    if (!bin) return { skipped: true, reason: `YARA non installato (brew install yara / apt install yara) — ${files.length} file di regole pronti`, findings: [], checks: [] };
    let target = ctx.path, tmp = null;
    if (!target || ctx.virtual) {
      tmp = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'gauntler-y-')), 'sample.bin');
      fs.writeFileSync(tmp, ctx.buffer);
      target = tmp;
    }
    return new Promise((resolve) => {
      execFile(bin, ['-w', '-s', '-g', '-m', '-p', '4', ...files, target], { timeout: 10 * 60 * 1000, maxBuffer: 256 * 1024 * 1024 }, (err, stdout, stderr) => {
        if (tmp) fs.rmSync(path.dirname(tmp), { recursive: true, force: true });
        if (err && !stdout) return resolve({ skipped: true, reason: 'Errore YARA: ' + String(stderr || err.message).split('\n')[0].slice(0, 200), findings: [], checks: [] });
        const ms = parse(String(stdout));
        const out = ms.map((m) => {
          const sevMeta = (m.meta.match(/severity="?(\w+)/i) || [])[1] || (m.meta.match(/score="?(\d+)/i) || [])[1];
          const desc = (m.meta.match(/description="([^"]+)"/i) || [])[1];
          let sev = 'high';
          if (sevMeta) sev = /^\d+$/.test(sevMeta) ? (+sevMeta >= 75 ? 'critical' : +sevMeta >= 50 ? 'high' : +sevMeta >= 30 ? 'medium' : 'low') : ({ critical: 'critical', high: 'high', medium: 'medium', low: 'low', info: 'info' }[sevMeta.toLowerCase()] || 'high');
          return { id: 'yara:' + m.rule, severity: sev, title: `YARA: ${m.rule}`, detail: desc || `Regola YARA corrispondente${m.tags.length ? ' (' + m.tags.join(', ') + ')' : ''}.`, evidence: m.strings.slice(0, 6).map((s) => `0x${s.offset.toString(16)} ${s.id}: ${s.data}`), loc: m.strings[0] ? { offset: m.strings[0].offset } : undefined, locs: m.strings.map((s) => ({ offset: s.offset })) };
        });
        resolve({ findings: out, checks: [{ name: `Regole YARA (${files.length} file)`, ok: !out.length, note: `${out.length} corrispondenze` }], info: { 'File di regole': files.length, 'Regole attivate': out.length } });
      });
    });
  },
};
