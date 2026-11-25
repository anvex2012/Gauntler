// Creato da anvex2012
'use strict';
const path = require('path');

let useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const C = (code) => (s) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : String(s));
const c = {
  bold: C('1'), dim: C('2'), red: C('31'), green: C('32'), yellow: C('33'), blue: C('34'), magenta: C('35'), cyan: C('36'), gray: C('90'), bgRed: C('41;97;1'),
};
const setColor = (on) => { useColor = on; };
const colorFor = (score) => (score >= 90 ? c.green : score >= 70 ? c.cyan : score >= 40 ? c.yellow : score >= 15 ? c.red : c.bgRed);
const SEV = { critical: [c.bgRed, 'CRITICO'], high: [c.red, 'ALTO   '], medium: [c.yellow, 'MEDIO  '], low: [c.blue, 'BASSO  '], info: [c.dim, 'INFO   '] };
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const cols = () => process.stdout.columns || 100;
const fmtBytes = (n) => { if (n < 1024) return n + ' B'; const u = ['KB', 'MB', 'GB', 'TB']; let i = -1; do { n /= 1024; i++; } while (n >= 1024 && i < 3); return n.toFixed(1) + ' ' + u[i]; };
const fmtDur = (ms) => { if (ms < 1000) return `${Math.round(ms)} ms`; const s = ms / 1000; if (s < 60) return `${s.toFixed(1)} s`; const m = Math.floor(s / 60); return m < 60 ? `${m}m ${Math.round(s % 60)}s` : `${Math.floor(m / 60)}h ${m % 60}m`; };
const strip = (s) => String(s).replace(/\x1b\[[0-9;]*m/g, '');
const pad = (s, n) => s + ' '.repeat(Math.max(0, n - strip(s).length));

function bar(score, width = 24) {
  const n = Math.round((score / 100) * width);
  return colorFor(score)('█'.repeat(n)) + c.dim('░'.repeat(width - n));
}

function relPath(p) { if (!p) return ''; const r = path.relative(process.cwd(), p); return r && !r.startsWith('..') ? r : p; }

/** Progress bar on stderr (does not disturb stdout output) */
class Progress {
  constructor(total, enabled) {
    this.total = total; this.done = 0; this.enabled = enabled && process.stderr.isTTY; this.t0 = Date.now(); this.bytes = 0; this.current = ''; this.last = 0;
  }
  tick(file, bytes = 0) { this.done++; this.bytes += bytes; this.current = file || this.current; this.draw(); }
  set(file) { this.current = file; this.draw(); }
  draw(force) {
    if (!this.enabled) return;
    const now = Date.now();
    if (!force && now - this.last < 80) return;
    this.last = now;
    const el = now - this.t0;
    const rate = this.done / Math.max(1, el / 1000);
    const eta = this.done ? ((this.total - this.done) / Math.max(rate, 1e-6)) * 1000 : 0;
    const w = 26, n = Math.round((this.done / Math.max(1, this.total)) * w);
    const head = `${c.cyan('█'.repeat(n))}${c.dim('░'.repeat(w - n))} ${this.done}/${this.total} ${c.dim(`· ${rate.toFixed(1)} file/s · ${fmtBytes(this.bytes)} · trascorsi ${fmtDur(el)}${this.done ? ' · fine tra ~' + fmtDur(eta) : ''}`)}`;
    const room = Math.max(10, (process.stderr.columns || 100) - strip(head).length - 3);
    const cur = this.current.length > room ? '…' + this.current.slice(-room + 1) : this.current;
    process.stderr.write(`\r${head} ${c.dim(cur)}\x1b[K`);
  }
  clear() { if (this.enabled) process.stderr.write('\r\x1b[K'); }
  log(line) { this.clear(); console.log(line); this.draw(true); }
}

/** Full text report of a file */
function printReport(r, opt = {}) {
  const o = r.overall;
  const W = Math.min(cols(), 110);
  const out = [];
  const P = (s = '') => out.push(s);
  P('\n' + c.dim('─'.repeat(W)));
  P(c.bold(r.file.name) + c.dim(`  ${r.file.type.label} · ${r.file.sizeHuman}${r.cached ? ' · dalla cache' : ''}`));
  if (r.file.path) P(c.dim(r.file.path));
  P(`\n  SICUREZZA GENERALE  ${colorFor(o.score)(c.bold(` ${o.score}/100 `))}  ${bar(o.score, 30)}  ${colorFor(o.score)(c.bold(o.verdict))}`);
  P(`  ${o.advice}\n`);
  for (const k of r.categories) {
    if (!k.applicable) {
      if (opt.verbose || k.skipped) P(`  ${c.dim(k.name.padEnd(32))} ${c.dim(k.skipped ? 'n/d — ' + k.reason : 'non applicabile')}`);
      continue;
    }
    const issues = k.findings.filter((f) => f.severity !== 'info').length;
    P(`  ${k.name.padEnd(32)} ${colorFor(k.score)(String(k.score).padStart(3) + '/100')}  ${bar(k.score)}  ${c.dim(issues ? issues + ' problemi' : '')}`);
  }
  const t = r.totals;
  P(c.dim(`\n  ${t.lines ? t.lines.toLocaleString('it-IT') + ' righe' : t.strings.toLocaleString('it-IT') + ' stringhe'} analizzate · ${t.checks} controlli (${t.checksFailed} non superati) · ${t.extracted} contenuti estratti · ${t.decoded} payload decodificati · ${t.children} file interni · ${fmtDur(r.durationMs)}`));
  const minSev = opt.minSeverity || (opt.verbose ? 'info' : 'low');
  const shown = r.findings.filter((f) => SEV_ORDER[f.severity] <= SEV_ORDER[minSev]);
  const limit = opt.verbose || opt.all ? Infinity : 40;
  if (shown.length) {
    P('\n  ' + c.bold('Problemi rilevati:'));
    for (const f of shown.slice(0, limit)) {
      const [col, label] = SEV[f.severity];
      P(`  ${col(label)} ${f.title} ${c.dim('· ' + f.category + (f.where ? ' · ' + f.where : ''))}`);
      P(`          ${c.dim(f.detail)}`);
      if (f.evidence && f.evidence.length) P(`          ${c.magenta('→ ' + f.evidence.slice(0, opt.verbose ? 10 : 3).join('  |  '))}`);
      if (opt.ids) P(`          ${c.gray('id: ' + f.id)}`);
    }
    if (shown.length > limit) P(c.dim(`  … altri ${shown.length - limit} (usa --all o --verbose)`));
  } else P('\n  ' + c.green('✔ Nessun problema rilevato'));
  if (r.suppressed && r.suppressed.length) P(c.dim(`  (${r.suppressed.length} segnalazioni nascoste dalle regole "suppress" della configurazione)`));
  if (opt.lines) {
    const ls = (r.lines || []).filter((l) => SEV_ORDER[l.sev] <= SEV_ORDER[minSev]);
    if (ls.length) {
      P('\n  ' + c.bold(`Righe segnalate (${ls.length}):`));
      let src = null;
      for (const l of ls) {
        if ((l.source || '') !== src) { src = l.source || ''; P('\n  ' + c.cyan(src || r.file.name)); }
        const [col] = SEV[l.sev];
        const pos = l.line != null ? String(l.line).padStart(6) : ('0x' + l.offset.toString(16)).padStart(10);
        P(`  ${col('▌')}${c.dim(pos)}  ${l.text.slice(0, Math.max(40, cols() - 16))}`);
        for (const tg of l.tags) if (SEV_ORDER[tg.sev] <= SEV_ORDER[minSev]) P(`  ${col('▌')}${' '.repeat(pos.length)}  ${SEV[tg.sev][0]('↳ ' + tg.label)} ${c.dim(tg.desc)}`);
      }
    }
  }
  if (opt.checks) {
    P('\n  ' + c.bold(`Controlli eseguiti (${r.totals.checks}):`));
    for (const k of r.categories.filter((k) => k.checks && k.checks.length)) {
      const ok = k.checks.filter((x) => x.ok).length;
      P(`  ${c.cyan(k.name)} ${c.dim(`${ok}/${k.checks.length}`)}`);
      for (const x of k.checks) if (opt.verbose || !x.ok) P(`    ${x.ok ? c.green('✓') : c.red('✗')} ${x.name}${x.note ? c.dim(' (' + x.note + ')') : ''}`);
    }
  }
  if (r.reputation) {
    P('\n  ' + c.bold('Reputazione online:'));
    for (const x of r.reputation) P(`   ${x.service.padEnd(14)} ${x.skipped ? c.dim(x.skipped) : x.error ? c.yellow('errore: ' + x.error) : !x.found ? c.green('non presente') : x.service === 'VirusTotal' ? colorFor(x.malicious ? 10 : 95)(`${x.malicious}/${x.engines} rilevamenti`) + (x.label ? c.dim(' · ' + x.label) : '') : c.red('malware noto: ' + (x.signature || '?'))}`);
  }
  if (r.children && r.children.length) {
    P('\n  ' + c.bold(`File interni analizzati (${r.children.length}):`));
    const ch = [...r.children].sort((a, b) => a.overall.score - b.overall.score);
    for (const k of ch.slice(0, opt.verbose ? Infinity : 30)) P(`   ${colorFor(k.overall.score)(String(k.overall.score).padStart(3))}  ${k.file.name} ${c.dim(k.file.type.label + (k.file.origin ? ' · ' + k.file.origin : ''))}`);
    if (!opt.verbose && ch.length > 30) P(c.dim(`   … altri ${ch.length - 30}`));
  }
  if (opt.verbose) {
    P('\n  ' + c.bold('Impronte:'));
    for (const [k, v] of Object.entries(r.file.hashes)) P(`   ${k.toUpperCase().padEnd(7)} ${c.dim(v)}`);
    for (const k of r.categories.filter((k) => k.applicable && k.info && Object.keys(k.info).length)) {
      P('\n  ' + c.bold(k.name));
      for (const [kk, v] of Object.entries(k.info)) P(`   ${c.dim(kk.padEnd(26))} ${typeof v === 'object' ? JSON.stringify(v) : String(v)}`);
    }
  } else P(c.dim(`\n  SHA-256 ${r.file.hashes.sha256}`));
  return out.join('\n');
}

/** One line per file */
function oneLine(r) {
  if (r.error) return `${c.dim('  —/100')}  ${c.yellow('Errore'.padEnd(14))} ${relPath(r.file.path)} ${c.dim(r.error)}`;
  const top = r.findings.find((f) => f.severity !== 'info');
  return `${colorFor(r.overall.score)(String(r.overall.score).padStart(3) + '/100')}  ${r.overall.verdict.padEnd(14)} ${relPath(r.file.path) || r.file.name}${top && r.overall.score < 90 ? c.dim('  — ' + top.title) : ''}${r.cached ? c.gray(' (cache)') : ''}`;
}

function table(rows, head) {
  const all = head ? [head, ...rows] : rows;
  const w = all[0].map((_, i) => Math.max(...all.map((r) => strip(String(r[i] ?? '')).length)));
  const line = (r) => '  ' + r.map((x, i) => pad(String(x ?? ''), i === r.length - 1 ? 0 : w[i])).join('  ');
  const out = [];
  if (head) { out.push(c.bold(line(head))); out.push(c.dim('  ' + w.map((n) => '─'.repeat(n)).join('  '))); }
  for (const r of rows) out.push(line(r));
  return out.join('\n');
}

module.exports = { c, setColor, colorFor, SEV, SEV_ORDER, bar, Progress, printReport, oneLine, table, relPath, fmtBytes, fmtDur, strip };
