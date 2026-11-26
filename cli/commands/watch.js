// Created by anvex2012
'use strict';
const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const core = require('../../core');
const config = require('../../core/config');
const history = require('../../core/history');
const quarantine = require('../../core/quarantine');
const { sanitizeFile } = require('../../core/sanitize');
const { ScanPool } = require('../../core/pool');
const { matcher } = require('../../core/glob');
const { buildScanOptions, SPEC: SCAN_SPEC } = require('./scan');
const { UsageError } = require('../args');
const ui = require('../ui');
const { c } = ui;
const i18n = require('../../core/i18n');
const { t } = i18n;

const SPEC = {
  ...SCAN_SPEC,
  notify: { alias: 'n', type: 'bool' },
  initial: { type: 'bool' },
  settle: { type: 'number', default: 1500 },
  sanitize: { type: 'bool' },
  sanitizeAll: { type: 'bool' },
};

const HELP = () => `
${c.bold('gauntler watch')} — ${t('protezione in tempo reale: analizza ogni file nuovo o modificato in una cartella')}

${c.bold(t('Uso'))}
  gauntler watch <${t('cartella')}…> [${t('opzioni')}]

${c.bold(t('Opzioni'))}
  -n, --notify             ${t('Notifica di sistema quando un file è sotto soglia')}
      --quarantine         ${t('Metti automaticamente in quarantena i file sotto --quarantine-below (predefinito 15)')}
      --sanitize           ${t('Crea subito una copia disarmata e verificata (nome.safe.ext) dei file sotto soglia')}
      --sanitize-all       ${t('Crea la copia sicura di OGNI file nuovo')}
      --initial            ${t('Analizza anche i file già presenti all\'avvio')}
  -t, --threshold <n>      ${t('Soglia di allarme (predefinito 40)')}
  -x, --exclude <glob>     ${t('Escludi file (es. "*.crdownload")')}
      --online             ${t('Reputazione online (solo impronta SHA-256)')}
  ${c.dim(t('+ tutte le opzioni di "gauntler scan" sul motore (--skip, --password, --yara, …)'))}

${c.bold(t('Esempio'))}
  gauntler watch ~/Downloads --notify --quarantine
  gauntler watch ~/Downloads --sanitize --quarantine   ${c.dim(t('copia sicura + originale in quarantena'))}
`;

function notify(title, msg) {
  if (process.platform === 'darwin') execFile('osascript', ['-e', `display notification ${JSON.stringify(msg)} with title ${JSON.stringify(title)} sound name "Basso"`], () => {});
  else if (process.platform === 'linux') execFile('notify-send', ['-u', 'critical', title, msg], () => {});
  else if (process.platform === 'win32') execFile('powershell', ['-NoProfile', '-Command', `[reflection.assembly]::loadwithpartialname('System.Windows.Forms')|Out-Null; $n=New-Object System.Windows.Forms.NotifyIcon; $n.Icon=[System.Drawing.SystemIcons]::Warning; $n.Visible=$true; $n.ShowBalloonTip(10000, ${JSON.stringify(title)}, ${JSON.stringify(msg)}, 'Warning')`], () => {});
}

const TEMP = /\.(crdownload|part|partial|download|tmp|swp|~)$|^\.~lock|^~\$|\.DS_Store$/i;

async function run(argv, { parse }) {
  const a = parse(argv, SPEC);
  if (a.help || !a._.length) { console.log(HELP()); return a.help ? 0 : 2; }
  const cfg = config.load();
  const threshold = a.threshold ?? cfg.threshold;
  const qBelow = a.quarantineBelow ?? cfg.quarantineBelow;
  const opts = buildScanOptions(a, cfg);
  const excl = matcher([...cfg.exclude, ...a.exclude]);
  const dirs = a._.map((d) => path.resolve(d));
  for (const d of dirs) if (!fs.existsSync(d) || !fs.statSync(d).isDirectory()) throw new UsageError(t('Non è una cartella: {path}', { path: d }));

  const pool = new ScanPool({ size: a.jobs || cfg.jobs, timeoutMs: (a.timeout || cfg.timeout) * 1000 });
  const pending = new Map();
  const lastSig = new Map();
  let scanned = 0, alerts = 0;

  const scanOne = async (file) => {
    let st;
    try { st = fs.statSync(file); } catch { return; }
    if (!st.isFile()) return;
    const sig = `${st.size}:${st.mtimeMs}`;
    if (lastSig.get(file) === sig) return;
    lastSig.set(file, sig);
    try {
      const r = await pool.scan(file, opts);
      scanned++;
      if (a.history) history.record(r);
      const ts = new Date().toLocaleTimeString(i18n.locale());
      let extra = '';
      if (a.sanitizeAll || (a.sanitize && r.overall.score < threshold)) {
        try {
          const s = await sanitizeFile(file, { passwords: opts.passwords });
          extra += s.status === 'blocked' ? c.red('  ✖ ' + t('non disarmabile: {r}', { r: s.reason })) : c.green('  ✔ ' + t('copia sicura {name}', { name: path.basename(s.outPath) }));
        } catch (e) { extra += c.yellow('  ' + t('disarmo non riuscito: {msg}', { msg: t(e.message) })); }
      }
      if (r.overall.score < threshold) {
        alerts++;
        if (a.quarantine && r.overall.score < qBelow) {
          try { const q = quarantine.add(file, { score: r.overall.score, verdict: r.overall.verdict, reason: r.findings.find((f) => f.severity !== 'info')?.title }); extra += c.magenta('  ' + t('quarantena {id}', { id: q.id })); }
          catch (e) { extra = c.yellow('  ' + t('quarantena non riuscita: {msg}', { msg: t(e.message) })); }
        }
        if (a.notify) notify(`Gauntler: ${r.overall.verdict} (${r.overall.score}/100)`, `${path.basename(file)} — ${r.findings.find((f) => f.severity !== 'info')?.title || ''}${extra ? ' · ' + t('messo in quarantena') : ''}`);
      }
      console.log(`${c.dim(ts)}  ${ui.oneLine(r)}${extra}`);
      if (a.lines && r.overall.score < threshold) console.log(ui.printReport(r, { lines: true }));
    } catch (e) {
      console.log(`${c.dim(new Date().toLocaleTimeString(i18n.locale()))}  ${c.yellow(t('errore'))} ${ui.relPath(file)}: ${t(e.message)}`);
    }
  };

  // Debounce: waits until the file is "stable" (finished downloading/copying)
  const schedule = (file) => {
    if (TEMP.test(path.basename(file)) || excl(file) || /\.(safe|verified)\.[^.]+$|\.gauntler-tmp-\d+$/.test(path.basename(file))) return;
    clearTimeout(pending.get(file));
    pending.set(file, setTimeout(() => { pending.delete(file); scanOne(file); }, a.settle));
  };

  console.log(c.bold('Gauntler watch') + c.dim(' — ' + t('controllo in tempo reale di {dirs} · soglia {n}', { dirs: dirs.map(ui.relPath).join(', '), n: threshold }) + (a.quarantine ? ' · ' + t('quarantena sotto {n}', { n: qBelow }) : '') + (a.notify ? ' · ' + t('notifiche') : '') + ' · ' + t('Ctrl+C per uscire')));
  if (a.initial) for (const d of dirs) for (const f of core.walk(d, { recursive: a.recursive, exclude: [...cfg.exclude, ...a.exclude] })) schedule(f);
  const watchers = dirs.map((d) => fs.watch(d, { recursive: a.recursive }, (_ev, name) => { if (name) schedule(path.join(d, name.toString())); }));

  await new Promise((resolve) => process.once('SIGINT', resolve));
  watchers.forEach((w) => w.close());
  await pool.close();
  console.log(c.dim('\n' + t('{n} file analizzati, {a} allarmi.', { n: scanned, a: alerts })));
  return 0;
}

module.exports = { run, get HELP() { return HELP(); }, get summary() { return t('Protezione in tempo reale di una cartella (es. Download)'); } };
