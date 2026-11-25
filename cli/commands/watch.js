// Creato da anvex2012
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

const SPEC = {
  ...SCAN_SPEC,
  notify: { alias: 'n', type: 'bool' },
  initial: { type: 'bool' },
  settle: { type: 'number', default: 1500 },
  sanitize: { type: 'bool' },
  sanitizeAll: { type: 'bool' },
};

const HELP = `
${c.bold('gauntler watch')} — protezione in tempo reale: analizza ogni file nuovo o modificato in una cartella

${c.bold('Uso')}
  gauntler watch <cartella…> [opzioni]

${c.bold('Opzioni')}
  -n, --notify             Notifica di sistema quando un file è sotto soglia
      --quarantine         Metti automaticamente in quarantena i file sotto --quarantine-below (predefinito 15)
      --sanitize           Crea subito una copia disarmata e verificata (nome.safe.ext) dei file sotto soglia
      --sanitize-all       Crea la copia sicura di OGNI file nuovo
      --initial            Analizza anche i file già presenti all'avvio
  -t, --threshold <n>      Soglia di allarme (predefinito 40)
  -x, --exclude <glob>     Escludi file (es. "*.crdownload")
      --online             Reputazione online (solo impronta SHA-256)
  ${c.dim('+ tutte le opzioni di "gauntler scan" sul motore (--skip, --password, --yara, …)')}

${c.bold('Esempio')}
  gauntler watch ~/Downloads --notify --quarantine
  gauntler watch ~/Downloads --sanitize --quarantine   ${c.dim('copia sicura + originale in quarantena')}
`;

function notify(title, msg) {
  if (process.platform === 'darwin') execFile('osascript', ['-e', `display notification ${JSON.stringify(msg)} with title ${JSON.stringify(title)} sound name "Basso"`], () => {});
  else if (process.platform === 'linux') execFile('notify-send', ['-u', 'critical', title, msg], () => {});
  else if (process.platform === 'win32') execFile('powershell', ['-NoProfile', '-Command', `[reflection.assembly]::loadwithpartialname('System.Windows.Forms')|Out-Null; $n=New-Object System.Windows.Forms.NotifyIcon; $n.Icon=[System.Drawing.SystemIcons]::Warning; $n.Visible=$true; $n.ShowBalloonTip(10000, ${JSON.stringify(title)}, ${JSON.stringify(msg)}, 'Warning')`], () => {});
}

const TEMP = /\.(crdownload|part|partial|download|tmp|swp|~)$|^\.~lock|^~\$|\.DS_Store$/i;

async function run(argv, { parse }) {
  const a = parse(argv, SPEC);
  if (a.help || !a._.length) { console.log(HELP); return a.help ? 0 : 2; }
  const cfg = config.load();
  const threshold = a.threshold ?? cfg.threshold;
  const qBelow = a.quarantineBelow ?? cfg.quarantineBelow;
  const opts = buildScanOptions(a, cfg);
  const excl = matcher([...cfg.exclude, ...a.exclude]);
  const dirs = a._.map((d) => path.resolve(d));
  for (const d of dirs) if (!fs.existsSync(d) || !fs.statSync(d).isDirectory()) throw new UsageError('Non è una cartella: ' + d);

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
      const ts = new Date().toLocaleTimeString('it-IT');
      let extra = '';
      if (a.sanitizeAll || (a.sanitize && r.overall.score < threshold)) {
        try {
          const s = await sanitizeFile(file, { passwords: opts.passwords });
          extra += s.status === 'blocked' ? c.red(`  ✖ non disarmabile: ${s.reason}`) : c.green(`  ✔ copia sicura ${path.basename(s.outPath)}`);
        } catch (e) { extra += c.yellow(`  disarmo non riuscito: ${e.message}`); }
      }
      if (r.overall.score < threshold) {
        alerts++;
        if (a.quarantine && r.overall.score < qBelow) {
          try { const q = quarantine.add(file, { score: r.overall.score, verdict: r.overall.verdict, reason: r.findings.find((f) => f.severity !== 'info')?.title }); extra += c.magenta(`  quarantena ${q.id}`); }
          catch (e) { extra = c.yellow(`  quarantena non riuscita: ${e.message}`); }
        }
        if (a.notify) notify(`Gauntler: ${r.overall.verdict} (${r.overall.score}/100)`, `${path.basename(file)} — ${r.findings.find((f) => f.severity !== 'info')?.title || ''}${extra ? ' · messo in quarantena' : ''}`);
      }
      console.log(`${c.dim(ts)}  ${ui.oneLine(r)}${extra}`);
      if (a.lines && r.overall.score < threshold) console.log(ui.printReport(r, { lines: true }));
    } catch (e) {
      console.log(`${c.dim(new Date().toLocaleTimeString('it-IT'))}  ${c.yellow('errore')} ${ui.relPath(file)}: ${e.message}`);
    }
  };

  // Debounce: waits until the file is "stable" (finished downloading/copying)
  const schedule = (file) => {
    if (TEMP.test(path.basename(file)) || excl(file) || /\.(safe|verified)\.[^.]+$|\.gauntler-tmp-\d+$/.test(path.basename(file))) return;
    clearTimeout(pending.get(file));
    pending.set(file, setTimeout(() => { pending.delete(file); scanOne(file); }, a.settle));
  };

  console.log(c.bold('Gauntler watch') + c.dim(` — controllo in tempo reale di ${dirs.map(ui.relPath).join(', ')} · soglia ${threshold}${a.quarantine ? ` · quarantena sotto ${qBelow}` : ''}${a.notify ? ' · notifiche' : ''} · Ctrl+C per uscire`));
  if (a.initial) for (const d of dirs) for (const f of core.walk(d, { recursive: a.recursive, exclude: [...cfg.exclude, ...a.exclude] })) schedule(f);
  const watchers = dirs.map((d) => fs.watch(d, { recursive: a.recursive }, (_ev, name) => { if (name) schedule(path.join(d, name.toString())); }));

  await new Promise((resolve) => process.once('SIGINT', resolve));
  watchers.forEach((w) => w.close());
  await pool.close();
  console.log(c.dim(`\n${scanned} file analizzati, ${alerts} allarmi.`));
  return 0;
}

module.exports = { run, HELP, summary: 'Protezione in tempo reale di una cartella (es. Download)' };
