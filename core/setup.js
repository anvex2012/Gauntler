// Creato da anvex2012
'use strict';
/**
 * External components: ClamAV (antivirus engine + signature database) and bsdtar (RAR/7z/ISO/CAB…).
 * Installed automatically on the first start of the terminal command or of the desktop app,
 * and on demand with "gauntler setup".
 *
 *   macOS    bsdtar is part of the system · ClamAV with Homebrew, or the official ClamAV .pkg (administrator password)
 *   Linux    apt / dnf / yum / pacman / zypper (sudo in the terminal, pkexec from the app)
 *   Windows  bsdtar is tar.exe (Windows 10+) · ClamAV with winget, or the official ClamAV .msi
 *
 * Signatures are downloaded with freshclam into ~/.gauntler/clamav, owned by the user: later updates
 * ("gauntler update", or the app every few days) never need a password.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const https = require('https');
const { spawn, spawnSync } = require('child_process');
const paths = require('./paths');

const WIN = process.platform === 'win32';
const MAC = process.platform === 'darwin';
const STATE = () => paths.file('setup.json');
const DB_DIR = () => paths.dir('clamav');
const STATE_VERSION = 1;

/* ───────────── helpers ───────────── */

const EXTRA_PATH = MAC ? ['/opt/homebrew/bin', '/usr/local/bin', '/usr/local/clamav/bin'] : WIN ? ['C:\\Program Files\\ClamAV'] : ['/usr/local/bin', '/usr/bin', '/usr/sbin', '/bin'];
/** PATH that also works from the desktop app (GUI apps on macOS do not inherit the shell PATH) */
function envPath() {
  const cur = (process.env.PATH || '').split(path.delimiter).filter(Boolean);
  return [...new Set([...cur, ...EXTRA_PATH])].join(path.delimiter);
}
const ENV = () => ({ ...process.env, PATH: envPath(), HOMEBREW_NO_AUTO_UPDATE: '1', HOMEBREW_NO_INSTALL_CLEANUP: '1', HOMEBREW_NO_ENV_HINTS: '1' });

/** Full path of a command, or null */
function which(cmd) {
  for (const d of envPath().split(path.delimiter)) {
    for (const ext of WIN ? ['.exe', '.cmd', '.bat', ''] : ['']) {
      const p = path.join(d, cmd + ext);
      try { if (fs.statSync(p).isFile()) return p; } catch { /* not here */ }
    }
  }
  return null;
}
const out = (cmd, args) => { try { const r = spawnSync(cmd, args, { encoding: 'utf8', timeout: 20000, env: ENV() }); return (r.stdout || '') + (r.stderr || ''); } catch { return ''; } };

/** Runs a command. interactive: shares the terminal (sudo password, live output); otherwise lines go to log */
function exec(cmd, args, { interactive, log = () => {}, cwd } = {}) {
  return new Promise((resolve) => {
    let child;
    try { child = spawn(cmd, args, { cwd, env: ENV(), stdio: interactive ? 'inherit' : ['ignore', 'pipe', 'pipe'], windowsHide: true }); }
    catch (e) { resolve({ code: -1, error: e.message }); return; }
    let tail = '';
    const onData = (d) => { const s = String(d); tail = (tail + s).slice(-4000); for (const l of s.split(/\r?\n|\r/)) if (l.trim()) log(l.trim(), 'out'); };
    if (!interactive) { child.stdout.on('data', onData); child.stderr.on('data', onData); }
    child.on('error', (e) => resolve({ code: -1, error: e.message }));
    child.on('close', (code) => resolve({ code, tail }));
  });
}

/** Downloads a URL (follows redirects) to a file */
function download(url, dest, log, depth = 0) {
  return new Promise((resolve, reject) => {
    if (depth > 6) return reject(new Error('troppi reindirizzamenti'));
    https.get(url, { headers: { 'User-Agent': 'gauntler-setup', Accept: 'application/octet-stream' } }, (res) => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode)) { res.resume(); return resolve(download(new URL(res.headers.location, url).toString(), dest, log, depth + 1)); }
      if (res.statusCode !== 200) { res.resume(); return reject(new Error(`HTTP ${res.statusCode}`)); }
      const total = +res.headers['content-length'] || 0;
      let got = 0, last = 0;
      const f = fs.createWriteStream(dest);
      res.on('data', (d) => { got += d.length; if (total && got - last > total / 10) { last = got; log(`  download ${Math.round((got / total) * 100)}%`, 'out'); } });
      res.pipe(f);
      f.on('finish', () => f.close(() => resolve(dest)));
      f.on('error', reject);
    }).on('error', reject);
  });
}
function getJson(url) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { 'User-Agent': 'gauntler-setup', Accept: 'application/vnd.github+json' } }, (res) => {
      let b = ''; res.on('data', (d) => { b += d; });
      res.on('end', () => { try { resolve(JSON.parse(b)); } catch (e) { reject(e); } });
    }).on('error', reject);
  });
}
/** Official ClamAV build from GitHub (Cisco-Talos/clamav), asset name matching re */
async function officialAsset(re) {
  const rel = await getJson('https://api.github.com/repos/Cisco-Talos/clamav/releases/latest');
  const a = (rel.assets || []).find((x) => re.test(x.name));
  if (!a) throw new Error('pacchetto ufficiale ClamAV non trovato');
  return { url: a.browser_download_url, name: a.name, version: rel.tag_name };
}

/* ───────────── detection ───────────── */

function clamscan() {
  return which('clamscan') || (WIN && fs.existsSync('C:\\Program Files\\ClamAV\\clamscan.exe') ? 'C:\\Program Files\\ClamAV\\clamscan.exe' : null);
}
function freshclam() {
  const c = clamscan();
  const near = c && path.join(path.dirname(c), WIN ? 'freshclam.exe' : 'freshclam');
  return (near && fs.existsSync(near) ? near : null) || which('freshclam');
}
/** Gauntler's own signature folder, if it holds a database */
function ownDatabase() {
  try {
    const d = path.join(paths.HOME, 'clamav');
    const files = fs.readdirSync(d).filter((f) => /\.(cvd|cld|cud)$/.test(f));
    return files.some((f) => /^(main|daily)\./.test(f)) ? d : null;
  } catch { return null; }
}
/** Does clamscan find a signature database (its own default one, or Gauntler's)? */
function databaseReady(bin = clamscan()) {
  if (!bin) return false;
  if (ownDatabase()) return true;
  return /ClamAV [\d.]+\/\d+/.test(out(bin, ['-V'])); // "ClamAV 1.5.5/27512/…" only when a database is loaded
}
function bsdtar() {
  const t = which('tar');
  if (t && /bsdtar/.test(out(t, ['--version']))) return t;
  return which('bsdtar');
}
function linuxManager() {
  for (const [bin, m] of [['apt-get', 'apt'], ['dnf', 'dnf'], ['yum', 'yum'], ['pacman', 'pacman'], ['zypper', 'zypper']]) if (which(bin)) return m;
  return null;
}
const LINUX_PKGS = {
  apt: { clamav: ['clamav'], bsdtar: ['libarchive-tools'], cmd: (p) => `DEBIAN_FRONTEND=noninteractive apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y -q ${p.join(' ')}` },
  dnf: { clamav: ['clamav', 'clamav-update'], bsdtar: ['bsdtar'], cmd: (p) => `dnf install -y ${p.join(' ')}` },
  yum: { clamav: ['clamav', 'clamav-update'], bsdtar: ['bsdtar'], cmd: (p) => `yum install -y ${p.join(' ')}` },
  pacman: { clamav: ['clamav'], bsdtar: ['libarchive'], cmd: (p) => `pacman -S --noconfirm --needed ${p.join(' ')}` },
  zypper: { clamav: ['clamav'], bsdtar: ['bsdtar'], cmd: (p) => `zypper --non-interactive install ${p.join(' ')}` },
};

function status() {
  const bin = clamscan();
  return { clamav: bin, database: databaseReady(bin), ownDatabase: ownDatabase(), freshclam: freshclam(), bsdtar: bsdtar(), platform: process.platform, brew: MAC ? which('brew') : null, linux: process.platform === 'linux' ? linuxManager() : null, winget: WIN ? which('winget') : null };
}

/* ───────────── state ───────────── */

function readState() { try { return JSON.parse(fs.readFileSync(STATE(), 'utf8')); } catch { return {}; } }
function writeState(s) { try { fs.mkdirSync(paths.HOME, { recursive: true }); fs.writeFileSync(STATE(), JSON.stringify({ ...readState(), ...s }, null, 2)); } catch { /* read-only home */ } }
/** Automatic setup still to do (never attempted, or the components are missing after a newer setup version) */
function needsAuto() {
  if (process.env.GAUNTLER_NO_AUTOINSTALL) return false;
  const st = readState();
  if (st.version >= STATE_VERSION && st.attempted) return false;
  const s = status();
  if (s.clamav && s.database && s.bsdtar) { writeState({ version: STATE_VERSION, attempted: new Date().toISOString(), result: 'già presenti' }); return false; }
  return true;
}

/* ───────────── installation ───────────── */

async function installClamav({ interactive, gui, log }) {
  if (MAC) {
    const brew = which('brew');
    if (brew) {
      log('Installo ClamAV con Homebrew (qualche minuto)…', 'step');
      const r = await exec(brew, ['install', 'clamav'], { interactive, log });
      if (r.code === 0 || clamscan()) return true;
      log('Homebrew non è riuscito: provo con il pacchetto ufficiale di ClamAV', 'warn');
    }
    const a = await officialAsset(/macos\.universal\.pkg$/);
    log(`Scarico ClamAV ${a.version} (pacchetto ufficiale)…`, 'step');
    const pkg = path.join(os.tmpdir(), a.name);
    await download(a.url, pkg, log);
    log('Installo ClamAV: macOS chiede la password di amministratore', 'step');
    const r = gui
      ? await exec('osascript', ['-e', `do shell script "/usr/sbin/installer -pkg " & quoted form of "${pkg.replace(/"/g, '\\"')}" & " -target /" with prompt "Gauntler installa l'antivirus ClamAV." with administrator privileges`], { log })
      : await exec('sudo', ['/usr/sbin/installer', '-pkg', pkg, '-target', '/'], { interactive: true, log });
    try { fs.unlinkSync(pkg); } catch { /* temp */ }
    return r.code === 0 && !!clamscan();
  }
  if (WIN) {
    const winget = which('winget');
    if (winget) {
      log('Installo ClamAV con winget…', 'step');
      const r = await exec(winget, ['install', '--id', 'Cisco.ClamAV', '--exact', '--silent', '--accept-package-agreements', '--accept-source-agreements'], { interactive, log });
      if (r.code === 0 || clamscan()) return true;
    }
    const a = await officialAsset(/win\.x64\.msi$/);
    log(`Scarico ClamAV ${a.version} (pacchetto ufficiale)…`, 'step');
    const msi = path.join(os.tmpdir(), a.name);
    await download(a.url, msi, log);
    log('Installo ClamAV: Windows chiede l\'autorizzazione', 'step');
    const r = await exec('msiexec', ['/i', msi, '/passive', '/norestart'], { log });
    return r.code === 0 && !!clamscan();
  }
  return false; // Linux: together with bsdtar, see installLinux
}

async function installLinux(pkgs, { interactive, gui, log }) {
  const m = linuxManager();
  if (!m) { log('Gestore di pacchetti non riconosciuto: installa a mano clamav e bsdtar', 'err'); return false; }
  const list = [...new Set(pkgs.flatMap((k) => LINUX_PKGS[m][k]))];
  const cmd = LINUX_PKGS[m].cmd(list);
  log(`Installo ${list.join(', ')} con ${m} (serve la password di amministratore)…`, 'step');
  let r;
  if (process.getuid && process.getuid() === 0) r = await exec('sh', ['-c', cmd], { interactive, log });
  else if (interactive && which('sudo')) r = await exec('sudo', ['sh', '-c', cmd], { interactive: true, log });
  else if (which('pkexec')) r = await exec('pkexec', ['sh', '-c', cmd], { log });
  else { log(`Esegui da terminale: sudo sh -c '${cmd}'`, 'err'); return false; }
  return r.code === 0;
}

/** Signature database in ~/.gauntler/clamav (no password needed, now or for updates) */
async function updateDatabase({ interactive, log = () => {}, quiet } = {}) {
  const fc = freshclam();
  if (!fc) { if (!quiet) log('freshclam non trovato: impossibile scaricare le firme', 'err'); return false; }
  const dir = DB_DIR();
  const conf = path.join(dir, 'freshclam.conf');
  fs.writeFileSync(conf, [
    '# Creato da anvex2012 - configurazione di freshclam usata da Gauntler',
    `DatabaseDirectory ${dir}`,
    'DatabaseMirror database.clamav.net',
    'ConnectTimeout 30',
    'ReceiveTimeout 0',
    'Checks 1',
    '',
  ].join('\n'));
  if (!quiet) log('Scarico le firme antivirus di ClamAV (circa 200 MB, la prima volta)…', 'step');
  const r = await exec(fc, [`--config-file=${conf}`, `--datadir=${dir}`, '--stdout'], { interactive, log });
  const ok = !!ownDatabase();
  if (ok) writeState({ databaseUpdated: new Date().toISOString() });
  else if (!quiet) log(`freshclam non è riuscito (codice ${r.code})${r.tail ? ': ' + r.tail.trim().split('\n').pop() : ''}`, 'err');
  return ok;
}
/** Refreshes Gauntler's signatures when older than maxDays (background, never asks anything) */
async function refreshDatabase(maxDays = 3) {
  if (!ownDatabase()) return false;
  const last = Date.parse(readState().databaseUpdated || 0) || 0;
  if (Date.now() - last < maxDays * 864e5) return false;
  return updateDatabase({ quiet: true });
}

/**
 * Installs whatever is missing. mode: 'terminal' (interactive, sudo allowed) or 'gui' (desktop app: graphical prompts).
 * log(text, kind): kind = step | ok | warn | err | out
 */
async function run({ mode = 'terminal', log = () => {} } = {}) {
  const interactive = mode === 'terminal' && process.stdin.isTTY;
  const gui = mode === 'gui';
  const res = { clamav: null, database: null, bsdtar: null };
  let s = status();

  // 1) bsdtar (Linux only: built into macOS and Windows 10+)
  // 2) ClamAV
  try {
    if (process.platform === 'linux') {
      const need = [!s.clamav && 'clamav', !s.bsdtar && 'bsdtar'].filter(Boolean);
      if (need.length) await installLinux(need, { interactive, gui, log });
    } else if (!s.clamav) {
      await installClamav({ interactive, gui, log });
    }
  } catch (e) { log('Installazione non riuscita: ' + e.message, 'err'); }

  s = status();
  res.bsdtar = s.bsdtar ? 'ok' : 'mancante';
  res.clamav = s.clamav ? 'ok' : 'mancante';
  log(s.bsdtar ? `bsdtar pronto (${s.bsdtar})` : 'bsdtar non disponibile: RAR/7z/ISO useranno solo gli strumenti presenti', s.bsdtar ? 'ok' : 'warn');
  log(s.clamav ? `ClamAV pronto (${s.clamav})` : 'ClamAV non installato', s.clamav ? 'ok' : 'warn');

  // 3) Signatures
  if (s.clamav) {
    if (s.database && !ownDatabase()) { res.database = 'ok'; log('Firme antivirus già presenti', 'ok'); }
    else { res.database = (await updateDatabase({ interactive, log })) ? 'ok' : 'mancante'; if (res.database === 'ok') log('Firme antivirus scaricate', 'ok'); }
  }

  // Engines cache their tool lookup: forget it so the new tools are used right away
  try { require('./analyzers/clamav').reset?.(); } catch { /* optional */ }
  try { require('./extract').resetTools?.(); } catch { /* optional */ }

  const complete = res.clamav === 'ok' && res.database === 'ok' && res.bsdtar === 'ok';
  writeState({ version: STATE_VERSION, attempted: new Date().toISOString(), result: res });
  return { ...res, complete };
}

module.exports = { run, status, needsAuto, updateDatabase, refreshDatabase, ownDatabase, readState, envPath, which };
