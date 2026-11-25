// Creato da anvex2012
'use strict';
/**
 * The "gauntler" terminal command.
 * A small sh launcher written to ~/.local/bin/gauntler (no sudo). It runs the CLI with the Node.js
 * runtime built into Gauntler.app (ELECTRON_RUN_AS_NODE), so it works even without Node installed;
 * from a source checkout it falls back to the system node.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const MARKER = '# GAUNTLER-LAUNCHER v1';
const BUNDLE_ID = 'app.gauntler.desktop';
const PROJECT = path.join(__dirname, '..');
const defaultDir = () => path.join(os.homedir(), '.local', 'bin');
const target = (dir = defaultDir()) => path.join(dir, 'gauntler');
const q = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`; // POSIX single-quote escaping

/** Is this file (path) the Gauntler app bundle's own copy of the CLI? */
const appFromCli = () => {
  const m = PROJECT.match(/^(.*?\.app)\/Contents\/Resources\/app$/);
  return m ? m[1] : null;
};

/** Packaged app on Linux (resources/app inside the app folder): its own Electron runtime runs the CLI */
const bundledRuntime = () => (process.versions.electron && !appFromCli() && /[\\/]resources[\\/]app$/.test(PROJECT) && fs.existsSync(process.execPath) ? process.execPath : null);

/** Gauntler.app locations, most specific first */
function appCandidates() {
  return [process.env.GAUNTLER_APP, appFromCli(), '/Applications/Gauntler.app', path.join(os.homedir(), 'Applications', 'Gauntler.app'), path.join(PROJECT, 'release', 'Gauntler.app')].filter(Boolean);
}

function findApp() {
  if (process.platform !== 'darwin') return null;
  for (const a of appCandidates()) if (fs.existsSync(path.join(a, 'Contents', 'MacOS', 'Gauntler'))) return a;
  try {
    const a = execFileSync('mdfind', [`kMDItemCFBundleIdentifier == '${BUNDLE_ID}'`], { encoding: 'utf8', timeout: 3000, stdio: ['ignore', 'pipe', 'ignore'] }).split('\n')[0];
    if (a && fs.existsSync(path.join(a, 'Contents', 'MacOS', 'Gauntler'))) return a;
  } catch { /* Spotlight unavailable */ }
  return null;
}

function launcherScript() {
  // A source checkout (not the copy inside the app) is used as fallback with the system node
  const project = appFromCli() ? null : PROJECT;
  const runtime = bundledRuntime();
  return `#!/bin/sh
${MARKER}
# Comando da terminale di Gauntler. Rimuovilo con: gauntler uninstall-command
${runtime ? `# Installato dall'app: usa il runtime incluso nell'app (non serve Node.js)
if [ -x ${q(runtime)} ] && [ -f ${q(path.join(PROJECT, 'cli', 'gauntler.js'))} ]; then
  ELECTRON_RUN_AS_NODE=1 exec ${q(runtime)} ${q(path.join(PROJECT, 'cli', 'gauntler.js'))} "$@"
fi
` : ''}${project ? `# Installato dai sorgenti: usa il codice della cartella del progetto (sempre aggiornato)
if command -v node >/dev/null 2>&1 && [ -f ${q(path.join(project, 'cli', 'gauntler.js'))} ]; then
  exec node ${q(path.join(project, 'cli', 'gauntler.js'))} "$@"
fi
` : ''}for APP in "$GAUNTLER_APP" '/Applications/Gauntler.app' "$HOME/Applications/Gauntler.app"${project ? ` ${q(path.join(project, 'release', 'Gauntler.app'))}` : ''}; do
  if [ -n "$APP" ] && [ -x "$APP/Contents/MacOS/Gauntler" ]; then
    GAUNTLER_APP="$APP" ELECTRON_RUN_AS_NODE=1 exec "$APP/Contents/MacOS/Gauntler" "$APP/Contents/Resources/app/cli/gauntler.js" "$@"
  fi
done
APP=$(command -v mdfind >/dev/null 2>&1 && mdfind "kMDItemCFBundleIdentifier == '${BUNDLE_ID}'" 2>/dev/null | head -n 1)
if [ -n "$APP" ] && [ -x "$APP/Contents/MacOS/Gauntler" ]; then
  GAUNTLER_APP="$APP" ELECTRON_RUN_AS_NODE=1 exec "$APP/Contents/MacOS/Gauntler" "$APP/Contents/Resources/app/cli/gauntler.js" "$@"
fi
echo "gauntler: app Gauntler non trovata. Spostala in Applicazioni oppure reinstalla il comando dall'app (Impostazioni → Sistema)." >&2
exit 127
`;
}

/** PATH of the user's login shell (GUI apps do not inherit it) */
function shellPath() {
  if (process.platform === 'win32') return process.env.PATH || '';
  try {
    const out = execFileSync(process.env.SHELL || '/bin/zsh', ['-ilc', 'printf "\\n__P__%s" "$PATH"'], { encoding: 'utf8', timeout: 4000, stdio: ['ignore', 'pipe', 'ignore'] });
    const m = out.match(/__P__(.*)$/m);
    if (m) return m[1];
  } catch { /* */ }
  return process.env.PATH || '';
}

const RC_BEGIN = '# >>> gauntler >>>';
const RC_END = '# <<< gauntler <<<';
/** Startup file of the user's shell */
function rcFile() {
  const sh = path.basename(process.env.SHELL || (process.platform === 'darwin' ? '/bin/zsh' : '/bin/bash'));
  const h = os.homedir();
  if (sh === 'zsh') return path.join(h, '.zshrc');
  if (sh === 'bash') return path.join(h, process.platform === 'darwin' ? '.bash_profile' : '.bashrc');
  if (sh === 'fish') return path.join(h, '.config', 'fish', 'config.fish');
  return path.join(h, '.profile');
}
const homeRel = (dir) => (dir.startsWith(os.homedir() + path.sep) ? '$HOME' + dir.slice(os.homedir().length) : dir);
/** Is dir already in PATH (current process) or added by the shell startup file? Fast: no shell is started */
function pathConfigured(dir = defaultDir()) {
  const abs = path.resolve(dir);
  if ((process.env.PATH || '').split(path.delimiter).some((d) => d && path.resolve(d) === abs)) return true;
  const files = [rcFile(), path.join(os.homedir(), '.zprofile'), path.join(os.homedir(), '.profile')];
  return files.some((f) => { try { const t = fs.readFileSync(f, 'utf8'); return t.includes(abs) || t.includes(homeRel(abs)) || t.includes(RC_BEGIN); } catch { return false; } });
}
/** Adds dir to PATH in the shell startup file (marked block, added only once). Returns the file changed, or null */
function ensurePath(dir = defaultDir()) {
  if (process.platform === 'win32' || pathConfigured(dir)) return null;
  const f = rcFile();
  const line = f.endsWith('config.fish') ? `fish_add_path ${homeRel(dir)}` : `export PATH="${homeRel(dir)}:$PATH"`;
  fs.mkdirSync(path.dirname(f), { recursive: true });
  let cur = ''; try { cur = fs.readFileSync(f, 'utf8'); } catch { /* new file */ }
  fs.appendFileSync(f, `${cur && !cur.endsWith('\n') ? '\n' : ''}\n${RC_BEGIN}\n# Comando "gauntler" (aggiunto da Gauntler, rimuovi con: gauntler uninstall-command)\n${line}\n${RC_END}\n`);
  return f;
}
function removePath() {
  const f = rcFile();
  try {
    const t = fs.readFileSync(f, 'utf8');
    const re = new RegExp(`\\n?${RC_BEGIN.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}[\\s\\S]*?${RC_END.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\n?`);
    if (re.test(t)) { fs.writeFileSync(f, t.replace(re, '\n')); return f; }
  } catch { /* nothing to remove */ }
  return null;
}

/**
 * First start (terminal or desktop app): installs the "gauntler" command if it is missing and
 * puts its folder in PATH. Never overwrites a launcher that already exists. Returns what it did, or null.
 * Disabled with GAUNTLER_NO_AUTOINSTALL=1.
 */
function autoInstall(dir = defaultDir()) {
  if (process.platform === 'win32' || process.env.GAUNTLER_NO_AUTOINSTALL) return null;
  try {
    const p = target(dir);
    if (fs.existsSync(p)) {
      // Already there: only make sure it can be found
      if (!fs.readFileSync(p, 'utf8').includes(MARKER)) return null;
      const rc = ensurePath(dir);
      return rc ? { path: p, rc, installed: false } : null;
    }
    install(dir);
    return { path: p, rc: ensurePath(dir), installed: true };
  } catch (e) {
    return { error: e.message };
  }
}

function status(dir = defaultDir()) {
  const p = target(dir);
  let installed = false, foreign = false;
  try { const t = fs.readFileSync(p, 'utf8'); installed = t.includes(MARKER); foreign = !installed; } catch { /* missing */ }
  const inPath = shellPath().split(':').some((d) => d && path.resolve(d.replace(/^~/, os.homedir())) === path.resolve(dir));
  return { path: p, dir, installed, foreign, inPath, app: findApp() };
}

function install(dir = defaultDir()) {
  if (process.platform === 'win32') throw new Error('Su Windows usa: npm link (dalla cartella del progetto)');
  const p = target(dir);
  if (fs.existsSync(p) && !fs.readFileSync(p, 'utf8').includes(MARKER)) throw new Error(`${p} esiste già e non è stato creato da Gauntler: non lo sovrascrivo`);
  fs.mkdirSync(dir, { recursive: true });
  const tmp = `${p}.tmp-${process.pid}`;
  fs.writeFileSync(tmp, launcherScript(), { mode: 0o755 });
  fs.renameSync(tmp, p);
  return status(dir);
}

function uninstall(dir = defaultDir()) {
  const p = target(dir);
  if (!fs.existsSync(p)) return { removed: false, path: p };
  if (!fs.readFileSync(p, 'utf8').includes(MARKER)) throw new Error(`${p} non è stato creato da Gauntler: non lo rimuovo`);
  fs.unlinkSync(p);
  return { removed: true, path: p, rc: removePath() };
}

module.exports = { appFromCli, install, uninstall, status, autoInstall, ensurePath, pathConfigured, rcFile, findApp, launcherScript, shellPath, MARKER, defaultDir };
