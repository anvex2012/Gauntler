// Created by anvex2012
'use strict';
/**
 * Builds the files to publish in a GitHub release, in release/upload/:
 *   Gauntler-<v>-macOS-arm64.dmg     disk image (drag to Applications)
 *   Gauntler-<v>-macOS-arm64.zip     the same app, zipped
 *   Gauntler-<v>-Windows-x64.zip     portable folder with Gauntler.exe
 *   Gauntler-<v>-Linux-x64.tar.gz    portable folder with the "gauntler" launcher + install.sh
 *   SHA256SUMS.txt
 *
 *   npm run release:build        (on a Mac: the .dmg needs hdiutil)
 *
 * Windows and Linux are cross-packaged with @electron/packager (Electron is downloaded once and cached;
 * the Windows icon and version info are written with resedit, so Wine is not needed).
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

if (process.platform !== 'darwin') { console.error('Run this script on a Mac (hdiutil is needed for the .dmg).'); process.exit(1); }

const ROOT = path.join(__dirname, '..');
const pkg = require(path.join(ROOT, 'package.json'));
const V = pkg.version;
const ELECTRON_VERSION = require(path.join(ROOT, 'node_modules', 'electron', 'package.json')).version;
const OUT = path.join(ROOT, 'release', 'upload');
const WORK = fs.mkdtempSync(path.join(os.tmpdir(), 'gauntler-release-'));
const run = (cmd, args, opts = {}) => execFileSync(cmd, args, { stdio: 'inherit', cwd: ROOT, ...opts });
const step = (s) => console.log(`\n▸ ${s}`);

fs.rmSync(OUT, { recursive: true, force: true });
fs.mkdirSync(OUT, { recursive: true });

/* ── macOS: app (package-mac.js), zip and dmg ── */
step('macOS: Gauntler.app');
run(process.execPath, [path.join(__dirname, 'package-mac.js')]);
const APP = path.join(ROOT, 'release', 'Gauntler.app');
const arch = execFileSync('lipo', ['-archs', path.join(APP, 'Contents', 'MacOS', 'Gauntler')], { encoding: 'utf8' }).trim().split(/\s+/).join('+');
const macTag = arch.includes('+') ? 'universal' : arch;

step('macOS: zip');
const macZip = path.join(OUT, `Gauntler-${V}-macOS-${macTag}.zip`);
run('ditto', ['-c', '-k', '--norsrc', '--keepParent', APP, macZip]);

step('macOS: dmg');
const dmgOut = path.join(OUT, `Gauntler-${V}-macOS-${macTag}.dmg`);
if (!fs.existsSync(path.join(ROOT, 'build', 'dmg-background.png'))) run(path.join(ROOT, 'node_modules', '.bin', 'electron'), [path.join(__dirname, 'build-dmg-background.js')]);
// dmgbuild (Python) writes the window layout without driving the Finder: kept in a private venv
const venv = path.join(ROOT, 'node_modules', '.cache', 'gauntler-dmgbuild');
const py = path.join(venv, 'bin', 'python3');
try { execFileSync(py, ['-c', 'import dmgbuild'], { stdio: 'ignore' }); }
catch {
  console.log('  preparing dmgbuild (once)…');
  run('python3', ['-m', 'venv', venv]);
  run(py, ['-m', 'pip', 'install', '-q', '--disable-pip-version-check', 'dmgbuild']);
}
run(py, ['-m', 'dmgbuild', '-s', path.join(__dirname, 'dmg-settings.py'),
  '-D', `app=${APP}`, '-D', `background=${path.join(ROOT, 'build', 'dmg-background.png')}`, '-D', `icon=${path.join(ROOT, 'build', 'icon.icns')}`,
  `Gauntler ${V}`, dmgOut], { stdio: ['ignore', 'ignore', 'inherit'] });

/* ── Common app folder for Windows and Linux (same content as the macOS app) ── */
step('App code for Windows and Linux');
const stage = path.join(WORK, 'app');
fs.mkdirSync(stage);
for (const d of ['electron', 'core', 'cli', 'dist']) fs.cpSync(path.join(ROOT, d), path.join(stage, d), { recursive: true });
fs.mkdirSync(path.join(stage, 'build'));
fs.copyFileSync(path.join(ROOT, 'build', 'icon.png'), path.join(stage, 'build', 'icon.png'));
fs.copyFileSync(path.join(ROOT, 'LICENSE.txt'), path.join(stage, 'LICENSE.txt'));
const { devDependencies, scripts, ...runtimePkg } = pkg;
fs.writeFileSync(path.join(stage, 'package.json'), JSON.stringify({ ...runtimePkg, productName: 'Gauntler', dependencies: {} }, null, 2));

// Windows icon: an .ico holding the 256×256 PNG (supported since Windows Vista)
const png256 = path.join(WORK, 'icon-256.png');
run('sips', ['-z', '256', '256', path.join(ROOT, 'build', 'icon.png'), '--out', png256], { stdio: 'ignore' });
const png = fs.readFileSync(png256);
const ico = Buffer.alloc(22);
ico.writeUInt16LE(0, 0); ico.writeUInt16LE(1, 2); ico.writeUInt16LE(1, 4);       // ICONDIR: 1 image
ico.writeUInt8(0, 6); ico.writeUInt8(0, 7); ico.writeUInt16LE(1, 10); ico.writeUInt16LE(32, 12); // 256×256, 32 bpp
ico.writeUInt32LE(png.length, 14); ico.writeUInt32LE(22, 18);
const ICO = path.join(WORK, 'icon.ico');
fs.writeFileSync(ICO, Buffer.concat([ico, png]));

async function cross() {
  const { packager } = await import('@electron/packager');
  const common = { dir: stage, out: path.join(WORK, 'out'), electronVersion: ELECTRON_VERSION, appVersion: V, buildVersion: V, overwrite: true, asar: false, prune: false, quiet: true, appCopyright: '© 2026 anvex2012' };

  /* ── Windows ── */
  step('Windows x64 (Electron ' + ELECTRON_VERSION + ')');
  const [winDir] = await packager({ ...common, platform: 'win32', arch: 'x64', name: 'Gauntler', icon: ICO, win32metadata: { CompanyName: 'anvex2012', ProductName: 'Gauntler', FileDescription: 'Gauntler - file security analysis', OriginalFilename: 'Gauntler.exe' } });
  const winName = `Gauntler-${V}-Windows-x64`;
  fs.renameSync(winDir, path.join(WORK, winName));
  fs.copyFileSync(path.join(ROOT, 'LICENSE.txt'), path.join(WORK, winName, 'LICENSE.txt'));
  fs.writeFileSync(path.join(WORK, winName, 'README.txt'), [
    'Gauntler ' + V + ' for Windows - Created by anvex2012',
    '',
    '1. Extract the whole folder (right-click the zip > Extract All).',
    '2. Open Gauntler.exe.',
    '   If Windows shows "Windows protected your PC": click "More info" > "Run anyway".',
    '3. Drag files or folders into the window, or use the "Choose files" / "Choose folder" buttons.',
    '   On first launch Gauntler asks for the language (Italian, English, Spanish, French, German).',
    '',
    'Terminal use (optional, requires Node.js): download the source code from GitHub and run',
    '   node cli\\gauntler.js <file>',
    '',
    'Full instructions: https://github.com/anvex2012/Gauntler/blob/main/INSTRUCTIONS.md',
    '',
  ].join('\r\n'));
  run('zip', ['-r', '-q', '-X', '-9', path.join(OUT, winName + '.zip'), winName], { cwd: WORK });

  /* ── Linux ── */
  step('Linux x64 (Electron ' + ELECTRON_VERSION + ')');
  const [linDir] = await packager({ ...common, platform: 'linux', arch: 'x64', name: 'Gauntler', executableName: 'gauntler-app' });
  const linName = `Gauntler-${V}-Linux-x64`;
  const L = path.join(WORK, linName);
  fs.renameSync(linDir, L);
  fs.copyFileSync(path.join(ROOT, 'build', 'icon.png'), path.join(L, 'gauntler.png'));
  fs.copyFileSync(path.join(ROOT, 'LICENSE.txt'), path.join(L, 'LICENSE.txt'));
  // Launcher: uses Chromium's sandbox when chrome-sandbox is set up (root + setuid), otherwise starts without it
  fs.writeFileSync(path.join(L, 'gauntler'), `#!/bin/sh
# Created by anvex2012 - starts the Gauntler app
DIR=$(dirname "$(readlink -f "$0")")
SB="$DIR/chrome-sandbox"
if [ "$(stat -c %u "$SB" 2>/dev/null)" = "0" ] && [ -u "$SB" ]; then
  exec "$DIR/gauntler-app" "$@"
fi
exec "$DIR/gauntler-app" --no-sandbox "$@"
`, { mode: 0o755 });
  // Optional installer: menu entry + "gauntler" terminal command
  fs.writeFileSync(path.join(L, 'install.sh'), `#!/bin/sh
# Created by anvex2012 - adds Gauntler to the applications menu and the "gauntler" command to the terminal
set -e
DIR=$(dirname "$(readlink -f "$0")")
APPS="\${XDG_DATA_HOME:-$HOME/.local/share}/applications"
mkdir -p "$APPS"
cat > "$APPS/gauntler.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Gauntler
Comment=File security analysis
Exec="$DIR/gauntler" %F
Icon=$DIR/gauntler.png
Terminal=false
Categories=Utility;Security;
EOF
chmod +x "$APPS/gauntler.desktop"
ELECTRON_RUN_AS_NODE=1 "$DIR/gauntler-app" "$DIR/resources/app/cli/gauntler.js" install-command
echo "Done: Gauntler is in the applications menu. Open a new terminal and type: gauntler"
`, { mode: 0o755 });
  fs.writeFileSync(path.join(L, 'README.txt'), [
    'Gauntler ' + V + ' for Linux - Created by anvex2012',
    '',
    '  tar -xzf ' + linName + '.tar.gz',
    '  cd ' + linName,
    '  ./gauntler            # opens the app',
    '  ./install.sh          # optional: applications menu + "gauntler" command in the terminal',
    '',
    'To use the Chromium sandbox (recommended):',
    '  sudo chown root:root chrome-sandbox && sudo chmod 4755 chrome-sandbox',
    '',
    'Full instructions: https://github.com/anvex2012/Gauntler/blob/main/INSTRUCTIONS.md',
    '',
  ].join('\n'));
  run('tar', ['--no-mac-metadata', '-czf', path.join(OUT, linName + '.tar.gz'), linName], { cwd: WORK, env: { ...process.env, COPYFILE_DISABLE: '1' } });
}

cross().then(() => {
  step('SHA-256 fingerprints');
  const files = fs.readdirSync(OUT).filter((f) => !f.endsWith('.txt')).sort();
  const sums = files.map((f) => `${require('crypto').createHash('sha256').update(fs.readFileSync(path.join(OUT, f))).digest('hex')}  ${f}`).join('\n') + '\n';
  fs.writeFileSync(path.join(OUT, 'SHA256SUMS.txt'), sums);
  fs.rmSync(WORK, { recursive: true, force: true });
  console.log('\nFiles ready in release/upload:');
  for (const f of fs.readdirSync(OUT)) console.log(`  ${f.padEnd(40)} ${(fs.statSync(path.join(OUT, f)).size / 1048576).toFixed(1)} MB`);
}, (e) => { console.error('✖ ' + (e.stack || e.message)); process.exit(1); });
