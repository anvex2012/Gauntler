// Creato da anvex2012
'use strict';
/**
 * Builds a standalone macOS desktop app: release/Gauntler.app
 * (Electron runtime + interface + analysis engine, with the Gauntler icon and name).
 *   npm run package
 * No extra dependencies: the bundled Electron.app is copied, renamed, given the icon and
 * re-signed ad hoc (required on Apple Silicon after the bundle is modified).
 */
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

if (process.platform !== 'darwin') { console.error('Questo script crea l\'app per macOS: va eseguito su un Mac.'); process.exit(1); }

const ROOT = path.join(__dirname, '..');
const pkg = require(path.join(ROOT, 'package.json'));
const ELECTRON_APP = path.join(ROOT, 'node_modules', 'electron', 'dist', 'Electron.app');
const OUT_DIR = path.join(ROOT, 'release');
const APP = path.join(OUT_DIR, 'Gauntler.app');
const ICNS = path.join(ROOT, 'build', 'icon.icns');
const run = (cmd, args, opts = {}) => execFileSync(cmd, args, { stdio: 'inherit', cwd: ROOT, ...opts });

if (!fs.existsSync(ELECTRON_APP)) throw new Error('Electron non trovato: esegui prima npm install');
if (!fs.existsSync(ICNS)) run(path.join(ROOT, 'node_modules', '.bin', 'electron'), [path.join(__dirname, 'build-icon.js')]);

console.log('1/5 Interfaccia (vite build)…');
run(path.join(ROOT, 'node_modules', '.bin', 'vite'), ['build', '--logLevel', 'warn']);

console.log('2/5 Copia del runtime Electron…');
fs.rmSync(APP, { recursive: true, force: true });
fs.mkdirSync(OUT_DIR, { recursive: true });
run('ditto', [ELECTRON_APP, APP]); // ditto keeps the framework symlinks intact

console.log('3/5 Nome, icona e Info.plist…');
const contents = path.join(APP, 'Contents');
const res = path.join(contents, 'Resources');
fs.renameSync(path.join(contents, 'MacOS', 'Electron'), path.join(contents, 'MacOS', 'Gauntler'));
fs.copyFileSync(ICNS, path.join(res, 'gauntler.icns'));
fs.rmSync(path.join(res, 'electron.icns'), { force: true });
fs.rmSync(path.join(res, 'default_app.asar'), { force: true });
const plist = path.join(contents, 'Info.plist');
const set = (key, type, value) => run('plutil', ['-replace', key, `-${type}`, value, plist]);
set('CFBundleName', 'string', 'Gauntler');
set('CFBundleDisplayName', 'string', 'Gauntler');
set('CFBundleExecutable', 'string', 'Gauntler');
set('CFBundleIdentifier', 'string', 'app.gauntler.desktop');
set('CFBundleIconFile', 'string', 'gauntler.icns');
set('CFBundleShortVersionString', 'string', pkg.version);
set('CFBundleVersion', 'string', pkg.version);
set('LSApplicationCategoryType', 'string', 'public.app-category.utilities');
set('NSHumanReadableCopyright', 'string', '© 2026 anvex2012 · Gauntler Custom Source Code License');

console.log('4/5 Codice dell\'app…');
const appDir = path.join(res, 'app');
fs.mkdirSync(appDir);
for (const d of ['electron', 'core', 'cli', 'dist']) fs.cpSync(path.join(ROOT, d), path.join(appDir, d), { recursive: true });
fs.mkdirSync(path.join(appDir, 'build'));
fs.copyFileSync(path.join(ROOT, 'build', 'icon.png'), path.join(appDir, 'build', 'icon.png'));
fs.copyFileSync(path.join(ROOT, 'licenza-gauntler.txt'), path.join(appDir, 'licenza-gauntler.txt'));
const { devDependencies, scripts, ...runtimePkg } = pkg;
fs.writeFileSync(path.join(appDir, 'package.json'), JSON.stringify({ ...runtimePkg, productName: 'Gauntler', dependencies: {} }, null, 2));

console.log('5/5 Firma ad hoc…');
run('codesign', ['--force', '--deep', '--sign', '-', APP], { stdio: ['ignore', 'ignore', 'inherit'] });
run('touch', [APP]); // refreshes the Finder icon cache

const size = execFileSync('du', ['-sh', APP], { encoding: 'utf8' }).split('\t')[0];
console.log(`\nCreata: ${path.relative(ROOT, APP)} (${size})`);
console.log('Trascinala in Applicazioni (o sul Desktop) e aprila con doppio clic.');
