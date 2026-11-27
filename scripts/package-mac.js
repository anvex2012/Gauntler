// Created by anvex2012
'use strict';
/**
 * Builds a standalone macOS desktop app: release/Gauntler.app
 * (Electron runtime + interface + analysis engine, with the Gauntler icon and name).
 *   npm run package
 * No extra dependencies: the bundled Electron.app is copied, renamed, given the icon and
 * re-signed ad hoc (required on Apple Silicon after the bundle is modified).
 *
 * Signing for distribution (optional): with a "Developer ID Application" certificate in the Keychain
 *   GAUNTLER_SIGN_IDENTITY="Developer ID Application: Name (TEAMID)"   signs with the hardened runtime
 *   GAUNTLER_NOTARY_PROFILE=gauntler                                     also notarizes and staples the app
 * The profile is created once with: xcrun notarytool store-credentials gauntler --apple-id … --team-id …
 * Then macOS opens the app with no "Open Anyway" step.
 */
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

if (process.platform !== 'darwin') { console.error('This script builds the macOS app: run it on a Mac.'); process.exit(1); }

const ROOT = path.join(__dirname, '..');
const pkg = require(path.join(ROOT, 'package.json'));
const ELECTRON_APP = path.join(ROOT, 'node_modules', 'electron', 'dist', 'Electron.app');
const OUT_DIR = path.join(ROOT, 'release');
const APP = path.join(OUT_DIR, 'Gauntler.app');
const ICNS = path.join(ROOT, 'build', 'icon.icns');
const run = (cmd, args, opts = {}) => execFileSync(cmd, args, { stdio: 'inherit', cwd: ROOT, ...opts });

if (!fs.existsSync(ELECTRON_APP)) throw new Error('Electron not found: run npm install first');
if (!fs.existsSync(ICNS)) run(path.join(ROOT, 'node_modules', '.bin', 'electron'), [path.join(__dirname, 'build-icon.js')]);

console.log('1/5 Interface (vite build)…');
run(path.join(ROOT, 'node_modules', '.bin', 'vite'), ['build', '--logLevel', 'warn']);

console.log('2/5 Copying the Electron runtime…');
fs.rmSync(APP, { recursive: true, force: true });
fs.mkdirSync(OUT_DIR, { recursive: true });
run('ditto', [ELECTRON_APP, APP]); // ditto keeps the framework symlinks intact

console.log('3/5 Name, icon and Info.plist…');
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

console.log('4/5 App code…');
const appDir = path.join(res, 'app');
fs.mkdirSync(appDir);
for (const d of ['electron', 'core', 'cli', 'dist']) fs.cpSync(path.join(ROOT, d), path.join(appDir, d), { recursive: true });
fs.mkdirSync(path.join(appDir, 'build'));
fs.copyFileSync(path.join(ROOT, 'build', 'icon.png'), path.join(appDir, 'build', 'icon.png'));
fs.copyFileSync(path.join(ROOT, 'LICENSE.txt'), path.join(appDir, 'LICENSE.txt'));
const { devDependencies, scripts, ...runtimePkg } = pkg;
fs.writeFileSync(path.join(appDir, 'package.json'), JSON.stringify({ ...runtimePkg, productName: 'Gauntler', dependencies: {} }, null, 2));

const IDENTITY = process.env.GAUNTLER_SIGN_IDENTITY;
const NOTARY_PROFILE = process.env.GAUNTLER_NOTARY_PROFILE;

(async () => {
  if (!IDENTITY) {
    console.log('5/5 Ad-hoc signing… (set GAUNTLER_SIGN_IDENTITY to sign with a Developer ID)');
    run('codesign', ['--force', '--deep', '--sign', '-', APP], { stdio: ['ignore', 'ignore', 'inherit'] });
  } else {
    console.log(`5/5 Signing with "${IDENTITY}" (hardened runtime)…`);
    const { sign } = require('@electron/osx-sign');
    const entitlements = path.join(ROOT, 'build', 'entitlements.mac.plist');
    // Every nested binary is signed from the inside out, each with the hardened runtime and the same minimal entitlements
    await sign({ app: APP, identity: IDENTITY, platform: 'darwin', optionsForFile: () => ({ hardenedRuntime: true, entitlements }) });
    run('codesign', ['--verify', '--deep', '--strict', '--verbose=2', APP]);
    if (NOTARY_PROFILE) {
      console.log(`   Notarization (profile "${NOTARY_PROFILE}"): a few minutes…`);
      const { notarize } = require('@electron/notarize');
      await notarize({ appPath: APP, keychainProfile: NOTARY_PROFILE });
      run('xcrun', ['stapler', 'validate', APP]);
    } else console.log('   Not notarized (set GAUNTLER_NOTARY_PROFILE): macOS will still ask to confirm the first launch.');
  }
  run('touch', [APP]); // refreshes the Finder icon cache

  const size = execFileSync('du', ['-sh', APP], { encoding: 'utf8' }).split('\t')[0];
  console.log(`\nCreated: ${path.relative(ROOT, APP)} (${size})`);
  console.log('Drag it to Applications (or the Desktop) and double-click it.');
})().catch((e) => { console.error(e.message || e); process.exit(1); });
