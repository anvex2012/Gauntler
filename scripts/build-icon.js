// Creato da anvex2012
'use strict';
/**
 * Renders build/icon.svg into the app icons (run with: npx electron scripts/build-icon.js)
 *  build/icon.png   1024×1024 (Linux/Windows window icon, source for the others)
 *  build/icon.icns  macOS (via iconutil, when available)
 *  src/assets/logo.png  128×128 logo used inside the interface
 */
const { app, BrowserWindow, nativeImage } = require('electron');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const SVG = fs.readFileSync(path.join(ROOT, 'build', 'icon.svg'), 'utf8');

async function render(size) {
  const win = new BrowserWindow({ width: size, height: size, show: false, transparent: true, frame: false, webPreferences: { offscreen: true } });
  const html = `<!doctype html><html><body style="margin:0;background:transparent;overflow:hidden">${SVG.replace('<svg ', `<svg style="display:block;width:${size}px;height:${size}px" `)}</body></html>`;
  await win.loadURL('data:text/html;charset=utf-8,' + encodeURIComponent(html));
  await new Promise((r) => setTimeout(r, 300));
  const img = await win.webContents.capturePage({ x: 0, y: 0, width: size, height: size });
  win.destroy();
  return img.resize({ width: size, height: size, quality: 'best' });
}


app.on('window-all-closed', () => { /* keep running until every size is written */ });
app.whenReady().then(async () => {
  const out = path.join(ROOT, 'build');
  const master = await render(1024);
  const at = (s) => nativeImage.createFromBuffer(master.toPNG()).resize({ width: s, height: s, quality: 'best' }).toPNG();
  fs.writeFileSync(path.join(out, 'icon.png'), master.toPNG());
  fs.mkdirSync(path.join(ROOT, 'src', 'assets'), { recursive: true });
  fs.writeFileSync(path.join(ROOT, 'src', 'assets', 'logo.png'), at(128));
  if (process.platform === 'darwin') {
    const set = path.join(out, 'icon.iconset');
    fs.rmSync(set, { recursive: true, force: true });
    fs.mkdirSync(set);
    for (const s of [16, 32, 128, 256, 512]) {
      fs.writeFileSync(path.join(set, `icon_${s}x${s}.png`), at(s));
      fs.writeFileSync(path.join(set, `icon_${s}x${s}@2x.png`), at(s * 2));
    }
    const r = spawnSync('iconutil', ['-c', 'icns', set, '-o', path.join(out, 'icon.icns')], { encoding: 'utf8' });
    fs.rmSync(set, { recursive: true, force: true });
    console.log(r.status === 0 ? 'build/icon.icns creato' : 'iconutil non riuscito: ' + r.stderr);
  }
  console.log('build/icon.png e src/assets/logo.png creati');
  app.quit();
});
