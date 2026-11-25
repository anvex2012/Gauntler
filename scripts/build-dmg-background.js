// Creato da anvex2012
'use strict';
/**
 * Renders the background of the macOS install window (the .dmg):
 *   build/dmg-background.png   660×420, used by scripts/package-all.js
 * Run with: npx electron scripts/build-dmg-background.js
 * Icon positions in the window (see package-all.js): app at (170, 175), Applications at (490, 175).
 */
const { app, BrowserWindow } = require('electron');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const W = 660, H = 420;

const HTML = `<!doctype html><html><head><meta charset="utf-8"><style>
  * { margin: 0; box-sizing: border-box; }
  html, body { width: ${W}px; height: ${H}px; overflow: hidden; }
  body { font-family: -apple-system, "SF Pro Text", "Helvetica Neue", sans-serif; color: #1d2330; -webkit-font-smoothing: antialiased;
         background: linear-gradient(180deg, #fbfbfd 0%, #f1f3f7 100%); position: relative; }
  .head { position: absolute; top: 26px; left: 0; right: 0; text-align: center; }
  .head h1 { font-size: 19px; font-weight: 650; letter-spacing: -.2px; }
  .head p { margin-top: 5px; font-size: 12.5px; color: #5d6575; }
  .arrow { position: absolute; top: 160px; left: 252px; width: 156px; height: 30px; }
  .card { position: absolute; left: 40px; right: 40px; bottom: 26px; padding: 13px 16px 14px; border-radius: 12px;
          background: #ffffff; border: 1px solid #e2e5eb; box-shadow: 0 1px 2px rgba(20, 30, 50, .04); }
  .card b { display: block; font-size: 12px; font-weight: 650; margin-bottom: 5px; }
  .card p { font-size: 11.5px; line-height: 1.5; color: #4a5263; }
  .card em { font-style: normal; font-weight: 600; color: #1d2330; }
  .step { display: inline-block; min-width: 17px; height: 17px; line-height: 17px; padding: 0 5px; border-radius: 9px; background: #2563eb; color: #fff;
          font-size: 10.5px; font-weight: 700; text-align: center; margin-right: 6px; vertical-align: 1px; }
</style></head><body>
  <div class="head"><h1>Installa Gauntler</h1><p>Trascina l'icona di Gauntler sulla cartella Applicazioni</p></div>
  <svg class="arrow" viewBox="0 0 156 30" aria-hidden="true">
    <path d="M6 15 H136" stroke="#2563eb" stroke-width="3" stroke-linecap="round" stroke-dasharray="1 9"/>
    <path d="M132 5 L148 15 L132 25" fill="none" stroke="#2563eb" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>
  </svg>
  <div class="card">
    <b>Al primo avvio</b>
    <p><span class="step">1</span>Apri Gauntler da Applicazioni. Se macOS la blocca, premi <em>Fine</em>.</p>
    <p><span class="step">2</span>Apri <em>Impostazioni di Sistema › Privacy e sicurezza</em> e premi <em>Apri comunque</em>.</p>
    <p style="margin-top:6px;color:#6b7383">Poi Gauntler installa da solo tutto il resto: comando <em>gauntler</em>, antivirus ClamAV e bsdtar.</p>
  </div>
</body></html>`;

async function render(scale) {
  const win = new BrowserWindow({ width: W, height: H, show: false, frame: false, useContentSize: true, webPreferences: { offscreen: true, zoomFactor: scale } });
  win.webContents.setZoomFactor(scale);
  win.setContentSize(W * scale, H * scale);
  await win.loadURL('data:text/html;charset=utf-8,' + encodeURIComponent(HTML.replace(/<body>/, `<body style="zoom:${scale}">`)));
  await new Promise((r) => setTimeout(r, 400));
  const img = await win.webContents.capturePage({ x: 0, y: 0, width: W * scale, height: H * scale });
  win.destroy();
  return img.resize({ width: W * scale, height: H * scale, quality: 'best' }).toPNG();
}

app.on('window-all-closed', () => { /* keep running */ });
app.whenReady().then(async () => {
  // A single 660×420 PNG: Finder on recent macOS shows the Retina variant of a multi-image TIFF at double size
  fs.writeFileSync(path.join(ROOT, 'build', 'dmg-background.png'), await render(1));
  console.log('build/dmg-background.png creato');
  app.quit();
});
