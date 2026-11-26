// Created by anvex2012
'use strict';
const { app, BrowserWindow, ipcMain, dialog, shell, nativeTheme } = require('electron');
const path = require('path');
const fs = require('fs');
const { walk, analyzers, clamavAvailable, VERSION } = require('../core');
const cliInstall = require('../cli/install');
const i18n = require('../core/i18n');
const config = require('../core/config');
const { t } = i18n;

// Same name everywhere: menu bar, About panel, Dock, notifications (also when running from sources)
app.setName('Gauntler');
const aboutPanel = () => app.setAboutPanelOptions({ applicationName: 'Gauntler', applicationVersion: VERSION, copyright: t('Analisi di sicurezza dei file — tutta locale') });
aboutPanel();

const DEV_URL = process.env.VITE_DEV_SERVER_URL;
const ICON = path.join(__dirname, '..', 'build', 'icon.png');
const MAX_FILES = 5000;
let win;
const pendingOpen = [];
app.on('open-file', (e, p) => { e.preventDefault(); if (win && !win.webContents.isLoading()) win.webContents.send('open-paths', [p]); else pendingOpen.push(p); });

// ---- Shared worker pool (same engine as the CLI: parallel, timeout per file) ----
const { ScanPool } = require('../core/pool');
const history = require('../core/history');
const report = require('../core/report');
const pool = new ScanPool({ size: Math.max(1, require('os').cpus().length - 1) });
const scanInWorker = (filePath, options) => pool.scan(filePath, options);

function expand(paths) {
  const files = [];
  for (const p of paths) {
    try {
      const st = fs.statSync(p);
      if (st.isDirectory()) files.push(...walk(p));
      else if (st.isFile()) files.push(p);
    } catch { /* inaccessible */ }
    if (files.length >= MAX_FILES) break;
  }
  return files.slice(0, MAX_FILES);
}

function createWindow() {
  win = new BrowserWindow({
    width: 1240,
    height: 820,
    minWidth: 880,
    minHeight: 600,
    title: 'Gauntler',
    backgroundColor: nativeTheme.shouldUseDarkColors ? '#0f1115' : '#f6f7f9',
    titleBarStyle: process.platform === 'darwin' ? 'hiddenInset' : 'default',
    icon: fs.existsSync(ICON) ? ICON : undefined, // Windows / Linux window and taskbar icon
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      spellcheck: false,
    },
  });
  // Security: no navigation or popups
  win.webContents.on('will-navigate', (e) => e.preventDefault());
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  // Files passed on the command line or via "Open with" (macOS)
  win.webContents.on('did-finish-load', () => {
    const argPaths = process.argv.slice(app.isPackaged ? 1 : 2).filter((a) => !a.startsWith('-') && a !== '.' && fs.existsSync(a));
    const all = [...argPaths, ...pendingOpen.splice(0)];
    if (all.length) win.webContents.send('open-paths', all.map((p) => path.resolve(p)));
    // Test mode: saves a screenshot of the window and exits
    if (process.env.GAUNTLER_SCREENSHOT) {
      setTimeout(async () => {
        if (process.env.GAUNTLER_SCREENSHOT_JS) { await win.webContents.executeJavaScript(process.env.GAUNTLER_SCREENSHOT_JS).catch(() => {}); await new Promise((r) => setTimeout(r, 700)); }
        const img = await win.webContents.capturePage();
        fs.writeFileSync(process.env.GAUNTLER_SCREENSHOT, img.toPNG());
        app.quit();
      }, Number(process.env.GAUNTLER_SCREENSHOT_DELAY || 3500));
    }
  });
  if (DEV_URL) win.loadURL(DEV_URL);
  else win.loadFile(path.join(__dirname, '..', 'dist', 'index.html'));
}

ipcMain.handle('env', () => ({ version: VERSION, clamav: clamavAvailable(), sevenZip: !!require('../core/extract').tools().sevenZip, analyzers: i18n.localize(analyzers), platform: process.platform }));

// Language (shared with the terminal, saved in ~/.gauntler/config.json): null until chosen on first use
ipcMain.handle('get-language', () => ({ lang: i18n.savedLanguage(), current: i18n.getLanguage(), system: i18n.normalize(app.getLocale()) || 'en', languages: i18n.LANGUAGES }));
ipcMain.handle('set-language', (_e, code) => {
  const c = i18n.normalize(code);
  if (!c) return false;
  try { config.set('language', c); } catch { /* not writable: still used for this session */ }
  i18n.setLanguage(c);
  aboutPanel();
  return c;
});

ipcMain.handle('pick', async (_e, kind) => {
  const props = kind === 'folder' ? ['openDirectory', 'multiSelections'] : ['openFile', 'multiSelections'];
  const r = await dialog.showOpenDialog(win, { properties: props, title: kind === 'folder' ? t('Scegli una cartella da analizzare') : t('Scegli i file da analizzare') });
  return r.canceled ? [] : r.filePaths;
});

// Expands folders and returns the list of files (the renderer then calls scan-one)
ipcMain.handle('expand', (_e, paths) => expand(Array.isArray(paths) ? paths : []));

ipcMain.handle('scan-one', async (_e, filePath, opts = {}) => {
  const passwords = Array.isArray(opts.passwords) ? opts.passwords.filter((p) => typeof p === 'string').slice(0, 500) : [];
  try {
    // Returned untranslated with its translation pack: the interface translates it (again, when the language changes)
    const result = await scanInWorker(filePath, { detail: true, passwords, localize: false });
    history.record(result);
    return { ok: true, result };
  }
  catch (e) { return { ok: false, error: t(e.message), path: filePath }; }
});

ipcMain.handle('save-report', async (_e, { name, result, format }) => {
  const ext = { html: 'html', json: 'json', sarif: 'sarif', csv: 'csv', md: 'md' }[format] || 'json';
  const data = report.render(format === 'md' ? 'md' : format, [i18n.finish(result, i18n.getLanguage())], { detail: false });
  const r = await dialog.showSaveDialog(win, { defaultPath: `gauntler-${name}.${ext}`, filters: [{ name: ext.toUpperCase(), extensions: [ext] }] });
  if (r.canceled || !r.filePath) return null;
  fs.writeFileSync(r.filePath, data);
  return r.filePath;
});

ipcMain.handle('sanitize', async (_e, filePath) => {
  if (typeof filePath !== 'string' || !fs.existsSync(filePath)) return { ok: false, error: t('file non trovato') };
  try {
    const { sanitizeFile } = require('../core/sanitize');
    const r = await sanitizeFile(filePath, { dryRun: true });
    if (r.status === 'blocked') return { ok: false, reason: r.reason + (r.blocking && r.blocking.length ? ': ' + r.blocking.join('; ') : '') };
    const d = await dialog.showSaveDialog(win, { defaultPath: path.join(path.dirname(filePath), r.outName) });
    if (d.canceled || !d.filePath) return null;
    if (path.resolve(d.filePath) === path.resolve(filePath)) return { ok: false, error: t('scegli un nome diverso dall\'originale') };
    fs.writeFileSync(d.filePath, r.output, { mode: 0o644 });
    return { ok: true, outPath: d.filePath, status: r.status, actions: r.actions, after: r.after };
  } catch (e) { return { ok: false, error: t(e.message) }; }
});

// Appearance: the theme is applied natively (window, scrollbars, menus, prefers-color-scheme in the page)
ipcMain.handle('set-theme', (_e, theme) => {
  if (!['system', 'light', 'dark'].includes(theme)) return false;
  nativeTheme.themeSource = theme;
  if (win) win.setBackgroundColor(nativeTheme.shouldUseDarkColors ? '#0b0c0e' : '#f3f4f6');
  return true;
});

// Terminal command "gauntler" (~/.local/bin): fixed location, never overwrites a file it did not create
// ---- Components (ClamAV + signatures, bsdtar): installed in the background on first launch ----
const setup = require('../core/setup');
let setupState = { running: false, text: '', result: null };
const sendSetup = () => { if (win && !win.isDestroyed()) win.webContents.send('setup', setupState); };
async function runSetup() {
  if (setupState.running) return setupState;
  setupState = { running: true, text: t('Installazione dei componenti (ClamAV, bsdtar)…'), result: null };
  sendSetup();
  let result;
  try {
    result = await setup.run({ mode: 'gui', log: (text, kind) => { if (kind === 'step') { setupState = { ...setupState, text }; sendSetup(); } } });
  } catch (e) { result = { complete: false, error: e.message }; }
  setupState = { running: false, text: '', result };
  sendSetup();
  return setupState;
}
ipcMain.handle('setup-state', () => setupState);
ipcMain.handle('setup-run', () => runSetup());

ipcMain.handle('cli-status', () => { try { return { ok: true, ...cliInstall.status() }; } catch (e) { return { ok: false, error: e.message }; } });
ipcMain.handle('cli-install', () => { try { return { ok: true, ...cliInstall.install() }; } catch (e) { return { ok: false, error: e.message }; } });
ipcMain.handle('cli-uninstall', () => { try { cliInstall.uninstall(); return { ok: true, ...cliInstall.status() }; } catch (e) { return { ok: false, error: e.message }; } });

ipcMain.handle('reveal', (_e, p) => { if (typeof p === 'string' && fs.existsSync(p)) shell.showItemInFolder(p); });

app.whenReady().then(() => {
  // First launch: also make the app usable from the terminal ("gauntler"), without overwriting an existing command
  setTimeout(() => {
    const r = cliInstall.autoInstall();
    if (r?.error) console.warn('gauntler: ' + t('comando da terminale non installato:'), r.error);
    // Then the components: everything missing on first launch, otherwise only a quiet signature refresh
    if (setup.needsAuto()) runSetup();
    else setup.refreshDatabase().catch(() => {});
  }, 1500);
  // macOS: Dock icon also when running unpackaged (npm start / npm run dev)
  if (process.platform === 'darwin' && app.dock && fs.existsSync(ICON)) app.dock.setIcon(ICON);
  createWindow();
  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
app.on('before-quit', () => { pool.close(); });
