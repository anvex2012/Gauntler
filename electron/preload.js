// Creato da anvex2012
'use strict';
const { contextBridge, ipcRenderer, webUtils, webFrame } = require('electron');

// Minimal, explicit API exposed to the interface
contextBridge.exposeInMainWorld('gauntler', {
  env: () => ipcRenderer.invoke('env'),
  getLanguage: () => ipcRenderer.invoke('get-language'),
  setLanguage: (code) => ipcRenderer.invoke('set-language', code),
  pick: (kind) => ipcRenderer.invoke('pick', kind),
  expand: (paths) => ipcRenderer.invoke('expand', paths),
  scanOne: (p, opts) => ipcRenderer.invoke('scan-one', p, opts),
  saveReport: (opts) => ipcRenderer.invoke('save-report', opts),
  reveal: (p) => ipcRenderer.invoke('reveal', p),
  sanitize: (p) => ipcRenderer.invoke('sanitize', p),
  pathForFile: (file) => webUtils.getPathForFile(file),
  setTheme: (theme) => ipcRenderer.invoke('set-theme', theme),
  cliStatus: () => ipcRenderer.invoke('cli-status'),
  cliInstall: () => ipcRenderer.invoke('cli-install'),
  cliUninstall: () => ipcRenderer.invoke('cli-uninstall'),
  // Interface size: 80%–150%, validated here so the page can never set an absurd zoom
  setZoom: (f) => { const n = Number(f); if (Number.isFinite(n)) webFrame.setZoomFactor(Math.min(1.5, Math.max(0.8, n))); },
  setupState: () => ipcRenderer.invoke('setup-state'),
  setupRun: () => ipcRenderer.invoke('setup-run'),
  onSetup: (cb) => {
    const h = (_e, st) => cb(st);
    ipcRenderer.on('setup', h);
    return () => ipcRenderer.removeListener('setup', h);
  },
  onOpenPaths: (cb) => {
    const h = (_e, paths) => cb(paths);
    ipcRenderer.on('open-paths', h);
    return () => ipcRenderer.removeListener('open-paths', h);
  },
});
