// Created by anvex2012
'use strict';
/* gauntler app · install-command · uninstall-command */
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const inst = require('../install');
const { c } = require('../ui');
const { t } = require('../../core/i18n');

const app = {
  get summary() { return t('Apre l\'app desktop Gauntler (con i file indicati da analizzare)'); },
  get HELP() {
    return `
${c.bold('gauntler app')} [file|${t('cartella')}…]

${t('Apre l\'app desktop. I file e le cartelle indicati vengono analizzati subito nell\'app.\nSe l\'app è già aperta, vengono aggiunti all\'elenco.')}

  gauntler app                     ${c.dim(t('apre l\'app'))}
  gauntler app ~/Downloads/x.zip   ${c.dim(t('apre l\'app e analizza il file'))}
`;
  },
  async run(argv, { parse }) {
    const a = parse(argv, {});
    if (a.help) { console.log(app.HELP); return 0; }
    const files = a._.map((f) => path.resolve(f));
    const missing = files.filter((f) => !fs.existsSync(f));
    if (missing.length) { console.error(c.red('✖ ' + t('Non trovato: {path}', { path: missing.join(', ') }))); return 2; }
    const bundle = inst.findApp();
    let child;
    if (bundle) child = spawn('open', ['-a', bundle, ...files], { stdio: 'ignore' });
    else {
      // Source checkout without the packaged app: Electron from node_modules
      const root = path.join(__dirname, '..', '..');
      let electron;
      try { electron = require(path.join(root, 'node_modules', 'electron')); } catch { electron = null; }
      if (!electron || !fs.existsSync(path.join(root, 'dist', 'index.html'))) {
        console.error(c.red('✖ ' + t('App Gauntler non trovata.')) + ' ' + t('Crea l\'app con: npm run package (poi spostala in Applicazioni)'));
        return 1;
      }
      child = spawn(electron, [root, ...files], { stdio: 'ignore', detached: true });
    }
    await new Promise((res) => { child.on('spawn', res); child.on('error', res); });
    child.unref();
    console.log(`${c.green('✔')} ${!files.length ? t('Gauntler aperto') : files.length === 1 ? t('Gauntler aperto con {n} elemento da analizzare', { n: 1 }) : t('Gauntler aperto con {n} elementi da analizzare', { n: files.length })}`);
    return 0;
  },
};

const installCommand = {
  get summary() { return t('Installa il comando "gauntler" nel terminale (~/.local/bin)'); },
  get HELP() {
    return `
${c.bold('gauntler install-command')} [--dir <${t('cartella')}>] [--skip-components]

${t('Crea il comando "gauntler" in ~/.local/bin (nessuna password di amministratore) e installa\ni componenti che mancano: ClamAV con le firme antivirus e bsdtar (salta con --skip-components).\nIl comando usa il motore incluso in Gauntler.app, quindi funziona anche senza Node.js.')}
`;
  },
  async run(argv, { parse }) {
    const a = parse(argv, { dir: { type: 'string' }, skipComponents: { type: 'bool' } });
    if (a.help) { console.log(installCommand.HELP); return 0; }
    const s = inst.install(a.dir ? path.resolve(a.dir) : undefined);
    console.log(`${c.green('✔')} ${t('Comando installato: {path}', { path: s.path })}`);
    console.log(`  ${t('Motore')}: ${inst.appFromCli() ? s.app || 'Gauntler.app' : s.app ? t('sorgenti del progetto con Node.js (se Node.js manca: {app})', { app: s.app }) : t('sorgenti del progetto con Node.js')}`);
    const rc = s.inPath ? null : inst.ensurePath(s.dir);
    if (rc) console.log(`  ${t('PATH aggiornato in {rc}', { rc })}: ${c.bold(t('apri una nuova finestra del terminale'))} ${t('e scrivi')} ${c.cyan('gauntler')}`);
    else console.log(`\n  ${t('Prova:')}  ${c.cyan('gauntler --help')}`);
    // Components (ClamAV + signatures, bsdtar): installed together with the command
    if (!a.skipComponents && process.stdout.isTTY && require('../../core/setup').needsAuto()) await require('./setup').runInTerminal({ auto: true });
    return 0;
  },
};

const uninstallCommand = {
  get summary() { return t('Rimuove il comando "gauntler" dal terminale'); },
  get HELP() { return `\n${c.bold('gauntler uninstall-command')} [--dir <${t('cartella')}>]\n\n${t('Rimuove il comando creato da "gauntler install-command".')}\n`; },
  async run(argv, { parse }) {
    const a = parse(argv, { dir: { type: 'string' } });
    if (a.help) { console.log(uninstallCommand.HELP); return 0; }
    const r = inst.uninstall(a.dir ? path.resolve(a.dir) : undefined);
    console.log(r.removed ? `${c.green('✔')} ${t('Rimosso: {path}', { path: r.path })}` : t('Nessun comando da rimuovere ({path})', { path: r.path }));
    if (r.rc) console.log('  ' + t('Riga del PATH rimossa da {rc}', { rc: r.rc }));
    return 0;
  },
};

module.exports = { app, 'install-command': installCommand, 'uninstall-command': uninstallCommand };
