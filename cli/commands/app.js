// Creato da anvex2012
'use strict';
/* gauntler app · install-command · uninstall-command */
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const inst = require('../install');
const { c } = require('../ui');

const app = {
  summary: 'Apre l\'app desktop Gauntler (con i file indicati da analizzare)',
  HELP: `
${c.bold('gauntler app')} [file|cartella…]

Apre l'app desktop. I file e le cartelle indicati vengono analizzati subito nell'app.
Se l'app è già aperta, vengono aggiunti all'elenco.

  gauntler app                     ${c.dim('apre l\'app')}
  gauntler app ~/Downloads/x.zip   ${c.dim('apre l\'app e analizza il file')}
`,
  async run(argv, { parse }) {
    const a = parse(argv, {});
    if (a.help) { console.log(app.HELP); return 0; }
    const files = a._.map((f) => path.resolve(f));
    const missing = files.filter((f) => !fs.existsSync(f));
    if (missing.length) { console.error(c.red(`✖ Non trovato: ${missing.join(', ')}`)); return 2; }
    const bundle = inst.findApp();
    let child;
    if (bundle) child = spawn('open', ['-a', bundle, ...files], { stdio: 'ignore' });
    else {
      // Source checkout without the packaged app: Electron from node_modules
      const root = path.join(__dirname, '..', '..');
      let electron;
      try { electron = require(path.join(root, 'node_modules', 'electron')); } catch { electron = null; }
      if (!electron || !fs.existsSync(path.join(root, 'dist', 'index.html'))) {
        console.error(c.red('✖ App Gauntler non trovata.') + ' Crea l\'app con: npm run package (poi spostala in Applicazioni)');
        return 1;
      }
      child = spawn(electron, [root, ...files], { stdio: 'ignore', detached: true });
    }
    await new Promise((res) => { child.on('spawn', res); child.on('error', res); });
    child.unref();
    console.log(`${c.green('✔')} Gauntler aperto${files.length ? ` con ${files.length} ${files.length === 1 ? 'elemento' : 'elementi'} da analizzare` : ''}`);
    return 0;
  },
};

const installCommand = {
  summary: 'Installa il comando "gauntler" nel terminale (~/.local/bin)',
  HELP: `
${c.bold('gauntler install-command')} [--dir <cartella>] [--skip-components]

Crea il comando "gauntler" in ~/.local/bin (nessuna password di amministratore) e installa
i componenti che mancano: ClamAV con le firme antivirus e bsdtar (salta con --skip-components).
Il comando usa il motore incluso in Gauntler.app, quindi funziona anche senza Node.js.
`,
  async run(argv, { parse }) {
    const a = parse(argv, { dir: { type: 'string' }, skipComponents: { type: 'bool' } });
    if (a.help) { console.log(installCommand.HELP); return 0; }
    const s = inst.install(a.dir ? path.resolve(a.dir) : undefined);
    console.log(`${c.green('✔')} Comando installato: ${s.path}`);
    console.log(`  Motore: ${inst.appFromCli() ? s.app || 'Gauntler.app' : `sorgenti del progetto con Node.js${s.app ? ` (se Node.js manca: ${s.app})` : ''}`}`);
    const rc = s.inPath ? null : inst.ensurePath(s.dir);
    if (rc) console.log(`  PATH aggiornato in ${rc}: ${c.bold('apri una nuova finestra del terminale')} e scrivi ${c.cyan('gauntler')}`);
    else console.log(`\n  Prova:  ${c.cyan('gauntler --help')}`);
    // Components (ClamAV + signatures, bsdtar): installed together with the command
    if (!a.skipComponents && process.stdout.isTTY && require('../../core/setup').needsAuto()) await require('./setup').runInTerminal({ auto: true });
    return 0;
  },
};

const uninstallCommand = {
  summary: 'Rimuove il comando "gauntler" dal terminale',
  HELP: `\n${c.bold('gauntler uninstall-command')} [--dir <cartella>]\n\nRimuove il comando creato da "gauntler install-command".\n`,
  async run(argv, { parse }) {
    const a = parse(argv, { dir: { type: 'string' } });
    if (a.help) { console.log(uninstallCommand.HELP); return 0; }
    const r = inst.uninstall(a.dir ? path.resolve(a.dir) : undefined);
    console.log(r.removed ? `${c.green('✔')} Rimosso: ${r.path}` : `Nessun comando da rimuovere (${r.path})`);
    if (r.rc) console.log(`  Riga del PATH rimossa da ${r.rc}`);
    return 0;
  },
};

module.exports = { app, 'install-command': installCommand, 'uninstall-command': uninstallCommand };
