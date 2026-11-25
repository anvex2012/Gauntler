// Creato da anvex2012
'use strict';
/* gauntler setup — installs ClamAV (with its signatures) and bsdtar */
const setup = require('../../core/setup');
const { c } = require('../ui');

const ICON = { step: c.cyan('▸'), ok: c.green('✔'), warn: c.yellow('!'), err: c.red('✖') };
function printer() {
  return (text, kind) => {
    if (kind === 'out') return; // tool output already shown live in the terminal (or not needed)
    console.log(`${ICON[kind] || ' '} ${kind === 'step' ? c.bold(text) : text}`);
  };
}

/** Runs the setup in the terminal. auto: first start (Ctrl+C skips it) */
async function runInTerminal({ auto = false } = {}) {
  console.log(`\n${c.bold('◆ Gauntler')} ${c.dim('·')} ${auto ? 'primo avvio: installo i componenti aggiuntivi' : 'installazione dei componenti'}`);
  console.log(c.dim('  ClamAV (antivirus) e bsdtar (archivi RAR, 7z, ISO). Può servire la password di amministratore.'));
  if (auto) console.log(c.dim('  Premi Ctrl+C per saltare: potrai farlo dopo con "gauntler setup".'));
  console.log('');
  let skipped = false;
  const onInt = () => { skipped = true; };
  process.on('SIGINT', onInt);
  let r;
  try { r = await setup.run({ mode: 'terminal', log: printer() }); } finally { process.off('SIGINT', onInt); }
  if (skipped) console.log(c.yellow('\n! Installazione interrotta. Riprova quando vuoi con: gauntler setup'));
  else if (r.complete) console.log(c.green('\n✔ Componenti pronti: ClamAV, firme antivirus e bsdtar.'));
  else console.log(c.yellow('\n! Alcuni componenti non sono stati installati. Gauntler funziona comunque; riprova con: gauntler setup'));
  console.log('');
  return r;
}

module.exports = {
  runInTerminal,
  summary: 'Installa i componenti aggiuntivi: ClamAV (con le firme) e bsdtar',
  HELP: `
${c.bold('gauntler setup')} [--status]

Installa ciò che manca, con il metodo adatto al sistema:
  macOS    ClamAV con Homebrew, oppure il pacchetto ufficiale ClamAV (password di amministratore);
           bsdtar è già incluso in macOS
  Linux    clamav e bsdtar con apt / dnf / yum / pacman / zypper (sudo)
  Windows  ClamAV con winget, oppure il pacchetto ufficiale .msi; bsdtar è tar.exe di Windows

Le firme antivirus vengono scaricate in ~/.gauntler/clamav e aggiornate con "gauntler update",
senza password. Viene eseguito da solo al primo avvio (disattivabile con GAUNTLER_NO_AUTOINSTALL=1).

  --status   Mostra solo cosa è installato
`,
  async run(argv, { parse }) {
    const a = parse(argv, { status: { type: 'bool' } });
    if (a.help) { console.log(module.exports.HELP); return 0; }
    if (a.status) {
      const s = setup.status();
      const row = (ok, name, val) => console.log(`  ${ok ? c.green('✔') : c.yellow('✖')} ${name.padEnd(16)} ${ok ? c.dim(val) : c.yellow(val)}`);
      row(!!s.clamav, 'ClamAV', s.clamav || 'non installato');
      row(s.database, 'Firme antivirus', s.database ? (s.ownDatabase || 'database di sistema') : 'mancanti');
      row(!!s.bsdtar, 'bsdtar', s.bsdtar || 'non installato');
      return s.clamav && s.database && s.bsdtar ? 0 : 1;
    }
    const r = await runInTerminal();
    return r.complete ? 0 : 1;
  },
};
