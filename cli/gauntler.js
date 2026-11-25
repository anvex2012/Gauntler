#!/usr/bin/env node
// Creato da anvex2012
'use strict';
const fs = require('fs');
const args = require('./args');
const ui = require('./ui');
const { c } = ui;

const scan = require('./commands/scan');
const watch = require('./commands/watch');
const manage = require('./commands/manage');
const disasm = require('./commands/disasm');
const sanitize = require('./commands/sanitize');
const appCmds = require('./commands/app');
const tui = require('./tui');
const setupCmd = require('./commands/setup');

const shell = { summary: tui.summary, HELP: tui.HELP, run: (argv) => (argv.includes('-h') || argv.includes('--help') ? (console.log(tui.HELP), 0) : tui.run()) };
const COMMANDS = { shell, setup: setupCmd, scan, sanitize, watch, disasm, ...manage, ...appCmds };
const ALIASES = { componenti: 'setup', 'installa-componenti': 'setup', i: 'shell', tui: 'shell', interattivo: 'shell', s: 'scan', w: 'watch', d: 'disasm', dis: 'disasm', cdr: 'sanitize', clean: 'sanitize', q: 'quarantine', h: 'history', cfg: 'config', allow: 'trust', gui: 'app', apri: 'app', open: 'app' };

function version() { return require('../core').VERSION; }

function mainHelp() {
  const w = Math.max(...Object.keys(COMMANDS).map((k) => k.length));
  return `
${c.bold('Gauntler')} ${version()} — analisi di sicurezza approfondita di qualsiasi file

${c.bold('Uso')}
  gauntler                                     ${c.dim('interfaccia interattiva (pulsante + per aggiungere file)')}
  gauntler <file|cartella|->  [opzioni]        ${c.dim('analizza (come "gauntler scan")')}
  gauntler <comando> [argomenti] [opzioni]

${c.bold('Comandi')}
${Object.entries(COMMANDS).map(([k, v]) => `  ${c.cyan(k.padEnd(w))}  ${v.summary}`).join('\n')}
  ${c.cyan('completion'.padEnd(w))}  Autocompletamento per la shell (bash / zsh)

${c.bold('Opzioni globali')}
  -h, --help        Aiuto (anche: gauntler <comando> --help)
      --version     Versione
      --no-color    Senza colori (anche NO_COLOR=1)

${c.bold('Punteggio')}  100 = sicuro · 1 = malevolo
  ${c.green('90-100 Sicuro')} · ${c.cyan('70-89 Basso rischio')} · ${c.yellow('40-69 Sospetto')} · ${c.red('15-39 Pericoloso')} · ${c.bgRed('1-14 Malevolo')}

${c.bold('Esempi')}
  gauntler ~/Downloads/fattura.pdf -l          ${c.dim('report con le righe segnalate')}
  gauntler ~/Downloads -q                      ${c.dim('una riga per file, in parallelo')}
  gauntler . -x "**/node_modules/**" -f sarif -o gauntler.sarif --fail-on high
  curl -s https://esempio.it/script.sh | gauntler - --name script.sh
  gauntler sanitize fattura.docm                ${c.dim('copia sicura: fattura.safe.docx')}
  gauntler disasm programma.exe -b               ${c.dim('assembly + codice binario')}
  gauntler watch ~/Downloads --notify --quarantine
  gauntler lookup sospetto.exe                  ${c.dim('VirusTotal/MalwareBazaar (solo impronta)')}
  gauntler doctor                               ${c.dim('verifica motori esterni e configurazione')}
  gauntler app ~/Downloads/fattura.pdf          ${c.dim('apre l\'app desktop e analizza il file')}
`;
}

function completion(shell) {
  const cmds = [...Object.keys(COMMANDS), 'completion'].join(' ');
  const opts = Object.keys(scan.SPEC).map((k) => '--' + k.replace(/[A-Z]/g, (m) => '-' + m.toLowerCase())).join(' ');
  if (shell === 'zsh') {
    return `#compdef gauntler
_gauntler() {
  local -a cmds; cmds=(${Object.entries(COMMANDS).map(([k, v]) => `'${k}:${v.summary.replace(/'/g, '')}'`).join(' ')})
  if (( CURRENT == 2 )); then _describe 'comando' cmds; _files; return; fi
  case $words[2] in
    quarantine) _values 'azione' list add restore delete ;;
    config) _values 'azione' list get set unset add remove path ;;
    rules) _values 'tipo' analyzers signatures tokens secrets yara ;;
    *) _arguments '*:file:_files' ${opts.split(' ').map((o) => `'${o}[]'`).join(' ')} ;;
  esac
}
compdef _gauntler gauntler
`;
  }
  return `# bash: aggiungi a ~/.bashrc →  eval "$(gauntler completion bash)"
_gauntler() {
  local cur=\${COMP_WORDS[COMP_CWORD]}
  if [ $COMP_CWORD -eq 1 ]; then COMPREPLY=( $(compgen -W "${cmds}" -- "$cur") $(compgen -f -- "$cur") ); return; fi
  case \${COMP_WORDS[1]} in
    quarantine) COMPREPLY=( $(compgen -W "list add restore delete" -- "$cur") ) ;;
    config) COMPREPLY=( $(compgen -W "list get set unset add remove path" -- "$cur") ) ;;
    rules) COMPREPLY=( $(compgen -W "analyzers signatures tokens secrets yara" -- "$cur") ) ;;
    *) if [[ $cur == -* ]]; then COMPREPLY=( $(compgen -W "${opts}" -- "$cur") ); else COMPREPLY=( $(compgen -f -- "$cur") ); fi ;;
  esac
}
complete -o filenames -F _gauntler gauntler
`;
}

async function main() {
  let argv = process.argv.slice(2);
  if (argv.includes('--no-color') || process.env.NO_COLOR) { ui.setColor(false); argv = argv.filter((x) => x !== '--no-color'); }
  if (argv.includes('--color')) { ui.setColor(true); argv = argv.filter((x) => x !== '--color'); }
  // First interactive run: install the "gauntler" command (only if missing) and put it in PATH
  let firstRun = null;
  if (process.stdout.isTTY && !['install-command', 'uninstall-command'].includes(argv[0])) firstRun = require('./install').autoInstall();
  const welcome = firstRun && !firstRun.error ? firstRun : null;
  // First interactive run: install ClamAV (with signatures) and bsdtar if they are missing
  const quick = ['setup', 'componenti', 'installa-componenti', 'install-command', 'uninstall-command', 'completion', '--version', '-V', '-h', '--help', 'help'];
  if (process.stdin.isTTY && process.stdout.isTTY && !quick.includes(argv[0]) && require('../core/setup').needsAuto()) {
    if (welcome) { console.error(`${c.green('✔')} Comando "gauntler" installato — da una nuova finestra del terminale basta scrivere ${c.cyan('gauntler')}`); }
    await setupCmd.runInTerminal({ auto: true });
  }
  // No arguments in an interactive terminal: full-screen interface
  if (!argv.length && process.stdin.isTTY && process.stdout.isTTY && !process.env.GAUNTLER_NO_TUI) return tui.run({ firstRun: welcome });
  if (welcome) console.error(`${c.green('✔')} ${welcome.installed ? 'Comando "gauntler" installato' : 'Comando "gauntler" aggiunto al PATH'}${welcome.rc ? ` · PATH aggiornato in ${welcome.rc}` : ''} — da una ${c.bold('nuova finestra del terminale')} basta scrivere ${c.cyan('gauntler')}\n`);
  if (!argv.length || argv[0] === '-h' || argv[0] === '--help' || argv[0] === 'help') {
    const sub = argv[0] === 'help' && argv[1] && COMMANDS[ALIASES[argv[1]] || argv[1]];
    console.log(sub ? sub.HELP : mainHelp());
    return argv.length ? 0 : 2;
  }
  if (argv[0] === '--version' || argv[0] === '-V') { console.log(version()); return 0; }
  if (argv[0] === 'completion') { process.stdout.write(completion(argv[1] || (process.env.SHELL || '').split('/').pop())); return 0; }
  if (argv[0] === '--list') argv = ['rules', 'analyzers']; // compatibility with v1

  let name = ALIASES[argv[0]] || argv[0];
  let rest = argv.slice(1);
  // An existing file/folder with the same name as a command takes precedence; "gauntler <path>" = scan
  if (!COMMANDS[name] || fs.existsSync(argv[0])) {
    if (!COMMANDS[name] && /^[a-z]+$/.test(argv[0]) && !fs.existsSync(argv[0])) throw new args.UsageError(`Comando o file sconosciuto: "${argv[0]}". Vedi: gauntler --help`);
    name = 'scan';
    rest = argv;
  }
  if (name === 'scan' || name === 'watch') rest = rest.map((x) => (x === '--json' ? '--format=json' : x)); // compatibility with v1
  const parse = (av, spec) => args.parse(av, { ...spec, help: { alias: 'h', type: 'bool' } });
  return COMMANDS[name].run(rest, { parse });
}

main().then(
  (code) => { process.exitCode = code ?? 0; },
  (e) => {
    if (e instanceof args.UsageError) { console.error(c.red('✖ ' + e.message)); process.exitCode = 2; }
    else { console.error(c.red('✖ ' + (e.message || e))); if (process.env.GAUNTLER_DEBUG) console.error(e.stack); process.exitCode = 3; }
  },
);
