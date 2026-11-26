#!/usr/bin/env node
// Creato da anvex2012
'use strict';
const fs = require('fs');
const args = require('./args');
const ui = require('./ui');
const { c } = ui;
const i18n = require('../core/i18n');
const { t } = i18n;

const scan = require('./commands/scan');
const watch = require('./commands/watch');
const manage = require('./commands/manage');
const disasm = require('./commands/disasm');
const sanitize = require('./commands/sanitize');
const appCmds = require('./commands/app');
const tui = require('./tui');
const setupCmd = require('./commands/setup');

const shell = { get summary() { return tui.summary; }, get HELP() { return tui.HELP; }, run: (argv) => (argv.includes('-h') || argv.includes('--help') ? (console.log(tui.HELP), 0) : tui.run()) };
const COMMANDS = { shell, setup: setupCmd, scan, sanitize, watch, disasm, ...manage, ...appCmds };
const ALIASES = { lingua: 'language', lang: 'language', languages: 'language', idioma: 'language', langue: 'language', sprache: 'language', componenti: 'setup', 'installa-componenti': 'setup', i: 'shell', tui: 'shell', interattivo: 'shell', s: 'scan', w: 'watch', d: 'disasm', dis: 'disasm', cdr: 'sanitize', clean: 'sanitize', q: 'quarantine', h: 'history', cfg: 'config', allow: 'trust', gui: 'app', apri: 'app', open: 'app' };

function version() { return require('../core').VERSION; }

function mainHelp() {
  const w = Math.max(...Object.keys(COMMANDS).map((k) => k.length));
  return `
${c.bold('Gauntler')} ${version()} — ${t('analisi di sicurezza approfondita di qualsiasi file')}

${c.bold(t('Uso'))}
  gauntler                                     ${c.dim(t('interfaccia interattiva (pulsante + per aggiungere file)'))}
  gauntler <file|${t('cartella')}|->  [${t('opzioni')}]        ${c.dim(t('analizza (come "gauntler scan")'))}
  gauntler <${t('comando')}> [${t('argomenti')}] [${t('opzioni')}]

${c.bold(t('Comandi'))}
${Object.entries(COMMANDS).map(([k, v]) => `  ${c.cyan(k.padEnd(w))}  ${v.summary}`).join('\n')}
  ${c.cyan('completion'.padEnd(w))}  ${t('Autocompletamento per la shell (bash / zsh)')}

${c.bold(t('Opzioni globali'))}
  -h, --help        ${t('Aiuto (anche: gauntler <comando> --help)')}
      --version     ${t('Versione')}
      --no-color    ${t('Senza colori (anche NO_COLOR=1)')}
      --lang <xx>   ${t('Lingua per questa esecuzione (it, en, es, fr, de)')} · ${t('per cambiarla sempre:')} gauntler language

${c.bold(t('Punteggio'))}  ${t('100 = sicuro · 1 = malevolo')}
  ${c.green('90-100 ' + t('Sicuro'))} · ${c.cyan('70-89 ' + t('Basso rischio'))} · ${c.yellow('40-69 ' + t('Sospetto'))} · ${c.red('15-39 ' + t('Pericoloso'))} · ${c.bgRed('1-14 ' + t('Malevolo'))}

${c.bold(t('Esempi'))}
  gauntler ~/Downloads/fattura.pdf -l          ${c.dim(t('report con le righe segnalate'))}
  gauntler ~/Downloads -q                      ${c.dim(t('una riga per file, in parallelo'))}
  gauntler . -x "**/node_modules/**" -f sarif -o gauntler.sarif --fail-on high
  curl -s https://esempio.it/script.sh | gauntler - --name script.sh
  gauntler sanitize fattura.docm                ${c.dim(t('copia sicura: fattura.safe.docx'))}
  gauntler disasm programma.exe -b               ${c.dim(t('assembly + codice binario'))}
  gauntler watch ~/Downloads --notify --quarantine
  gauntler lookup sospetto.exe                  ${c.dim(t('VirusTotal/MalwareBazaar (solo impronta)'))}
  gauntler doctor                               ${c.dim(t('verifica motori esterni e configurazione'))}
  gauntler language en                          ${c.dim(t('cambia la lingua'))}
  gauntler app ~/Downloads/fattura.pdf          ${c.dim(t('apre l\'app desktop e analizza il file'))}
`;
}

function completion(shell) {
  const cmds = [...Object.keys(COMMANDS), 'completion'].join(' ');
  const opts = Object.keys(scan.SPEC).map((k) => '--' + k.replace(/[A-Z]/g, (m) => '-' + m.toLowerCase())).join(' ');
  if (shell === 'zsh') {
    return `#compdef gauntler
_gauntler() {
  local -a cmds; cmds=(${Object.entries(COMMANDS).map(([k, v]) => `'${k}:${v.summary.replace(/'/g, '')}'`).join(' ')})
  if (( CURRENT == 2 )); then _describe 'command' cmds; _files; return; fi
  case $words[2] in
    quarantine) _values 'action' list add restore delete ;;
    config) _values 'action' list get set unset add remove path ;;
    rules) _values 'type' analyzers signatures tokens secrets yara ;;
    language) _values 'language' it en es fr de ;;
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
    language) COMPREPLY=( $(compgen -W "it en es fr de" -- "$cur") ) ;;
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
  // --lang xx / --lang=xx: language for this run only
  const li = argv.findIndex((x) => x === '--lang' || x.startsWith('--lang='));
  if (li >= 0) {
    const v = argv[li].includes('=') ? argv[li].split('=')[1] : argv[li + 1];
    if (!i18n.normalize(v)) throw new args.UsageError(t('Lingua non disponibile: {l}. Disponibili: {list}', { l: v || '', list: i18n.CODES.join(', ') }));
    i18n.setLanguage(v);
    process.env.GAUNTLER_LANG = i18n.getLanguage(); // also for the analysis threads and the app opened from here
    argv.splice(li, argv[li].includes('=') ? 1 : 2);
  }
  // First interactive run: choose the language (asked once, then "gauntler language" changes it)
  const noAsk = ['language', 'lingua', 'lang', 'completion', '--version', '-V'];
  if (process.stdin.isTTY && process.stdout.isTTY && !noAsk.includes(argv[0])) await require('./language').firstRun();
  // First interactive run: install the "gauntler" command (only if missing) and put it in PATH
  let firstRun = null;
  if (process.stdout.isTTY && !['install-command', 'uninstall-command'].includes(argv[0])) firstRun = require('./install').autoInstall();
  const welcome = firstRun && !firstRun.error ? firstRun : null;
  // First interactive run: install ClamAV (with signatures) and bsdtar if they are missing
  const quick = ['setup', 'componenti', 'installa-componenti', 'install-command', 'uninstall-command', 'completion', '--version', '-V', '-h', '--help', 'help'];
  if (process.stdin.isTTY && process.stdout.isTTY && !quick.includes(argv[0]) && require('../core/setup').needsAuto()) {
    if (welcome) { console.error(`${c.green('✔')} ${t('Comando "gauntler" installato — da una nuova finestra del terminale basta scrivere')} ${c.cyan('gauntler')}`); }
    await setupCmd.runInTerminal({ auto: true });
  }
  // No arguments in an interactive terminal: full-screen interface
  if (!argv.length && process.stdin.isTTY && process.stdout.isTTY && !process.env.GAUNTLER_NO_TUI) return tui.run({ firstRun: welcome });
  if (welcome) console.error(`${c.green('✔')} ${welcome.installed ? t('Comando "gauntler" installato') : t('Comando "gauntler" aggiunto al PATH')}${welcome.rc ? ' · ' + t('PATH aggiornato in {rc}', { rc: welcome.rc }) : ''} — ${t('da una nuova finestra del terminale basta scrivere')} ${c.cyan('gauntler')}\n`);
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
    if (!COMMANDS[name] && /^[a-z]+$/.test(argv[0]) && !fs.existsSync(argv[0])) throw new args.UsageError(t('Comando o file sconosciuto: "{x}". Vedi: gauntler --help', { x: argv[0] }));
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
    if (e instanceof args.UsageError) { console.error(c.red('✖ ' + t(e.message))); process.exitCode = 2; }
    else { console.error(c.red('✖ ' + t(String(e.message || e)))); if (process.env.GAUNTLER_DEBUG) console.error(e.stack); process.exitCode = 3; }
  },
);
