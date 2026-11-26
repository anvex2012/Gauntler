// Created by anvex2012
'use strict';
/* gauntler sanitize: Content Disarm & Reconstruction — produces safe copies of files */
const fs = require('fs');
const path = require('path');
const core = require('../../core');
const config = require('../../core/config');
const { sanitizeFile } = require('../../core/sanitize');
const { UsageError } = require('../args');
const ui = require('../ui');
const { c } = ui;
const { t } = require('../../core/i18n');

const SPEC = {
  out: { alias: 'o', type: 'string' },
  outDir: { alias: 'd', type: 'string' },
  inPlace: { type: 'bool' },
  strict: { type: 'bool' },
  keepMetadata: { type: 'bool' },
  stripLinks: { type: 'bool' },
  password: { alias: 'p', type: 'list' },
  recursive: { alias: 'r', type: 'bool', default: true },
  exclude: { alias: 'x', type: 'list' },
  dryRun: { alias: 'n', type: 'bool' },
  json: { type: 'bool' },
  quiet: { alias: 'q', type: 'bool' },
};

const HELP = () => `
${c.bold('gauntler sanitize')} — ${t('rende sicuri i file: li ricostruisce senza contenuti attivi e li ri-verifica')}

${c.bold(t('Uso'))}
  gauntler sanitize <file|${t('cartella')}…> [${t('opzioni')}]

${c.bold(t('Cosa fa'))} ${c.dim('(Content Disarm & Reconstruction)')}
  PDF        ${t('rimuove JavaScript, azioni automatiche, Launch, allegati, XFA; ricostruisce il file da zero')}
  Word/Excel/PowerPoint  ${t('rimuove macro VBA e XLM, ActiveX, oggetti OLE, DDE, template remoti; .docm → .docx')}
  .doc/.xls  ${t('azzera progetto VBA, oggetti incorporati ed Equation Editor')}
  RTF        ${t('rimuove oggetti incorporati (\\object, \\objdata) e campi DDE')}
  HTML/SVG   ${t('rimuove script, iframe, gestori on…, URL javascript:, destinazioni dei moduli')}
  ${t('Immagini').padEnd(10)} ${t('rimuove EXIF/GPS/XMP/commenti e i dati nascosti dopo la fine dell\'immagine')}
  ${t('Testo/CSV').padEnd(10)} ${t('rimuove caratteri invisibili e bidirezionali (Trojan Source), neutralizza le formule CSV')}
  ${t('Archivi').padEnd(10)} ${t('disarma ogni file interno, elimina quelli pericolosi, percorsi anomali e link simbolici')}
  ${t('Programmi e script non si possono disarmare: escono solo se l\'analisi è pulita (o mai, con --strict)')}
  ${c.bold(t('Ogni file prodotto viene ri-analizzato da tutto il motore: se resta qualcosa di pericoloso, viene bloccato.'))}

${c.bold(t('Opzioni'))}
  -o, --out <file>        ${t('File di destinazione (un solo file in ingresso)')}
  -d, --out-dir <dir>     ${t('Cartella di destinazione (predefinito: accanto all\'originale, nome.safe.ext)')}
      --in-place          ${t('Sostituisce l\'originale (che va in quarantena, ripristinabile)')}
      --strict            ${t('Blocca sempre programmi e script')}
      --keep-metadata     ${t('Mantiene autore/azienda nei documenti Office')}
      --strip-links       ${t('Rimuove anche i collegamenti web dai PDF')}
  -p, --password <pw>     ${t('Password per archivi protetti')}
  -n, --dry-run           ${t('Mostra cosa verrebbe fatto senza scrivere file')}
      --json              ${t('Output JSON')}

${c.bold(t('Codici di uscita'))}  ${t('0 tutti i file resi sicuri · 1 almeno un file bloccato · 3 errori')}

${c.bold(t('Esempi'))}
  gauntler sanitize fattura.docm                ${c.dim('→ fattura.safe.docx')}
  gauntler sanitize ~/Downloads -d ~/Sicuri
  gauntler sanitize allegato.pdf --in-place
`;

const ICON = new Proxy({ sanitized: [c.green, '✔ ', 'disarmato'], clean: [c.green, '✔ ', 'già pulito'], verified: [c.cyan, '✔ ', 'verificato'], blocked: [c.red, '✖ ', 'bloccato'] }, { get: (o, k) => (o[k] ? o[k][0](o[k][1] + t(o[k][2])) : undefined) });

async function run(argv, { parse }) {
  const a = parse(argv, SPEC);
  if (a.help || !a._.length) { console.log(HELP()); return a.help ? 0 : 2; }
  const cfg = config.load();
  const files = [];
  for (const p of a._) {
    if (!fs.existsSync(p)) throw new UsageError(t('Non trovato: {path}', { path: p }));
    if (fs.statSync(p).isDirectory()) files.push(...core.walk(p, { recursive: a.recursive, exclude: [...cfg.exclude, ...a.exclude, '**/*.safe.*', '**/*.verified.*'] }));
    else files.push(path.resolve(p));
  }
  if (a.out && files.length > 1) throw new UsageError(t('--out vale per un solo file: usa --out-dir'));
  const opts = { out: a.out, outDir: a.outDir, inPlace: a.inPlace, strict: a.strict, keepMetadata: a.keepMetadata, stripLinks: a.stripLinks, passwords: [...a.password, ...(cfg.passwords || [])], dryRun: a.dryRun, scanOptions: { passwords: [...a.password, ...(cfg.passwords || [])] } };
  const results = [];
  let blocked = 0, errors = 0;
  for (const f of files) {
    let r;
    try { r = await sanitizeFile(f, opts); } catch (e) { errors++; if (!a.json) console.log(`${c.yellow('! ' + t('errore'))}  ${ui.relPath(f)}: ${t(e.message)}`); results.push({ path: f, status: 'error', error: e.message }); continue; }
    if (r.status === 'blocked') blocked++;
    results.push(r);
    if (a.json) continue;
    const dest = r.outPath ? c.dim(' → ') + ui.relPath(r.outPath) : r.status !== 'blocked' && a.dryRun ? c.dim(' → ' + r.outName + ' ' + t('(prova)')) : '';
    console.log(`${ICON[r.status]}  ${ui.relPath(f)}${dest}${r.after ? c.dim('  ' + t('[{score}/100 dopo la verifica]', { score: r.after.score })) : ''}`);
    if (r.status === 'blocked') {
      console.log(`     ${c.red(r.reason)}`);
      for (const b of r.blocking || []) console.log(c.dim(`     · ${b}`));
    }
    if (!a.quiet) for (const x of r.actions) console.log(c.dim(`     · ${x}`));
    if (r.quarantineId) console.log(c.dim('     · ' + t('originale in quarantena: {id}', { id: r.quarantineId })));
  }
  if (a.json) console.log(JSON.stringify(results.map(({ output, ...r }) => r), null, 2));
  else if (files.length > 1) console.log(c.dim('\n' + t('{n} file · {ok} sicuri · {b} bloccati', { n: files.length, ok: files.length - blocked - errors, b: blocked }) + (errors ? ' · ' + t('{n} errori', { n: errors }) : '')));
  return errors ? 3 : blocked ? 1 : 0;
}

module.exports = { run, get HELP() { return HELP(); }, SPEC, get summary() { return t('Rende sicuri i file (disarmo e ricostruzione + verifica)'); } };
