// Creato da anvex2012
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

const HELP = `
${c.bold('gauntler sanitize')} — rende sicuri i file: li ricostruisce senza contenuti attivi e li ri-verifica

${c.bold('Uso')}
  gauntler sanitize <file|cartella…> [opzioni]

${c.bold('Cosa fa')} ${c.dim('(Content Disarm & Reconstruction)')}
  PDF        rimuove JavaScript, azioni automatiche, Launch, allegati, XFA; ricostruisce il file da zero
  Word/Excel/PowerPoint  rimuove macro VBA e XLM, ActiveX, oggetti OLE, DDE, template remoti; .docm → .docx
  .doc/.xls  azzera progetto VBA, oggetti incorporati ed Equation Editor
  RTF        rimuove oggetti incorporati (\\object, \\objdata) e campi DDE
  HTML/SVG   rimuove script, iframe, gestori on…, URL javascript:, destinazioni dei moduli
  Immagini   rimuove EXIF/GPS/XMP/commenti e i dati nascosti dopo la fine dell'immagine
  Testo/CSV  rimuove caratteri invisibili e bidirezionali (Trojan Source), neutralizza le formule CSV
  Archivi    disarma ogni file interno, elimina quelli pericolosi, percorsi anomali e link simbolici
  Programmi e script non si possono disarmare: escono solo se l'analisi è pulita (o mai, con --strict)
  ${c.bold('Ogni file prodotto viene ri-analizzato da tutto il motore: se resta qualcosa di pericoloso, viene bloccato.')}

${c.bold('Opzioni')}
  -o, --out <file>        File di destinazione (un solo file in ingresso)
  -d, --out-dir <dir>     Cartella di destinazione (predefinito: accanto all'originale, nome.safe.ext)
      --in-place          Sostituisce l'originale (che va in quarantena, ripristinabile)
      --strict            Blocca sempre programmi e script
      --keep-metadata     Mantiene autore/azienda nei documenti Office
      --strip-links       Rimuove anche i collegamenti web dai PDF
  -p, --password <pw>     Password per archivi protetti
  -n, --dry-run           Mostra cosa verrebbe fatto senza scrivere file
      --json              Output JSON

${c.bold('Codici di uscita')}  0 tutti i file resi sicuri · 1 almeno un file bloccato · 3 errori

${c.bold('Esempi')}
  gauntler sanitize fattura.docm                ${c.dim('→ fattura.safe.docx')}
  gauntler sanitize ~/Downloads -d ~/Sicuri
  gauntler sanitize allegato.pdf --in-place
`;

const ICON = { sanitized: c.green('✔ disarmato'), clean: c.green('✔ già pulito'), verified: c.cyan('✔ verificato'), blocked: c.red('✖ bloccato') };

async function run(argv, { parse }) {
  const a = parse(argv, SPEC);
  if (a.help || !a._.length) { console.log(HELP); return a.help ? 0 : 2; }
  const cfg = config.load();
  const files = [];
  for (const p of a._) {
    if (!fs.existsSync(p)) throw new UsageError('Non trovato: ' + p);
    if (fs.statSync(p).isDirectory()) files.push(...core.walk(p, { recursive: a.recursive, exclude: [...cfg.exclude, ...a.exclude, '**/*.safe.*', '**/*.verified.*'] }));
    else files.push(path.resolve(p));
  }
  if (a.out && files.length > 1) throw new UsageError('--out vale per un solo file: usa --out-dir');
  const opts = { out: a.out, outDir: a.outDir, inPlace: a.inPlace, strict: a.strict, keepMetadata: a.keepMetadata, stripLinks: a.stripLinks, passwords: [...a.password, ...(cfg.passwords || [])], dryRun: a.dryRun, scanOptions: { passwords: [...a.password, ...(cfg.passwords || [])] } };
  const results = [];
  let blocked = 0, errors = 0;
  for (const f of files) {
    let r;
    try { r = await sanitizeFile(f, opts); } catch (e) { errors++; if (!a.json) console.log(`${c.yellow('! errore')}  ${ui.relPath(f)}: ${e.message}`); results.push({ path: f, status: 'error', error: e.message }); continue; }
    if (r.status === 'blocked') blocked++;
    results.push(r);
    if (a.json) continue;
    const dest = r.outPath ? c.dim(' → ') + ui.relPath(r.outPath) : r.status !== 'blocked' && a.dryRun ? c.dim(' → ' + r.outName + ' (prova)') : '';
    console.log(`${ICON[r.status]}  ${ui.relPath(f)}${dest}${r.after ? c.dim(`  [${r.after.score}/100 dopo la verifica]`) : ''}`);
    if (r.status === 'blocked') {
      console.log(`     ${c.red(r.reason)}`);
      for (const b of r.blocking || []) console.log(c.dim(`     · ${b}`));
    }
    if (!a.quiet) for (const x of r.actions) console.log(c.dim(`     · ${x}`));
    if (r.quarantineId) console.log(c.dim(`     · originale in quarantena: ${r.quarantineId}`));
  }
  if (a.json) console.log(JSON.stringify(results.map(({ output, ...r }) => r), null, 2));
  else if (files.length > 1) console.log(c.dim(`\n${files.length} file · ${files.length - blocked - errors} sicuri · ${blocked} bloccati${errors ? ` · ${errors} errori` : ''}`));
  return errors ? 3 : blocked ? 1 : 0;
}

module.exports = { run, HELP, SPEC, summary: 'Rende sicuri i file (disarmo e ricostruzione + verifica)' };
