// Created by anvex2012
'use strict';
const fs = require('fs');
const path = require('path');
const core = require('../../core');
const config = require('../../core/config');
const history = require('../../core/history');
const quarantine = require('../../core/quarantine');
const report = require('../../core/report');
const { ScanPool } = require('../../core/pool');
const { parseSize, UsageError } = require('../args');
const ui = require('../ui');
const { c } = ui;
const { t } = require('../../core/i18n');

const SPEC = {
  jobs: { alias: 'j', type: 'number' },
  format: { alias: 'f', type: 'string', default: 'text' },
  out: { alias: 'o', type: 'string' },
  quiet: { alias: 'q', type: 'bool' },
  verbose: { alias: 'v', type: 'bool' },
  lines: { alias: 'l', type: 'bool' },
  checks: { alias: 'c', type: 'bool' },
  all: { alias: 'a', type: 'bool' },
  ids: { type: 'bool' },
  summary: { alias: 's', type: 'bool' },
  password: { alias: 'p', type: 'list' },
  detail: { type: 'bool' },
  threshold: { alias: 't', type: 'number' },
  failOn: { type: 'string' },
  minSeverity: { type: 'string' },
  only: { type: 'list' },
  skip: { type: 'list' },
  exclude: { alias: 'x', type: 'list' },
  include: { alias: 'i', type: 'list' },
  maxSize: { type: 'string' },
  recursive: { alias: 'r', type: 'bool', default: true },
  followSymlinks: { type: 'bool' },
  clamav: { type: 'bool', default: true },
  yara: { type: 'list' },
  cache: { type: 'bool' },
  online: { type: 'bool' },
  quarantine: { type: 'bool' },
  quarantineBelow: { type: 'number' },
  history: { type: 'bool', default: true },
  timeout: { type: 'number' },
  name: { type: 'string', default: 'stdin' },
  suppress: { type: 'list' },
  sort: { type: 'string', default: 'score' },
};

const HELP = () => `
${c.bold('gauntler scan')} — ${t('analizza file e cartelle')} ${c.dim(t('(comando predefinito: "gauntler <percorso>" equivale a "gauntler scan <percorso>")'))}

${c.bold(t('Uso'))}
  gauntler scan <file|${t('cartella')}|-> [${t('altri…')}] [${t('opzioni')}]
  ${c.dim(t('"-" legge il file da stdin, es.: curl -s https://… | gauntler -'))}

${c.bold('Output')}
  -f, --format <fmt>       ${t('text (predefinito) · json · sarif · csv · md · html')}
  -o, --out <file>         ${t('Salva il report su file (il formato si deduce dall\'estensione)')}
  -q, --quiet              ${t('Una riga per file')}
  -s, --summary            ${t('Solo il riepilogo finale')}
  -v, --verbose            ${t('Tutto: righe, controlli, metriche, impronte')}
  -l, --lines              ${t('Righe segnalate con spiegazione')}
  -c, --checks             ${t('Controlli non superati (con -v: tutti)')}
  -a, --all                ${t('Nessun limite al numero di problemi mostrati')}
      --ids                ${t('Mostra l\'id di ogni segnalazione (per sopprimerla)')}
      --min-severity <s>   ${t('Mostra da questo livello in su: critical|high|medium|low|info')}
      --detail             ${t('Nel JSON include testo completo e stringhe estratte')}
      --sort <campo>       ${t('Ordine del riepilogo: score (predefinito) · name · size')}

${c.bold(t('Selezione dei file'))}
  -x, --exclude <glob>     ${t('Escludi (ripetibile), es. -x "**/node_modules/**" -x "*.log"')}
  -i, --include <glob>     ${t('Analizza solo i file che corrispondono, es. -i "*.{exe,dll,js}"')}
      --max-size <dim>     ${t('Salta i file più grandi (es. 50M, 2G)')}
      --no-recursive       ${t('Non entrare nelle sottocartelle')}
      --follow-symlinks    ${t('Segui i collegamenti simbolici')}

${c.bold(t('Motore'))}
  -j, --jobs <n>           ${t('Analisi in parallelo (predefinito: un thread per core)')}
      --timeout <sec>      ${t('Tempo massimo per file (predefinito 900)')}
      --only <criteri>     ${t('Solo questi criteri (es. --only signatures,secrets)')}
      --skip <criteri>     ${t('Escludi criteri (es. --skip social,privacy)')}
  -p, --password <pw>      ${t('Password per archivi protetti (ripetibile)')}
      --yara <percorso>    ${t('File/cartelle di regole YARA aggiuntive')}
      --online             ${t('Reputazione online (VirusTotal, MalwareBazaar): invia SOLO l\'impronta SHA-256')}
      --no-clamav          ${t('Non usare ClamAV')}
      --no-cache           ${t('Rianalizza anche i file già visti')}
      --suppress <id>      ${t('Ignora una segnalazione (ripetibile, supporta *)')}
      --no-history         ${t('Non registrare nella cronologia')}
      --lang <codice>      ${t('Lingua per questa esecuzione (it, en, es, fr, de)')}

${c.bold(t('Azioni ed esito'))}
  -t, --threshold <n>      ${t('Codice di uscita 1 se un file ha punteggio < n (predefinito 40)')}
      --fail-on <livello>  ${t('Codice di uscita 1 se c\'è almeno un problema di questo livello (es. high)')}
      --quarantine         ${t('Metti in quarantena i file sotto --quarantine-below')}
      --quarantine-below <n>  ${t('Soglia per la quarantena (predefinito 15 = malevoli)')}

${c.bold(t('Codici di uscita'))}  ${t('0 ok · 1 trovati file sotto soglia/problemi · 2 uso errato · 3 errori di analisi')}

${c.bold(t('Esempi'))}
  gauntler ~/Downloads -q
  gauntler progetto/ -x "**/node_modules/**" -f sarif -o gauntler.sarif --fail-on high
  gauntler allegato.zip -l --ids
  gauntler ~/Downloads --quarantine -q
`;

function buildScanOptions(a, cfg) {
  return {
    passwords: a.password,
    detail: a.detail || ['json'].includes(a.format) && a.detail,
    only: a.only.length ? a.only : null,
    skip: a.skip,
    noClamav: !a.clamav,
    yara: a.yara,
    online: !!a.online,
    suppress: a.suppress,
    cache: a.cache !== undefined ? a.cache : cfg.cache,
    lang: require('../../core/i18n').getLanguage(),
  };
}

function formatFromPath(p) {
  const ext = path.extname(p).slice(1).toLowerCase();
  return { sarif: 'sarif', json: 'json', csv: 'csv', md: 'md', markdown: 'md', html: 'html', htm: 'html', txt: 'text' }[ext];
}

async function readStdin() {
  const chunks = [];
  for await (const ch of process.stdin) chunks.push(ch);
  return Buffer.concat(chunks);
}

async function run(argv, { parse }) {
  const a = parse(argv, SPEC);
  if (a.help) { console.log(HELP()); return 0; }
  const cfg = config.load();
  if (a.out && a.format === 'text') a.format = formatFromPath(a.out) || 'text';
  if (!report.FORMATS[a.format] && a.format !== 'text') throw new UsageError(t('Formato sconosciuto: {f}', { f: a.format }));
  const threshold = a.threshold ?? cfg.threshold;
  const qBelow = a.quarantineBelow ?? cfg.quarantineBelow;
  const failOn = a.failOn ? a.failOn.toLowerCase() : null;
  if (failOn && ui.SEV_ORDER[failOn] === undefined) throw new UsageError(t('--fail-on accetta: critical, high, medium, low'));
  const valid = core.analyzers.map((x) => x.id);
  for (const id of [...a.only, ...a.skip]) if (!valid.includes(id)) throw new UsageError(t('Criterio sconosciuto "{id}". Validi: {list}', { id, list: valid.join(', ') }));
  if (!a._.length) { console.log(HELP()); return 2; }

  const text = a.format === 'text';
  const toStdout = !a.out;
  const opts = buildScanOptions(a, cfg);
  const printOpt = { verbose: a.verbose, lines: a.lines || a.verbose, checks: a.checks || a.verbose, all: a.all, ids: a.ids, minSeverity: a.minSeverity };

  // 1) File collection
  const files = [];
  let stdinBuf = null;
  const walkErr = [];
  for (const target of a._) {
    if (target === '-') { stdinBuf = await readStdin(); continue; }
    if (!fs.existsSync(target)) { console.error(c.red(t('Non trovato: {path}', { path: target }))); walkErr.push(target); continue; }
    const st = fs.statSync(target);
    if (st.isDirectory()) files.push(...core.walk(target, { recursive: a.recursive, exclude: [...cfg.exclude, ...a.exclude], include: a.include, maxSize: parseSize(a.maxSize), followSymlinks: a.followSymlinks, onError: (d) => walkErr.push(d) }));
    else files.push(target);
  }
  const unique = [...new Set(files.map((f) => path.resolve(f)))];

  // 2) Parallel analysis
  const results = [];
  const prog = new ui.Progress(unique.length + (stdinBuf ? 1 : 0), unique.length > 1);
  const handle = (r) => {
    results.push(r);
    if (!r.error && a.history) history.record(r);
    if (!r.error && a.quarantine && r.overall.score < qBelow && r.file.path) {
      try {
        const q = quarantine.add(r.file.path, { score: r.overall.score, verdict: r.overall.verdict, reason: r.findings.find((f) => f.severity !== 'info')?.title });
        r.quarantined = q.id;
      } catch (e) { r.quarantineError = t(e.message); }
    }
    if (text && toStdout && !a.summary) {
      if (a.quiet) prog.log(ui.oneLine(r) + (r.quarantined ? c.magenta('  → ' + t('quarantena {id}', { id: r.quarantined })) : ''));
      else if (r.error) prog.log(c.red(t('Errore su {path}: {msg}', { path: r.file.path, msg: t(r.error) })));
      else prog.log(ui.printReport(r, printOpt) + (r.quarantined ? '\n  ' + c.magenta(t('Spostato in quarantena (id {id}) — ripristina con: gauntler quarantine restore {id}', { id: r.quarantined })) : ''));
    }
    prog.tick(r.file?.path ? ui.relPath(r.file.path) : '', r.file?.size || 0);
  };

  if (stdinBuf) {
    try { handle(await core.scanBuffer(stdinBuf, a.name, opts)); }
    catch (e) { handle({ file: { path: '(stdin)' }, error: e.message }); }
  }
  const pool = new ScanPool({ size: a.jobs || cfg.jobs, timeoutMs: (a.timeout || cfg.timeout) * 1000 });
  const onSig = () => { prog.clear(); console.error(c.yellow('\n' + t('Interrotto.'))); pool.close().then(() => process.exit(130)); };
  process.once('SIGINT', onSig);
  const t0 = Date.now();
  await Promise.all(unique.map((f) => pool.scan(f, opts).then(handle, (e) => handle({ file: { path: f, name: path.basename(f) }, error: e.message, code: e.code }))));
  await pool.close();
  process.removeListener('SIGINT', onSig);
  prog.clear();

  // 3) Output in non-text formats
  const ok = results.filter((r) => !r.error);
  const errors = results.filter((r) => r.error);
  if (!text || a.out) {
    const fmt = text ? 'json' : a.format;
    const body = report.render(fmt, results, { detail: a.detail });
    if (a.out) { fs.writeFileSync(a.out, body); console.error(c.dim(t('Report {fmt} salvato in {path}', { fmt: fmt.toUpperCase(), path: a.out }))); }
    else process.stdout.write(body);
  }

  // 4) Summary
  if (text && toStdout && (ok.length > 1 || a.summary || errors.length)) {
    const by = (lvl) => ok.filter((r) => r.overall.level === lvl).length;
    const el = Date.now() - t0;
    console.log('\n' + c.bold(t('Riepilogo')) + '  ' + t('{n} file in {d}', { n: ok.length, d: ui.fmtDur(el) }) + ' · ' +
      [c.green(t('{n} sicuri', { n: by('safe') })), c.cyan(t('{n} basso rischio', { n: by('low') })), c.yellow(t('{n} sospetti', { n: by('medium') })), c.red(t('{n} pericolosi', { n: by('high') })), c.bgRed(t('{n} malevoli', { n: by('critical') }))].join(c.dim(' · ')) +
      (errors.length ? c.yellow(' · ' + t('{n} errori', { n: errors.length })) : '') + c.dim(' · ' + t('{n} dalla cache', { n: ok.filter((r) => r.cached).length }) + ` · ${ui.fmtBytes(ok.reduce((s, r) => s + r.file.size, 0))}`));
    const sorter = { score: (x, y) => x.overall.score - y.overall.score, name: (x, y) => x.file.name.localeCompare(y.file.name), size: (x, y) => y.file.size - x.file.size }[a.sort] || ((x, y) => x.overall.score - y.overall.score);
    const bad = ok.filter((r) => r.overall.score < Math.max(threshold, 70)).sort(sorter);
    if (bad.length) {
      console.log(ui.table(bad.slice(0, a.all ? Infinity : 25).map((r) => [ui.colorFor(r.overall.score)(String(r.overall.score)), r.overall.verdict, ui.relPath(r.file.path), c.dim(r.findings.find((f) => f.severity !== 'info')?.title || '')]), [t('Punti'), t('Verdetto'), 'File', t('Problema principale')]));
      if (!a.all && bad.length > 25) console.log(c.dim('  ' + t('… altri {n} (usa --all)', { n: bad.length - 25 })));
    }
    const quar = ok.filter((r) => r.quarantined);
    if (quar.length) console.log(c.magenta('\n' + t('{n} file spostati in quarantena (gauntler quarantine list)', { n: quar.length })));
    for (const e of errors) console.log(c.yellow(`  ! ${ui.relPath(e.file.path)}: ${t(e.error)}`));
  }
  if (text && toStdout && !a.quiet && !a.summary && !core.clamavAvailable() && ok.length) console.log(c.dim('\n' + t('Suggerimento: installa ClamAV per una scansione antivirus aggiuntiva (brew install clamav). Controlla l\'ambiente con: gauntler doctor')));

  // 5) Exit code
  const below = ok.some((r) => r.overall.score < threshold);
  const sevHit = failOn && ok.some((r) => r.findings.some((f) => ui.SEV_ORDER[f.severity] <= ui.SEV_ORDER[failOn]));
  if (below || sevHit) return 1;
  if (errors.length || walkErr.length) return 3;
  return 0;
}

module.exports = { run, get HELP() { return HELP(); }, SPEC, buildScanOptions, get summary() { return t('Analizza file e cartelle (predefinito)'); } };
