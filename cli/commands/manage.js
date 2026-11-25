// Creato da anvex2012
'use strict';
/* Management commands: quarantine, history, config, cache, hash, lookup, update, rules, doctor */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const core = require('../../core');
const config = require('../../core/config');
const history = require('../../core/history');
const quarantine = require('../../core/quarantine');
const cache = require('../../core/cache');
const online = require('../../core/online');
const paths = require('../../core/paths');
const { UsageError } = require('../args');
const ui = require('../ui');
const { c } = ui;

const asJson = (o) => { console.log(JSON.stringify(o, null, 2)); return 0; };

/* ---------------- quarantine ---------------- */
const quarantineCmd = {
  summary: 'Gestisce i file in quarantena (list · add · restore · delete)',
  HELP: `
${c.bold('gauntler quarantine')} — file messi in sicurezza (resi innocui e non eseguibili)

  gauntler quarantine list [--json]
  gauntler quarantine add <file…>             Sposta in quarantena (senza analisi)
  gauntler quarantine restore <id> [--to <percorso>] [--force]
  gauntler quarantine delete <id…>            Elimina definitivamente
  ${c.dim('L\'id può essere abbreviato (prime cifre) o essere l\'impronta SHA-256.')}
`,
  async run(argv, { parse }) {
    const a = parse(argv, { json: { type: 'bool' }, to: { type: 'string' }, force: { type: 'bool' }, yes: { alias: 'y', type: 'bool' } });
    const [sub = 'list', ...rest] = a._;
    if (a.help) { console.log(this.HELP); return 0; }
    if (sub === 'list' || sub === 'ls') {
      const l = quarantine.list();
      if (a.json) return asJson(l);
      if (!l.length) { console.log(c.dim('La quarantena è vuota.')); return 0; }
      console.log(ui.table(l.map((q) => [c.bold(q.id), q.score != null ? ui.colorFor(q.score)(String(q.score)) : '-', ui.fmtBytes(q.size), q.date.slice(0, 16).replace('T', ' '), ui.relPath(q.originalPath), c.dim(q.reason || '')]), ['Id', 'Punti', 'Dim.', 'Data', 'Percorso originale', 'Motivo']));
      console.log(c.dim(`\n${l.length} elementi · cartella ${paths.dir('quarantine')}`));
      return 0;
    }
    if (sub === 'add') {
      if (!rest.length) throw new UsageError('Indica i file da mettere in quarantena');
      for (const f of rest) { const q = quarantine.add(f, { reason: 'aggiunto manualmente' }); console.log(`${c.magenta('in quarantena:')} ${ui.relPath(f)} → ${c.bold(q.id)}`); }
      return 0;
    }
    if (sub === 'restore') {
      if (!rest[0]) throw new UsageError('Indica l\'id da ripristinare (gauntler quarantine list)');
      const r = quarantine.restore(rest[0], { to: a.to, force: a.force });
      console.log(`${c.green('✔')} Ripristinato in ${r.restoredTo}`);
      return 0;
    }
    if (sub === 'delete' || sub === 'rm') {
      if (!rest.length) throw new UsageError('Indica gli id da eliminare');
      for (const id of rest) { const m = quarantine.remove(id); console.log(`${c.red('✖')} Eliminato definitivamente ${m.id} (${m.name})`); }
      return 0;
    }
    throw new UsageError(`Sottocomando sconosciuto: ${sub}`);
  },
};

/* ---------------- history ---------------- */
const historyCmd = {
  summary: 'Cronologia delle analisi',
  HELP: `
${c.bold('gauntler history')} — cronologia delle analisi

  gauntler history [-n 30] [--below 40] [--search testo] [--json]
  gauntler history clear
`,
  async run(argv, { parse }) {
    const a = parse(argv, { limit: { alias: 'n', type: 'number', default: 30 }, below: { type: 'number' }, search: { type: 'string' }, json: { type: 'bool' } });
    if (a.help) { console.log(this.HELP); return 0; }
    if (a._[0] === 'clear') { history.clear(); console.log('Cronologia cancellata.'); return 0; }
    const rows = history.list({ limit: a.limit, below: a.below, search: a.search || a._[0] });
    if (a.json) return asJson(rows);
    if (!rows.length) { console.log(c.dim('Nessuna analisi in cronologia.')); return 0; }
    console.log(ui.table(rows.map((r) => [new Date(r.ts).toLocaleString('it-IT').slice(0, 17), ui.colorFor(r.score)(String(r.score).padStart(3)), r.verdict, ui.relPath(r.path) || r.name, c.dim((r.top || [])[0] || '')]), ['Quando', 'Punti', 'Verdetto', 'File', 'Problema principale']));
    return 0;
  },
};

/* ---------------- config ---------------- */
const configCmd = {
  summary: 'Configurazione (password, esclusioni, soglie, chiavi API…)',
  HELP: `
${c.bold('gauntler config')} — configurazione in ${config.path()}

  gauntler config [list]                 Mostra la configurazione effettiva
  gauntler config get <chiave>
  gauntler config set <chiave> <valore>  es. config set threshold 50 · config set weights.privacy 0.5
  gauntler config unset <chiave>
  gauntler config add <lista> <valore>   es. config add passwords infected2024 · config add exclude "**/node_modules/**"
  gauntler config remove <lista> <valore>
  gauntler config path

${c.bold('Chiavi')}
  threshold, jobs, timeout, cache, passwords[], exclude[], disabled[], weights{}, allowlist[] (SHA-256 attendibili),
  suppress[] (id segnalazioni, supporta *), yara[] (cartelle regole), online.virustotal, online.malwarebazaar, quarantineBelow,
  limits.{maxEntryBytes,maxTotalBytes,maxRatio,ratioMinBytes,maxFiles,maxMemoryBytes} (limiti anti zip bomb)
`,
  async run(argv, { parse }) {
    const a = parse(argv, { json: { type: 'bool' } });
    if (a.help) { console.log(this.HELP); return 0; }
    const [sub = 'list', key, ...vals] = a._;
    const val = vals.join(' ');
    const mask = (o) => JSON.parse(JSON.stringify(o, (k, v) => (['virustotal', 'malwarebazaar'].includes(k) && v ? v.slice(0, 4) + '…' : v)));
    switch (sub) {
      case 'list': case 'show': {
        const cfg = mask(config.load());
        if (a.json) return asJson(cfg);
        for (const [k, v] of Object.entries(cfg)) console.log(`  ${c.cyan(k.padEnd(16))} ${typeof v === 'object' ? JSON.stringify(v) : v}`);
        console.log(c.dim(`\n  File: ${config.path()}`));
        return 0;
      }
      case 'get': { const v = config.get(key); console.log(typeof v === 'object' ? JSON.stringify(mask({ [key]: v })[key], null, 2) : v); return 0; }
      case 'set': if (!key || !vals.length) throw new UsageError('Uso: gauntler config set <chiave> <valore>'); config.set(key, val); console.log(`${c.green('✔')} ${key} = ${/virustotal|malwarebazaar/.test(key) ? '(nascosto)' : val}`); return 0;
      case 'unset': config.unset(key); console.log(`${c.green('✔')} ${key} rimosso`); return 0;
      case 'add': if (!key || !vals.length) throw new UsageError('Uso: gauntler config add <lista> <valore>'); console.log(config.add(key, val) ? `${c.green('✔')} aggiunto a ${key}` : c.dim('già presente')); return 0;
      case 'remove': case 'rm': config.remove(key, val); console.log(`${c.green('✔')} rimosso da ${key}`); return 0;
      case 'path': console.log(config.path()); return 0;
      default: throw new UsageError(`Sottocomando sconosciuto: ${sub}`);
    }
  },
};

/* ---------------- trust / ignore (scorciatoie) ---------------- */
const trustCmd = {
  summary: 'Segna un file come attendibile (allowlist)',
  HELP: `\n${c.bold('gauntler trust')} <file|sha256…>   Aggiunge alla lista dei file attendibili (punteggio 100)\n${c.bold('gauntler trust')} --remove <file|sha256>\n`,
  async run(argv, { parse }) {
    const a = parse(argv, { remove: { type: 'bool' } });
    if (a.help || !a._.length) { console.log(this.HELP); return a.help ? 0 : 2; }
    for (const t of a._) {
      const sha = /^[a-f0-9]{64}$/i.test(t) ? t.toLowerCase() : await core.sha256File(t);
      if (a.remove) { config.remove('allowlist', sha); console.log(`${c.green('✔')} rimosso ${sha}`); }
      else { config.add('allowlist', sha); console.log(`${c.green('✔')} attendibile: ${ui.relPath(t)} ${c.dim(sha)}`); }
    }
    return 0;
  },
};
const ignoreCmd = {
  summary: 'Ignora un tipo di segnalazione (per id, supporta *)',
  HELP: `\n${c.bold('gauntler ignore')} <id…>   es. gauntler ignore "lines:eval" "secrets:stringhe-casuali-*"\n  ${c.dim('Gli id si vedono con: gauntler scan <file> --ids')}\n${c.bold('gauntler ignore')} --remove <id>\n${c.bold('gauntler ignore')} --list\n`,
  async run(argv, { parse }) {
    const a = parse(argv, { remove: { type: 'bool' }, list: { type: 'bool' } });
    if (a.help) { console.log(this.HELP); return 0; }
    if (a.list || !a._.length) { const l = config.get('suppress'); console.log(l.length ? l.join('\n') : c.dim('Nessuna segnalazione ignorata.')); return 0; }
    for (const id of a._) { a.remove ? config.remove('suppress', id) : config.add('suppress', id); console.log(`${c.green('✔')} ${a.remove ? 'non più ignorato' : 'ignorato'}: ${id}`); }
    return 0;
  },
};

/* ---------------- cache ---------------- */
const cacheCmd = {
  summary: 'Stato e pulizia della cache dei risultati',
  HELP: `\n${c.bold('gauntler cache')} [stats|clear]\n`,
  async run(argv, { parse }) {
    const a = parse(argv, {});
    if (a.help) { console.log(this.HELP); return 0; }
    if (a._[0] === 'clear') { cache.clear(); console.log('Cache svuotata.'); return 0; }
    const s = cache.stats();
    console.log(`  ${s.files} risultati in cache · ${ui.fmtBytes(s.bytes)} · impronta motore ${cache.engineFingerprint()}`);
    return 0;
  },
};

/* ---------------- hash ---------------- */
const hashCmd = {
  summary: 'Calcola le impronte (MD5, SHA-1, SHA-256, SHA-512) di file',
  HELP: `\n${c.bold('gauntler hash')} <file…> [--algo sha256] [--json]\n`,
  async run(argv, { parse }) {
    const a = parse(argv, { algo: { type: 'list' }, json: { type: 'bool' } });
    if (a.help || !a._.length) { console.log(this.HELP); return a.help ? 0 : 2; }
    const algos = a.algo.length ? a.algo : ['md5', 'sha1', 'sha256', 'sha512'];
    const out = [];
    for (const f of a._) {
      const hs = algos.map((x) => crypto.createHash(x));
      await new Promise((res, rej) => fs.createReadStream(f).on('data', (d) => hs.forEach((h) => h.update(d))).on('end', res).on('error', rej));
      const row = { file: f, ...Object.fromEntries(algos.map((x, i) => [x, hs[i].digest('hex')])) };
      out.push(row);
      if (!a.json) { console.log(c.bold(f)); for (const x of algos) console.log(`  ${x.toUpperCase().padEnd(7)} ${row[x]}`); }
    }
    if (a.json) asJson(out.length === 1 ? out[0] : out);
    return 0;
  },
};

/* ---------------- lookup ---------------- */
const lookupCmd = {
  summary: 'Reputazione online di un file o impronta (VirusTotal, MalwareBazaar)',
  HELP: `
${c.bold('gauntler lookup')} <file|sha256…> [--json]
  Invia SOLO l'impronta SHA-256, mai il file. Servono le chiavi API:
    gauntler config set online.virustotal <chiave>      (oppure VT_API_KEY)
    gauntler config set online.malwarebazaar <chiave>   (oppure MB_API_KEY, chiave gratuita su auth.abuse.ch)
`,
  async run(argv, { parse }) {
    const a = parse(argv, { json: { type: 'bool' } });
    if (a.help || !a._.length) { console.log(this.HELP); return a.help ? 0 : 2; }
    const keys = config.get('online');
    let worst = 0;
    const all = [];
    for (const t of a._) {
      const sha = /^[a-f0-9]{64}$/i.test(t) ? t.toLowerCase() : await core.sha256File(t);
      const res = await online.lookup(sha, keys);
      all.push({ target: t, sha256: sha, results: res });
      if (a.json) continue;
      console.log(`${c.bold(t)} ${c.dim(sha)}`);
      for (const r of res) {
        let s;
        if (r.skipped) s = c.dim(r.skipped);
        else if (r.error) s = c.yellow('errore: ' + r.error);
        else if (!r.found) s = c.green('non presente nel database');
        else if (r.service === 'VirusTotal') { s = ui.colorFor(r.malicious >= 5 ? 5 : r.malicious ? 30 : 95)(`${r.malicious}/${r.engines} antivirus lo rilevano`) + (r.label ? ` · ${r.label}` : '') + c.dim(` · ${r.link}`); if (r.malicious) worst = 1; }
        else { s = c.red(`MALWARE NOTO: ${r.signature || '?'}`) + c.dim(` · ${(r.tags || []).join(', ')} · ${r.link}`); worst = 1; }
        console.log(`  ${r.service.padEnd(14)} ${s}`);
      }
    }
    if (a.json) asJson(all);
    return worst;
  },
};

/* ---------------- update ---------------- */
const updateCmd = {
  summary: 'Scarica gli elenchi aggiornati di impronte di malware e le firme di ClamAV',
  HELP: `\n${c.bold('gauntler update')}  Scarica i feed pubblici di impronte malevole (abuse.ch MalwareBazaar) in ${paths.HOME}/feeds\n  ${c.dim('Vengono poi usati offline da ogni analisi. Nessun dato tuo viene inviato.')}\n`,
  async run(argv, { parse }) {
    const a = parse(argv, {});
    if (a.help) { console.log(this.HELP); return 0; }
    console.log(c.dim('Download dei feed in corso…'));
    const res = await online.updateFeeds(config.get('online'));
    let ok = 0;
    for (const r of res) {
      if (r.error) console.log(`  ${c.yellow('✗')} ${r.name}: ${r.error}`);
      else { ok++; console.log(`  ${c.green('✔')} ${r.name}: ${r.count.toLocaleString('it-IT')} impronte`); }
    }
    console.log(c.dim(`Impronte malevole disponibili offline: ${require('../../core/analyzers/signatures').knownCount().toLocaleString('it-IT')}`));
    // ClamAV signatures managed by Gauntler (~/.gauntler/clamav): incremental update, no password
    const setup = require('../../core/setup');
    if (setup.ownDatabase()) {
      console.log(c.dim('Aggiornamento delle firme di ClamAV…'));
      const done = await setup.updateDatabase({ log: (t, k) => { if (k === 'err') console.log(`  ${c.yellow('✗')} ${t}`); } });
      if (done) console.log(`  ${c.green('✔')} Firme ClamAV aggiornate`);
    } else if (!setup.status().clamav) console.log(c.dim('ClamAV non installato: installalo con "gauntler setup"'));
    return ok ? 0 : 3;
  },
};

/* ---------------- rules ---------------- */
const rulesCmd = {
  summary: 'Elenca criteri, regole, indicatori e rilevatori del motore',
  HELP: `\n${c.bold('gauntler rules')} [analyzers|signatures|tokens|secrets|yara] [--search testo] [--json]\n`,
  async run(argv, { parse }) {
    const a = parse(argv, { search: { type: 'string' }, json: { type: 'bool' } });
    if (a.help) { console.log(this.HELP); return 0; }
    const what = a._[0] || 'analyzers';
    const q = (a.search || '').toLowerCase();
    const f = (rows) => rows.filter((r) => !q || JSON.stringify(r).toLowerCase().includes(q));
    let rows;
    if (what === 'analyzers') rows = f(core.analyzers.map((x) => ({ id: x.id, nome: x.name, peso: x.weight, descrizione: x.description })));
    else if (what === 'signatures') rows = f(require('../../core/data/rules').map((r) => ({ id: r.id, gravita: r.severity, famiglia: r.family, descrizione: r.desc, condizione: r.condition, indicatori: r.strings.length })));
    else if (what === 'tokens') { const { TOKENS, GROUPS } = require('../../core/data/tokens'); rows = f(TOKENS.map((t) => ({ id: t[0], gravita: t[2], gruppo: GROUPS[t[3]], nome: t[4], descrizione: t[5] }))); }
    else if (what === 'secrets') { const src = fs.readFileSync(path.join(__dirname, '../../core/analyzers/secrets.js'), 'utf8'); rows = f([...src.matchAll(/\['(\w+)', '([^']+)', '(\w+)', \//g)].map((m) => ({ id: m[1], nome: m[2], gravita: m[3] }))); }
    else if (what === 'yara') rows = f(require('../../core/analyzers/yara').ruleFiles(config.get('yara')).map((p) => ({ file: p })));
    else throw new UsageError('Scegli: analyzers, signatures, tokens, secrets, yara');
    if (a.json) return asJson(rows);
    if (!rows.length) { console.log(c.dim('Nessun risultato.')); return 0; }
    const keys = Object.keys(rows[0]);
    console.log(ui.table(rows.map((r) => keys.map((k) => (k === 'gravita' ? ui.SEV[r[k]][0](r[k]) : k === 'descrizione' ? c.dim(String(r[k]).slice(0, 90)) : r[k]))), keys));
    console.log(c.dim(`\n${rows.length} voci`));
    return 0;
  },
};

/* ---------------- doctor ---------------- */
const doctorCmd = {
  summary: 'Controlla l\'ambiente (motori esterni, configurazione, feed)',
  HELP: `\n${c.bold('gauntler doctor')}  Verifica ClamAV, YARA, 7-Zip, configurazione, cache e feed\n`,
  async run(argv, { parse }) {
    const a = parse(argv, {});
    if (a.help) { console.log(this.HELP); return 0; }
    const X = require('../../core/extract').tools();
    const cfg = config.load();
    const yaraFiles = require('../../core/analyzers/yara').ruleFiles(cfg.yara);
    const feedsDir = paths.dir('feeds');
    const feeds = fs.readdirSync(feedsDir).filter((f) => f.endsWith('.txt'));
    const ok = (b) => (b ? c.green('✔') : c.yellow('✗'));
    const rows = [
      [ok(true), 'Motore Gauntler', `v${core.VERSION} · ${core.analyzers.length} criteri · impronta ${cache.engineFingerprint()}`],
      [ok(true), 'Node.js', `${process.version} · ${require('os').cpus().length} core`],
      [ok(core.clamavAvailable()), 'ClamAV', core.clamavAvailable() ? 'disponibile' : 'non installato → gauntler setup'],
      [ok(core.yaraAvailable()), 'YARA', core.yaraAvailable() ? `disponibile · ${yaraFiles.length} file di regole` : `non installato → brew install yara${yaraFiles.length ? ` (${yaraFiles.length} regole pronte)` : ''}`],
      [ok(!!yaraFiles.length), 'Regole YARA', yaraFiles.length ? `${yaraFiles.length} file` : `nessuna → copia file .yar in ${paths.dir('yara')}`],
      [ok(!!X.sevenZip), '7-Zip', X.sevenZip ? X.sevenZip : 'non installato (RAR/7z limitati) → brew install sevenzip'],
      [ok(require('../../core/setup').status().database), 'Firme ClamAV', require('../../core/setup').status().database ? (require('../../core/setup').ownDatabase() || 'database di sistema') : 'mancanti → gauntler setup'],
      [ok(!!X.bsdtar), 'bsdtar', X.bsdtar || 'non disponibile → gauntler setup'],
      [ok(!!feeds.length), 'Feed impronte malevole', feeds.length ? `${feeds.length} feed · ${require('../../core/analyzers/signatures').knownCount().toLocaleString('it-IT')} impronte` : 'nessuno → gauntler update'],
      [ok(!!cfg.online.virustotal), 'Chiave VirusTotal', cfg.online.virustotal ? 'configurata' : 'assente (facoltativa)'],
      [ok(!!cfg.online.malwarebazaar), 'Chiave abuse.ch', cfg.online.malwarebazaar ? 'configurata' : 'assente (facoltativa)'],
      [ok(true), 'Cache', `${cache.stats().files} risultati · ${ui.fmtBytes(cache.stats().bytes)}${cfg.cache ? '' : ' (disattivata)'}`],
      [ok(true), 'Quarantena', `${quarantine.list().length} file`],
      [ok(true), 'Cartella dati', paths.HOME],
    ];
    console.log(ui.table(rows, ['', 'Componente', 'Stato']));
    return 0;
  },
};

module.exports = { quarantine: quarantineCmd, history: historyCmd, config: configCmd, trust: trustCmd, ignore: ignoreCmd, cache: cacheCmd, hash: hashCmd, lookup: lookupCmd, update: updateCmd, rules: rulesCmd, doctor: doctorCmd };
