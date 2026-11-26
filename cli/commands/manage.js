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
const i18n = require('../../core/i18n');
const { t } = i18n;

const asJson = (o) => { console.log(JSON.stringify(o, null, 2)); return 0; };

/* ---------------- quarantine ---------------- */
const quarantineCmd = {
  get summary() { return t('Gestisce i file in quarantena (list · add · restore · delete)'); },
  get HELP() {
    return `
${c.bold('gauntler quarantine')} — ${t('file messi in sicurezza (resi innocui e non eseguibili)')}

  gauntler quarantine list [--json]
  gauntler quarantine add <file…>             ${t('Sposta in quarantena (senza analisi)')}
  gauntler quarantine restore <id> [--to <${t('percorso')}>] [--force]
  gauntler quarantine delete <id…>            ${t('Elimina definitivamente')}
  ${c.dim(t('L\'id può essere abbreviato (prime cifre) o essere l\'impronta SHA-256.'))}
`;
  },
  async run(argv, { parse }) {
    const a = parse(argv, { json: { type: 'bool' }, to: { type: 'string' }, force: { type: 'bool' }, yes: { alias: 'y', type: 'bool' } });
    const [sub = 'list', ...rest] = a._;
    if (a.help) { console.log(this.HELP); return 0; }
    if (sub === 'list' || sub === 'ls') {
      const l = quarantine.list();
      if (a.json) return asJson(l);
      if (!l.length) { console.log(c.dim(t('La quarantena è vuota.'))); return 0; }
      console.log(ui.table(l.map((q) => [c.bold(q.id), q.score != null ? ui.colorFor(q.score)(String(q.score)) : '-', ui.fmtBytes(q.size), q.date.slice(0, 16).replace('T', ' '), ui.relPath(q.originalPath), c.dim(t(q.reason || ''))]), ['Id', t('Punti'), t('Dim.'), t('Data'), t('Percorso originale'), t('Motivo')]));
      console.log(c.dim('\n' + t('{n} elementi · cartella {dir}', { n: l.length, dir: paths.dir('quarantine') })));
      return 0;
    }
    if (sub === 'add') {
      if (!rest.length) throw new UsageError(t('Indica i file da mettere in quarantena'));
      for (const f of rest) { const q = quarantine.add(f, { reason: 'aggiunto manualmente' }); console.log(`${c.magenta(t('in quarantena:'))} ${ui.relPath(f)} → ${c.bold(q.id)}`); }
      return 0;
    }
    if (sub === 'restore') {
      if (!rest[0]) throw new UsageError(t('Indica l\'id da ripristinare (gauntler quarantine list)'));
      const r = quarantine.restore(rest[0], { to: a.to, force: a.force });
      console.log(`${c.green('✔')} ${t('Ripristinato in {path}', { path: r.restoredTo })}`);
      return 0;
    }
    if (sub === 'delete' || sub === 'rm') {
      if (!rest.length) throw new UsageError(t('Indica gli id da eliminare'));
      for (const id of rest) { const m = quarantine.remove(id); console.log(`${c.red('✖')} ${t('Eliminato definitivamente {id} ({name})', { id: m.id, name: m.name })}`); }
      return 0;
    }
    throw new UsageError(t('Sottocomando sconosciuto: {sub}', { sub }));
  },
};

/* ---------------- history ---------------- */
const historyCmd = {
  get summary() { return t('Cronologia delle analisi'); },
  get HELP() {
    return `
${c.bold('gauntler history')} — ${t('cronologia delle analisi')}

  gauntler history [-n 30] [--below 40] [--search ${t('testo')}] [--json]
  gauntler history clear
`;
  },
  async run(argv, { parse }) {
    const a = parse(argv, { limit: { alias: 'n', type: 'number', default: 30 }, below: { type: 'number' }, search: { type: 'string' }, json: { type: 'bool' } });
    if (a.help) { console.log(this.HELP); return 0; }
    if (a._[0] === 'clear') { history.clear(); console.log(t('Cronologia cancellata.')); return 0; }
    const rows = history.list({ limit: a.limit, below: a.below, search: a.search || a._[0] });
    if (a.json) return asJson(rows);
    if (!rows.length) { console.log(c.dim(t('Nessuna analisi in cronologia.'))); return 0; }
    console.log(ui.table(rows.map((r) => [new Date(r.ts).toLocaleString(i18n.locale()).slice(0, 17), ui.colorFor(r.score)(String(r.score).padStart(3)), t(r.verdict), ui.relPath(r.path) || r.name, c.dim(t((r.top || [])[0] || ''))]), [t('Quando'), t('Punti'), t('Verdetto'), 'File', t('Problema principale')]));
    return 0;
  },
};

/* ---------------- config ---------------- */
const configCmd = {
  get summary() { return t('Configurazione (password, esclusioni, soglie, chiavi API…)'); },
  get HELP() {
    return `
${c.bold('gauntler config')} — ${t('configurazione in {path}', { path: config.path() })}

  gauntler config [list]                 ${t('Mostra la configurazione effettiva')}
  gauntler config get <${t('chiave')}>
  gauntler config set <${t('chiave')}> <${t('valore')}>  ${t('es. config set threshold 50 · config set weights.privacy 0.5')}
  gauntler config unset <${t('chiave')}>
  gauntler config add <${t('lista')}> <${t('valore')}>   ${t('es. config add passwords infected2024 · config add exclude "**/node_modules/**"')}
  gauntler config remove <${t('lista')}> <${t('valore')}>
  gauntler config path

${c.bold(t('Chiavi'))}
  ${t('threshold, jobs, timeout, cache, passwords[], exclude[], disabled[], weights{}, allowlist[] (SHA-256 attendibili),\n  suppress[] (id segnalazioni, supporta *), yara[] (cartelle regole), online.virustotal, online.malwarebazaar, quarantineBelow,\n  limits.{maxEntryBytes,maxTotalBytes,maxRatio,ratioMinBytes,maxFiles,maxMemoryBytes} (limiti anti zip bomb)')}
  language (it, en, es, fr, de)
`;
  },
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
      case 'set': if (!key || !vals.length) throw new UsageError(t('Uso: gauntler config set <chiave> <valore>')); if (key === 'language' && !i18n.normalize(val)) throw new UsageError(t('Lingua non disponibile: {l}. Disponibili: {list}', { l: val, list: i18n.CODES.join(', ') })); config.set(key, key === 'language' ? i18n.normalize(val) : val); console.log(`${c.green('✔')} ${key} = ${/virustotal|malwarebazaar/.test(key) ? t('(nascosto)') : val}`); return 0;
      case 'unset': config.unset(key); console.log(`${c.green('✔')} ${t('{key} rimosso', { key })}`); return 0;
      case 'add': if (!key || !vals.length) throw new UsageError(t('Uso: gauntler config add <lista> <valore>')); console.log(config.add(key, val) ? `${c.green('✔')} ${t('aggiunto a {key}', { key })}` : c.dim(t('già presente'))); return 0;
      case 'remove': case 'rm': config.remove(key, val); console.log(`${c.green('✔')} ${t('rimosso da {key}', { key })}`); return 0;
      case 'path': console.log(config.path()); return 0;
      default: throw new UsageError(t('Sottocomando sconosciuto: {sub}', { sub }));
    }
  },
};

/* ---------------- trust / ignore (scorciatoie) ---------------- */
const trustCmd = {
  get summary() { return t('Segna un file come attendibile (allowlist)'); },
  get HELP() { return `\n${c.bold('gauntler trust')} <file|sha256…>   ${t('Aggiunge alla lista dei file attendibili (punteggio 100)')}\n${c.bold('gauntler trust')} --remove <file|sha256>\n`; },
  async run(argv, { parse }) {
    const a = parse(argv, { remove: { type: 'bool' } });
    if (a.help || !a._.length) { console.log(this.HELP); return a.help ? 0 : 2; }
    for (const target of a._) {
      const sha = /^[a-f0-9]{64}$/i.test(target) ? target.toLowerCase() : await core.sha256File(target);
      if (a.remove) { config.remove('allowlist', sha); console.log(`${c.green('✔')} ${t('rimosso {sha}', { sha })}`); }
      else { config.add('allowlist', sha); console.log(`${c.green('✔')} ${t('attendibile:')} ${ui.relPath(target)} ${c.dim(sha)}`); }
    }
    return 0;
  },
};
const ignoreCmd = {
  get summary() { return t('Ignora un tipo di segnalazione (per id, supporta *)'); },
  get HELP() { return `\n${c.bold('gauntler ignore')} <id…>   ${t('es.')} gauntler ignore "lines:eval" "secrets:stringhe-casuali-*"\n  ${c.dim(t('Gli id si vedono con: gauntler scan <file> --ids'))}\n${c.bold('gauntler ignore')} --remove <id>\n${c.bold('gauntler ignore')} --list\n`; },
  async run(argv, { parse }) {
    const a = parse(argv, { remove: { type: 'bool' }, list: { type: 'bool' } });
    if (a.help) { console.log(this.HELP); return 0; }
    if (a.list || !a._.length) { const l = config.get('suppress'); console.log(l.length ? l.join('\n') : c.dim(t('Nessuna segnalazione ignorata.'))); return 0; }
    for (const id of a._) { a.remove ? config.remove('suppress', id) : config.add('suppress', id); console.log(`${c.green('✔')} ${a.remove ? t('non più ignorato') : t('ignorato')}: ${id}`); }
    return 0;
  },
};

/* ---------------- cache ---------------- */
const cacheCmd = {
  get summary() { return t('Stato e pulizia della cache dei risultati'); },
  HELP: `\n${c.bold('gauntler cache')} [stats|clear]\n`,
  async run(argv, { parse }) {
    const a = parse(argv, {});
    if (a.help) { console.log(this.HELP); return 0; }
    if (a._[0] === 'clear') { cache.clear(); console.log(t('Cache svuotata.')); return 0; }
    const s = cache.stats();
    console.log('  ' + t('{n} risultati in cache · {size} · impronta motore {fp}', { n: s.files, size: ui.fmtBytes(s.bytes), fp: cache.engineFingerprint() }));
    return 0;
  },
};

/* ---------------- hash ---------------- */
const hashCmd = {
  get summary() { return t('Calcola le impronte (MD5, SHA-1, SHA-256, SHA-512) di file'); },
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
  get summary() { return t('Reputazione online di un file o impronta (VirusTotal, MalwareBazaar)'); },
  get HELP() {
    return `
${c.bold('gauntler lookup')} <file|sha256…> [--json]
  ${t('Invia SOLO l\'impronta SHA-256, mai il file. Servono le chiavi API:')}
    gauntler config set online.virustotal <${t('chiave')}>      ${t('(oppure VT_API_KEY)')}
    gauntler config set online.malwarebazaar <${t('chiave')}>   ${t('(oppure MB_API_KEY, chiave gratuita su auth.abuse.ch)')}
`;
  },
  async run(argv, { parse }) {
    const a = parse(argv, { json: { type: 'bool' } });
    if (a.help || !a._.length) { console.log(this.HELP); return a.help ? 0 : 2; }
    const keys = config.get('online');
    let worst = 0;
    const all = [];
    for (const target of a._) {
      const sha = /^[a-f0-9]{64}$/i.test(target) ? target.toLowerCase() : await core.sha256File(target);
      const res = await online.lookup(sha, keys);
      all.push({ target, sha256: sha, results: res });
      if (a.json) continue;
      console.log(`${c.bold(target)} ${c.dim(sha)}`);
      for (const r of res) {
        let s;
        if (r.skipped) s = c.dim(t(r.skipped));
        else if (r.error) s = c.yellow(t('errore: {msg}', { msg: i18n.translate(r.error) }));
        else if (!r.found) s = c.green(t('non presente nel database'));
        else if (r.service === 'VirusTotal') { s = ui.colorFor(r.malicious >= 5 ? 5 : r.malicious ? 30 : 95)(t('{a}/{b} antivirus lo rilevano', { a: r.malicious, b: r.engines })) + (r.label ? ` · ${r.label}` : '') + c.dim(` · ${r.link}`); if (r.malicious) worst = 1; }
        else { s = c.red(t('MALWARE NOTO: {sig}', { sig: r.signature || '?' })) + c.dim(` · ${(r.tags || []).join(', ')} · ${r.link}`); worst = 1; }
        console.log(`  ${r.service.padEnd(14)} ${s}`);
      }
    }
    if (a.json) asJson(all);
    return worst;
  },
};

/* ---------------- update ---------------- */
const updateCmd = {
  get summary() { return t('Scarica gli elenchi aggiornati di impronte di malware e le firme di ClamAV'); },
  get HELP() { return `\n${c.bold('gauntler update')}  ${t('Scarica i feed pubblici di impronte malevole (abuse.ch MalwareBazaar) in {dir}', { dir: paths.HOME + '/feeds' })}\n  ${c.dim(t('Vengono poi usati offline da ogni analisi. Nessun dato tuo viene inviato.'))}\n`; },
  async run(argv, { parse }) {
    const a = parse(argv, {});
    if (a.help) { console.log(this.HELP); return 0; }
    console.log(c.dim(t('Download dei feed in corso…')));
    const res = await online.updateFeeds(config.get('online'));
    let ok = 0;
    for (const r of res) {
      if (r.error) console.log(`  ${c.yellow('✗')} ${r.name}: ${t(r.error)}`);
      else { ok++; console.log(`  ${c.green('✔')} ${r.name}: ${t('{n} impronte', { n: r.count.toLocaleString(i18n.locale()) })}`); }
    }
    console.log(c.dim(t('Impronte malevole disponibili offline: {n}', { n: require('../../core/analyzers/signatures').knownCount().toLocaleString(i18n.locale()) })));
    // ClamAV signatures managed by Gauntler (~/.gauntler/clamav): incremental update, no password
    const setup = require('../../core/setup');
    if (setup.ownDatabase()) {
      console.log(c.dim(t('Aggiornamento delle firme di ClamAV…')));
      const done = await setup.updateDatabase({ log: (msg, k) => { if (k === 'err') console.log(`  ${c.yellow('✗')} ${msg}`); } });
      if (done) console.log(`  ${c.green('✔')} ${t('Firme ClamAV aggiornate')}`);
    } else if (!setup.status().clamav) console.log(c.dim(t('ClamAV non installato: installalo con "gauntler setup"')));
    return ok ? 0 : 3;
  },
};

/* ---------------- rules ---------------- */
const rulesCmd = {
  get summary() { return t('Elenca criteri, regole, indicatori e rilevatori del motore'); },
  get HELP() { return `\n${c.bold('gauntler rules')} [analyzers|signatures|tokens|secrets|yara] [--search ${t('testo')}] [--json]\n`; },
  async run(argv, { parse }) {
    const a = parse(argv, { search: { type: 'string' }, json: { type: 'bool' } });
    if (a.help) { console.log(this.HELP); return 0; }
    const what = a._[0] || 'analyzers';
    const q = (a.search || '').toLowerCase();
    const f = (rows) => rows.filter((r) => !q || JSON.stringify(r).toLowerCase().includes(q));
    let rows;
    if (what === 'analyzers') rows = f(core.analyzers.map((x) => ({ id: x.id, nome: i18n.translate(x.name), peso: x.weight, descrizione: i18n.translate(x.description) })));
    else if (what === 'signatures') rows = f(require('../../core/data/rules').map((r) => ({ id: r.id, gravita: r.severity, famiglia: r.family, descrizione: t(r.desc), condizione: r.condition, indicatori: r.strings.length })));
    else if (what === 'tokens') { const { TOKENS, GROUPS } = require('../../core/data/tokens'); rows = f(TOKENS.map((x) => ({ id: x[0], gravita: x[2], gruppo: t(GROUPS[x[3]]), nome: t(x[4]), descrizione: t(x[5]) }))); }
    else if (what === 'secrets') { const src = fs.readFileSync(path.join(__dirname, '../../core/analyzers/secrets.js'), 'utf8'); rows = f([...src.matchAll(/\['(\w+)', '([^']+)', '(\w+)', \//g)].map((m) => ({ id: m[1], nome: t(m[2]), gravita: m[3] }))); }
    else if (what === 'yara') rows = f(require('../../core/analyzers/yara').ruleFiles(config.get('yara')).map((p) => ({ file: p })));
    else throw new UsageError(t('Scegli: analyzers, signatures, tokens, secrets, yara'));
    if (a.json) return asJson(rows);
    if (!rows.length) { console.log(c.dim(t('Nessun risultato.'))); return 0; }
    const keys = Object.keys(rows[0]);
    console.log(ui.table(rows.map((r) => keys.map((k) => (k === 'gravita' ? ui.SEV[r[k]][0](r[k]) : k === 'descrizione' ? c.dim(String(r[k]).slice(0, 90)) : r[k]))), keys.map((k) => (k === 'id' || k === 'file' ? k : t(k)))));
    console.log(c.dim('\n' + t('{n} voci', { n: rows.length })));
    return 0;
  },
};

/* ---------------- doctor ---------------- */
const doctorCmd = {
  get summary() { return t('Controlla l\'ambiente (motori esterni, configurazione, feed)'); },
  get HELP() { return `\n${c.bold('gauntler doctor')}  ${t('Verifica ClamAV, YARA, 7-Zip, configurazione, cache e feed')}\n`; },
  async run(argv, { parse }) {
    const a = parse(argv, {});
    if (a.help) { console.log(this.HELP); return 0; }
    const X = require('../../core/extract').tools();
    const cfg = config.load();
    const yaraFiles = require('../../core/analyzers/yara').ruleFiles(cfg.yara);
    const feedsDir = paths.dir('feeds');
    const feeds = fs.readdirSync(feedsDir).filter((f) => f.endsWith('.txt'));
    const ok = (b) => (b ? c.green('✔') : c.yellow('✗'));
    const st = require('../../core/setup');
    const L = i18n.locale();
    const rows = [
      [ok(true), t('Motore Gauntler'), t('v{v} · {n} criteri · impronta {fp}', { v: core.VERSION, n: core.analyzers.length, fp: cache.engineFingerprint() })],
      [ok(true), 'Node.js', `${process.version} · ${require('os').cpus().length} core`],
      [ok(core.clamavAvailable()), 'ClamAV', core.clamavAvailable() ? t('disponibile') : t('non installato → gauntler setup')],
      [ok(core.yaraAvailable()), 'YARA', core.yaraAvailable() ? t('disponibile · {n} file di regole', { n: yaraFiles.length }) : yaraFiles.length ? t('non installato → brew install yara ({n} regole pronte)', { n: yaraFiles.length }) : t('non installato → brew install yara')],
      [ok(!!yaraFiles.length), t('Regole YARA'), yaraFiles.length ? t('{n} file', { n: yaraFiles.length }) : t('nessuna → copia file .yar in {dir}', { dir: paths.dir('yara') })],
      [ok(!!X.sevenZip), '7-Zip', X.sevenZip ? X.sevenZip : t('non installato (RAR/7z limitati) → brew install sevenzip')],
      [ok(st.status().database), t('Firme ClamAV'), st.status().database ? (st.ownDatabase() || t('database di sistema')) : t('mancanti → gauntler setup')],
      [ok(!!X.bsdtar), 'bsdtar', X.bsdtar || t('non disponibile → gauntler setup')],
      [ok(!!feeds.length), t('Feed impronte malevole'), feeds.length ? t('{n} feed · {h} impronte', { n: feeds.length, h: require('../../core/analyzers/signatures').knownCount().toLocaleString(L) }) : t('nessuno → gauntler update')],
      [ok(!!cfg.online.virustotal), t('Chiave VirusTotal'), cfg.online.virustotal ? t('configurata') : t('assente (facoltativa)')],
      [ok(!!cfg.online.malwarebazaar), t('Chiave abuse.ch'), cfg.online.malwarebazaar ? t('configurata') : t('assente (facoltativa)')],
      [ok(true), 'Cache', t('{n} risultati · {size}', { n: cache.stats().files, size: ui.fmtBytes(cache.stats().bytes) }) + (cfg.cache ? '' : ' ' + t('(disattivata)'))],
      [ok(true), t('Quarantena'), t('{n} file', { n: quarantine.list().length })],
      [ok(true), t('Lingua'), (i18n.LANGUAGES.find((l) => l.code === i18n.getLanguage()) || {}).name || i18n.getLanguage()],
      [ok(true), t('Cartella dati'), paths.HOME],
    ];
    console.log(ui.table(rows, ['', t('Componente'), t('Stato')]));
    return 0;
  },
};

/* ---------------- language ---------------- */
const languageCmd = {
  get summary() { return t('Cambia la lingua del terminale e dell\'app (it, en, es, fr, de)'); },
  get HELP() {
    return `
${c.bold('gauntler language')} [${t('codice')}]   ${t('Senza codice: scelta interattiva della lingua')}
  ${i18n.LANGUAGES.map((l) => `${c.cyan(l.code)} ${l.name}`).join(' · ')}
  ${c.dim(t('La lingua vale per il terminale e per l\'app desktop. Per una sola esecuzione: --lang <codice>'))}
`;
  },
  async run(argv, { parse }) {
    const a = parse(argv, { list: { type: 'bool' } });
    if (a.help) { console.log(this.HELP); return 0; }
    if (a.list) { for (const l of i18n.LANGUAGES) console.log(`  ${l.code === i18n.getLanguage() ? c.green('●') : ' '} ${c.cyan(l.code)}  ${l.name}`); return 0; }
    let code = a._[0];
    if (!code) {
      if (!process.stdin.isTTY) { console.log(i18n.getLanguage()); return 0; }
      code = await require('../language').choose();
      if (!code) return 1;
    }
    const norm = i18n.normalize(code);
    if (!norm) throw new UsageError(t('Lingua non disponibile: {l}. Disponibili: {list}', { l: code, list: i18n.CODES.join(', ') }));
    require('../language').save(norm);
    console.log(`${c.green('✔')} ${t('Lingua impostata: {name}', { name: i18n.LANGUAGES.find((l) => l.code === norm).name })}`);
    return 0;
  },
};

module.exports = { language: languageCmd, quarantine: quarantineCmd, history: historyCmd, config: configCmd, trust: trustCmd, ignore: ignoreCmd, cache: cacheCmd, hash: hashCmd, lookup: lookupCmd, update: updateCmd, rules: rulesCmd, doctor: doctorCmd };
