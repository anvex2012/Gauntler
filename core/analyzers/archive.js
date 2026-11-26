// Created by anvex2012
'use strict';
const { m: msg } = require('../i18n');
const zlib = require('zlib');
const { readZip, extract, readTar, overlappingEntries } = require('../zip');
const { fmt } = require('../limits');
const { systemExtract, tools } = require('../extract');
const { DANGEROUS_EXT } = require('../filetype');

// Common passwords for protected archives (malware samples are usually distributed with "infected")
const PASSWORDS = ['infected', 'malware', 'virus', 'password', 'Password', '1234', '12345', '123456', '1234567890', '0000', '1111', 'test', 'secret', 'admin', 'abc123', 'qwerty', 'pass', 'P@ssw0rd', '2023', '2024', '2025', '2026', 'fattura', 'Fattura', 'documento', 'invoice', 'Invoice', 'order', 'zip', 'open', 'apri', 'archivio'];
const ARCHIVES = ['zip', 'jar', 'apk', 'gzip', 'tar', 'rar', '7z', 'iso', 'cab', 'bzip2', 'xz', 'xar', 'dmg', 'vhd'];

function severityOf(child) {
  const threat = child.findings.filter((f) => !['identity', 'privacy', 'statistics', 'metadata', 'lines'].includes(f.categoryId));
  if (threat.some((f) => f.severity === 'critical') || child.overall.score < 25) return 'critical';
  if (threat.some((f) => f.severity === 'high') || child.overall.score < 50) return 'high';
  return 'medium';
}

module.exports = {
  id: 'archive',
  name: 'Archivi & file incorporati',
  description: 'Apre TUTTI gli archivi (ZIP/JAR/APK anche cifrati con password comuni, TAR, GZIP, RAR, 7z, ISO, CAB, PKG, XZ, BZ2) e ogni file incorporato o decodificato (allegati PDF, oggetti Office/RTF, payload base64), analizzando ricorsivamente ogni file interno con tutti i criteri.',
  weight: 2,
  applies: (ctx) => ARCHIVES.includes(ctx.type.id) || ctx.embedded.length > 0 || ['jpeg', 'png', 'gif', 'pdf'].includes(ctx.type.id) || ctx.budget.tripped,
  async run(ctx) {
    const out = [], info = {}, checks = [];
    const C = (name, ok, note) => checks.push({ name, ok, note });
    const id = ctx.type.id;
    const passwords = [...(ctx.options.passwords || []), ...PASSWORDS];
    const files = []; // { name, data, origin }
    const entriesMeta = [];
    const budget = ctx.budget, L = budget.limits;
    info['Limiti di decompressione'] = msg('{entry} per file · {total} in totale · rapporto {ratio}:1 · {files} file · memoria {mem}', { entry: fmt(L.maxEntryBytes), total: fmt(L.maxTotalBytes), ratio: L.maxRatio, files: L.maxFiles, mem: fmt(L.maxMemoryBytes) });

    if (id === 'zip' || id === 'jar' || id === 'apk') {
      const zip = readZip(ctx.buffer, { maxEntries: L.maxFiles + 1 });
      C('Struttura ZIP integra', !zip.broken);
      if (zip.broken) out.push({ severity: 'medium', title: 'Archivio ZIP danneggiato o manipolato', detail: 'Directory centrale non trovata: le voci sono state ricostruite dalle intestazioni locali.' });
      const e = zip.entries;
      info['Voci'] = e.length;
      const totalU = e.reduce((a, x) => a + x.usize, 0), totalC = e.reduce((a, x) => a + x.csize, 0) || 1;
      info['Dimensione decompressa'] = totalU;
      info['Rapporto di compressione'] = `${(totalU / totalC).toFixed(1)}:1`;
      // Pre-flight on the declared values (before decompressing anything). The real output is enforced
      // again while inflating, because the declared sizes can lie.
      if (zip.truncated || e.length > L.maxFiles) budget.trip('files', msg('L\'archivio contiene più di {n} voci.', { n: L.maxFiles }), ctx.name);
      else if (totalU > budget.remaining()) budget.trip('total', msg('L\'archivio dichiara {size} di dati decompressi (limite {max}).', { size: fmt(totalU), max: fmt(L.maxTotalBytes) }), ctx.name);
      else if (totalU > L.ratioMinBytes && totalU / totalC > L.maxRatio) budget.trip('ratio', msg('Rapporto di compressione dichiarato {r}:1 (limite {max}:1).', { r: Math.round(totalU / totalC), max: L.maxRatio }), ctx.name);
      const overlap = overlappingEntries(ctx.buffer, e);
      C('Nessuna voce con dati sovrapposti', !overlap.length, overlap.length ? `${overlap.length}` : '');
      if (overlap.length) {
        out.push({ severity: 'critical', title: 'Zip bomb a voci sovrapposte', detail: 'Più voci puntano agli stessi dati compressi: tecnica della "zip bomb non ricorsiva", che moltiplica la dimensione decompressa senza annidare archivi. Estrazione interrotta.', evidence: overlap.slice(0, 10) });
        budget.trip('overlap', 'Voci ZIP con dati compressi sovrapposti.', ctx.name);
      }
      const trav = e.filter((x) => /(^|[\\/])\.\.([\\/]|$)|^[\\/]|^[a-z]:/i.test(x.name));
      C('Nessun percorso che esce dalla cartella (Zip Slip)', !trav.length);
      if (trav.length) out.push({ severity: 'high', title: 'Path traversal (Zip Slip)', detail: 'Percorsi che scrivono fuori dalla cartella di estrazione.', evidence: trav.map((x) => x.name) });
      const dup = e.length - new Set(e.map((x) => x.name)).size;
      C('Nessun nome duplicato', !dup);
      if (dup) out.push({ severity: 'medium', title: 'Voci con nomi duplicati', detail: 'Tecnica per mostrare un file e farne estrarre un altro.' });
      const isPkg = id === 'jar' || id === 'apk';
      const danger = e.filter((x) => DANGEROUS_EXT.has((x.name.split('.').pop() || '').toLowerCase()) && !x.name.endsWith('/'));
      C('Nessun file eseguibile/script nell\'archivio', !danger.length || isPkg, `${danger.length}`);
      if (danger.length && !isPkg) out.push({ severity: danger.length === e.filter((x) => !x.name.endsWith('/')).length ? 'high' : 'medium', title: msg('File eseguibili/script nell\'archivio ({n})', { n: danger.length }), detail: 'Archivio che contiene programmi o script.', evidence: danger.map((x) => x.name) });
      if (e.filter((x) => !x.name.endsWith('/')).length === 1 && danger.length === 1) out.push({ severity: 'medium', title: 'Archivio con un singolo eseguibile', detail: 'Schema tipico degli allegati email malevoli.' });
      if (id === 'apk') {
        const dex = e.filter((x) => /\.dex$/.test(x.name)).length;
        info['File DEX'] = dex;
        if (dex > 3) out.push({ severity: 'low', title: msg('Molti file DEX ({n})', { n: dex }), detail: 'App molto grande o con codice caricato dinamicamente.' });
        const signed = e.some((x) => /^META-INF\/.*\.(RSA|DSA|EC)$/i.test(x.name));
        C('APK firmato (schema v1)', signed);
        if (!signed) out.push({ severity: 'low', title: 'APK senza firma v1', detail: 'Verifica la firma con apksigner (potrebbe usare solo lo schema v2/v3).' });
        if (e.some((x) => /^assets\/.*\.(dex|jar|apk|so|bin|dat)$/i.test(x.name))) out.push({ severity: 'medium', title: 'Codice nascosto negli asset', detail: 'File eseguibili negli asset: possibile caricamento dinamico di payload.' });
      }
      let enc = 0, cracked = 0, failed = [];
      for (const x of e) {
        if (x.name.endsWith('/')) continue;
        entriesMeta.push({ name: x.name, size: x.usize, csize: x.csize, encrypted: x.encrypted, method: x.method });
        if (budget.tripped || !budget.admitFile(x.name)) break;
        const r = extract(ctx.buffer, x, passwords, { budget });
        if (r.limit) break;
        if (x.encrypted) { enc++; if (r.data) cracked++; }
        if (r.data) files.push({ name: x.name, data: r.data, origin: x.encrypted ? msg('archivio (password "{pw}")', { pw: r.password }) : 'archivio' });
        else failed.push(`${x.name}: ${r.error}`);
      }
      C('Nessun file protetto da password', !enc, `${enc}`);
      if (enc) {
        out.push({ severity: cracked === enc ? 'medium' : 'high', title: msg('File protetti da password ({n})', { n: enc }), detail: cracked ? msg('I malware usano archivi cifrati per eludere gli antivirus. {a}/{b} sbloccati con password comuni e analizzati.', { a: cracked, b: enc }) : 'I malware usano archivi cifrati per eludere gli antivirus. Password sconosciuta: aggiungila nelle opzioni per analizzarli.' });
      }
      if (failed.length) out.push({ severity: 'low', title: msg('File non estraibili ({n})', { n: failed.length }), detail: 'Alcune voci non sono state decompresse.', evidence: failed.slice(0, 20) });
    } else if (id === 'gzip') {
      const r = budget.inflate(zlib.gunzipSync, ctx.buffer, ctx.name);
      if (r.data) {
        const inner = r.data;
        const ratio = inner.length / Math.max(1, ctx.buffer.length);
        info['Dimensione decompressa'] = inner.length;
        info['Rapporto di compressione'] = `${ratio.toFixed(1)}:1`;
        const isTar = inner.length > 262 && inner.toString('latin1', 257, 262) === 'ustar';
        if (isTar) {
          for (const t of readTar(inner, { maxEntries: L.maxFiles + 1 })) {
            entriesMeta.push({ name: t.name, size: t.size, special: t.special });
            if (t.data && !budget.admitFile(t.name)) break;
            if (t.data) files.push({ name: t.name, data: t.data, origin: 'archivio tar.gz' });
          }
        } else if (budget.admitFile('contenuto')) files.push({ name: ctx.name.replace(/\.(gz|tgz)$/i, '') || 'contenuto', data: inner, origin: 'decompressione gzip' });
      } else if (!r.limit) {
        out.push({ severity: 'low', title: 'GZIP non decompressibile', detail: 'Archivio danneggiato.' });
      }
    } else if (id === 'tar') {
      for (const t of readTar(ctx.buffer, { maxEntries: L.maxFiles + 1 })) {
        entriesMeta.push({ name: t.name, size: t.size, special: t.special, link: t.link });
        if (t.data && !budget.admitFile(t.name)) break;
        if (t.data) files.push({ name: t.name, data: t.data, origin: 'archivio tar' });
      }
      const links = entriesMeta.filter((m) => m.special === 'symlink' && /^\/|\.\./.test(m.link || ''));
      C('Nessun collegamento simbolico verso l\'esterno', !links.length);
      if (links.length) out.push({ severity: 'high', title: 'Collegamenti simbolici verso l\'esterno', detail: 'All\'estrazione possono sovrascrivere file di sistema.', evidence: links.map((l) => `${l.name} → ${l.link}`) });
      const suid = entriesMeta.filter((m) => m.special === 'char device' || m.special === 'block device');
      if (suid.length) out.push({ severity: 'medium', title: 'File di dispositivo nell\'archivio', detail: 'Voci speciali insolite.' });
    } else if (ARCHIVES.includes(id)) {
      const r = await systemExtract(ctx.buffer, id, ctx.virtual ? null : ctx.path, passwords, budget);
      info['Strumento di estrazione'] = r.tool || 'nessuno';
      C(msg('Archivio {label} estratto', { label: ctx.type.label }), !!r.files.length, r.error || r.tool);
      if (!r.files.length && !r.limit) {
        const t = tools();
        out.push({ severity: ['iso', 'vhd', 'dmg'].includes(id) ? 'medium' : 'low', title: 'Contenuto dell\'archivio non ispezionato', detail: !t.sevenZip ? msg('{err} Installa 7-Zip (brew install sevenzip / apt install 7zip) per aprire tutti i formati.', { err: r.error || 'Estrazione non riuscita.' }) : (r.error || 'Estrazione non riuscita.') });
      }
      for (const f of r.files) { files.push({ name: f.name, data: f.data, origin: msg('archivio {id}', { id }) }); entriesMeta.push({ name: f.name, size: f.data.length }); }
      if (['iso', 'vhd', 'img'].includes(id)) out.push({ severity: 'low', title: 'Immagine disco', detail: 'Le immagini ISO/VHD sono usate per aggirare la protezione "Mark-of-the-Web" di Windows.' });
      const exe = r.files.filter((f) => DANGEROUS_EXT.has((f.name.split('.').pop() || '').toLowerCase()));
      if (exe.length) out.push({ severity: 'medium', title: msg('File eseguibili/script nell\'archivio ({n})', { n: exe.length }), detail: 'Archivio che contiene programmi o script.', evidence: exe.map((f) => f.name) });
    }

    // Files embedded / decoded inside the file
    for (const e of ctx.embedded) files.push({ name: e.name, data: e.buffer, origin: e.origin });
    if (ctx.embedded.length) {
      info['File incorporati/decodificati'] = ctx.embedded.length;
      const benign = ctx.embedded.every((e) => /\.(wasm|png|jpg|gz)$/.test(e.name));
      out.push({ severity: benign ? 'info' : 'low', title: msg('File nascosti dentro il file ({n})', { n: ctx.embedded.length }), detail: 'Sono stati estratti file incorporati o codificati: ognuno è stato analizzato separatamente.', evidence: ctx.embedded.map((e) => msg('{name} — {origin}', { name: e.name, origin: e.origin })) });
    }

    // Recursive analysis of EVERY internal file
    let analyzed = 0;
    if (budget.tripped) files.length = 0; // limit exceeded: nothing else is analyzed (and the buffers are released)
    for (const f of files) {
      if (budget.tripped) break;
      const child = await ctx.scanChild(f.data, f.name, f.origin);
      if (!child && budget.tripped) break;
      if (!child) { out.push({ severity: 'medium', title: 'Annidamento eccessivo', detail: 'Troppi archivi uno dentro l\'altro (possibile "zip quine"): analisi interrotta a questo livello.' }); break; }
      analyzed++;
      ctx.children.push(child);
      if (child.overall.score < 70) {
        const worst = child.findings.filter((x) => ['critical', 'high'].includes(x.severity)).slice(0, 4);
        out.push({
          severity: severityOf(child),
          title: msg('File interno sospetto: {name}', { name: f.name }),
          detail: msg('Punteggio {score}/100 — {verdict} ({origin}).', { score: child.overall.score, verdict: child.overall.verdict, origin: f.origin }),
          evidence: worst.map((x) => msg('[{cat}] {title}', { cat: x.category, title: x.title })),
          forceScore: child.overall.score < 10 ? Math.max(1, child.overall.score) : undefined,
          child: child.file.name,
        });
      }
    }
    info['File analizzati in profondità'] = analyzed;
    // Decompression limits: checked last, so a trip caused by any nested file is reported here too
    C('Nessuna bomba di decompressione (limiti rispettati)', !budget.tripped, budget.tripped ? budget.exceeded.detail : msg('{size} decompressi, {n} file', { size: fmt(budget.totalBytes), n: budget.files }));
    if (budget.tripped) {
      const ex = budget.exceeded;
      const label = { ratio: 'rapporto di compressione', total: 'dimensione decompressa totale', entry: 'dimensione di un singolo file', files: 'numero di file', memory: 'memoria', overlap: 'voci sovrapposte' }[ex.reason] || ex.reason;
      out.push({
        severity: 'critical',
        title: msg('Zip bomb: limite di sicurezza superato ({label})', { label }),
        detail: ex.where ? msg('{detail} L\'estrazione e l\'analisi dei contenuti sono state interrotte per proteggere il computer. Punto di arresto: {where}.', { detail: ex.detail, where: ex.where }) : msg('{detail} L\'estrazione e l\'analisi dei contenuti sono state interrotte per proteggere il computer.', { detail: ex.detail }),
        evidence: [msg('decompressi finora: {size}', { size: fmt(budget.totalBytes) }), msg('file estratti: {n}', { n: budget.files })],
      });
      info['Analisi interrotta'] = ex.detail;
    }
    if (!ARCHIVES.includes(id) && !files.length && !budget.tripped) return { skipped: true, reason: 'nessun file incorporato', findings: [], checks: [] };
    const bad = ctx.children.filter((c) => c.overall.score < 70).length;
    C('Tutti i file interni sono sicuri', !bad, msg('{a} sospetti su {b}', { a: bad, b: analyzed }));
    return { findings: out, checks, info, extra: { archiveEntries: entriesMeta } };
  },
};
