// Created by anvex2012
'use strict';
const { t } = require('./i18n');
/**
 * Quarantine: the file is moved into ~/.gauntler/quarantine, its bytes are XOR-ed (so it can no longer
 * be executed or opened by mistake, and antivirus software doesn't detect it again) and it is made read-only.
 * It can be restored exactly to its original location.
 *
 * Integrity guarantees:
 *  - every item has a random UUID (v4) as id: two files (even identical, even quarantined in the same
 *    millisecond) never share an id, so one can never overwrite the other;
 *  - the full SHA-256 of the original content is stored and verified before the original is deleted
 *    AND before a restore is written;
 *  - data and metadata are written atomically (temporary file + fsync + rename, never overwriting):
 *    a crash leaves either a complete item or nothing visible, never a half-written one;
 *  - a restore is atomic too (temporary file in the destination folder + rename) and the item is
 *    "claimed" with a rename first, so two concurrent restores of the same item cannot both succeed.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { dir } = require('./paths');

const KEY = Buffer.from('gauntler-quarantine-v1');
function xor(buf) {
  const out = Buffer.allocUnsafe(buf.length);
  for (let i = 0; i < buf.length; i++) out[i] = buf[i] ^ KEY[i % KEY.length];
  return out;
}
const Q = () => dir('quarantine');
const sha256 = (b) => crypto.createHash('sha256').update(b).digest('hex');
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SAFE_ID = /^[0-9A-Za-z-]+$/; // ids are used as file names: never accept separators

/** Writes `data` to `dest` atomically: unique temp file in the same folder, fsync, rename */
function atomicWrite(dest, data, { mode = 0o600, overwrite = false } = {}) {
  const tmp = path.join(path.dirname(dest), `.${path.basename(dest)}.${crypto.randomUUID()}.tmp`);
  const fd = fs.openSync(tmp, 'wx', 0o600);
  try {
    fs.writeSync(fd, data, 0, data.length, 0);
    fs.fsyncSync(fd);
  } catch (e) {
    fs.closeSync(fd); fs.rmSync(tmp, { force: true }); throw e;
  }
  fs.closeSync(fd);
  try {
    fs.chmodSync(tmp, mode);
    if (!overwrite) {
      // link() fails with EEXIST instead of silently replacing: no item can ever overwrite another
      try { fs.linkSync(tmp, dest); fs.unlinkSync(tmp); } catch (e) {
        if (!['EPERM', 'ENOTSUP', 'EOPNOTSUPP', 'ENOSYS', 'EMLINK'].includes(e.code)) throw e;
        // File systems without hard links (FAT, some network shares): check, then rename
        if (fs.existsSync(dest)) { const err = new Error(`EEXIST: ${dest}`); err.code = 'EEXIST'; throw err; }
        fs.renameSync(tmp, dest);
      }
    } else fs.renameSync(tmp, dest);
  } catch (e) {
    fs.rmSync(tmp, { force: true });
    throw e;
  }
  fsyncDir(path.dirname(dest));
}
function fsyncDir(d) { try { const fd = fs.openSync(d, 'r'); try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); } } catch { /* not supported on every platform */ } }

const binOf = (id) => path.join(Q(), id + '.quar');
const metaOf = (id) => path.join(Q(), id + '.json');

function add(filePath, info = {}) {
  // A symbolic link is resolved: the real file is what must be neutralized
  const abs = fs.realpathSync(path.resolve(filePath));
  const st = fs.statSync(abs);
  if (!st.isFile()) throw new Error(t('Non è un file: {path}', { path: abs }));
  const data = fs.readFileSync(abs);
  const hash = sha256(data);
  const id = crypto.randomUUID();
  const meta = {
    id, format: 2, originalPath: abs, name: path.basename(abs), size: data.length, mode: st.mode & 0o7777, sha256: hash,
    date: new Date().toISOString(), score: info.score, verdict: info.verdict, reason: info.reason,
  };
  const binPath = binOf(id), metaPath = metaOf(id);
  atomicWrite(binPath, xor(data), { mode: 0o400 });
  try {
    // Verify the stored copy (read back from disk) before touching the original
    if (sha256(xor(fs.readFileSync(binPath))) !== hash) throw new Error('Verifica della copia in quarantena fallita: file originale NON rimosso.');
    atomicWrite(metaPath, Buffer.from(JSON.stringify(meta, null, 2)), { mode: 0o600 });
  } catch (e) {
    forceRm(binPath); forceRm(metaPath);
    throw e;
  }
  // The original may have changed while it was being copied: delete it only if it is still the same content
  if (fs.statSync(abs).size !== data.length || sha256(fs.readFileSync(abs)) !== hash) {
    forceRm(binPath); forceRm(metaPath);
    throw new Error('Il file è cambiato durante la messa in quarantena: originale NON rimosso, riprova.');
  }
  fs.unlinkSync(abs);
  return meta;
}

function readMeta(file) {
  const m = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (!m || typeof m.id !== 'string' || !SAFE_ID.test(m.id) || path.basename(file) !== m.id + '.json') return null;
  return m;
}

function list() {
  const out = [];
  let names = [];
  try { names = fs.readdirSync(Q()); } catch { return out; }
  for (const f of names) {
    if (!f.endsWith('.json') || f.startsWith('.')) continue; // temp files and claimed items are hidden
    try { const m = readMeta(path.join(Q(), f)); if (m) out.push(m); } catch { /* damaged metadata: skipped */ }
  }
  return out.sort((a, b) => String(b.date).localeCompare(String(a.date)) || a.id.localeCompare(b.id));
}

/** Exact id first; otherwise a unique prefix of the id or of the SHA-256 (at least 4 characters) */
function find(idOrPrefix) {
  const q = String(idOrPrefix || '').trim().toLowerCase();
  if (!q) throw new Error('Indica l\'id dell\'elemento in quarantena');
  const all = list();
  const exact = all.find((x) => x.id.toLowerCase() === q);
  if (exact) return exact;
  if (q.length < 4) throw new Error('Id troppo corto: indica almeno 4 caratteri');
  const m = all.filter((x) => x.id.toLowerCase().startsWith(q) || String(x.sha256 || '').startsWith(q));
  if (!m.length) throw new Error(t('Nessun elemento in quarantena con id {id}', { id: idOrPrefix }));
  if (m.length > 1) throw new Error(t('Id ambiguo, corrisponde a: {list}', { list: m.map((x) => `${x.id} (${x.name})`).join(', ') }));
  return m[0];
}

function restore(idOrPrefix, { to, force } = {}) {
  const meta = find(idOrPrefix);
  const dest = path.resolve(to || meta.originalPath);
  if (fs.existsSync(dest) && !force) throw new Error(t('Esiste già un file in {dest} (usa --force per sovrascrivere o --to per un altro percorso)', { dest }));
  // Claim the item: only one restore can rename the metadata away
  const claimed = path.join(Q(), `.${meta.id}.json.restoring-${process.pid}-${crypto.randomUUID()}`);
  try { fs.renameSync(metaOf(meta.id), claimed); } catch (e) {
    if (e.code === 'ENOENT') throw new Error(t('L\'elemento {id} è già stato ripristinato o eliminato', { id: meta.id }));
    throw e;
  }
  try {
    const data = xor(fs.readFileSync(binOf(meta.id)));
    if (meta.size != null && data.length !== meta.size) throw new Error(t('Copia in quarantena danneggiata ({a} byte invece di {b}): ripristino annullato.', { a: data.length, b: meta.size }));
    if (meta.sha256 && sha256(data) !== meta.sha256) throw new Error('Copia in quarantena danneggiata (SHA-256 diverso): ripristino annullato.');
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    atomicWrite(dest, data, { mode: meta.mode || 0o644, overwrite: !!force });
  } catch (e) {
    try { fs.renameSync(claimed, metaOf(meta.id)); } catch { /* */ }
    throw e;
  }
  // Restored and verified: the item can go (data first, then the claimed metadata)
  forceRm(binOf(meta.id));
  forceRm(claimed);
  return { ...meta, restoredTo: dest };
}

function forceRm(p) {
  try { fs.chmodSync(p, 0o600); } catch { /* */ }
  fs.rmSync(p, { force: true });
}

function remove(idOrPrefix) {
  const meta = find(idOrPrefix);
  // Metadata first: the item disappears from the list atomically, then its data is deleted
  forceRm(metaOf(meta.id));
  forceRm(binOf(meta.id));
  return meta;
}

module.exports = { add, list, restore, remove, find, UUID_RE };
