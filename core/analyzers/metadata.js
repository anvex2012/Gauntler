// Creato da anvex2012
'use strict';
const fs = require('fs');
const { execFileSync } = require('child_process');
const { truncate } = require('../utils');

/* ---- EXIF (TIFF) ---- */
function readTiff(buf, base) {
  const le = buf.toString('latin1', base, base + 2) === 'II';
  const u16 = (o) => (le ? buf.readUInt16LE(base + o) : buf.readUInt16BE(base + o));
  const u32 = (o) => (le ? buf.readUInt32LE(base + o) : buf.readUInt32BE(base + o));
  const SIZES = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8 };
  const ifd = (off) => {
    const res = {};
    if (base + off + 2 > buf.length) return res;
    const n = u16(off);
    for (let i = 0; i < n && base + off + 2 + i * 12 + 12 <= buf.length; i++) {
      const e = off + 2 + i * 12;
      const tag = u16(e), type = u16(e + 2), count = u32(e + 4);
      const size = (SIZES[type] || 1) * count;
      const vo = size <= 4 ? e + 8 : u32(e + 8);
      if (base + vo + size > buf.length) continue;
      if (type === 2) res[tag] = buf.toString('latin1', base + vo, base + vo + count).replace(/\0+$/, '').trim();
      else if (type === 3) res[tag] = u16(vo);
      else if (type === 4) res[tag] = u32(vo);
      else if (type === 5 || type === 10) { const a = []; for (let k = 0; k < Math.min(count, 8); k++) { const d = u32(vo + k * 8 + 4); a.push(d ? u32(vo + k * 8) / d : 0); } res[tag] = a; }
      else if (type === 1 || type === 7) res[tag] = buf.subarray(base + vo, base + vo + Math.min(count, 64));
    }
    return res;
  };
  const i0 = ifd(u32(4));
  const exif = i0[0x8769] ? ifd(i0[0x8769]) : {};
  const gps = i0[0x8825] ? ifd(i0[0x8825]) : {};
  return { i0, exif, gps };
}

function parseExif(buf) {
  let base = -1;
  const ex = buf.indexOf(Buffer.from('Exif\0\0'));
  if (ex >= 0 && ex < 128 * 1024) base = ex + 6;
  else {
    const png = buf.indexOf(Buffer.from('eXIf'));
    if (png > 0) base = png + 4;
  }
  if (base < 0 || !/^(II|MM)$/.test(buf.toString('latin1', base, base + 2))) return null;
  try {
    const { i0, exif, gps } = readTiff(buf, base);
    const out = {};
    const put = (k, v) => { if (v !== undefined && v !== '' && !(v instanceof Buffer)) out[k] = v; };
    put('Produttore fotocamera', i0[0x010f]); put('Modello', i0[0x0110]); put('Software', i0[0x0131]); put('Data', i0[0x0132]); put('Autore', i0[0x013b]); put('Copyright', i0[0x8298]);
    put('Data scatto', exif[0x9003]); put('Proprietario fotocamera', exif[0xa430]); put('Numero di serie', exif[0xa431]); put('Obiettivo', exif[0xa434]);
    if (Array.isArray(gps[2]) && Array.isArray(gps[4])) {
      const dms = (a) => a[0] + (a[1] || 0) / 60 + (a[2] || 0) / 3600;
      const lat = dms(gps[2]) * (gps[1] === 'S' ? -1 : 1), lon = dms(gps[4]) * (gps[3] === 'W' ? -1 : 1);
      if (lat || lon) out.GPS = { lat: +lat.toFixed(6), lon: +lon.toFixed(6), alt: Array.isArray(gps[6]) ? Math.round(gps[6][0]) : undefined };
    }
    return out;
  } catch { return null; }
}

function xmp(text) {
  const i = text.indexOf('<x:xmpmeta');
  if (i < 0) return null;
  const x = text.slice(i, text.indexOf('</x:xmpmeta>', i) + 12 || i + 100000);
  const g = (re) => (x.match(re) || [])[1];
  const out = {};
  const set = (k, v) => { if (v) out[k] = truncate(v.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim(), 200); };
  set('Autore (XMP)', g(/<dc:creator>([\s\S]*?)<\/dc:creator>/));
  set('Strumento (XMP)', g(/xmp:CreatorTool[=>]"?([^"<]+)/));
  set('Produttore (XMP)', g(/pdf:Producer[=>]"?([^"<]+)/));
  set('Creato (XMP)', g(/xmp:CreateDate[=>]"?([^"<]+)/));
  set('Modificato (XMP)', g(/xmp:ModifyDate[=>]"?([^"<]+)/));
  set('ID documento', g(/xmpMM:DocumentID[=>]"?([^"<]+)/));
  const lat = g(/exif:GPSLatitude[=>]"?([^"<]+)/), lon = g(/exif:GPSLongitude[=>]"?([^"<]+)/);
  if (lat && lon) out['GPS (XMP)'] = `${lat}, ${lon}`;
  return out;
}

function pdfInfo(text) {
  const out = {};
  for (const k of ['Title', 'Author', 'Subject', 'Keywords', 'Creator', 'Producer', 'CreationDate', 'ModDate']) {
    const m = text.match(new RegExp(`/${k}\\s*\\(((?:\\\\.|[^\\\\)])*)\\)`)) || text.match(new RegExp(`/${k}\\s*<([0-9A-Fa-f]+)>`));
    if (!m) continue;
    let v = m[1];
    if (/^[0-9A-Fa-f]+$/.test(v) && v.length % 2 === 0 && m[0].includes('<')) { const b = Buffer.from(v, 'hex'); v = b[0] === 0xfe ? b.swap16().toString('utf16le').slice(1) : b.toString('latin1'); }
    if (v.startsWith('\xfe\xff')) v = Buffer.from(v.slice(2), 'latin1').swap16().toString('utf16le');
    const it = { Title: 'Titolo', Author: 'Autore', Subject: 'Oggetto', Keywords: 'Parole chiave', Creator: 'Creato con', Producer: 'Prodotto da', CreationDate: 'Data creazione', ModDate: 'Data modifica' }[k];
    out[it] = truncate(v.replace(/^D:(\d{4})(\d{2})(\d{2})(\d{2})?(\d{2})?.*/, (_, y, mo, d, h = '00', mi = '00') => `${y}-${mo}-${d} ${h}:${mi}`), 200);
  }
  return out;
}

function officeInfo(extracted) {
  const out = {};
  const core = extracted.find((e) => /docProps\/core\.xml|meta\.xml/.test(e.label));
  const app = extracted.find((e) => /docProps\/app\.xml/.test(e.label));
  const g = (t, re) => ((t || '').match(re) || [])[1];
  if (core) {
    const t = core.text;
    const s = { 'Autore': g(t, /<dc:creator>([^<]*)/), 'Ultima modifica di': g(t, /<cp:lastModifiedBy>([^<]*)/), 'Creato': g(t, /<dcterms:created[^>]*>([^<]*)/), 'Modificato': g(t, /<dcterms:modified[^>]*>([^<]*)/), 'Titolo': g(t, /<dc:title>([^<]*)/), 'Revisione': g(t, /<cp:revision>([^<]*)/), 'Stampato': g(t, /<cp:lastPrinted>([^<]*)/), 'Autore (ODF)': g(t, /<meta:initial-creator>([^<]*)/) };
    for (const [k, v] of Object.entries(s)) if (v) out[k] = v;
  }
  if (app) {
    const t = app.text;
    const s = { 'Applicazione': g(t, /<Application>([^<]*)/), 'Versione app': g(t, /<AppVersion>([^<]*)/), 'Azienda': g(t, /<Company>([^<]*)/), 'Modello': g(t, /<Template>([^<]*)/), 'Tempo di modifica (min)': g(t, /<TotalTime>([^<]*)/), 'Responsabile': g(t, /<Manager>([^<]*)/) };
    for (const [k, v] of Object.entries(s)) if (v) out[k] = v;
  }
  return out;
}

function provenance(p) {
  const out = {};
  if (!p) return out;
  try {
    if (process.platform === 'darwin') {
      try {
        const q = execFileSync('xattr', ['-p', 'com.apple.quarantine', p], { encoding: 'utf8', timeout: 3000, stdio: ['ignore', 'pipe', 'ignore'] }).trim();
        const parts = q.split(';');
        out.quarantine = { flags: parts[0], date: parts[1] ? new Date(parseInt(parts[1], 16) * 1000).toISOString() : undefined, agent: parts[2] };
      } catch { /* no quarantine */ }
      try {
        const w = execFileSync('mdls', ['-raw', '-name', 'kMDItemWhereFroms', p], { encoding: 'utf8', timeout: 3000, stdio: ['ignore', 'pipe', 'ignore'] });
        const urls = [...w.matchAll(/"([^"]+)"/g)].map((m) => m[1]);
        if (urls.length) out.whereFrom = urls;
      } catch { /* */ }
    } else if (process.platform === 'win32') {
      try {
        const z = fs.readFileSync(p + ':Zone.Identifier', 'utf8');
        out.zone = { id: (z.match(/ZoneId=(\d)/) || [])[1], host: (z.match(/HostUrl=(.+)/) || [])[1], referrer: (z.match(/ReferrerUrl=(.+)/) || [])[1] };
      } catch { /* */ }
    }
  } catch { /* */ }
  return out;
}

module.exports = {
  id: 'metadata',
  name: 'Metadati & provenienza',
  description: 'Legge i metadati nascosti: posizione GPS e fotocamera nelle foto (EXIF/XMP), autore, azienda e software di documenti Office/PDF, provenienza del download (quarantena macOS / Zone.Identifier Windows), permessi e date del file.',
  weight: 1,
  applies: () => true,
  run(ctx) {
    const out = [], checks = [], fields = {};
    const C = (n, ok, note) => checks.push({ name: n, ok, note });
    // File system
    const st = ctx.fsStat;
    if (st) {
      Object.assign(fields, { 'Creato': st.birthtime?.toISOString?.(), 'Modificato': st.mtime.toISOString(), 'Ultimo accesso': st.atime.toISOString(), 'Permessi': '0' + (st.mode & 0o7777).toString(8), 'Proprietario (uid)': st.uid });
      const execBit = !!(st.mode & 0o111);
      const nonExec = !['executable', 'script'].includes(ctx.type.family) && process.platform !== 'win32';
      C('Permesso di esecuzione coerente con il tipo', !(execBit && nonExec));
      if (execBit && nonExec && ctx.type.family !== 'unknown') out.push({ severity: 'low', title: 'Documento con permesso di esecuzione', detail: 'Il file è marcato come eseguibile pur non essendo un programma.' });
      const suid = !!(st.mode & 0o6000);
      C('Nessun bit SUID/SGID', !suid);
      if (suid) out.push({ severity: 'high', title: 'File con SUID/SGID', detail: 'Viene eseguito con i privilegi del proprietario (possibile escalation).' });
      const ww = !!(st.mode & 0o002);
      C('Non scrivibile da tutti', !ww);
      if (ww && process.platform !== 'win32') out.push({ severity: 'low', title: 'Scrivibile da qualsiasi utente', detail: 'Chiunque può modificare il file.' });
      if (st.mtime > new Date(Date.now() + 86400000)) out.push({ severity: 'low', title: 'Data di modifica nel futuro', detail: 'Date alterate (timestomping).' });
    }
    // Provenance
    const prov = ctx.virtual ? {} : provenance(ctx.path);
    if (prov.quarantine) fields['Scaricato con'] = prov.quarantine.agent || '?';
    if (prov.quarantine?.date) fields['Scaricato il'] = prov.quarantine.date;
    if (prov.whereFrom) fields['Scaricato da'] = prov.whereFrom.join(' ← ');
    if (prov.zone) Object.assign(fields, { 'Zona (Windows)': { 0: 'Computer locale', 1: 'Intranet', 2: 'Siti attendibili', 3: 'Internet', 4: 'Siti con restrizioni' }[prov.zone.id] || prov.zone.id, 'Scaricato da': prov.zone.host || prov.zone.referrer });
    const fromNet = !!(prov.quarantine || prov.whereFrom || prov.zone?.id === '3');
    C('Provenienza: non scaricato da Internet', !fromNet, fields['Scaricato da'] || '');
    if (fromNet) out.push({ severity: ['executable', 'script', 'shortcut'].includes(ctx.type.family) ? 'low' : 'info', title: 'File scaricato da Internet', detail: fields['Scaricato da'] ? `Origine: ${truncate(fields['Scaricato da'], 200)}` : 'Il sistema ha marcato il file come proveniente da Internet.', evidence: prov.whereFrom });
    // Content
    const exif = ['jpeg', 'png', 'heic', 'webp', 'tiff', 'mp4'].includes(ctx.type.id) || ctx.type.family === 'media' ? parseExif(ctx.buffer) : null;
    if (exif) {
      for (const [k, v] of Object.entries(exif)) if (k !== 'GPS') fields[k] = v;
      if (exif.GPS) {
        fields['Posizione GPS'] = `${exif.GPS.lat}, ${exif.GPS.lon}${exif.GPS.alt !== undefined ? ` (alt. ${exif.GPS.alt} m)` : ''}`;
        out.push({ severity: 'high', title: 'La foto contiene la posizione GPS', detail: 'Chi riceve la foto può sapere esattamente dove è stata scattata. Rimuovi i metadati prima di condividerla.', evidence: [fields['Posizione GPS'], `https://www.openstreetmap.org/?mlat=${exif.GPS.lat}&mlon=${exif.GPS.lon}#map=16/${exif.GPS.lat}/${exif.GPS.lon}`] });
      }
      if (exif['Numero di serie'] || exif['Proprietario fotocamera']) out.push({ severity: 'low', title: 'Identificativi della fotocamera', detail: 'Numero di serie o proprietario possono collegare la foto a te.', evidence: [exif['Numero di serie'], exif['Proprietario fotocamera']].filter(Boolean) });
    }
    C('Nessuna posizione GPS nei metadati', !exif?.GPS);
    if (ctx.type.id === 'pdf') Object.assign(fields, pdfInfo(ctx.text));
    if (['docx', 'xlsx', 'pptx', 'odf'].includes(ctx.type.id)) Object.assign(fields, officeInfo(ctx.extracted));
    const x = ctx.isText || ctx.type.family !== 'executable' ? xmp(ctx.text) : null;
    if (x) Object.assign(fields, x);
    if (x && x['GPS (XMP)'] && !exif?.GPS) out.push({ severity: 'medium', title: 'Posizione GPS nei metadati XMP', detail: 'Il file rivela un luogo.', evidence: [x['GPS (XMP)']] });
    const people = ['Autore', 'Ultima modifica di', 'Autore (XMP)', 'Autore (ODF)', 'Azienda', 'Responsabile', 'Artist'].map((k) => fields[k]).filter(Boolean);
    C('Nessun nome di persona/azienda nei metadati', !people.length, people.join(', '));
    if (people.length) out.push({ severity: 'info', title: 'Nomi di persone o aziende nei metadati', detail: 'Il documento rivela chi lo ha creato o modificato.', evidence: [...new Set(people)] });
    const tmpl = fields['Modello'];
    if (tmpl && /^https?:|\\\\/.test(tmpl)) out.push({ severity: 'high', title: 'Modello del documento remoto', detail: 'Il modello viene caricato da un percorso remoto.', evidence: [tmpl] });
    if (fields['Tempo di modifica (min)'] === '0' && ['docx', 'xlsx'].includes(ctx.type.id) && ctx.macros.length) out.push({ severity: 'low', title: 'Documento generato automaticamente', detail: 'Tempo di modifica zero + macro: tipico dei documenti malevoli generati da tool.' });
    for (const k of Object.keys(fields)) if (fields[k] === undefined) delete fields[k];
    return { findings: out, checks, info: fields, extra: { metadata: fields } };
  },
};
