// Created by anvex2012
'use strict';
const { m: msg } = require('./i18n');
/**
 * Online reputation (OPTIONAL, only when explicitly requested).
 * Only the SHA-256 fingerprint of the file is sent, never its content.
 */
const fs = require('fs');
const path = require('path');
const { dir } = require('./paths');

const UA = 'Gauntler-Scanner';

async function http(url, opts = {}, ms = 20000) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), ms);
  try {
    return await fetch(url, { ...opts, signal: ctl.signal, headers: { 'User-Agent': UA, ...(opts.headers || {}) } });
  } finally { clearTimeout(t); }
}

async function virustotal(sha256, key) {
  if (!key) return { service: 'VirusTotal', skipped: 'chiave API mancante (gauntler config set online.virustotal <chiave> oppure VT_API_KEY)' };
  const res = await http(`https://www.virustotal.com/api/v3/files/${sha256}`, { headers: { 'x-apikey': key } });
  if (res.status === 404) return { service: 'VirusTotal', found: false };
  if (!res.ok) return { service: 'VirusTotal', error: `HTTP ${res.status}` };
  const a = (await res.json()).data?.attributes || {};
  const s = a.last_analysis_stats || {};
  const names = Object.values(a.last_analysis_results || {}).filter((x) => x.category === 'malicious' && x.result).map((x) => x.result);
  return {
    service: 'VirusTotal', found: true,
    malicious: s.malicious || 0, suspicious: s.suspicious || 0, harmless: s.harmless || 0, undetected: s.undetected || 0,
    engines: Object.keys(a.last_analysis_results || {}).length,
    label: a.popular_threat_classification?.suggested_threat_label, names: [...new Set(names)].slice(0, 10),
    firstSeen: a.first_submission_date ? new Date(a.first_submission_date * 1000).toISOString().slice(0, 10) : undefined,
    reputation: a.reputation, link: `https://www.virustotal.com/gui/file/${sha256}`,
  };
}

async function malwarebazaar(sha256, key) {
  if (!key) return { service: 'MalwareBazaar', skipped: 'chiave Auth-Key abuse.ch mancante (gauntler config set online.malwarebazaar <chiave> oppure MB_API_KEY)' };
  const res = await http('https://mb-api.abuse.ch/api/v1/', { method: 'POST', headers: { 'Auth-Key': key, 'Content-Type': 'application/x-www-form-urlencoded' }, body: `query=get_info&hash=${sha256}` });
  if (!res.ok) return { service: 'MalwareBazaar', error: `HTTP ${res.status}` };
  const j = await res.json();
  if (j.query_status !== 'ok') return { service: 'MalwareBazaar', found: false, status: j.query_status };
  const d = j.data?.[0] || {};
  return { service: 'MalwareBazaar', found: true, signature: d.signature, tags: d.tags, firstSeen: d.first_seen, fileType: d.file_type, link: `https://bazaar.abuse.ch/sample/${sha256}/` };
}

async function lookup(sha256, keys = {}) {
  const out = [];
  for (const fn of [virustotal, malwarebazaar]) {
    try { out.push(await fn(sha256, fn === virustotal ? keys.virustotal : keys.malwarebazaar)); }
    catch (e) { out.push({ service: fn === virustotal ? 'VirusTotal' : 'MalwareBazaar', error: e.name === 'AbortError' ? 'timeout' : e.message }); }
  }
  return out;
}

/* ---- Feeds of malicious hashes (stored locally, then used offline) ----
 * abuse.ch requires a free Auth-Key (https://auth.abuse.ch) for the exports since 2025.
 */
const FEEDS = [
  { id: 'malwarebazaar-recent', name: 'MalwareBazaar — campioni delle ultime 48 ore', url: (k) => `https://mb-api.abuse.ch/v2/files/exports/${encodeURIComponent(k)}/recent.csv`, auth: 'malwarebazaar' },
];

/** Extracts sha256 + family (signature column) from an abuse.ch CSV */
function parseCsv(text) {
  const out = new Map();
  let sigIdx = -1, shaIdx = -1;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    const cells = line.replace(/^#\s*/, '').split(/","|",\s*"|,(?=(?:[^"]*"[^"]*")*[^"]*$)/).map((x) => x.replace(/^"|"$/g, '').trim());
    if (line.startsWith('#')) {
      const lower = cells.map((x) => x.toLowerCase());
      if (lower.includes('sha256_hash')) { shaIdx = lower.indexOf('sha256_hash'); sigIdx = lower.indexOf('signature'); }
      continue;
    }
    const sha = shaIdx >= 0 ? (cells[shaIdx] || '').toLowerCase() : (line.match(/\b[a-f0-9]{64}\b/i) || [''])[0].toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(sha)) continue;
    const sig = sigIdx >= 0 && cells[sigIdx] && cells[sigIdx] !== 'n/a' ? cells[sigIdx] : '';
    out.set(sha, sig);
  }
  return out;
}

async function updateFeeds(keys = {}) {
  const res = [];
  for (const f of FEEDS) {
    const key = f.auth ? keys[f.auth] : null;
    if (f.auth && !key) { res.push({ ...f, error: 'serve una Auth-Key gratuita di abuse.ch → registrati su https://auth.abuse.ch e poi: gauntler config set online.malwarebazaar <chiave>' }); continue; }
    try {
      const r = await http(f.url(key), {}, 120000);
      if (!r.ok) { res.push({ ...f, error: r.status === 401 || r.status === 403 ? msg('HTTP {s} (Auth-Key non valida)', { s: r.status }) : `HTTP ${r.status}` }); continue; }
      let buf = Buffer.from(await r.arrayBuffer());
      if (buf[0] === 0x50 && buf[1] === 0x4b) { // ZIP export
        const { readZip, extract } = require('./zip');
        const e = readZip(buf).entries[0];
        buf = e ? extract(buf, e).data || Buffer.alloc(0) : Buffer.alloc(0);
      }
      const map = parseCsv(buf.toString('utf8'));
      if (!map.size) { res.push({ ...f, error: 'risposta senza impronte valide' }); continue; }
      const dest = path.join(dir('feeds'), f.id + '.txt');
      fs.writeFileSync(dest, `# ${f.name}\n# aggiornato ${new Date().toISOString()}\n` + [...map].map(([h, sig]) => `${h} ${sig ? `${sig} (MalwareBazaar)` : 'MalwareBazaar'}`).join('\n') + '\n');
      res.push({ ...f, url: undefined, count: map.size, file: dest });
    } catch (e) {
      res.push({ ...f, error: e.name === 'AbortError' ? 'timeout' : e.message });
    }
  }
  return res;
}

module.exports = { lookup, virustotal, malwarebazaar, updateFeeds, parseCsv, FEEDS };
