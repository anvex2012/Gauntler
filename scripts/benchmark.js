// Created by anvex2012
'use strict';
/**
 * Measures Gauntler on real files, so the README can show numbers instead of claims.
 *
 *   node scripts/benchmark.js --clean <dir>…   [--malware <dir>…] [--max N] [--clamav] [--json out.json]
 *
 * --clean    folders of files known to be clean (system programs, apps, libraries, documents):
 *            measures FALSE POSITIVES (clean files that Gauntler scores as Suspicious or worse)
 * --malware  folders of known malware samples (e.g. from MalwareBazaar, in a VM):
 *            measures DETECTION (samples scored as Dangerous/Malicious, or at least Suspicious).
 *            The script never downloads malware: you choose the samples.
 * --max N    at most N files per folder group (random sample, fixed seed: reproducible)
 * --clamav   also run ClamAV (slower: by default it is off, so the numbers measure Gauntler's own engine)
 *
 * Nothing is written to ~/.gauntler: the run uses a temporary data folder, no cache, no online lookup.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');

process.env.GAUNTLER_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'gauntler-bench-'));
process.env.GAUNTLER_LANG = process.env.GAUNTLER_LANG || 'en';
const { ScanPool } = require('../core/pool');
const { VERSION } = require('../core');

const args = process.argv.slice(2);
const groups = { clean: [], malware: [] };
let max = Infinity, withClam = false, jsonOut = null, mode = null;
for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === '--clean' || a === '--malware') mode = a.slice(2);
  else if (a === '--max') max = Number(args[++i]);
  else if (a === '--clamav') withClam = true;
  else if (a === '--json') jsonOut = args[++i];
  else if (mode) groups[mode].push(a);
  else { console.error(`Unknown argument: ${a}`); process.exit(2); }
}
if (!groups.clean.length && !groups.malware.length) {
  console.error('Usage: node scripts/benchmark.js --clean <dir>… [--malware <dir>…] [--max N] [--clamav] [--json out.json]');
  process.exit(2);
}

/** Regular files under the folders (symbolic links and empty files skipped), deduplicated by inode */
function collect(dirs) {
  const out = [], seen = new Set();
  const walk = (p) => {
    let st; try { st = fs.lstatSync(p, { bigint: true }); } catch { return; } // bigint: system-volume inodes exceed 2^53
    if (st.isSymbolicLink()) return;
    if (st.isDirectory()) { let e = []; try { e = fs.readdirSync(p); } catch { return; } for (const n of e) walk(path.join(p, n)); return; }
    if (!st.isFile() || st.size === 0n) return;
    const key = `${st.dev}:${st.ino}`;
    if (seen.has(key)) return;
    seen.add(key);
    try { fs.accessSync(p, fs.constants.R_OK); out.push(p); } catch { /* unreadable */ }
  };
  for (const d of dirs) walk(path.resolve(d));
  return out.sort();
}

/** Deterministic sample (mulberry32, fixed seed) so two runs on the same machine measure the same files */
function sample(list, n) {
  if (list.length <= n) return list;
  let s = 0x9e3779b9;
  const rnd = () => { s |= 0; s = (s + 0x6d2b79f5) | 0; let t = Math.imul(s ^ (s >>> 15), 1 | s); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
  const a = list.slice();
  for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(rnd() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; }
  return a.slice(0, n).sort();
}

// Score bands of core/index.js verdictFor(): 90+ Safe, 70+ Low risk, 40+ Suspicious, 15+ Dangerous, below Malicious
const LEVELS = ['safe', 'low', 'suspicious', 'dangerous', 'malicious'];
const band = (score) => (score >= 90 ? 'safe' : score >= 70 ? 'low' : score >= 40 ? 'suspicious' : score >= 15 ? 'dangerous' : 'malicious');
const pct = (n, d) => (d ? (100 * n / d).toFixed(1) + '%' : '—');

async function run(kind, files, pool) {
  const res = { files: files.length, levels: Object.fromEntries(LEVELS.map((l) => [l, 0])), errors: 0, errorList: [], ms: 0, flagged: [] };
  let done = 0;
  const t0 = Date.now();
  await Promise.all(files.map(async (f) => {
    try {
      const r = await pool.scan(f, { useConfig: false, cache: false, online: false, noClamav: !withClam, lang: 'en' });
      res.levels[band(r.overall.score)]++;
      const bad = kind === 'clean' ? r.overall.score < 70 : r.overall.score >= 40;
      if (bad) res.flagged.push({ file: f, score: r.overall.score, verdict: r.overall.verdict, top: r.findings.filter((x) => x.severity !== 'info').slice(0, 3).map((x) => x.title) });
    } catch (e) { res.errors++; res.errorList.push({ file: f, error: e.message }); }
    if (++done % 50 === 0 || done === files.length) process.stderr.write(`\r  ${kind}: ${done}/${files.length}`);
  }));
  process.stderr.write('\n');
  res.ms = Date.now() - t0;
  res.flagged.sort((a, b) => a.score - b.score);
  return res;
}

(async () => {
  const pool = new ScanPool({ timeoutMs: 5 * 60 * 1000 });
  const out = { version: VERSION, date: new Date().toISOString().slice(0, 10), platform: `${os.platform()} ${os.arch()}`, clamav: withClam, groups };
  try {
    for (const kind of ['clean', 'malware']) {
      if (!groups[kind].length) continue;
      const files = sample(collect(groups[kind]), max);
      out[kind] = await run(kind, files, pool);
    }
  } finally {
    await pool.close();
    fs.rmSync(process.env.GAUNTLER_HOME, { recursive: true, force: true });
  }

  console.log(`\nGauntler ${out.version} · ${out.platform} · ClamAV ${withClam ? 'on' : 'off'} · ${out.date}\n`);
  if (out.clean) {
    const c = out.clean, n = c.files - c.errors;
    const fp70 = c.levels.suspicious + c.levels.dangerous + c.levels.malicious, fp40 = c.levels.dangerous + c.levels.malicious;
    console.log(`Clean files: ${c.files} (${groups.clean.join(', ')}), ${(c.ms / 1000).toFixed(0)} s, ${c.errors} errors`);
    console.log(`  Safe ${c.levels.safe} · Low risk ${c.levels.low} · Suspicious ${c.levels.suspicious} · Dangerous ${c.levels.dangerous} · Malicious ${c.levels.malicious}`);
    console.log(`  False positives: ${pct(fp70, n)} scored below 70 (Suspicious or worse), ${pct(fp40, n)} below 40 (Dangerous or worse)`);
    for (const f of c.flagged.slice(0, 15)) console.log(`    ${String(f.score).padStart(3)}  ${f.file}  — ${f.top.join(' | ')}`);
    for (const e of c.errorList.slice(0, 5)) console.log(`    error  ${e.file}  — ${e.error}`);
  }
  if (out.malware) {
    const m = out.malware, n = m.files - m.errors;
    console.log(`\nMalware samples: ${m.files}, ${(m.ms / 1000).toFixed(0)} s, ${m.errors} errors`);
    console.log(`  Safe ${m.levels.safe} · Low risk ${m.levels.low} · Suspicious ${m.levels.suspicious} · Dangerous ${m.levels.dangerous} · Malicious ${m.levels.malicious}`);
    console.log(`  Detected: ${pct(m.levels.dangerous + m.levels.malicious, n)} below 40, ${pct(m.levels.suspicious + m.levels.dangerous + m.levels.malicious, n)} below 70`);
    console.log(`  Missed (scored 40 or more): ${m.flagged.length}`);
  }
  if (jsonOut) fs.writeFileSync(jsonOut, JSON.stringify(out, null, 2));
})().catch((e) => { console.error(e); process.exit(1); });
