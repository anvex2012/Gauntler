// Created by anvex2012
'use strict';
const fs = require('fs');
const { dir, file } = require('./paths');

const P = () => file('history.jsonl');

/** Records a summary of each analysis (no file content) */
function record(r) {
  if (!r || !r.file) return;
  const entry = {
    ts: r.scannedAt || new Date().toISOString(),
    path: r.file.path, name: r.file.name, size: r.file.size, type: r.file.type?.label,
    sha256: r.file.hashes?.sha256, score: r.overall.score, verdict: r.overall.verdict, level: r.overall.level,
    counts: r.overall.counts, durationMs: r.durationMs, cached: !!r.cached,
    top: r.findings.filter((f) => f.severity !== 'info').slice(0, 3).map((f) => f.title),
  };
  try { dir(); fs.appendFileSync(P(), JSON.stringify(entry) + '\n'); } catch { /* */ }
}

function list({ limit = 50, search, below } = {}) {
  let rows = [];
  try { rows = fs.readFileSync(P(), 'utf8').split('\n').filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean); } catch { return []; }
  if (search) { const s = search.toLowerCase(); rows = rows.filter((r) => (r.path || r.name || '').toLowerCase().includes(s) || r.sha256 === s); }
  if (below != null) rows = rows.filter((r) => r.score < below);
  return rows.slice(-limit).reverse();
}

function clear() { try { fs.unlinkSync(P()); } catch { /* */ } }

module.exports = { record, list, clear, path: P };
