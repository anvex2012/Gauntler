// Creato da anvex2012
'use strict';
/**
 * Report exporters: json · sarif (GitHub code scanning / CI) · csv · md · html
 * Every function accepts a list of results (also partial: { file, error }).
 */
const path = require('path');
const { VERSION } = require('../index');
const i18n = require('../i18n');
const { t } = i18n;

const SEV_IT = { critical: 'Critico', high: 'Alto', medium: 'Medio', low: 'Basso', info: 'Info' };
const SEV_LABEL = new Proxy(SEV_IT, { get: (o, k) => (typeof k === 'string' && o[k] ? t(o[k]) : o[k]) });
const SEV_HEX = { critical: '#dc2626', high: '#ea580c', medium: '#d97706', low: '#0d9488', info: '#6b7280' };
const LVL_HEX = { safe: '#16a34a', low: '#0d9488', medium: '#d97706', high: '#ea580c', critical: '#dc2626' };
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmtLoc = (l) => (!l ? '' : [l.source, l.line != null ? t('riga {n}', { n: l.line }) : l.offset != null ? `offset 0x${l.offset.toString(16)}` : ''].filter(Boolean).join(', '));

/** Removes the heavy fields (full text and strings) if not requested */
function slim(r, keepDetail) {
  if (keepDetail || !r || r.error) return r;
  const { source, strings, ...rest } = r;
  return { ...rest, extracted: (r.extracted || []).map(({ text, ...e }) => e), children: (r.children || []).map((c) => slim(c, false)) };
}

function json(results, { detail } = {}) {
  const list = results.map((r) => slim(r, detail));
  return JSON.stringify(list.length === 1 ? list[0] : list, null, 2);
}

function sarif(results, { cwd = process.cwd() } = {}) {
  const rules = new Map();
  const out = [];
  const level = (s) => (s === 'critical' || s === 'high' ? 'error' : s === 'medium' ? 'warning' : 'note');
  for (const r of results) {
    if (r.error) continue;
    const uri = r.file.path ? path.relative(cwd, r.file.path).split(path.sep).join('/') : r.file.name;
    for (const f of r.findings) {
      if (f.severity === 'info') continue;
      if (!rules.has(f.id)) {
        rules.set(f.id, {
          id: f.id, name: f.id.replace(/[^A-Za-z0-9]/g, '_'),
          shortDescription: { text: f.title.replace(/\s*\(\d+\)|\s*—\s*\d+.*$/, '') },
          fullDescription: { text: f.detail },
          defaultConfiguration: { level: level(f.severity) },
          properties: { category: f.category, 'security-severity': { critical: '9.5', high: '8.0', medium: '5.5', low: '3.0' }[f.severity], tags: ['security', f.categoryId] },
        });
      }
      const locs = (f.locs && f.locs.length ? f.locs : [f.loc]).filter(Boolean).filter((l) => !l.source).slice(0, 50);
      const physical = (l) => ({ physicalLocation: { artifactLocation: { uri }, ...(l && l.line != null ? { region: { startLine: l.line } } : l && l.offset != null ? { region: { byteOffset: l.offset } } : {}) } });
      out.push({
        ruleId: f.id,
        level: level(f.severity),
        message: { text: `${f.title}: ${f.detail}${f.evidence && f.evidence.length ? ' — ' + f.evidence.slice(0, 3).join(' | ') : ''}${f.where && (f.loc || {}).source ? ` (${f.where})` : ''}` },
        locations: locs.length ? locs.map(physical) : [physical(null)],
        partialFingerprints: { 'gauntler/v1': `${r.file.hashes.sha256}:${f.id}` },
        properties: { severity: f.severity, score: r.overall.score },
      });
    }
  }
  return JSON.stringify({
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{ tool: { driver: { name: 'Gauntler', version: VERSION, informationUri: 'https://github.com/', rules: [...rules.values()] } }, results: out }],
  }, null, 2);
}

function csv(results) {
  const q = (v) => { const s = String(v ?? ''); return /[",\n;]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
  const rows = [['file', 'sha256', t('punteggio'), t('verdetto'), t('criterio'), t('gravita'), 'id', t('problema'), t('posizione'), t('dettaglio'), t('evidenze')].join(',')];
  for (const r of results) {
    if (r.error) { rows.push([r.file.path, '', '', t('ERRORE'), '', '', '', r.error, '', '', ''].map(q).join(',')); continue; }
    const base = [r.file.path || r.file.name, r.file.hashes.sha256, r.overall.score, r.overall.verdict];
    const fs_ = r.findings.filter((f) => f.severity !== 'info');
    if (!fs_.length) rows.push([...base, '', '', '', '', '', '', ''].map(q).join(','));
    for (const f of fs_) rows.push([...base, f.category, SEV_LABEL[f.severity], f.id, f.title, f.where || '', f.detail, (f.evidence || []).join(' | ')].map(q).join(','));
  }
  return rows.join('\n') + '\n';
}

function md(results) {
  const ok = results.filter((r) => !r.error);
  const L = [t('# Report Gauntler {v}', { v: VERSION }), '', `_${new Date().toLocaleString(i18n.locale())} · ${t('{n} file analizzati', { n: ok.length })}_`, ''];
  if (ok.length > 1) {
    L.push(`| ${t('Punteggio')} | ${t('Verdetto')} | File | ${t('Problema principale')} |`, '|---:|---|---|---|');
    for (const r of [...ok].sort((a, b) => a.overall.score - b.overall.score)) L.push(`| **${r.overall.score}** | ${r.overall.verdict} | \`${r.file.path || r.file.name}\` | ${r.findings.find((f) => f.severity !== 'info')?.title || '—'} |`);
    L.push('');
  }
  for (const r of ok) {
    L.push(`## ${r.file.name} — ${r.overall.score}/100 ${r.overall.verdict}`, '', `${r.file.type.label} · ${r.file.sizeHuman} · SHA-256 \`${r.file.hashes.sha256}\``, '', `> ${r.overall.advice}`, '');
    L.push(`| ${t('Criterio')} | ${t('Punteggio')} |`, '|---|---:|');
    for (const c of r.categories.filter((c) => c.applicable)) L.push(`| ${c.name} | ${c.score} |`);
    L.push('');
    const fs_ = r.findings.filter((f) => f.severity !== 'info');
    if (fs_.length) {
      L.push(`### ${t('Problemi')}`, '');
      for (const f of fs_) L.push(`- **[${SEV_LABEL[f.severity]}] ${f.title}** — ${f.detail}${f.where ? ` _(${f.where})_` : ''}${f.evidence?.length ? `\n  \`${f.evidence.slice(0, 3).join(' | ').replace(/`/g, "'")}\`` : ''}`);
      L.push('');
    }
  }
  for (const r of results.filter((r) => r.error)) L.push(`- ${t('Errore')}: \`${r.file.path}\`: ${r.error}`);
  return L.join('\n') + '\n';
}

function htmlOne(r) {
  const app = r.categories.filter((c) => c.applicable);
  const cats = app.map((c) => `<tr><td>${esc(c.name)}</td><td style="color:${LVL_HEX[c.level]};font-weight:700">${c.score}/100</td><td>${esc(c.verdict)}</td><td>${c.findings.filter((f) => f.severity !== 'info').length}</td><td>${(c.checks || []).filter((k) => k.ok).length}/${(c.checks || []).length}</td></tr>`).join('');
  const finds = r.findings.map((f) => `<li><b style="color:${SEV_HEX[f.severity]}">[${SEV_LABEL[f.severity]}]</b> ${esc(f.title)} <small>· ${esc(f.category)}${f.where ? ' · ' + esc(f.where) : ''} · <code>${esc(f.id)}</code></small><br><span>${esc(f.detail)}</span>${f.evidence?.length ? `<br><code>${f.evidence.map(esc).join(' | ')}</code>` : ''}</li>`).join('');
  const lines = (r.lines || []).filter((l) => l.sev !== 'info').map((l) => `<tr><td style="white-space:nowrap;color:${SEV_HEX[l.sev]}">${esc(fmtLoc(l))}</td><td><code>${esc(l.text)}</code><br><small>${l.tags.map((t) => esc(t.label)).join(' · ')}</small></td></tr>`).join('');
  const checks = app.map((c) => `<details><summary>${esc(c.name)} — ${(c.checks || []).filter((k) => k.ok).length}/${(c.checks || []).length}</summary><ul class="chk">${(c.checks || []).map((k) => `<li>${k.ok ? '✅' : '❌'} ${esc(k.name)}${k.note ? ` <small>(${esc(k.note)})</small>` : ''}</li>`).join('')}</ul></details>`).join('');
  const hashes = Object.entries(r.file.hashes || {}).map(([k, v]) => `<tr><td>${k.toUpperCase()}</td><td><code>${v}</code></td></tr>`).join('');
  return `<section id="f-${r.file.hashes.sha256.slice(0, 12)}"><h1>${esc(r.file.name)}</h1><p><small>${esc(r.file.type.label)} · ${esc(r.file.sizeHuman)} · ${esc(r.file.path || (r.file.chain || []).join(' › '))}</small></p>
<div class="score" style="color:${LVL_HEX[r.overall.level]}">${r.overall.score}/100 <span>${esc(r.overall.verdict)}</span></div><p>${esc(r.overall.advice)}</p>
<p><small>${esc(t(r.totals.lines ? '{n} righe analizzate' : '{n} stringhe analizzate', { n: r.totals.lines || r.totals.strings }))} · ${esc(t('{n} controlli ({f} non superati)', { n: r.totals.checks, f: r.totals.checksFailed }))} · ${esc(t('{n} contenuti estratti', { n: r.totals.extracted }))} · ${esc(t('{n} file interni', { n: r.totals.children }))} · ${r.durationMs} ms</small></p>
<h2>${t('Punteggi per criterio')}</h2><table><tr><th>${t('Criterio')}</th><th>${t('Punteggio')}</th><th>${t('Esito')}</th><th>${t('Problemi')}</th><th>${t('Controlli')}</th></tr>${cats}</table>
<h2>${t('Problemi ({n})', { n: r.findings.length })}</h2><ul>${finds || `<li>${t('Nessuno')}</li>`}</ul>
<h2>${t('Righe segnalate ({n})', { n: (r.lines || []).filter((l) => l.sev !== 'info').length })}</h2><table>${lines || `<tr><td>${t('Nessuna')}</td></tr>`}</table>
<h2>${t('Controlli eseguiti ({n})', { n: r.totals.checks })}</h2>${checks}
<h2>${t('Impronte')}</h2><table>${hashes}</table></section>`;
}

function html(results) {
  const ok = results.filter((r) => !r.error);
  const index = ok.length > 1 ? `<h1>${t('Riepilogo ({n} file)', { n: ok.length })}</h1><table><tr><th>${t('Punteggio')}</th><th>${t('Verdetto')}</th><th>File</th></tr>${[...ok].sort((a, b) => a.overall.score - b.overall.score).map((r) => `<tr><td style="color:${LVL_HEX[r.overall.level]};font-weight:700">${r.overall.score}</td><td>${esc(r.overall.verdict)}</td><td><a href="#f-${r.file.hashes.sha256.slice(0, 12)}">${esc(r.file.path || r.file.name)}</a></td></tr>`).join('')}</table><hr>` : '';
  return `<!doctype html><html lang="${i18n.getLanguage()}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${t('Report Gauntler')}${ok.length === 1 ? ' – ' + esc(ok[0].file.name) : ''}</title>
<style>body{font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;max-width:1000px;margin:32px auto;padding:0 16px;color:#111827}h1{margin:24px 0 0}.score{font-size:52px;font-weight:800}.score span{font-size:22px}table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #e5e7eb;padding:6px 8px;text-align:left;vertical-align:top}li{margin:8px 0}code{background:#f3f4f6;padding:1px 4px;border-radius:4px;word-break:break-all;font-size:12px}small{color:#6b7280}.chk li{margin:2px 0;list-style:none}summary{cursor:pointer;font-weight:600;margin:6px 0}section{margin-bottom:48px}</style></head><body>
<p><small>${t('Report generato da Gauntler {v}', { v: VERSION })} · ${new Date().toLocaleString(i18n.locale())}</small></p>${index}${ok.map(htmlOne).join('<hr>')}
${results.filter((r) => r.error).map((r) => `<p>${t('Errore')}: ${esc(r.file.path)}: ${esc(r.error)}</p>`).join('')}</body></html>`;
}

const FORMATS = { json, sarif, csv, md, markdown: md, html };
function render(format, results, opts) {
  const fn = FORMATS[format];
  if (!fn) throw new Error(t('Formato sconosciuto: {f}. Disponibili: {list}', { f: format, list: Object.keys(FORMATS).join(', ') }));
  return fn(results, opts);
}

module.exports = { render, json, sarif, csv, md, html, slim, FORMATS };
