// Creato da anvex2012
import { t, locale } from './i18n.js';

export const LEVEL_COLOR = { safe: 'var(--safe)', low: 'var(--low)', medium: 'var(--medium)', high: 'var(--high)', critical: 'var(--critical)' };
export const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export function levelOf(score) {
  if (score >= 90) return 'safe';
  if (score >= 70) return 'low';
  if (score >= 40) return 'medium';
  if (score >= 15) return 'high';
  return 'critical';
}

export const SEVERITY = {
  critical: { label: 'Critico', color: 'var(--critical)' },
  high: { label: 'Alto', color: 'var(--high)' },
  medium: { label: 'Medio', color: 'var(--medium)' },
  low: { label: 'Basso', color: 'var(--low)' },
  info: { label: 'Info', color: 'var(--muted)' },
};

/** What to do, in plain language, for each criterion */
export const CATEGORY_ADVICE = {
  identity: 'Controlla l\'estensione reale: se un "documento" è in realtà un programma, non aprirlo.',
  signatures: 'Il file contiene tracce di malware noti: eliminalo o mettilo in quarantena.',
  clamav: 'L\'antivirus ha riconosciuto il file come infetto: eliminalo.',
  executable: 'Esegui solo programmi firmati scaricati dal sito ufficiale dello sviluppatore.',
  documents: 'Non abilitare macro o contenuti attivi; apri il documento in visualizzazione protetta.',
  code: 'Il codice è nascosto di proposito: non eseguirlo senza averlo fatto controllare.',
  lines: 'Leggi le righe evidenziate nella scheda "Codice" per capire cosa fa il file.',
  archive: 'Non estrarre l\'archivio: uno o più file al suo interno sono pericolosi.',
  secrets: 'Cambia subito le password/chiavi trovate e non condividere questo file.',
  privacy: 'Il file contiene dati personali: condividilo solo con chi è autorizzato.',
  social: 'È un tentativo di truffa: non cliccare i link e non inserire dati.',
  network: 'Non visitare i link segnalati.',
  metadata: 'Rimuovi i metadati (posizione, autore) prima di condividere il file.',
  statistics: 'Il contenuto è cifrato o nascosto: non è possibile sapere cosa contiene.',
};

export function formatBytes(n) {
  if (n == null) return '';
  if (n < 1024) return n + ' B';
  const u = ['KB', 'MB', 'GB', 'TB'];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(1) + ' ' + u[i];
}
export const fmtNum = (n) => (typeof n === 'number' ? n.toLocaleString(locale()) : n);
export const fmtMs = (ms) => (ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`);
export function fmtLoc(loc) {
  if (!loc) return '';
  const p = [];
  if (loc.source) p.push(loc.source);
  if (loc.line != null) p.push(t('riga {n}', { n: loc.line }));
  else if (loc.offset != null) p.push(`offset 0x${loc.offset.toString(16)}`);
  return p.join(' · ');
}

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const SEV_HEX = { critical: '#dc2626', high: '#ea580c', medium: '#d97706', low: '#0d9488', info: '#6b7280' };

/** Complete, self-contained HTML report (every problem, every flagged line, every check) */
export function buildHtmlReport(r) {
  const col = (s) => ({ safe: '#16a34a', low: '#0d9488', medium: '#d97706', high: '#ea580c', critical: '#dc2626' }[levelOf(s)]);
  const app = r.categories.filter((c) => c.applicable);
  const cats = app.map((c) => `<tr><td>${esc(c.name)}</td><td style="color:${col(c.score)};font-weight:700">${c.score}/100</td><td>${esc(c.verdict)}</td><td>${c.findings.filter((f) => f.severity !== 'info').length}</td><td>${(c.checks || []).filter((k) => k.ok).length}/${(c.checks || []).length}</td></tr>`).join('');
  const finds = r.findings.map((f) => `<li><b style="color:${SEV_HEX[f.severity]}">[${esc(SEVERITY[f.severity].label)}]</b> ${esc(f.title)} <small>· ${esc(f.category)}${f.where ? ' · ' + esc(f.where) : ''}</small><br><span>${esc(f.detail)}</span>${f.evidence?.length ? `<br><code>${f.evidence.map(esc).join(' | ')}</code>` : ''}</li>`).join('');
  const lines = (r.lines || []).filter((l) => l.sev !== 'info').map((l) => `<tr><td style="white-space:nowrap;color:${SEV_HEX[l.sev]}">${esc(fmtLoc(l))}</td><td><code>${esc(l.text)}</code><br><small>${l.tags.map((t) => esc(t.label)).join(' · ')}</small></td></tr>`).join('');
  const checks = app.map((c) => `<h3>${esc(c.name)}</h3><ul class="chk">${(c.checks || []).map((k) => `<li><b class="${k.ok ? 'ok' : 'ko'}">${k.ok ? 'OK' : 'NO'}</b> ${esc(k.name)}${k.note ? ` <small>(${esc(k.note)})</small>` : ''}</li>`).join('')}</ul>`).join('');
  const hashes = Object.entries(r.file.hashes || {}).map(([k, v]) => `<tr><td>${k.toUpperCase()}</td><td><code>${v}</code></td></tr>`).join('');
  return `<!doctype html><html lang="it"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Report Gauntler – ${esc(r.file.name)}</title>
<style>body{font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;max-width:980px;margin:32px auto;padding:0 16px;color:#111827}h1{margin:0}.score{font-size:56px;font-weight:800;color:${col(r.overall.score)}}table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #e5e7eb;padding:6px 8px;text-align:left;vertical-align:top}li{margin:8px 0}code{background:#f3f4f6;padding:1px 4px;border-radius:4px;word-break:break-all;font-size:12px}small{color:#6b7280}.chk li{margin:2px 0;list-style:none}.chk b{display:inline-block;width:28px;font-size:11px}.chk .ok{color:#15803d}.chk .ko{color:#c2410c}.chk{padding-left:4px}</style></head><body>
<p><small>Report generato da Gauntler ${esc(r.scanner.version)} · ${new Date(r.scannedAt).toLocaleString('it-IT')} · analisi in ${fmtMs(r.durationMs)}</small></p>
<h1>${esc(r.file.name)}</h1><p><small>${esc(r.file.type.label)} · ${esc(r.file.sizeHuman)} · ${esc(r.file.path || (r.file.chain || []).join(' › '))}</small></p>
<div class="score">${r.overall.score}/100 <span style="font-size:24px">${esc(r.overall.verdict)}</span></div><p>${esc(r.overall.advice)}</p>
<p><small>${fmtNum(r.totals.lines || r.totals.strings)} ${r.totals.lines ? 'righe' : 'stringhe'} analizzate · ${fmtNum(r.totals.checks)} controlli (${fmtNum(r.totals.checksFailed)} non superati) · ${fmtNum(r.totals.extracted)} contenuti estratti · ${fmtNum(r.totals.children)} file interni</small></p>
<h2>Punteggi per criterio</h2><table><tr><th>Criterio</th><th>Punteggio</th><th>Esito</th><th>Problemi</th><th>Controlli superati</th></tr>${cats}</table>
<h2>Problemi rilevati (${r.findings.length})</h2><ul>${finds || '<li>Nessuno</li>'}</ul>
<h2>Righe segnalate (${(r.lines || []).filter((l) => l.sev !== 'info').length})</h2><table>${lines || '<tr><td>Nessuna</td></tr>'}</table>
<h2>Controlli eseguiti (${r.totals.checks})</h2>${checks}
<h2>Impronte digitali</h2><table>${hashes}</table></body></html>`;
}
