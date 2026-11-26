// Creato da anvex2012
'use strict';
const { m: msg } = require('../i18n');
const { lookup } = require('../online');

module.exports = {
  id: 'reputation',
  name: 'Reputazione online',
  description: 'Su richiesta (--online), confronta l\'impronta SHA-256 con VirusTotal (70+ antivirus) e MalwareBazaar. Viene inviata SOLO l\'impronta, mai il contenuto del file.',
  weight: 3,
  applies: (ctx) => !!ctx.options.online && ctx.depth === 0,
  async run(ctx) {
    const keys = ctx.options.onlineKeys || {};
    const res = await lookup(ctx.hashes.sha256, keys);
    const out = [], checks = [], info = {};
    for (const r of res) {
      if (r.skipped) { checks.push({ name: `${r.service}`, ok: true, note: 'non configurato' }); info[r.service] = 'non configurato'; continue; }
      if (r.error) { checks.push({ name: `${r.service}`, ok: true, note: msg('errore: {msg}', { msg: r.error }) }); info[r.service] = msg('errore: {msg}', { msg: r.error }); continue; }
      if (r.service === 'VirusTotal') {
        if (!r.found) { info.VirusTotal = 'impronta mai vista'; checks.push({ name: 'VirusTotal', ok: true, note: 'sconosciuto' }); out.push({ severity: 'info', title: 'File sconosciuto a VirusTotal', detail: 'Nessuno ha mai caricato questo file: non è necessariamente sicuro, ma non è un malware diffuso.' }); continue; }
        info.VirusTotal = msg('{a}/{b} antivirus lo rilevano', { a: r.malicious, b: r.engines });
        if (r.label) info['Classificazione VT'] = r.label;
        if (r.firstSeen) info['Visto per la prima volta'] = r.firstSeen;
        checks.push({ name: 'VirusTotal: nessun antivirus lo rileva', ok: !r.malicious, note: `${r.malicious}/${r.engines}` });
        if (r.malicious >= 5) out.push({ severity: 'critical', title: msg('{a} antivirus su {b} lo rilevano come malware', { a: r.malicious, b: r.engines }), detail: r.label ? msg('VirusTotal — classificazione: {label}.', { label: r.label }) : 'VirusTotal.', evidence: [...r.names.slice(0, 6), r.link], forceScore: Math.max(1, 15 - r.malicious) });
        else if (r.malicious >= 1) out.push({ severity: 'high', title: msg('{a} antivirus su {b} lo rilevano', { a: r.malicious, b: r.engines }), detail: 'Pochi rilevamenti: possibile malware nuovo o falso positivo.', evidence: [...r.names.slice(0, 6), r.link] });
        else if (r.suspicious) out.push({ severity: 'medium', title: msg('{n} antivirus lo considerano sospetto', { n: r.suspicious }), detail: 'VirusTotal.', evidence: [r.link] });
        else out.push({ severity: 'info', title: msg('Nessuno dei {n} antivirus lo rileva', { n: r.engines }), detail: 'VirusTotal.', evidence: [r.link] });
      } else {
        checks.push({ name: 'MalwareBazaar: non presente nel database di malware', ok: !r.found });
        info.MalwareBazaar = r.found ? msg('malware noto: {sig}', { sig: r.signature || 'sì' }) : 'non presente';
        if (r.found) out.push({ severity: 'critical', title: r.signature ? msg('Campione di malware noto: {sig}', { sig: r.signature }) : 'Campione di malware noto', detail: r.firstSeen ? msg('Presente nel database MalwareBazaar (abuse.ch) dal {date}.', { date: r.firstSeen }) : 'Presente nel database MalwareBazaar (abuse.ch).', evidence: [...(r.tags || []), r.link], forceScore: 1 });
      }
    }
    return { findings: out, checks, info, extra: { reputation: res } };
  },
};
