// Creato da anvex2012
'use strict';
const { m: msg } = require('../i18n');
const { execFile, execFileSync } = require('child_process');
const fs = require('fs');

const CANDIDATES = ['clamscan', '/opt/homebrew/bin/clamscan', '/usr/local/bin/clamscan', '/usr/local/clamav/bin/clamscan', '/usr/bin/clamscan', 'C:\\Program Files\\ClamAV\\clamscan.exe', 'clamdscan', '/opt/homebrew/bin/clamdscan'];
let BIN;
let CHECKED = 0;

/** Signatures downloaded by Gauntler (~/.gauntler/clamav), used in place of the system database */
function ownDatabase() { try { return require('../setup').ownDatabase(); } catch { return null; } }

function findClam() {
  // A missing ClamAV is looked up again after a minute: it may have just been installed (gauntler setup)
  if (BIN || (BIN === null && Date.now() - CHECKED < 60000)) return BIN;
  BIN = null; CHECKED = Date.now();
  for (const c of CANDIDATES) {
    try {
      if (c.includes('/') || c.includes('\\')) { if (fs.existsSync(c)) { BIN = c; break; } }
      else { execFileSync(process.platform === 'win32' ? 'where' : 'which', [c], { stdio: 'ignore' }); BIN = c; break; }
    } catch { /* not found */ }
  }
  return BIN;
}

module.exports = {
  id: 'clamav',
  name: 'Antivirus ClamAV',
  description: 'Scansione con il motore antivirus open-source ClamAV (milioni di firme) con TUTTI i limiti rimossi: dimensione file, ricorsione negli archivi, euristiche, macro, file cifrati e PE danneggiati.',
  weight: 3,
  applies: (ctx) => !!ctx.path && !ctx.virtual && !ctx.options.noClamav,
  available: () => !!findClam(),
  reset: () => { BIN = undefined; },
  run(ctx) {
    const bin = findClam();
    if (!bin) return { skipped: true, reason: 'ClamAV non installato (installalo con: gauntler setup)', findings: [], checks: [{ name: 'Scansione antivirus ClamAV', ok: true, note: 'non installato' }] };
    return new Promise((resolve) => {
      const daemon = /clamdscan/.test(bin);
      const args = daemon ? ['--no-summary', '--stdout', '--fdpass', ctx.path] : [
        '--no-summary', '--stdout', '--infected',
        '--max-filesize=4000M', '--max-scansize=4000M', '--max-files=0', '--max-recursion=64', '--max-dir-recursion=64',
        '--max-embeddedpe=4000M', '--max-htmlnormalize=4000M', '--max-htmlnotags=4000M', '--max-scriptnormalize=4000M', '--max-ziptypercg=4000M',
        '--max-scantime=0', '--pcre-max-filesize=4000M',
        ...(ownDatabase() ? [`--database=${ownDatabase()}`] : []),
        '--heuristic-alerts=yes', '--alert-macros=yes', '--alert-encrypted=yes', '--alert-broken=yes', '--alert-exceeds-max=yes', '--alert-phishing-ssl=yes', '--alert-phishing-cloak=yes', '--alert-partition-intersection=yes',
        '--detect-pua=yes', '--scan-mail=yes', '--scan-archive=yes', '--scan-pdf=yes', '--scan-ole2=yes', '--scan-html=yes', '--scan-pe=yes', '--scan-elf=yes', '--scan-swf=yes', '--scan-xmldocs=yes', '--scan-hwp3=yes',
        ctx.path,
      ];
      execFile(bin, args, { timeout: 30 * 60 * 1000, maxBuffer: 64 * 1024 * 1024 }, (err, stdout, stderr) => {
        const lines = String(stdout || '').split('\n').filter(l => /FOUND$/.test(l));
        if (err && err.code !== 1 && !lines.length && !daemon && /unrecognized|unknown option|invalid option/i.test(String(err.message) + String(stderr || ''))) {
          // Older ClamAV version: retry with the basic options
          return execFile(bin, ['--no-summary', '--stdout', '--infected', '--max-filesize=4000M', '--max-scansize=4000M', '--max-recursion=64', ...(ownDatabase() ? [`--database=${ownDatabase()}`] : []), ctx.path], { timeout: 30 * 60 * 1000, maxBuffer: 64 * 1024 * 1024 }, (e2, out2) => {
            const l2 = String(out2 || '').split('\n').filter((l) => /FOUND$/.test(l));
            resolve({ findings: l2.map((l) => ({ severity: 'critical', title: msg('Virus rilevato: {sig}', { sig: l.replace(/^.*?:\s*/, '').replace(/\s*FOUND$/, '') }), detail: 'Rilevato dal database firme di ClamAV.', forceScore: 1 })), info: { Motore: 'clamscan (opzioni base)' } });
          });
        }
        if (err && err.code !== 1 && !lines.length) return resolve({ skipped: true, reason: msg('Errore ClamAV: {msg}', { msg: String(err.message).slice(0, 120) }), findings: [] });
        const findings = lines.map(l => {
          const sig = l.replace(/^.*?:\s*/, '').replace(/\s*FOUND$/, '');
          const pua = /^(PUA|Heuristics)\./.test(sig);
          return { severity: pua ? 'medium' : 'critical', title: pua ? msg('Software potenzialmente indesiderato: {sig}', { sig }) : msg('Virus rilevato: {sig}', { sig }), detail: 'Rilevato dal database firme di ClamAV.', forceScore: pua ? undefined : (/Eicar/i.test(sig) ? 5 : 1) };
        });
        resolve({ findings, checks: [{ name: 'Scansione antivirus ClamAV (limiti rimossi)', ok: !findings.length, note: findings.length ? msg('{n} rilevamenti', { n: findings.length }) : 'pulito' }], info: { Motore: bin.split(/[\\/]/).pop(), Esito: findings.length ? 'INFETTO' : 'pulito' } });
      });
    });
  },
};
