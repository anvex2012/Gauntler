// Created by anvex2012
'use strict';
const { m: msg } = require('../i18n');
const crypto = require('crypto');
const { shannon } = require('../utils');

const SUSPICIOUS_IMPORTS = {
  'Iniezione in altri processi': ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'CreateRemoteThreadEx', 'NtUnmapViewOfSection', 'ZwUnmapViewOfSection', 'QueueUserAPC', 'SetThreadContext', 'NtWriteVirtualMemory', 'RtlCreateUserThread', 'NtCreateThreadEx', 'NtMapViewOfSection'],
  'Registrazione tasti / spionaggio': ['SetWindowsHookExA', 'SetWindowsHookExW', 'GetAsyncKeyState', 'GetKeyboardState', 'GetKeyState', 'BitBlt', 'GetClipboardData', 'OpenClipboard', 'GetForegroundWindow', 'GetWindowTextW'],
  'Anti-analisi / anti-debug': ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess', 'OutputDebugStringA', 'NtSetInformationThread', 'GetTickCount64', 'QueryPerformanceCounter', 'NtQuerySystemInformation'],
  'Scaricamento da Internet': ['URLDownloadToFileA', 'URLDownloadToFileW', 'InternetOpenUrlA', 'InternetOpenUrlW', 'InternetReadFile', 'WinHttpOpen', 'WinHttpSendRequest', 'HttpSendRequestA', 'HttpSendRequestW', 'InternetConnectA'],
  'Esecuzione di comandi': ['WinExec', 'ShellExecuteA', 'ShellExecuteW', 'ShellExecuteExW', 'CreateProcessA', 'CreateProcessW', 'CreateProcessAsUserW'],
  'Crittografia (possibile ransomware)': ['CryptEncrypt', 'BCryptEncrypt', 'CryptGenKey', 'CryptImportKey', 'CryptAcquireContextW', 'CryptDeriveKey', 'BCryptGenerateSymmetricKey'],
  'Privilegi elevati': ['AdjustTokenPrivileges', 'LookupPrivilegeValueA', 'LookupPrivilegeValueW', 'OpenProcessToken', 'ImpersonateLoggedOnUser', 'DuplicateTokenEx'],
  'Persistenza / servizi': ['RegSetValueExA', 'RegSetValueExW', 'CreateServiceA', 'CreateServiceW', 'RegCreateKeyExW', 'ChangeServiceConfigW'],
  'Caricamento dinamico': ['LoadLibraryA', 'LoadLibraryW', 'LoadLibraryExW', 'GetProcAddress', 'LdrLoadDll', 'LdrGetProcedureAddress'],
  'Accesso a credenziali': ['CryptUnprotectData', 'CredEnumerateW', 'CredReadW', 'LsaRetrievePrivateData', 'SamQueryInformationUser', 'LsaEnumerateLogonSessions'],
  'Enumerazione file e processi': ['FindFirstFileW', 'FindNextFileW', 'CreateToolhelp32Snapshot', 'Process32FirstW', 'Process32NextW', 'EnumProcesses', 'GetLogicalDrives'],
  'Accesso diretto a disco/driver': ['DeviceIoControl', 'NtLoadDriver', 'ZwLoadDriver'],
};
const PACKER_SECTIONS = { UPX0: 'UPX', UPX1: 'UPX', UPX2: 'UPX', '.aspack': 'ASPack', '.adata': 'ASPack', '.nsp0': 'NsPack', '.nsp1': 'NsPack', '.MPRESS1': 'MPRESS', '.MPRESS2': 'MPRESS', '.petite': 'Petite', '.themida': 'Themida', '.winlice': 'WinLicense', '.vmp0': 'VMProtect', '.vmp1': 'VMProtect', '.vmp2': 'VMProtect', '.enigma1': 'Enigma', '.enigma2': 'Enigma', '.packed': 'Generico', pebundle: 'PEBundle', '.perplex': 'Perplex', '.yP': 'Y0da', '.boom': 'Boomerang', '.ccg': 'CCG', '.svkp': 'SVKP', 'kkrunchy': 'kkrunchy', '.taz': 'PESpin', '.spack': 'Simple Pack', '.mew': 'MEW', '.FSG!': 'FSG', '.RLPack': 'RLPack', '.pec': 'PECompact', 'PEC2': 'PECompact', '.MaskPE': 'MaskPE', '.rmnet': 'Ramnit' };
const STD_SECTIONS = new Set(['.text', '.data', '.rdata', '.idata', '.edata', '.pdata', '.rsrc', '.reloc', '.tls', '.bss', '.CRT', '.didat', '.gfids', '.00cfg', '.xdata', '.debug', 'CODE', 'DATA', 'BSS', '.ndata', '.orpc', '.retplne', '.voltbl', '.fptable', '_RDATA', '.textbss', '.msvcjmc', '.rodata', '.init', '.fini', '.eh_fram', '.buildid', '.symtab', '.wixburn', '.sxdata', '.gehcont', 'PAGE', 'INIT', '.edata', '.cfguard']);
const TOOLCHAIN = [
  [/Go build ID: "|runtime\.gopanic|go\.buildid/, 'Go', 'info'], [/rustc\/[0-9a-f]{40}|\/rustc\//, 'Rust', 'info'], [/nimGC|NimMain|@nim\b/, 'Nim', 'low'],
  [/PyInstaller|pyi-runtime-tmpdir|_MEIPASS|MEI\x0c\x0b\x0a\x0b\x0e/, 'Python impacchettato (PyInstaller)', 'low'], [/Nuitka|__compiled__/, 'Python compilato (Nuitka)', 'low'],
  [/AU3!EA06|AutoIt v3|AutoIt3/, 'AutoIt (molto usato da malware)', 'medium'], [/Nullsoft Install System|NSIS Error/, 'Installer NSIS', 'info'], [/Inno Setup/, 'Installer Inno Setup', 'info'],
  [/electron\.asar|Electron Framework/, 'Electron', 'info'], [/Embarcadero|Borland|Delphi/i, 'Delphi', 'info'], [/mingw|GCC: \(GNU\)/, 'GCC/MinGW', 'info'],
  [/ConfuserEx|Confused by|\.NET Reactor|SmartAssembly|Eazfuscator|Babel Obfuscator|dotNetPatcher|Dotfuscator|Agile\.NET|ArmDot|Obfuscar/, 'Offuscatore .NET', 'medium'],
  [/BoxedAppSDK|Enigma Virtual Box/, 'Virtualizzatore di file', 'medium'], [/\bgarble\b/, 'Offuscatore Go (garble)', 'medium'],
];
const VERSION_KEYS = ['CompanyName', 'FileDescription', 'FileVersion', 'InternalName', 'LegalCopyright', 'OriginalFilename', 'ProductName', 'ProductVersion'];

function parsePE(buf) {
  const r = { format: 'PE', sections: [], imports: {}, importCount: 0, exports: [], signed: false, dotnet: false };
  const lf = buf.readUInt32LE(0x3c);
  const coff = lf + 4;
  r.machine = { 0x14c: 'x86', 0x8664: 'x64', 0xaa64: 'ARM64', 0x1c0: 'ARM', 0x200: 'IA64' }[buf.readUInt16LE(coff)] || 'sconosciuta';
  const nsec = buf.readUInt16LE(coff + 2);
  r.timestamp = buf.readUInt32LE(coff + 4);
  const optSize = buf.readUInt16LE(coff + 16);
  r.characteristics = buf.readUInt16LE(coff + 18);
  const opt = coff + 20;
  const is64 = buf.readUInt16LE(opt) === 0x20b;
  r.bits = is64 ? 64 : 32;
  r.linker = `${buf[opt + 2]}.${buf[opt + 3]}`;
  r.entryRva = buf.readUInt32LE(opt + 16);
  r.imageBase = is64 ? '0x' + buf.readBigUInt64LE(opt + 24).toString(16) : '0x' + buf.readUInt32LE(opt + 28).toString(16);
  r.checksum = buf.readUInt32LE(opt + 64);
  r.subsystem = { 1: 'Driver/Nativo', 2: 'GUI (finestre)', 3: 'Console', 9: 'Windows CE', 10: 'EFI' }[buf.readUInt16LE(opt + 68)] || 'altro';
  r.dllChars = buf.readUInt16LE(opt + 70);
  const ddOff = opt + (is64 ? 112 : 96);
  const numDD = buf.readUInt32LE(opt + (is64 ? 108 : 92));
  const dd = (i) => (i < numDD ? { rva: buf.readUInt32LE(ddOff + i * 8), size: buf.readUInt32LE(ddOff + i * 8 + 4) } : { rva: 0, size: 0 });
  const secOff = opt + optSize;
  for (let i = 0; i < nsec && secOff + i * 40 + 40 <= buf.length; i++) {
    const o = secOff + i * 40;
    const name = buf.toString('latin1', o, o + 8).replace(/\0+$/, '');
    const vsize = buf.readUInt32LE(o + 8), va = buf.readUInt32LE(o + 12), rsize = buf.readUInt32LE(o + 16), rptr = buf.readUInt32LE(o + 20), ch = buf.readUInt32LE(o + 36);
    const end = Math.min(buf.length, rptr + rsize);
    r.sections.push({ name, va, vsize, rsize, rptr, ch, entropy: rptr < buf.length && end > rptr ? +shannon(buf, rptr, end).toFixed(2) : 0, exec: !!(ch & 0x20000000), write: !!(ch & 0x80000000), read: !!(ch & 0x40000000) });
  }
  const rva2off = (rva) => {
    for (const s of r.sections) if (rva >= s.va && rva < s.va + Math.max(s.vsize, s.rsize)) return rva - s.va + s.rptr;
    return rva < (r.sections[0]?.rptr || 0x400) ? rva : -1;
  };
  const cstr = (off, max = 256) => (off < 0 || off >= buf.length ? '' : buf.toString('latin1', off, Math.min(buf.length, off + max)).split('\0')[0]);
  r.entrySection = (r.sections.find((s) => r.entryRva >= s.va && r.entryRva < s.va + Math.max(s.vsize, s.rsize)) || {}).name;
  r.signed = dd(4).rva > 0 && dd(4).size > 0;
  r.signatureSize = dd(4).size;
  r.dotnet = dd(14).rva > 0;
  r.tls = dd(9).rva > 0;
  r.resourcesSize = dd(2).size;
  r.relocs = dd(5).size > 0;
  r.debug = dd(6).rva > 0;
  r.cfg = !!(r.dllChars & 0x4000);
  // Imports
  const imp = dd(1);
  let off = imp.rva ? rva2off(imp.rva) : -1;
  for (let n = 0; off > 0 && off + 20 <= buf.length && n < 4096; n++, off += 20) {
    const oft = buf.readUInt32LE(off), nameRva = buf.readUInt32LE(off + 12), ft = buf.readUInt32LE(off + 16);
    if (!nameRva) break;
    const dll = cstr(rva2off(nameRva), 128);
    if (!dll) break;
    const fns = [];
    let to = rva2off(oft || ft);
    for (let k = 0; to > 0 && to + 8 <= buf.length && k < 65536; k++) {
      const v = is64 ? buf.readBigUInt64LE(to) : BigInt(buf.readUInt32LE(to));
      if (!v) break;
      const ordinal = is64 ? (v >> 63n) === 1n : (v & 0x80000000n) !== 0n;
      if (ordinal) fns.push('ord' + Number(v & 0xffffn));
      else { const ho = rva2off(Number(v & 0x7fffffffn)); if (ho > 0) fns.push(cstr(ho + 2, 256)); }
      to += is64 ? 8 : 4;
    }
    r.imports[dll] = (r.imports[dll] || []).concat(fns);
    r.importCount += fns.length;
  }
  // imphash (as in pefile / VirusTotal)
  const parts = [];
  for (const [dll, fns] of Object.entries(r.imports)) {
    const d = dll.toLowerCase().replace(/\.(dll|ocx|sys)$/, '');
    for (const f of fns) parts.push(`${d}.${f.toLowerCase()}`);
  }
  r.imphash = parts.length ? crypto.createHash('md5').update(parts.join(',')).digest('hex') : null;
  // Exports
  const exp = dd(0);
  const eo = exp.rva ? rva2off(exp.rva) : -1;
  if (eo > 0 && eo + 40 <= buf.length) {
    r.exportName = cstr(rva2off(buf.readUInt32LE(eo + 12)), 128);
    const nNames = buf.readUInt32LE(eo + 24), namesOff = rva2off(buf.readUInt32LE(eo + 32));
    for (let i = 0; i < nNames && namesOff > 0 && namesOff + i * 4 + 4 <= buf.length; i++) r.exports.push(cstr(rva2off(buf.readUInt32LE(namesOff + i * 4)), 256));
  }
  const lastEnd = r.sections.reduce((a, s) => Math.max(a, s.rptr + s.rsize), 0);
  r.overlay = lastEnd && buf.length > lastEnd ? buf.length - lastEnd - (r.signed ? r.signatureSize : 0) : 0;
  r.rich = buf.subarray(0x80, lf).includes(Buffer.from('Rich'));
  // Version info (VS_VERSIONINFO, UTF-16)
  r.version = {};
  const u16 = buf.toString('utf16le');
  for (const k of VERSION_KEYS) {
    const m = u16.match(new RegExp(k + '\\u0000+([^\\u0000]{1,200})'));
    if (m) r.version[k] = m[1].trim();
  }
  const pdb = buf.toString('latin1').match(/[A-Za-z]:\\[^\0\n]{3,240}?\.pdb|\/(?:home|Users)\/[^\0\n]{3,240}?\.pdb/);
  if (pdb) r.pdb = pdb[0];
  return r;
}

function parseELF(buf) {
  const r = { format: 'ELF', sections: [], segments: [] };
  const is64 = buf[4] === 2;
  const le = buf[5] === 1;
  r.bits = is64 ? 64 : 32;
  const u16 = (o) => (le ? buf.readUInt16LE(o) : buf.readUInt16BE(o));
  const u32 = (o) => (le ? buf.readUInt32LE(o) : buf.readUInt32BE(o));
  const uN = (o) => (is64 ? Number(le ? buf.readBigUInt64LE(o) : buf.readBigUInt64BE(o)) : u32(o));
  r.osabi = { 0: 'System V', 3: 'Linux', 9: 'FreeBSD', 6: 'Solaris' }[buf[7]] || String(buf[7]);
  r.type = { 1: 'Oggetto rilocabile', 2: 'Eseguibile', 3: 'Libreria condivisa / PIE', 4: 'Core dump' }[u16(16)] || 'altro';
  r.machine = { 3: 'x86', 62: 'x86-64', 40: 'ARM', 183: 'AArch64', 8: 'MIPS', 243: 'RISC-V', 20: 'PowerPC', 21: 'PowerPC64', 2: 'SPARC', 42: 'SuperH' }[u16(18)] || 'altra';
  const phoff = uN(is64 ? 0x20 : 0x1c), shoff = uN(is64 ? 0x28 : 0x20);
  const phentsize = u16(is64 ? 0x36 : 0x2a), phnum = u16(is64 ? 0x38 : 0x2c);
  const shentsize = u16(is64 ? 0x3a : 0x2e), shnum = u16(is64 ? 0x3c : 0x30), shstrndx = u16(is64 ? 0x3e : 0x32);
  for (let i = 0; i < phnum && phoff + (i + 1) * phentsize <= buf.length; i++) {
    const o = phoff + i * phentsize;
    const type = u32(o), flags = is64 ? u32(o + 4) : u32(o + 24);
    const seg = { type: { 1: 'LOAD', 2: 'DYNAMIC', 3: 'INTERP', 4: 'NOTE', 6: 'PHDR', 7: 'TLS', 0x6474e550: 'GNU_EH_FRAME', 0x6474e551: 'GNU_STACK', 0x6474e552: 'GNU_RELRO' }[type] || '0x' + type.toString(16), flags: (flags & 4 ? 'R' : '-') + (flags & 2 ? 'W' : '-') + (flags & 1 ? 'X' : '-') };
    if (type === 3) { const off = uN(o + (is64 ? 8 : 4)), sz = uN(o + (is64 ? 32 : 16)); r.interp = buf.toString('latin1', off, off + sz).replace(/\0.*$/, ''); }
    r.segments.push(seg);
  }
  if (shoff && shnum && shoff + shnum * shentsize <= buf.length) {
    const strO = shoff + shstrndx * shentsize;
    const strOff = uN(strO + (is64 ? 0x18 : 0x10));
    for (let i = 0; i < shnum; i++) {
      const o = shoff + i * shentsize;
      const nameOff = u32(o);
      const off = uN(o + (is64 ? 0x18 : 0x10)), size = uN(o + (is64 ? 0x20 : 0x14));
      const name = buf.toString('latin1', strOff + nameOff, Math.min(buf.length, strOff + nameOff + 64)).split('\0')[0];
      const end = Math.min(buf.length, off + size);
      r.sections.push({ name, size, entropy: off < buf.length && end > off && u32(o + 4) !== 8 ? +shannon(buf, off, end).toFixed(2) : 0 });
    }
  }
  r.stripped = !r.sections.some((s) => s.name === '.symtab');
  r.static = !r.interp && !r.segments.some((s) => s.type === 'DYNAMIC');
  r.noSections = !r.sections.length;
  return r;
}

function parseMachO(buf) {
  const r = { format: 'Mach-O', signed: false, dylibs: [], segments: [], entitlements: [] };
  const magic = buf.readUInt32BE(0);
  const txt = buf.toString('latin1');
  for (const m of txt.matchAll(/<key>(com\.apple\.[\w.-]+)<\/key>\s*<(true|false|string|array)/g)) if (m[2] !== 'false' && !r.entitlements.includes(m[1])) r.entitlements.push(m[1]);
  const cd = buf.indexOf(Buffer.from([0xfa, 0xde, 0x0c, 0x02]));
  if (cd >= 0 && cd + 16 <= buf.length) r.adhoc = !!(buf.readUInt32BE(cd + 12) & 0x2);
  r.teamId = (txt.match(/\x00([A-Z0-9]{10})\x00/) || [])[1];
  if (magic === 0xcafebabe) { r.fat = true; r.archs = buf.readUInt32BE(4); r.signed = buf.includes(Buffer.from([0xfa, 0xde, 0x0c, 0xc0])); return r; }
  const le = magic === 0xcffaedfe || magic === 0xcefaedfe;
  const u32 = (o) => (le ? buf.readUInt32LE(o) : buf.readUInt32BE(o));
  r.bits = magic === 0xcffaedfe || magic === 0xfeedfacf ? 64 : 32;
  r.cpu = { 7: 'x86', 0x01000007: 'x86-64', 12: 'ARM', 0x0100000c: 'ARM64' }[u32(4)] || 'altra';
  r.filetype = { 1: 'Oggetto', 2: 'Eseguibile', 6: 'Libreria dinamica', 8: 'Bundle', 7: 'Linker dinamico' }[u32(12)] || 'altro';
  const ncmds = u32(16);
  let off = r.bits === 64 ? 32 : 28;
  for (let i = 0; i < ncmds && off + 8 <= buf.length; i++) {
    const cmd = u32(off), size = u32(off + 4);
    if (cmd === 0x1d) r.signed = true;
    if ([0xc, 0x80000018, 0xd, 0x8000001f, 0x80000023].includes(cmd) && off + 24 < buf.length) {
      const so = u32(off + 8);
      r.dylibs.push(buf.toString('latin1', off + so, Math.min(buf.length, off + size)).split('\0')[0]);
    }
    if (cmd === 0x19 || cmd === 0x1) r.segments.push(buf.toString('latin1', off + 8, off + 24).replace(/\0+$/, ''));
    if (cmd === 0x80000028) r.hasMain = true;
    if (cmd === 0x2c || cmd === 0x21) r.encrypted = u32(off + 16) !== 0;
    if (size < 8) break;
    off += size;
  }
  return r;
}

module.exports = {
  id: 'executable',
  name: 'Analisi eseguibile',
  description: 'Analisi strutturale completa di programmi Windows (PE/.NET), Linux (ELF) e macOS (Mach-O): firma digitale, imphash, informazioni di versione, impersonificazione, packer e offuscatori, sezioni/segmenti con entropia, API importate ed esportate, protezioni (ASLR, DEP, CFG), TLS, overlay, percorsi PDB, entitlement.',
  weight: 2,
  applies: (ctx) => ['pe', 'dll', 'elf', 'macho'].includes(ctx.type.id),
  run(ctx) {
    const out = [];
    const checks = [];
    const C = (name, ok, note) => checks.push({ name, ok, note });
    const buf = ctx.buffer;
    const info = {};
    let p;
    try {
      p = ctx.type.id === 'elf' ? parseELF(buf) : ctx.type.id === 'macho' ? parseMachO(buf) : parsePE(buf);
    } catch (e) {
      out.push({ severity: 'medium', title: 'Struttura dell\'eseguibile danneggiata', detail: 'Intestazioni non valide: possibile manomissione o tecnica anti-analisi.' });
      return { findings: out, checks: [{ name: 'Intestazioni valide', ok: false, note: e.message }], info };
    }
    C('Intestazioni del formato valide', true);
    const text = ctx.text;
    const techs = [];
    for (const [re, label, sev] of TOOLCHAIN) {
      if (re.test(text)) {
        techs.push(label);
        info['Tecnologia'] = msg('{list}', { list: techs });
        if (sev !== 'info') out.push({ severity: sev, title: msg('Rilevato: {label}', { label }), detail: sev === 'medium' ? 'Strumento molto usato per nascondere il codice dei malware.' : 'Programma impacchettato: il codice reale è contenuto all\'interno.' });
      }
    }

    if (p.format === 'PE') {
      const v = p.version;
      Object.assign(info, {
        Formato: msg('PE {bits}-bit ({machine})', { bits: p.bits, machine: p.machine }), Sottosistema: p.subsystem, '.NET': p.dotnet ? 'sì' : 'no', 'Firma digitale': p.signed ? msg('presente ({n} byte)', { n: p.signatureSize }) : 'assente',
        'Funzioni importate': p.importCount, 'DLL importate': Object.keys(p.imports).length, 'Funzioni esportate': p.exports.length, imphash: p.imphash || '-', Linker: p.linker, 'Image base': p.imageBase,
        'Data compilazione': p.timestamp ? new Date(p.timestamp * 1000).toISOString().slice(0, 19).replace('T', ' ') : 'azzerata',
      });
      for (const k of VERSION_KEYS) if (v[k]) info[k] = v[k];
      if (p.pdb) info['Percorso PDB'] = p.pdb;

      C('Firma digitale Authenticode presente', p.signed);
      if (!p.signed) out.push({ severity: 'medium', title: 'Programma senza firma digitale', detail: 'Non è possibile verificare chi ha creato il programma. I software legittimi sono quasi sempre firmati.' });
      else out.push({ severity: 'info', title: 'Firma digitale presente', detail: 'Il file contiene una firma Authenticode (la validità del certificato non è verificata offline).' });
      const claimsMs = /microsoft/i.test((v.CompanyName || '') + (v.LegalCopyright || '') + (v.ProductName || ''));
      C('Non si spaccia per software Microsoft senza firma', !(claimsMs && !p.signed));
      if (claimsMs && !p.signed) out.push({ severity: 'high', title: 'Si spaccia per software Microsoft ma non è firmato', detail: 'Le informazioni di versione dichiarano Microsoft, ma i programmi Microsoft sono sempre firmati: tipico dei malware che si camuffano.', evidence: [v.CompanyName, v.FileDescription].filter(Boolean) });
      const orig = (v.OriginalFilename || '').replace(/\.mui$/i, '');
      const renamed = orig && orig.toLowerCase() !== ctx.name.toLowerCase() && !ctx.virtual;
      C('Nome originale uguale al nome attuale', !renamed, orig || 'n/d');
      if (renamed) out.push({ severity: /^(psexec|procdump|rclone|anydesk|nc|ncat|plink|mimikatz|rubeus|7z|winrar|certutil|cmd|powershell)/i.test(orig) ? 'high' : 'low', title: 'Programma rinominato', detail: msg('Il nome originale era "{orig}". I malware e gli attaccanti rinominano gli strumenti per nasconderli.', { orig }) });
      const fakeSys = /^(svchost|lsass|csrss|winlogon|services|smss|explorer|rundll32|dllhost|spoolsv|taskhostw?|conhost|wininit)\.exe$/i.test(ctx.name) && !p.signed;
      C('Non imita processi di sistema Windows', !fakeSys);
      if (fakeSys) out.push({ severity: 'critical', title: 'Imita un processo di sistema di Windows', detail: msg('"{name}" è il nome di un componente di Windows, ma questo file non è firmato.', { name: ctx.name }) });

      const future = p.timestamp > Date.now() / 1000 + 86400;
      C('Data di compilazione plausibile', !future && !(p.timestamp && p.timestamp < 631152000 && !p.dotnet), info['Data compilazione']);
      if (future) out.push({ severity: 'medium', title: 'Data di compilazione nel futuro', detail: 'Il timestamp è stato falsificato.' });
      else if (p.timestamp && p.timestamp < 631152000 && !p.dotnet) out.push({ severity: 'low', title: 'Data di compilazione anomala', detail: msg('Data: {date} (possibile falsificazione).', { date: info['Data compilazione'] }) });

      const packers = new Set(p.sections.map((s) => PACKER_SECTIONS[s.name]).filter(Boolean));
      C('Nessun packer/protettore noto', !packers.size, [...packers].join(', '));
      if (packers.size) out.push({ severity: 'high', title: msg('Compresso con packer: {list}', { list: [...packers] }), detail: 'Il codice è compresso/cifrato per nascondere il contenuto reale.' });
      const odd = p.sections.filter((s) => !STD_SECTIONS.has(s.name) && !PACKER_SECTIONS[s.name]);
      C('Nomi di sezione standard', !odd.length, odd.map((s) => s.name).join(', '));
      if (odd.length) out.push({ severity: 'low', title: 'Sezioni con nomi insoliti', detail: 'Nomi di sezione non standard (packer o compilatori rari).', evidence: odd.map((s) => JSON.stringify(s.name)) });
      const highEnt = p.sections.filter((s) => s.entropy > 7.2 && s.rsize > 1024 && s.name !== '.rsrc');
      C('Sezioni non cifrate (entropia ≤ 7.2)', !highEnt.length);
      if (highEnt.length && !packers.size) out.push({ severity: 'medium', title: 'Sezioni con dati cifrati o compressi', detail: 'Entropia molto alta: possibile codice nascosto.', evidence: highEnt.map((s) => `${s.name}: ${s.entropy}`) });
      const wx = p.sections.filter((s) => s.exec && s.write);
      C('Nessuna sezione scrivibile + eseguibile', !wx.length);
      if (wx.length) out.push({ severity: 'high', title: 'Sezioni scrivibili ed eseguibili', detail: 'Il codice può modificarsi da solo (tipico di malware e packer).', evidence: wx.map((s) => s.name) });
      const virt = p.sections.filter((s) => s.rsize === 0 && s.vsize > 0x10000 && s.exec);
      if (virt.length) out.push({ severity: 'medium', title: 'Sezione eseguibile vuota su disco', detail: 'Verrà riempita in memoria a runtime (tipico dei packer).', evidence: virt.map((s) => s.name) });
      const epOk = !p.entrySection || /^(\.text|CODE|\.code|\.init|INIT|\.textbss|PAGE)$/i.test(p.entrySection);
      C('Punto di avvio nella sezione di codice', epOk && !(!p.entrySection && p.entryRva), p.entrySection || '-');
      if (!epOk) out.push({ severity: 'medium', title: 'Punto di avvio in sezione insolita', detail: msg('L\'esecuzione parte dalla sezione "{name}" invece di ".text".', { name: p.entrySection }) });
      if (!p.entrySection && p.entryRva && ctx.type.id === 'pe') out.push({ severity: 'high', title: 'Punto di avvio fuori dalle sezioni', detail: 'Struttura manipolata.' });
      const fewImp = !p.dotnet && p.importCount > 0 && p.importCount < 10;
      C('Tabella import completa (≥ 10 funzioni)', !fewImp && !(p.importCount === 0 && !p.dotnet), `${p.importCount}`);
      if (fewImp) out.push({ severity: 'medium', title: 'Pochissime funzioni importate', detail: msg('Solo {n} importazioni: tipico di programmi impacchettati che caricano il codice a runtime.', { n: p.importCount }), evidence: Object.values(p.imports).flat().slice(0, 10) });
      if (!p.dotnet && p.importCount === 0 && ctx.type.id === 'pe') out.push({ severity: 'medium', title: 'Nessuna tabella di import', detail: 'Il programma nasconde le funzioni che usa.' });
      C('Nessun callback TLS', !p.tls);
      if (p.tls) out.push({ severity: 'low', title: 'Callback TLS', detail: 'Codice eseguito prima del punto di avvio (tecnica anti-debug, ma usata anche da programmi legittimi).' });
      const bigOverlay = p.overlay > 1024 * 1024 && p.overlay > buf.length * 0.5;
      C('Nessun grande blocco di dati in coda (overlay)', !bigOverlay, `${Math.round(p.overlay / 1024)} KB`);
      if (bigOverlay && !p.signed) out.push({ severity: 'low', title: 'Grandi dati in coda al file (overlay)', detail: msg('{n} KB aggiunti dopo il programma (installer o payload nascosto).', { n: Math.round(p.overlay / 1024) }) });
      C('ASLR attivo', !!(p.dllChars & 0x40)); C('DEP/NX attivo', !!(p.dllChars & 0x100)); C('Control Flow Guard', p.cfg); C('Rich header presente (compilatore Microsoft)', p.rich);
      if (!(p.dllChars & 0x40)) out.push({ severity: 'low', title: 'ASLR disattivato', detail: 'Protezione di sicurezza della memoria assente.' });
      if (!(p.dllChars & 0x100)) out.push({ severity: 'low', title: 'DEP/NX disattivato', detail: 'Protezione contro l\'esecuzione di dati assente.' });
      if (p.pdb && /\\(users|documents and settings)\\[^\\]+\\/i.test(p.pdb)) out.push({ severity: 'info', title: 'Percorso di compilazione con nome utente', detail: 'Il programma rivela il computer dello sviluppatore.', evidence: [p.pdb] });

      const allFns = new Set(Object.values(p.imports).flat());
      let groupsHit = 0;
      for (const [group, fns] of Object.entries(SUSPICIOUS_IMPORTS)) {
        const hit = fns.filter((f) => allFns.has(f));
        const minHits = group === 'Caricamento dinamico' || group === 'Esecuzione di comandi' || group === 'Enumerazione file e processi' ? 99 : 2;
        const triggered = hit.length >= Math.min(minHits, fns.length);
        C(msg('API: {group}', { group }), !triggered, hit.length ? hit.join(', ') : 'nessuna');
        if (triggered) {
          groupsHit++;
          const sev = /Iniezione|tasti|credenziali|disco/.test(group) ? 'high' : 'low';
          out.push({ severity: sev, title: msg('Funzioni di sistema: {group}', { group }), detail: 'API importate associate a comportamenti sospetti.', evidence: hit });
        }
      }
      C('Combinazione di capacità rischiose (< 4 categorie)', groupsHit < 4, `${groupsHit}`);
      if (groupsHit >= 4) out.push({ severity: 'high', title: 'Combinazione di capacità sospette', detail: msg('{n} categorie di API rischiose nello stesso programma.', { n: groupsHit }) });
      return { findings: out, checks, info, extra: { executable: { format: 'PE', sections: p.sections, imports: p.imports, exports: p.exports, version: v, imphash: p.imphash } } };
    }

    if (p.format === 'ELF') {
      Object.assign(info, { Formato: msg('ELF {bits}-bit ({machine})', { bits: p.bits, machine: p.machine }), Tipo: p.type, ABI: p.osabi, Interprete: p.interp || '-', Simboli: p.stripped ? 'rimossi' : 'presenti', Linking: p.static ? 'statico' : 'dinamico', Sezioni: p.sections.length, Segmenti: p.segments.map((s) => `${s.type}[${s.flags}]`).join(' ') });
      const rwx = p.segments.filter((s) => s.type === 'LOAD' && s.flags === 'RWX');
      C('Nessun segmento RWX', !rwx.length);
      if (rwx.length) out.push({ severity: 'high', title: 'Segmento leggibile, scrivibile ed eseguibile', detail: 'Codice automodificante (tipico di packer e malware).' });
      const xstack = p.segments.find((s) => s.type === 'GNU_STACK' && s.flags.includes('X'));
      C('Stack non eseguibile', !xstack);
      if (xstack) out.push({ severity: 'medium', title: 'Stack eseguibile', detail: 'Protezione NX disattivata.' });
      C('Tabella delle sezioni presente', !p.noSections);
      if (p.noSections) out.push({ severity: 'medium', title: 'Tabella delle sezioni rimossa', detail: 'Struttura alterata per ostacolare l\'analisi.' });
      C('Binario non statico e senza simboli', !(p.stripped && p.static));
      if (p.stripped && p.static) out.push({ severity: 'low', title: 'Binario statico senza simboli', detail: 'Comune nei malware Linux/IoT (ma anche in alcuni tool legittimi).' });
      const upx = text.includes('UPX!');
      C('Non compresso con UPX', !upx);
      if (upx) out.push({ severity: 'high', title: 'Compresso con UPX', detail: 'Eseguibile impacchettato.' });
      const highEnt = p.sections.filter((s) => s.entropy > 7.2 && s.size > 1024);
      if (highEnt.length) out.push({ severity: 'medium', title: 'Sezioni cifrate', detail: 'Entropia molto alta.', evidence: highEnt.map((s) => `${s.name}: ${s.entropy}`) });
      if (/mips|arm|superh|powerpc/i.test(p.machine) && p.static) out.push({ severity: 'low', title: 'Binario per dispositivi IoT/router', detail: 'Architettura tipica delle botnet IoT (Mirai, Gafgyt).' });
      return { findings: out, checks, info, extra: { executable: { format: 'ELF', sections: p.sections, segments: p.segments } } };
    }

    Object.assign(info, { Formato: p.fat ? msg('Mach-O universale ({n} architetture)', { n: p.archs }) : msg('Mach-O {bits}-bit ({cpu})', { bits: p.bits, cpu: p.cpu }), Tipo: p.filetype || '-', 'Firma codice': p.signed ? (p.adhoc ? 'ad-hoc (senza sviluppatore)' : 'presente') : 'assente', 'Team ID': p.teamId || '-', Librerie: (p.dylibs || []).length, Entitlement: p.entitlements.length });
    C('Firma del codice presente', p.signed);
    if (!p.signed) out.push({ severity: 'medium', title: 'App macOS non firmata', detail: 'Gatekeeper bloccherà l\'esecuzione: provenienza non verificabile.' });
    C('Firma di uno sviluppatore (non ad-hoc)', !p.adhoc);
    if (p.adhoc) out.push({ severity: 'medium', title: 'Firma ad-hoc', detail: 'Il programma è firmato senza un certificato sviluppatore Apple (comune nei malware per Mac).' });
    const weird = (p.dylibs || []).filter((d) => /^(\/tmp|\/private\/tmp|\/Users\/Shared|@executable_path\/\.\.|\/var\/folders)/.test(d));
    C('Librerie da percorsi di sistema', !weird.length);
    if (weird.length) out.push({ severity: 'medium', title: 'Librerie caricate da percorsi insoliti', detail: 'Possibile dylib hijacking.', evidence: weird });
    const risky = p.entitlements.filter((e) => /disable-library-validation|allow-unsigned-executable-memory|allow-dyld-environment-variables|disable-executable-page-protection|get-task-allow|cs\.debugger/.test(e));
    C('Nessun entitlement che disattiva protezioni', !risky.length);
    if (risky.length) out.push({ severity: 'medium', title: 'Entitlement che indeboliscono la sicurezza', detail: 'L\'app chiede di disattivare protezioni di macOS.', evidence: risky });
    const sensitive = p.entitlements.filter((e) => /device\.camera|device\.microphone|personal-information|automation\.apple-events|files\.all|network\.server/.test(e));
    if (sensitive.length) out.push({ severity: 'info', title: 'Permessi sensibili richiesti', detail: 'Accesso a fotocamera, microfono, dati personali o automazione.', evidence: sensitive });
    if (p.encrypted) out.push({ severity: 'info', title: 'Binario cifrato (FairPlay)', detail: 'App dell\'App Store cifrata.' });
    return { findings: out, checks, info, extra: { executable: { format: 'Mach-O', dylibs: p.dylibs, segments: p.segments, entitlements: p.entitlements } } };
  },
};
