// Creato da anvex2012
'use strict';
const { isLikelyText } = require('./utils');

const starts = (buf, bytes, off = 0) => bytes.every((b, i) => buf[off + i] === b);
const ascii = (buf, s, off = 0) => buf.length >= off + s.length && buf.toString('latin1', off, off + s.length) === s;

/**
 * Detects the real file type from its "magic bytes" (ignoring the extension).
 * Returns { id, label, family, mime }
 */
function detectType(buf, name = '') {
  const T = (id, label, family, mime = 'application/octet-stream') => ({ id, label, family, mime });
  if (buf.length < 2) return T('empty', 'File vuoto o minuscolo', 'unknown');

  if (starts(buf, [0x4d, 0x5a])) {
    const lf = buf.length > 0x40 ? buf.readUInt32LE(0x3c) : 0;
    if (lf && lf + 24 < buf.length && ascii(buf, 'PE\0\0', lf)) {
      const ch = buf.readUInt16LE(lf + 22);
      return (ch & 0x2000) ? T('dll', 'Libreria Windows (DLL)', 'executable', 'application/x-msdownload')
        : T('pe', 'Eseguibile Windows (PE)', 'executable', 'application/x-msdownload');
    }
    return T('mz', 'Eseguibile DOS/MZ', 'executable');
  }
  if (starts(buf, [0x7f, 0x45, 0x4c, 0x46])) return T('elf', 'Eseguibile Linux (ELF)', 'executable', 'application/x-elf');
  const m32 = buf.length >= 4 ? buf.readUInt32BE(0) : 0;
  if ([0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe].includes(m32)) return T('macho', 'Eseguibile macOS (Mach-O)', 'executable', 'application/x-mach-binary');
  if (m32 === 0xcafebabe) {
    const n = buf.readUInt32BE(4);
    return n > 0 && n < 20 ? T('macho', 'Eseguibile macOS universale (Mach-O fat)', 'executable')
      : T('class', 'Classe Java compilata', 'executable', 'application/java-vm');
  }
  if (ascii(buf, 'dex\n')) return T('dex', 'Bytecode Android (DEX)', 'executable');
  if (ascii(buf, '%PDF')) return T('pdf', 'Documento PDF', 'document', 'application/pdf');
  if (starts(buf, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])) return T('ole', 'Documento Office legacy / MSI (OLE)', 'document', 'application/x-ole-storage');
  if (ascii(buf, '{\\rt')) return T('rtf', 'Documento RTF', 'document', 'application/rtf');
  if (starts(buf, [0x50, 0x4b, 0x03, 0x04]) || starts(buf, [0x50, 0x4b, 0x05, 0x06])) {
    const head = buf.toString('latin1', 0, Math.min(buf.length, 65536));
    const tail = buf.toString('latin1', Math.max(0, buf.length - 65536));
    const all = head + tail;
    if (all.includes('AndroidManifest.xml')) return T('apk', 'App Android (APK)', 'archive', 'application/vnd.android.package-archive');
    if (all.includes('word/')) return T('docx', 'Documento Word (OOXML)', 'document');
    if (all.includes('xl/')) return T('xlsx', 'Foglio Excel (OOXML)', 'document');
    if (all.includes('ppt/')) return T('pptx', 'Presentazione PowerPoint (OOXML)', 'document');
    if (all.includes('META-INF/MANIFEST.MF')) return T('jar', 'Archivio Java (JAR)', 'archive', 'application/java-archive');
    if (all.includes('mimetypeapplication/vnd.oasis')) return T('odf', 'Documento OpenDocument', 'document');
    return T('zip', 'Archivio ZIP', 'archive', 'application/zip');
  }
  if (ascii(buf, 'Rar!')) return T('rar', 'Archivio RAR', 'archive', 'application/vnd.rar');
  if (starts(buf, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])) return T('7z', 'Archivio 7-Zip', 'archive', 'application/x-7z-compressed');
  if (starts(buf, [0x1f, 0x8b])) return T('gzip', 'Archivio GZIP', 'archive', 'application/gzip');
  if (ascii(buf, 'BZh')) return T('bzip2', 'Archivio BZIP2', 'archive');
  if (starts(buf, [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00])) return T('xz', 'Archivio XZ', 'archive');
  if (buf.length > 262 && ascii(buf, 'ustar', 257)) return T('tar', 'Archivio TAR', 'archive', 'application/x-tar');
  if (buf.length > 0x8006 && ascii(buf, 'CD001', 0x8001)) return T('iso', 'Immagine disco ISO', 'archive');
  if (ascii(buf, 'koly', Math.max(0, buf.length - 512))) return T('dmg', 'Immagine disco macOS (DMG)', 'archive');
  if (ascii(buf, 'MSCF')) return T('cab', 'Archivio CAB', 'archive');
  if (ascii(buf, 'xar!')) return T('xar', 'Pacchetto installer macOS (PKG/XAR)', 'archive');
  if (ascii(buf, 'ITSF')) return T('chm', 'Guida compilata Windows (CHM)', 'document');
  if (starts(buf, [0xe4, 0x52, 0x5c, 0x7b, 0x8c, 0xd8, 0xa7, 0x4d])) return T('one', 'Documento OneNote', 'document');
  if (ascii(buf, 'conectix') || ascii(buf, 'vhdxfile')) return T('vhd', 'Disco virtuale (VHD/VHDX)', 'archive');
  if (buf.length > 16 && buf[2] === 0x0d && buf[3] === 0x0a && buf[1] < 0x10) return T('pyc', 'Bytecode Python (.pyc)', 'executable');
  if (starts(buf, [0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00])) return T('lnk', 'Collegamento Windows (LNK)', 'shortcut');

  if (starts(buf, [0x89, 0x50, 0x4e, 0x47])) return T('png', 'Immagine PNG', 'media', 'image/png');
  if (starts(buf, [0xff, 0xd8, 0xff])) return T('jpeg', 'Immagine JPEG', 'media', 'image/jpeg');
  if (ascii(buf, 'GIF8')) return T('gif', 'Immagine GIF', 'media', 'image/gif');
  if (ascii(buf, 'RIFF') && ascii(buf, 'WEBP', 8)) return T('webp', 'Immagine WebP', 'media', 'image/webp');
  if (ascii(buf, 'RIFF') && ascii(buf, 'WAVE', 8)) return T('wav', 'Audio WAV', 'media', 'audio/wav');
  if (ascii(buf, 'RIFF') && ascii(buf, 'AVI ', 8)) return T('avi', 'Video AVI', 'media', 'video/x-msvideo');
  if (ascii(buf, 'BM') && buf.length > 14 && buf.readUInt32LE(2) === buf.length) return T('bmp', 'Immagine BMP', 'media', 'image/bmp');
  if (ascii(buf, 'ftyp', 4)) {
    const brand = buf.toString('latin1', 8, 12);
    if (/heic|heix|mif1/.test(brand)) return T('heic', 'Immagine HEIC', 'media', 'image/heic');
    return T('mp4', 'Video/Audio MP4/MOV', 'media', 'video/mp4');
  }
  if (ascii(buf, 'ID3') || starts(buf, [0xff, 0xfb])) return T('mp3', 'Audio MP3', 'media', 'audio/mpeg');
  if (ascii(buf, 'OggS')) return T('ogg', 'Audio/Video OGG', 'media', 'audio/ogg');
  if (ascii(buf, 'fLaC')) return T('flac', 'Audio FLAC', 'media', 'audio/flac');
  if (starts(buf, [0x1a, 0x45, 0xdf, 0xa3])) return T('mkv', 'Video Matroska/WebM', 'media', 'video/x-matroska');
  if (ascii(buf, 'SQLite format 3')) return T('sqlite', 'Database SQLite', 'data', 'application/vnd.sqlite3');
  if (starts(buf, [0x00, 0x61, 0x73, 0x6d])) return T('wasm', 'WebAssembly', 'executable', 'application/wasm');
  if (ascii(buf, '\x03\xd9\xa2\x9a')) return T('kdbx', 'Database KeePass', 'data');

  if (isLikelyText(buf)) {
    const head = buf.toString('utf8', 0, Math.min(buf.length, 4096));
    const h = head.trimStart().toLowerCase();
    if (h.startsWith('#!')) {
      const line = h.split('\n')[0];
      if (/python/.test(line)) return T('python', 'Script Python', 'script', 'text/x-python');
      if (/node/.test(line)) return T('javascript', 'Script Node.js', 'script', 'text/javascript');
      if (/perl/.test(line)) return T('perl', 'Script Perl', 'script');
      if (/ruby/.test(line)) return T('ruby', 'Script Ruby', 'script');
      return T('shell', 'Script Shell', 'script', 'text/x-shellscript');
    }
    if (/^(received|return-path|from|delivered-to|mime-version|x-[\w-]+|message-id|dkim-signature|date|subject|to|arc-[\w-]+|authentication-results):/m.test(h.slice(0, 600)) && /\n(from|subject|to|date):/i.test(h)) return T('eml', 'Email (EML/MIME)', 'text', 'message/rfc822');
    if (h.startsWith('<?php') || /<\?php/.test(h)) return T('php', 'Script PHP', 'script', 'application/x-php');
    if (h.startsWith('<svg') || (h.startsWith('<?xml') && h.includes('<svg'))) return T('svg', 'Immagine SVG', 'markup', 'image/svg+xml');
    if (h.startsWith('<!doctype html') || h.startsWith('<html') || /<(script|body|iframe|head)[\s>]/.test(h)) return T('html', 'Pagina HTML', 'markup', 'text/html');
    if (h.startsWith('<?xml')) return T('xml', 'Documento XML', 'text', 'application/xml');
    if (h.startsWith('{') || h.startsWith('[')) return T('json', 'Dati JSON / testo', 'text', 'application/json');
    const ext = (name.split('.').pop() || '').toLowerCase();
    const scriptExt = { ps1: 'PowerShell', psm1: 'PowerShell', bat: 'Batch', cmd: 'Batch', vbs: 'VBScript', vbe: 'VBScript', js: 'JavaScript', jse: 'JScript', mjs: 'JavaScript', cjs: 'JavaScript', ts: 'TypeScript', py: 'Python', sh: 'Shell', bash: 'Shell', zsh: 'Shell', rb: 'Ruby', pl: 'Perl', hta: 'HTA', wsf: 'Windows Script', applescript: 'AppleScript', scpt: 'AppleScript', lua: 'Lua', go: 'Go', java: 'Java', c: 'C', cpp: 'C++', cs: 'C#', rs: 'Rust', swift: 'Swift', kt: 'Kotlin', psd1: 'PowerShell' };
    if (scriptExt[ext]) return T('script-' + ext, 'Script ' + scriptExt[ext], 'script', 'text/plain');
    if (/powershell|invoke-expression|\$env:|new-object\s+net\.webclient/i.test(head)) return T('script-ps1', 'Script PowerShell (rilevato)', 'script');
    if (/^@echo off/im.test(head)) return T('script-bat', 'Script Batch (rilevato)', 'script');
    return T('text', 'Testo', 'text', 'text/plain');
  }
  return T('binary', 'Dati binari sconosciuti', 'unknown');
}

/** Which real types are compatible with each extension */
const EXT_EXPECT = {
  exe: ['pe', 'mz'], dll: ['dll', 'pe'], sys: ['pe', 'dll'], scr: ['pe'], com: ['mz', 'pe', 'binary'],
  pdf: ['pdf'], doc: ['ole', 'rtf'], xls: ['ole'], ppt: ['ole'], msi: ['ole'],
  docx: ['docx', 'zip'], xlsx: ['xlsx', 'zip'], pptx: ['pptx', 'zip'], docm: ['docx', 'zip'], xlsm: ['xlsx', 'zip'], pptm: ['pptx', 'zip'],
  odt: ['odf', 'zip'], ods: ['odf', 'zip'], odp: ['odf', 'zip'],
  zip: ['zip', 'docx', 'xlsx', 'pptx', 'jar', 'apk', 'odf'], jar: ['jar', 'zip'], apk: ['apk', 'zip'], rar: ['rar'], '7z': ['7z'],
  gz: ['gzip'], tgz: ['gzip'], bz2: ['bzip2'], xz: ['xz'], tar: ['tar'], iso: ['iso'], dmg: ['dmg', 'binary', 'bzip2', 'zip'], cab: ['cab'],
  png: ['png'], jpg: ['jpeg'], jpeg: ['jpeg'], gif: ['gif'], webp: ['webp'], bmp: ['bmp'], heic: ['heic'],
  mp4: ['mp4'], mov: ['mp4'], m4a: ['mp4'], mp3: ['mp3'], wav: ['wav'], ogg: ['ogg'], flac: ['flac'], mkv: ['mkv'], webm: ['mkv'], avi: ['avi'],
  rtf: ['rtf'], lnk: ['lnk'], pkg: ['xar'], chm: ['chm'], one: ['one'], vhd: ['vhd'], vhdx: ['vhd'], pyc: ['pyc'], eml: ['eml', 'text'], sqlite: ['sqlite'], db: ['sqlite', 'binary'], wasm: ['wasm'], kdbx: ['kdbx'], class: ['class'], dex: ['dex'],
};

const DANGEROUS_EXT = new Set(['exe', 'scr', 'pif', 'com', 'bat', 'cmd', 'ps1', 'psm1', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh', 'hta', 'lnk', 'msi', 'msp', 'dll', 'cpl', 'jar', 'apk', 'reg', 'sct', 'inf', 'scf', 'iso', 'img', 'vhd', 'vhdx', 'chm', 'appx', 'msix', 'app', 'command', 'workflow', 'pkg', 'dmg', 'sh', 'elf', 'xll', 'docm', 'xlsm', 'pptm', 'one', 'chm', 'vhd', 'vhdx', 'pyc', 'url', 'website', 'library-ms', 'settingcontent-ms', 'appref-ms', 'gadget', 'mde', 'accde', 'iqy', 'slk']);

module.exports = { detectType, EXT_EXPECT, DANGEROUS_EXT };
