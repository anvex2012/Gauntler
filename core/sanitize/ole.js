// Created by anvex2012
'use strict';
/**
 * Compound File Binary (OLE2) — in-place disarm of legacy Office documents (.doc .xls .ppt).
 * The file structure is kept intact (same size, same sector chains) while the CONTENT of dangerous
 * streams is overwritten with zeros: the VBA project (macros), embedded OLE objects / packages,
 * Equation Editor objects (CVE-2017-11882), Excel 4.0 macro sheets cannot be removed this way and are
 * reported so that the verification step can block the file.
 */
const ENDOFCHAIN = 0xfffffffe, FREESECT = 0xffffffff;

function parse(buf) {
  if (buf.readUInt32LE(0) !== 0xe011cfd0 || buf.readUInt32LE(4) !== 0xe11ab1a1) throw new Error('non è un file OLE');
  const ss = 1 << buf.readUInt16LE(0x1e);
  const mss = 1 << buf.readUInt16LE(0x20);
  const nFat = buf.readUInt32LE(0x2c);
  const dirStart = buf.readUInt32LE(0x30);
  const cutoff = buf.readUInt32LE(0x38);
  const miniFatStart = buf.readUInt32LE(0x3c);
  const nMiniFat = buf.readUInt32LE(0x40);
  let difatStart = buf.readUInt32LE(0x44);
  const nDifat = buf.readUInt32LE(0x48);
  const secOff = (s) => (s + 1) * ss;
  // DIFAT → FAT sectors
  const fatSectors = [];
  for (let i = 0; i < 109 && fatSectors.length < nFat; i++) { const v = buf.readUInt32LE(0x4c + i * 4); if (v !== FREESECT) fatSectors.push(v); }
  for (let k = 0; k < nDifat && difatStart !== ENDOFCHAIN && difatStart < 0xfffffff0; k++) {
    const o = secOff(difatStart);
    for (let i = 0; i < ss / 4 - 1 && fatSectors.length < nFat; i++) { const v = buf.readUInt32LE(o + i * 4); if (v !== FREESECT) fatSectors.push(v); }
    difatStart = buf.readUInt32LE(o + ss - 4);
  }
  const fat = [];
  for (const fs of fatSectors) { const o = secOff(fs); if (o + ss > buf.length) break; for (let i = 0; i < ss / 4; i++) fat.push(buf.readUInt32LE(o + i * 4)); }
  const chain = (start, table) => {
    const out = [];
    const seen = new Set();
    for (let s = start; s < 0xfffffff0 && !seen.has(s) && s < table.length; s = table[s]) { seen.add(s); out.push(s); }
    return out;
  };
  // Directory
  const entries = [];
  for (const s of chain(dirStart, fat)) {
    const o = secOff(s);
    for (let i = 0; i < ss / 128; i++) {
      const e = o + i * 128;
      if (e + 128 > buf.length) break;
      const nameLen = buf.readUInt16LE(e + 64);
      entries.push({
        id: entries.length, name: buf.toString('utf16le', e, e + Math.max(0, Math.min(64, nameLen) - 2)), type: buf[e + 66],
        left: buf.readUInt32LE(e + 68), right: buf.readUInt32LE(e + 72), child: buf.readUInt32LE(e + 76),
        start: buf.readUInt32LE(e + 116), size: buf.readUInt32LE(e + 120), entryOff: e,
      });
    }
  }
  const miniFat = [];
  for (const s of chain(miniFatStart, fat).slice(0, nMiniFat || Infinity)) { const o = secOff(s); for (let i = 0; i < ss / 4; i++) miniFat.push(buf.readUInt32LE(o + i * 4)); }
  const root = entries[0];
  const miniStreamSectors = root ? chain(root.start, fat) : [];
  // Parent paths: walk the red-black trees from the root
  const pathOf = new Map();
  const walk = (id, prefix, depth = 0) => {
    if (id === FREESECT || id >= entries.length || depth > 64) return;
    const stack = [id];
    const seen = new Set();
    while (stack.length) {
      const k = stack.pop();
      if (k === FREESECT || k >= entries.length || seen.has(k)) continue;
      seen.add(k);
      const e = entries[k];
      pathOf.set(k, prefix + e.name);
      stack.push(e.left, e.right);
      if (e.type === 1) walk(e.child, prefix + e.name + '/', depth + 1);
    }
  };
  if (root) walk(root.child, '');
  for (const e of entries) e.path = pathOf.get(e.id) || e.name;
  return { ss, mss, cutoff, fat, miniFat, miniStreamSectors, entries, secOff, chain };
}

/** Overwrites the content of a stream with zeros (keeps the size and the allocation) */
function zeroStream(buf, ole, e) {
  if (e.size === 0) return 0;
  let zeroed = 0;
  if (e.size < ole.cutoff) {
    for (const ms of ole.chain(e.start, ole.miniFat)) {
      const byteOff = ms * ole.mss;
      const sec = ole.miniStreamSectors[Math.floor(byteOff / ole.ss)];
      if (sec == null) break;
      const o = ole.secOff(sec) + (byteOff % ole.ss);
      const n = Math.min(ole.mss, e.size - zeroed);
      buf.fill(0, o, o + n);
      zeroed += n;
      if (zeroed >= e.size) break;
    }
  } else {
    for (const s of ole.chain(e.start, ole.fat)) {
      const o = ole.secOff(s);
      const n = Math.min(ole.ss, e.size - zeroed);
      buf.fill(0, o, Math.min(buf.length, o + n));
      zeroed += n;
      if (zeroed >= e.size) break;
    }
  }
  return zeroed;
}

const DANGEROUS = [
  { re: /(^|\/)(Macros|_VBA_PROJECT_CUR|VBA)(\/|$)/i, why: 'progetto VBA (macro)' },
  { re: /(^|\/)ObjectPool\//i, why: 'oggetto OLE incorporato' },
  { re: /\x01Ole10Native$/i, why: 'pacchetto OLE (file incorporato)' },
  { re: /Equation Native$/i, why: 'oggetto Equation Editor (exploit CVE-2017-11882)' },
  { re: /(^|\/)MBD[0-9A-F]{8}\//i, why: 'oggetto incorporato (Excel/PowerPoint)' },
  { re: /\x01CompObj$|\x03ObjInfo$/i, why: null }, // descriptive streams: harmless
];

/**
 * Disarms a legacy Office file. Returns { output, actions, residual }
 * residual: things that could not be disarmed in place (e.g. Excel 4.0 macro sheets in the Workbook stream)
 */
function disarm(input) {
  const buf = Buffer.from(input);
  const ole = parse(buf);
  const actions = [];
  const residual = [];
  for (const e of ole.entries) {
    if (e.type !== 2) continue;
    const d = DANGEROUS.find((x) => x.re.test(e.path));
    if (!d || !d.why) continue;
    const n = zeroStream(buf, ole, e);
    if (n) actions.push(`Rimosso ${d.why}: ${e.path.replace(/[\x00-\x1f]/g, '')} (${n} byte)`);
  }
  // Excel 4.0 macros (XLM) live inside the Workbook stream as BOUNDSHEET records of type "macro"
  const wb = ole.entries.find((e) => e.type === 2 && /^(Workbook|Book)$/i.test(e.name));
  if (wb && /\bauto_open\b|EXEC\(|CALL\(|REGISTER\(/i.test(buf.toString('latin1'))) residual.push('Possibili macro Excel 4.0 (XLM) nel foglio di lavoro');
  return { output: buf, actions, residual };
}

module.exports = { parse, disarm, zeroStream };
