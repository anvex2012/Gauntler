// Created by anvex2012
'use strict';
/**
 * Finds the machine code inside an executable: architecture, entry point, executable regions,
 * imported functions with their IAT/stub addresses (to label indirect calls in the listing).
 * Supports PE (x86/x64/ARM64), ELF (x86/x86-64/AArch64), Mach-O (thin and universal/fat).
 */

function loadPE(buf) {
  const lf = buf.readUInt32LE(0x3c);
  const coff = lf + 4;
  const machine = buf.readUInt16LE(coff);
  const arch = { 0x14c: 'x86', 0x8664: 'x64', 0xaa64: 'arm64' }[machine];
  const nsec = buf.readUInt16LE(coff + 2);
  const optSize = buf.readUInt16LE(coff + 16);
  const opt = coff + 20;
  const is64 = buf.readUInt16LE(opt) === 0x20b;
  const entryRva = buf.readUInt32LE(opt + 16);
  const imageBase = is64 ? Number(buf.readBigUInt64LE(opt + 24)) : buf.readUInt32LE(opt + 28);
  const subsystem = buf.readUInt16LE(opt + 68);
  const numDD = buf.readUInt32LE(opt + (is64 ? 108 : 92));
  const ddOff = opt + (is64 ? 112 : 96);
  const dd = (i) => (i < numDD ? { rva: buf.readUInt32LE(ddOff + i * 8), size: buf.readUInt32LE(ddOff + i * 8 + 4) } : { rva: 0, size: 0 });
  const sections = [];
  const secOff = opt + optSize;
  for (let i = 0; i < nsec && secOff + i * 40 + 40 <= buf.length; i++) {
    const o = secOff + i * 40;
    sections.push({
      name: buf.toString('latin1', o, o + 8).replace(/\0+$/, ''),
      vsize: buf.readUInt32LE(o + 8), va: buf.readUInt32LE(o + 12), rsize: buf.readUInt32LE(o + 16), rptr: buf.readUInt32LE(o + 20), ch: buf.readUInt32LE(o + 36),
    });
  }
  const rva2off = (rva) => {
    for (const s of sections) if (rva >= s.va && rva < s.va + Math.max(s.vsize, s.rsize) && rva - s.va < s.rsize) return rva - s.va + s.rptr;
    return -1;
  };
  const cstr = (off, max = 256) => (off < 0 || off >= buf.length ? '' : buf.toString('latin1', off, Math.min(buf.length, off + max)).split('\0')[0]);
  // Imports: IAT slot address → "dll!Function"
  const symbols = new Map();
  const imp = dd(1);
  let off = imp.rva ? rva2off(imp.rva) : -1;
  for (let n = 0; off > 0 && off + 20 <= buf.length && n < 4096; n++, off += 20) {
    const oft = buf.readUInt32LE(off), nameRva = buf.readUInt32LE(off + 12), ft = buf.readUInt32LE(off + 16);
    if (!nameRva) break;
    const dll = cstr(rva2off(nameRva), 128).toLowerCase();
    let to = rva2off(oft || ft);
    for (let k = 0; to > 0 && to + 8 <= buf.length && k < 65536; k++) {
      const v = is64 ? buf.readBigUInt64LE(to) : BigInt(buf.readUInt32LE(to));
      if (!v) break;
      const ordinal = is64 ? (v >> 63n) === 1n : (v & 0x80000000n) !== 0n;
      const fn = ordinal ? 'ord' + Number(v & 0xffffn) : cstr(rva2off(Number(v & 0x7fffffffn)) + 2, 256);
      symbols.set(imageBase + ft + k * (is64 ? 8 : 4), `${dll}!${fn}`);
      to += is64 ? 8 : 4;
    }
  }
  // Exports as function names
  const exp = dd(0);
  const eo = exp.rva ? rva2off(exp.rva) : -1;
  const functions = [];
  if (eo > 0 && eo + 40 <= buf.length) {
    const nFn = buf.readUInt32LE(eo + 20), nNames = buf.readUInt32LE(eo + 24);
    const fnOff = rva2off(buf.readUInt32LE(eo + 28)), namesOff = rva2off(buf.readUInt32LE(eo + 32)), ordOff = rva2off(buf.readUInt32LE(eo + 36));
    for (let i = 0; i < nNames && namesOff > 0 && ordOff > 0 && fnOff > 0 && namesOff + i * 4 + 4 <= buf.length && i < 65536; i++) {
      const ord = buf.readUInt16LE(ordOff + i * 2);
      if (ord >= nFn || fnOff + ord * 4 + 4 > buf.length) continue;
      const rva = buf.readUInt32LE(fnOff + ord * 4);
      const name = cstr(rva2off(buf.readUInt32LE(namesOff + i * 4)), 256);
      if (rva < exp.rva || rva >= exp.rva + exp.size) { functions.push(imageBase + rva); symbols.set(imageBase + rva, name); }
    }
  }
  // TLS callbacks run before the entry point
  const tls = dd(9);
  const tlsOff = tls.rva ? rva2off(tls.rva) : -1;
  if (tlsOff > 0 && tlsOff + (is64 ? 32 : 16) <= buf.length) {
    let cbVa = is64 ? Number(buf.readBigUInt64LE(tlsOff + 24)) : buf.readUInt32LE(tlsOff + 12);
    let co = cbVa ? rva2off(cbVa - imageBase) : -1;
    for (let i = 0; co > 0 && co + 8 <= buf.length && i < 64; i++, co += is64 ? 8 : 4) {
      const cb = is64 ? Number(buf.readBigUInt64LE(co)) : buf.readUInt32LE(co);
      if (!cb) break;
      functions.push(cb); symbols.set(cb, `TlsCallback_${i}`);
    }
  }
  const regions = sections.filter((s) => s.ch & 0x20000000 || s.ch & 0x20).filter((s) => s.rsize > 0 && s.rptr < buf.length)
    .map((s) => ({ name: s.name, off: s.rptr, size: Math.min(s.rsize, s.vsize || s.rsize, buf.length - s.rptr), va: imageBase + s.va }));
  const entryOff = rva2off(entryRva);
  return {
    format: 'PE', arch, bits: arch === 'x86' ? 32 : 64, imageBase, entry: entryRva ? imageBase + entryRva : null, entryOff,
    regions, symbols, functions, native: subsystem === 1, dotnet: dd(14).rva > 0,
  };
}

function loadELF(buf) {
  const is64 = buf[4] === 2, le = buf[5] === 1;
  const u16 = (o) => (le ? buf.readUInt16LE(o) : buf.readUInt16BE(o));
  const u32 = (o) => (le ? buf.readUInt32LE(o) : buf.readUInt32BE(o));
  const uN = (o) => (is64 ? Number(le ? buf.readBigUInt64LE(o) : buf.readBigUInt64BE(o)) : u32(o));
  const machine = u16(18);
  const arch = { 3: 'x86', 62: 'x64', 183: 'arm64' }[machine];
  const entry = uN(0x18);
  const phoff = uN(is64 ? 0x20 : 0x1c), shoff = uN(is64 ? 0x28 : 0x20);
  const phentsize = u16(is64 ? 0x36 : 0x2a), phnum = u16(is64 ? 0x38 : 0x2c);
  const shentsize = u16(is64 ? 0x3a : 0x2e), shnum = u16(is64 ? 0x3c : 0x30), shstrndx = u16(is64 ? 0x3e : 0x32);
  const regions = [];
  const symbols = new Map();
  const functions = [];
  const secs = [];
  if (shoff && shnum && shoff + shnum * shentsize <= buf.length) {
    const strOff = uN(shoff + shstrndx * shentsize + (is64 ? 0x18 : 0x10));
    for (let i = 0; i < shnum; i++) {
      const o = shoff + i * shentsize;
      const s = {
        name: buf.toString('latin1', strOff + u32(o), Math.min(buf.length, strOff + u32(o) + 64)).split('\0')[0],
        type: u32(o + 4), flags: uN(o + 8), addr: uN(o + (is64 ? 0x10 : 0x0c)), off: uN(o + (is64 ? 0x18 : 0x10)), size: uN(o + (is64 ? 0x20 : 0x14)),
        link: u32(o + (is64 ? 0x28 : 0x18)), entsize: uN(o + (is64 ? 0x38 : 0x24)),
      };
      secs.push(s);
      if (s.flags & 4 && s.type !== 8 && s.size && s.off < buf.length) regions.push({ name: s.name, off: s.off, size: Math.min(s.size, buf.length - s.off), va: s.addr });
    }
    // Symbol tables (.symtab / .dynsym): function names
    for (const s of secs.filter((x) => x.type === 2 || x.type === 11)) {
      const str = secs[s.link];
      if (!str) continue;
      const es = s.entsize || (is64 ? 24 : 16);
      for (let k = 0; k * es + es <= s.size && s.off + k * es + es <= buf.length && k < 200000; k++) {
        const o = s.off + k * es;
        const nameOff = u32(o);
        const info = is64 ? buf[o + 4] : buf[o + 12];
        const value = is64 ? uN(o + 8) : u32(o + 4);
        if ((info & 15) === 2 && value) {
          const name = buf.toString('latin1', str.off + nameOff, Math.min(buf.length, str.off + nameOff + 200)).split('\0')[0];
          if (name) { symbols.set(value, name); functions.push(value); }
        }
      }
    }
  }
  // .eh_frame_hdr binary-search table: start address of every function with unwind info (C, C++, Rust,
  // Go…), present even in stripped binaries.
  const ehh = secs.find((x) => x.name === '.eh_frame_hdr');
  if (ehh && ehh.off + 12 <= buf.length && buf[ehh.off] === 1) {
    const ptrEnc = buf[ehh.off + 1], cntEnc = buf[ehh.off + 2], tabEnc = buf[ehh.off + 3];
    const ptrLen = { 0x03: 4, 0x0b: 4, 0x1b: 4, 0x3b: 4, 0x04: 8, 0x0c: 8, 0x1c: 8 }[ptrEnc];
    if (ptrLen && (cntEnc === 0x03 || cntEnc === 0x0b) && tabEnc === 0x3b) {
      const cntOff = ehh.off + 4 + ptrLen;
      const n = cntOff + 4 <= buf.length ? u32(cntOff) : 0;
      for (let k = 0, o = cntOff + 4; k < n && k < 2000000 && o + 8 <= buf.length && o + 8 <= ehh.off + ehh.size; k++, o += 8) {
        const rel = le ? buf.readInt32LE(o) : buf.readInt32BE(o);
        functions.push(ehh.addr + rel); // datarel = relative to the start of .eh_frame_hdr
      }
    }
  }
  if (!regions.length) {
    for (let i = 0; i < phnum && phoff + (i + 1) * phentsize <= buf.length; i++) {
      const o = phoff + i * phentsize;
      const type = u32(o), flags = is64 ? u32(o + 4) : u32(o + 24);
      if (type !== 1 || !(flags & 1)) continue;
      const off = uN(o + (is64 ? 8 : 4)), va = uN(o + (is64 ? 16 : 8)), fsz = uN(o + (is64 ? 32 : 16));
      if (off < buf.length) regions.push({ name: 'LOAD[R-X]', off, size: Math.min(fsz, buf.length - off), va });
    }
  }
  let entryOff = -1;
  for (const r of regions) if (entry >= r.va && entry < r.va + r.size) entryOff = r.off + (entry - r.va);
  return { format: 'ELF', arch, bits: arch === 'x86' ? 32 : 64, entry: entry || null, entryOff, regions, symbols, functions, machine };
}

const CPU = { 7: 'x86', 0x01000007: 'x64', 0x0100000c: 'arm64' };
function loadMachO(buf, base = 0) {
  const magic = buf.readUInt32BE(base);
  if (magic === 0xcafebabe) {
    const n = buf.readUInt32BE(base + 4);
    const slices = [];
    for (let i = 0; i < n && i < 20; i++) {
      const o = base + 8 + i * 20;
      const off = buf.readUInt32BE(o + 8), size = buf.readUInt32BE(o + 12);
      if (off + size <= buf.length && off) { try { slices.push(loadMachO(buf, off)); } catch { /* */ } }
    }
    const best = slices.find((s) => s.arch === 'arm64') || slices.find((s) => s.arch === 'x64') || slices.find((s) => s.arch) || slices[0];
    if (!best) throw new Error('Mach-O universale senza architetture supportate');
    return { ...best, slices };
  }
  const le = magic === 0xcffaedfe || magic === 0xcefaedfe;
  const u32 = (o) => (le ? buf.readUInt32LE(o) : buf.readUInt32BE(o));
  const u64 = (o) => Number(le ? buf.readBigUInt64LE(o) : buf.readBigUInt64BE(o));
  const is64 = magic === 0xcffaedfe || magic === 0xfeedfacf;
  const arch = CPU[u32(base + 4)];
  const ncmds = u32(base + 16);
  let off = base + (is64 ? 32 : 28);
  const regions = [];
  const symbols = new Map();
  const functions = [];
  let textVmaddr = null, entryoff = null, textFileoff = 0;
  let symtab = null, stubs = null, indirect = null, fnStarts = null;
  for (let i = 0; i < ncmds && off + 8 <= buf.length; i++) {
    const cmd = u32(off), size = u32(off + 4);
    if (cmd === 0x19 || cmd === 0x1) {
      const seg = buf.toString('latin1', off + 8, off + 24).replace(/\0+$/, '');
      const vmaddr = is64 ? u64(off + 24) : u32(off + 24);
      const fileoff = is64 ? u64(off + 40) : u32(off + 32);
      if (seg === '__TEXT') { textVmaddr = vmaddr; textFileoff = fileoff; }
      const nsects = u32(off + (is64 ? 64 : 48));
      let so = off + (is64 ? 72 : 56);
      for (let k = 0; k < nsects; k++, so += is64 ? 80 : 68) {
        const sect = buf.toString('latin1', so, so + 16).replace(/\0+$/, '');
        const addr = is64 ? u64(so + 32) : u32(so + 32);
        const ssize = is64 ? u64(so + 40) : u32(so + 36);
        const sofs = u32(so + (is64 ? 48 : 40));
        const flags = u32(so + (is64 ? 64 : 56));
        if (flags & 0x80000400) regions.push({ name: `${seg},${sect}`, off: base + sofs, size: Math.min(ssize, buf.length - base - sofs), va: addr });
        if (sect === '__stubs' || sect === '__auth_stubs') stubs = { addr, size: ssize, reserved1: u32(so + (is64 ? 68 : 60)), reserved2: u32(so + (is64 ? 72 : 64)) };
      }
    }
    if (cmd === 0x80000028) entryoff = u64(off + 8);
    if (cmd === 0x2) symtab = { symoff: u32(off + 8), nsyms: u32(off + 12), stroff: u32(off + 16) };
    if (cmd === 0xb) indirect = { off: u32(off + 56), n: u32(off + 60) };
    if (cmd === 0x26) fnStarts = { off: u32(off + 8), size: u32(off + 12) }; // LC_FUNCTION_STARTS
    if (size < 8) break;
    off += size;
  }
  // Symbol names (functions + imported stubs)
  if (symtab) {
    const es = is64 ? 16 : 12;
    const names = [];
    for (let k = 0; k < symtab.nsyms && k < 500000; k++) {
      const o = base + symtab.symoff + k * es;
      if (o + es > buf.length) break;
      const strx = u32(o), type = buf[o + 4], sect = buf[o + 5];
      const value = is64 ? u64(o + 8) : u32(o + 8);
      const name = buf.toString('latin1', base + symtab.stroff + strx, Math.min(buf.length, base + symtab.stroff + strx + 200)).split('\0')[0];
      names.push(name);
      if (!(type & 0xe0) && (type & 0x0e) === 0x0e && sect && value) { symbols.set(value, name.replace(/^_/, '')); functions.push(value); }
    }
    if (stubs && indirect) {
      const stubSize = stubs.reserved2 || (arch === 'arm64' ? 12 : 6);
      for (let k = 0; k * stubSize < stubs.size; k++) {
        const io = base + indirect.off + (stubs.reserved1 + k) * 4;
        if (io + 4 > buf.length) break;
        const idx = u32(io);
        if (idx < names.length) symbols.set(stubs.addr + k * stubSize, names[idx].replace(/^_/, '') + '@stub');
      }
    }
  }
  // LC_FUNCTION_STARTS: ULEB128 deltas from the start of __TEXT, present even in stripped binaries.
  // Without them the code reached only through function pointers (callbacks, vtables, Objective-C
  // methods, blocks) would look "unreachable".
  if (fnStarts && textVmaddr != null) {
    let p = base + fnStarts.off, addr = textVmaddr;
    const end = Math.min(buf.length, p + fnStarts.size);
    for (let n = 0; p < end && n < 2000000; n++) {
      let v = 0, shift = 0, b;
      do { b = buf[p++]; v += (b & 0x7f) * 2 ** shift; shift += 7; } while (b & 0x80 && p < end && shift < 63);
      if (!v) break;
      addr += v;
      functions.push(addr);
    }
  }
  const entry = entryoff != null && textVmaddr != null ? textVmaddr + entryoff - textFileoff : null;
  let entryOff = -1;
  for (const r of regions) if (entry != null && entry >= r.va && entry < r.va + r.size) entryOff = r.off + (entry - r.va);
  return { format: 'Mach-O', arch, bits: arch === 'x86' ? 32 : 64, entry, entryOff, regions, symbols, functions };
}

function load(buf, typeId) {
  if (typeId === 'pe' || typeId === 'dll') return loadPE(buf);
  if (typeId === 'elf') return loadELF(buf);
  if (typeId === 'macho') return loadMachO(buf);
  return null;
}

module.exports = { load, loadPE, loadELF, loadMachO };
