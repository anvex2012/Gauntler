// Creato da anvex2012
'use strict';
/**
 * Disassembly engine:
 *  - decoder(arch): unified decoder for x86 (32), x64 and arm64
 *  - explore(): recursive-descent disassembly (follows jumps and calls from the entry point, exports,
 *    TLS callbacks and symbols), builds the control-flow graph: basic blocks, edges, functions,
 *    cyclomatic complexity, natural loops (back edges found with an iterative DFS)
 *  - listing(): assembly listing with addresses, bytes (hex and binary), symbols and cross-references
 */
const x86 = require('./x86');
const arm64 = require('./arm64');
const loader = require('./loader');

function decoder(arch) {
  if (arch === 'x86') return (buf, off, address) => x86.decode(buf, off, { bits: 32, address });
  if (arch === 'x64') return (buf, off, address) => x86.decode(buf, off, { bits: 64, address });
  if (arch === 'arm64') return (buf, off, address) => arm64.decode(buf, off, { address });
  return null;
}

/** Region lookup by virtual address (binary search over sorted regions) */
function regionIndex(regions) {
  const rs = [...regions].sort((a, b) => a.va - b.va);
  return (va) => {
    let lo = 0, hi = rs.length - 1;
    while (lo <= hi) {
      const m = (lo + hi) >> 1, r = rs[m];
      if (va < r.va) hi = m - 1;
      else if (va >= r.va + r.size) lo = m + 1;
      else return r;
    }
    return null;
  };
}

/** Functions that never return: the bytes after a call to them are padding or data, not code */
const NORETURN = new Set(['__stack_chk_fail', '__stack_chk_fail_local', 'abort', 'exit', '_exit', '_Exit', 'quick_exit', '__assert_rtn', '__assert_fail',
  '__assert', 'err', 'errx', 'verr', 'verrx', 'errc', 'pthread_exit', 'longjmp', 'siglongjmp', '_longjmp', '__longjmp_chk', '__cxa_throw', '__cxa_rethrow',
  '__cxa_bad_cast', '__cxa_bad_typeid', '__cxa_throw_bad_array_new_length', '_Unwind_Resume', 'objc_exception_throw', 'objc_exception_rethrow',
  '__chk_fail', '__fortify_fail', '__libc_fatal', '__builtin_trap', 'swift_unexpectedError', 'swift_errorInMain', 'swift_reportError', '_ZSt9terminatev',
  '_ZSt17__throw_bad_allocv', '_ZSt20__throw_length_errorPKc', '_ZSt24__throw_out_of_range_fmtPKcz', '_ZSt20__throw_out_of_rangePKc',
  '_ZSt19__throw_logic_errorPKc', '__throw_bad_alloc', 'ExitProcess', 'ExitThread', 'FatalExit', 'FatalAppExitA', 'FatalAppExitW', 'RtlExitUserProcess',
  'RtlExitUserThread', '_invalid_parameter_noinfo_noreturn', '__report_rangecheckfailure', '__fastfail', '_CxxThrowException', 'RaiseFailFastException']);
function isNoReturnCall(ins, image) {
  const sym = image.symbols;
  if (!sym || !sym.size) return false;
  let a = ins.target;
  if (a == null) for (const o of ins.operands || []) if (o.type === 'mem') a = o.rip ? o.target : (!o.base && !o.index && typeof o.disp === 'number' ? o.disp >>> 0 : null);
  if (a == null || !sym.has(a)) return false;
  // "kernel32.dll!ExitProcess", "_abort@stub", "__stack_chk_fail@plt", "exit@GLIBC_2.2.5"
  const n = String(sym.get(a)).replace(/^.*!/, '').replace(/@.*$/, '');
  return NORETURN.has(n) || NORETURN.has(n.replace(/^_/, ''));
}
const TRAP = /^(int3|int1|ud2|ud1|ud0|hlt|udf|brk)$/;
/**
 * After a call whose callee is unknown: if the next instructions are only filler and then a trap (or
 * cannot be decoded), the callee does not return and what follows is not code.
 */
function fallsIntoTrap(buf, r, va, dec) {
  for (let i = 0; i < 16; i++) {
    if (va >= r.va + r.size) return true;
    const ins = dec(buf, r.off + (va - r.va), va);
    if (ins.flow === 'invalid' || ins.invalid || TRAP.test(ins.mnemonic)) return true;
    if (ins.mnemonic !== 'nop') return false;
    va += ins.length;
  }
  return false;
}

/**
 * Recursive descent. Keeps only a compact record per instruction (length, flow, target) so that even
 * very large programs fit in memory; full instructions are passed to opts.onIns (e.g. the behavioural
 * Detector) in execution-path order, and re-decoded on demand for listings.
 * Returns { insns: Map(va → {len, flow, target, off}), functions, blocks, xrefs, truncated, find, dec }
 */
function explore(buf, image, opts = {}) {
  const dec = decoder(image.arch);
  if (!dec) return null;
  const find = regionIndex(image.regions);
  const maxInsns = opts.maxInsns || 2000000;
  const onIns = opts.onIns || null;
  const insns = new Map();
  const functions = new Set();
  const leaders = new Set();
  const xrefs = new Map(); // target → count of references
  const work = [];
  const push = (va, isFn) => { if (va == null || !find(va)) return; if (isFn) functions.add(va); leaders.add(va); work.push(va); };
  // LIFO work list: the entry point is pushed last so it is explored first
  for (const e of opts.entries || []) push(e, true);
  for (const f of image.functions || []) push(f, true);
  if (image.entry != null) push(image.entry, true);
  let truncated = false;
  while (work.length) {
    let va = work.pop();
    if (insns.has(va)) continue;
    let first = true;
    for (;;) {
      if (insns.size >= maxInsns) { truncated = true; work.length = 0; break; }
      const r = find(va);
      if (!r) break;
      const ins = dec(buf, r.off + (va - r.va), va);
      if (va + ins.length > r.va + r.size) break;
      insns.set(va, { len: ins.length, flow: ins.flow, target: ins.target, off: ins.offset, mn: ins.mnemonic });
      if (onIns) { if (first) onIns(null); onIns(ins); }
      first = false;
      const t = ins.target;
      if (t != null && find(t)) xrefs.set(t, (xrefs.get(t) || 0) + 1);
      if (ins.flow === 'call') {
        if (t != null) push(t, true);
        if (isNoReturnCall(ins, image) || fallsIntoTrap(buf, r, va + ins.length, dec)) break;
      }
      else if (ins.flow === 'jcc') { if (t != null) push(t); leaders.add(va + ins.length); }
      else if (ins.flow === 'jmp') { if (t != null) push(t); break; }
      else if (ins.flow === 'ret' || ins.flow === 'invalid' || ins.flow === 'halt') break;
      else if (ins.flow === 'int' && /^(int3|brk|int1)$/.test(ins.mnemonic)) break;
      va += ins.length;
      if (insns.has(va)) { leaders.add(va); break; }
    }
  }
  // Basic blocks
  const sorted = [...insns.keys()].sort((a, b) => a - b);
  const blocks = new Map();
  let cur = null;
  for (let i = 0; i < sorted.length; i++) {
    const va = sorted[i], ins = insns.get(va);
    if (!cur || leaders.has(va) || cur.end !== va) { cur = { start: va, end: va, n: 0, succ: [] }; blocks.set(va, cur); }
    cur.n++;
    cur.end = va + ins.len;
    const terminator = ins.flow !== 'seq' && ins.flow !== 'call' && ins.flow !== 'syscall' && !(ins.flow === 'int' && !/^(int3|brk|int1)$/.test(ins.mn));
    if (terminator || leaders.has(cur.end)) {
      if ((ins.flow === 'jcc' || ins.flow === 'jmp') && ins.target != null && insns.has(ins.target)) cur.succ.push(ins.target);
      if (ins.flow === 'jcc' || (!terminator && insns.has(cur.end))) cur.succ.push(cur.end);
      cur = null;
    }
  }
  return { insns, functions, blocks, xrefs, truncated, find, dec };
}

/**
 * Function starts recognized by their prologue, accepted only right after a terminator or padding
 * (ret / jmp / int3 / nop / zero fill / 16-byte alignment), so a byte pattern in the middle of a function
 * is not mistaken for a new one. Used as extra seeds for the recursive descent: functions reached only
 * through pointers (callbacks, vtables, jump tables, Objective-C/Swift metadata) are otherwise missed.
 */
function prologueStarts(buf, image, limit = 500000) {
  const out = [];
  for (const r of image.regions) {
    const end = r.off + r.size;
    if (image.arch === 'arm64') {
      for (let o = r.off + ((4 - ((r.va - r.off) & 3)) & 3); o + 4 <= end && out.length < limit; o += 4) {
        const w = buf.readUInt32LE(o);
        const prologue = w === 0xd503237f || w === 0xd503233f || w === 0xd503245f || w === 0xd50324df // pacibsp/paciasp/bti c/bti jc
          || ((w & 0xffc003e0) === 0xa98003e0 && ((w >> 15) & 0x40)) // stp xA, xB, [sp, #-N]!
          || (w & 0xff8003ff) === 0xd10003ff; // sub sp, sp, #N
        if (!prologue) continue;
        if (o === r.off) { out.push(r.va); continue; }
        const p = buf.readUInt32LE(o - 4);
        const after = p === 0xd65f03c0 || p === 0xd65f0bff || p === 0xd65f0fff // ret / retaa / retab
          || (p >>> 26) === 0x05 || (p & 0xfffffc1f) === 0xd61f0000 || (p & 0xfffffc1f) === 0xd71f081f // b / br / braa…
          || p === 0 || p === 0xd503201f || (p & 0xffe0001f) === 0xd4200000; // udf / nop / brk
        if (after) out.push(r.va + (o - r.off));
      }
    } else if (image.arch === 'x86' || image.arch === 'x64') {
      for (let o = r.off; o + 4 <= end && out.length < limit; o++) {
        const b0 = buf[o];
        if (b0 !== 0x55 && b0 !== 0xf3) continue;
        const prologue = (b0 === 0xf3 && buf[o + 1] === 0x0f && buf[o + 2] === 0x1e && (buf[o + 3] === 0xfa || buf[o + 3] === 0xfb)) // endbr64/32
          || (b0 === 0x55 && buf[o + 1] === 0x48 && ((buf[o + 2] === 0x89 && buf[o + 3] === 0xe5) || (buf[o + 2] === 0x8b && buf[o + 3] === 0xec))) // push rbp; mov rbp, rsp
          || (image.arch === 'x86' && b0 === 0x55 && ((buf[o + 1] === 0x89 && buf[o + 2] === 0xe5) || (buf[o + 1] === 0x8b && buf[o + 2] === 0xec))); // push ebp; mov ebp, esp
        if (!prologue) continue;
        const va = r.va + (o - r.off);
        const p = o > r.off ? buf[o - 1] : 0xcc;
        if (p === 0xc3 || p === 0xcc || p === 0x90 || p === 0x00 || (va & 15) === 0) out.push(va);
      }
    }
  }
  return out;
}

/**
 * Code coverage that ignores alignment padding (int3 / nop / multi-byte nop / zero fill / arm64 udf),
 * plus the entropy of the code that was NOT reached: compiler-generated code sits around 6–6.7 bits per
 * byte, while compressed or encrypted bytes (a packer's payload) are close to 8.
 */
function coverage(buf, image, cfg) {
  const keys = [...cfg.insns.keys()].sort((a, b) => a - b);
  const hist = new Float64Array(256);
  let total = 0, padding = 0, reached = 0, gapBytes = 0, k = 0;
  const regions = [...image.regions].sort((a, b) => a.va - b.va);
  const isArm = image.arch === 'arm64';
  const gap = (from, to, r) => {
    if (to <= from) return;
    let o = r.off + (from - r.va);
    const end = r.off + (to - r.va);
    if (isArm) {
      for (; o + 4 <= end; o += 4) {
        const w = buf.readUInt32LE(o);
        if (w === 0 || w === 0xd503201f || (w & 0xffff0000) === 0) { padding += 4; continue; } // zero / nop / udf #imm
        for (let i = 0; i < 4; i++) hist[buf[o + i]]++;
        gapBytes += 4;
      }
      return;
    }
    while (o < end) {
      const c = buf[o];
      // runs of the single-byte fillers
      if (c === 0xcc || c === 0x90 || c === 0x00) { padding++; o++; continue; }
      const ins = cfg.dec(buf, o, r.va + (o - r.off));
      const len = Math.max(1, Math.min(ins.length, end - o));
      if (ins.mnemonic === 'nop' || ins.mnemonic === 'int3' || /^(nop[wl]?|xchg ax, ax|data16)/.test(ins.text || '')) { padding += len; o += len; continue; }
      for (let i = 0; i < len; i++) hist[buf[o + i]]++;
      gapBytes += len; o += len;
    }
  };
  for (const r of regions) {
    total += r.size;
    let cur = r.va;
    while (k < keys.length && keys[k] < r.va) k++;
    for (; k < keys.length && keys[k] < r.va + r.size; k++) {
      const va = keys[k], len = cfg.insns.get(va).len;
      if (va > cur) gap(cur, va, r);
      const s = Math.max(va, cur), e = Math.min(va + len, r.va + r.size);
      if (e > s) reached += e - s;
      cur = Math.max(cur, va + len);
    }
    if (cur < r.va + r.size) gap(cur, r.va + r.size, r);
  }
  let entropy = 0;
  for (let i = 0; i < 256; i++) if (hist[i]) { const p = hist[i] / gapBytes; entropy -= p * Math.log2(p); }
  const effective = Math.max(1, total - padding);
  return { total, padding, reached, effective, ratio: Math.min(1, reached / effective), unreached: gapBytes, unreachedEntropy: gapBytes >= 4096 ? entropy : 0 };
}

/** Per-function metrics: blocks, edges, cyclomatic complexity, loops (back edges) */
function analyzeFunctions(cfg, limit = 20000) {
  const out = [];
  for (const f of cfg.functions) {
    if (out.length >= limit) break;
    if (!cfg.blocks.has(f)) continue;
    // iterative DFS with colors → back edges
    const color = new Map();
    const stack = [[f, 0]];
    color.set(f, 1);
    let nodes = 0, edges = 0;
    const loops = [];
    let size = 0;
    while (stack.length) {
      const top = stack[stack.length - 1];
      const b = cfg.blocks.get(top[0]);
      if (top[1] === 0) { nodes++; size += b.end - b.start; edges += b.succ.length; }
      if (top[1] < b.succ.length) {
        const s = b.succ[top[1]++];
        if (cfg.functions.has(s) && s !== f) continue; // tail call into another function
        const c = color.get(s);
        if (c === 1) loops.push({ from: b.end, head: s });
        else if (!c && cfg.blocks.has(s)) { color.set(s, 1); stack.push([s, 0]); }
      } else { color.set(top[0], 2); stack.pop(); }
    }
    out.push({ start: f, blocks: nodes, edges, size, cyclomatic: Math.max(1, edges - nodes + 2), loops });
  }
  return out;
}

const hex = (n, w = 0) => '0x' + n.toString(16).padStart(w, '0');
const bin = (bytes) => Array.from(bytes, (b) => b.toString(2).padStart(8, '0')).join(' ');

/** Comment for an instruction: imported symbol, target function, string reference */
function annotate(ins, image, cfg, buf) {
  const sym = image.symbols || new Map();
  const notes = [];
  if (ins.target != null && sym.has(ins.target)) notes.push(sym.get(ins.target));
  for (const o of ins.operands || []) {
    if (o.type === 'mem') {
      const a = o.rip ? o.target : (!o.base && !o.index && typeof o.disp === 'number' ? o.disp >>> 0 : null);
      if (a != null && sym.has(a)) notes.push(sym.get(a));
      else if (a != null && cfg && buf) { const s = stringAt(buf, image, a); if (s) notes.push(JSON.stringify(s)); }
    }
    if (o.type === 'imm' && typeof o.value === 'number' && o.value > 0x1000 && cfg && buf) { const s = stringAt(buf, image, o.value >>> 0); if (s) notes.push(JSON.stringify(s)); }
  }
  if (ins.pcrel != null && buf) { const s = stringAt(buf, image, ins.pcrel); if (s) notes.push(JSON.stringify(s)); }
  return notes.join(' · ');
}

/** Printable string at a virtual address (any section with file data) */
function stringAt(buf, image, va) {
  const secs = image.allSections || image.regions;
  for (const r of secs) {
    if (va >= r.va && va < r.va + r.size) {
      const o = r.off + (va - r.va);
      let e = o;
      while (e < buf.length && e - o < 200 && buf[e] >= 0x20 && buf[e] < 0x7f) e++;
      if (e - o >= 4 && (buf[e] === 0 || e - o >= 200)) return buf.toString('latin1', o, e);
      return null;
    }
  }
  return null;
}

/**
 * Listing (array of rows). mode 'flow': functions found by recursive descent, in address order.
 * Each row: { va, off, hex, bin, text, label, note, flow }
 */
function listing(buf, image, cfg, { max = Infinity, binary = false, from = null } = {}) {
  const rows = [];
  const keys = [...cfg.insns.keys()].sort((a, b) => a - b);
  let i = from != null ? keys.findIndex((k) => k >= from) : 0;
  if (i < 0) i = keys.length;
  let prevEnd = null;
  for (; i < keys.length && rows.length < max; i++) {
    const rec = cfg.insns.get(keys[i]);
    const ins = cfg.dec(buf, rec.off, keys[i]);
    let label = null;
    if (cfg.functions.has(ins.address)) label = (image.symbols && image.symbols.get(ins.address)) || (ins.address === image.entry ? 'entry_point' : `sub_${ins.address.toString(16)}`);
    else if (cfg.blocks.has(ins.address) && cfg.xrefs.has(ins.address)) label = `loc_${ins.address.toString(16)}`;
    if (prevEnd != null && ins.address !== prevEnd) rows.push({ gap: true });
    rows.push({
      va: ins.address, off: ins.offset, hex: Buffer.from(ins.bytes).toString('hex'), bin: binary ? bin(ins.bytes) : undefined,
      text: ins.text, label, note: annotate(ins, image, cfg, buf) || undefined, flow: ins.flow,
    });
    prevEnd = ins.address + ins.length;
  }
  return rows;
}

/** Linear listing of a raw byte range (shellcode, unknown data) */
function linear(buf, start, end, arch, base = 0, { binary = false, max = Infinity } = {}) {
  const dec = decoder(arch);
  const rows = [];
  for (let off = start; off < end && rows.length < max;) {
    const ins = dec(buf, off, base + (off - start));
    rows.push({ va: ins.address, off, hex: Buffer.from(ins.bytes).toString('hex'), bin: binary ? bin(ins.bytes) : undefined, text: ins.text, flow: ins.flow });
    off += ins.length;
  }
  return rows;
}

function formatRows(rows, { binary = false, width = 24 } = {}) {
  const out = [];
  for (const r of rows) {
    if (r.gap) { out.push(''); continue; }
    if (r.label) out.push(`\n${r.label}:`);
    const bytes = binary ? r.bin : r.hex.replace(/(..)/g, '$1 ').trim();
    out.push(`  ${hex(r.va, 8)}  ${bytes.padEnd(binary ? 36 : width)}  ${r.text}${r.note ? '    ; ' + r.note : ''}`);
  }
  return out.join('\n');
}

module.exports = { decoder, explore, analyzeFunctions, prologueStarts, coverage, listing, linear, formatRows, load: loader.load, regionIndex, stringAt, bin };
