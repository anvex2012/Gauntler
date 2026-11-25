// Creato da anvex2012
'use strict';
/**
 * AArch64 (ARM64) disassembler — fixed 32-bit instructions.
 * Covers control flow (B, BL, B.cond, CBZ/CBNZ, TBZ/TBNZ, BR/BLR/RET + pointer-authentication
 * variants), exceptions (SVC/HVC/SMC/BRK/UDF), hints (NOP, PACIASP, BTI…), system registers (MRS/MSR),
 * PC-relative (ADR/ADRP), arithmetic and logical immediates, wide moves, register arithmetic/logic,
 * loads/stores (unsigned offset, pre/post index, register, pairs, literal). Other encodings are
 * shown as ".inst 0x…" but never break the stream (every instruction is 4 bytes).
 */
const COND = ['eq', 'ne', 'hs', 'lo', 'mi', 'pl', 'vs', 'vc', 'hi', 'ls', 'ge', 'lt', 'gt', 'le', 'al', 'nv'];
const sx = (v, bits) => (v << (32 - bits)) >> (32 - bits);
const X = (n, sf, sp) => (n === 31 ? (sp ? (sf ? 'sp' : 'wsp') : (sf ? 'xzr' : 'wzr')) : (sf ? 'x' : 'w') + n);
const h = (n) => (n < 0 ? '-0x' + (-n).toString(16) : '0x' + n.toString(16));
const SYSREG = { 0xdf02: 'cntvct_el0', 0xdf01: 'cntpct_el0', 0xda10: 'fpcr', 0xda11: 'fpsr', 0xde82: 'tpidr_el0', 0xde83: 'tpidrro_el0', 0xc000: 'midr_el1', 0xc005: 'mpidr_el1', 0xd807: 'dczid_el0', 0xc020: 'id_aa64pfr0_el1', 0xc030: 'id_aa64isar0_el1', 0xda20: 'nzcv' };

function decodeBitMask(N, imms, immr, sf) {
  const len = 31 - Math.clz32(((N << 6) | (~imms & 0x3f)) >>> 0);
  if (len < 1) return null;
  const size = 1 << len, levels = size - 1;
  const S = imms & levels, R = immr & levels;
  if (S === levels) return null;
  let welem = (1n << BigInt(S + 1)) - 1n;
  const sz = BigInt(size);
  const mask = (1n << sz) - 1n;
  welem = ((welem >> BigInt(R)) | (welem << (sz - BigInt(R)))) & mask;
  let v = 0n;
  for (let i = 0; i < (sf ? 64 : 32) / size; i++) v |= welem << (BigInt(i) * sz);
  return v;
}

function decode(buf, off, opts = {}) {
  const addr = opts.address != null ? opts.address : off;
  const ins = { address: addr, offset: off, length: 4, mnemonic: '', operands: [], flow: 'seq', text: '' };
  if (off + 4 > buf.length) { ins.length = Math.max(1, buf.length - off); ins.mnemonic = '(bad)'; ins.flow = 'invalid'; ins.invalid = 'troncata'; ins.text = '(bad)'; ins.bytes = buf.subarray(off, off + ins.length); return ins; }
  const w = buf.readUInt32LE(off);
  ins.bytes = buf.subarray(off, off + 4);
  ins.word = w;
  const M = (mask, val) => ((w & mask) >>> 0) === val;
  const set = (m, ops, extra) => { ins.mnemonic = m; ins.opText = ops || ''; Object.assign(ins, extra || {}); };

  // ---- Branches, exceptions, system
  if (M(0x7c000000, 0x14000000)) { // B / BL
    const t = addr + sx(w & 0x3ffffff, 26) * 4;
    set(w & 0x80000000 ? 'bl' : 'b', h(t), { flow: w & 0x80000000 ? 'call' : 'jmp', target: t });
  } else if (M(0xff000010, 0x54000000)) { // B.cond
    const t = addr + sx((w >> 5) & 0x7ffff, 19) * 4;
    set('b.' + COND[w & 15], h(t), { flow: 'jcc', target: t });
  } else if (M(0x7e000000, 0x34000000)) { // CBZ / CBNZ
    const t = addr + sx((w >> 5) & 0x7ffff, 19) * 4;
    set(w & 0x01000000 ? 'cbnz' : 'cbz', `${X(w & 31, w >>> 31)}, ${h(t)}`, { flow: 'jcc', target: t });
  } else if (M(0x7e000000, 0x36000000)) { // TBZ / TBNZ
    const t = addr + sx((w >> 5) & 0x3fff, 14) * 4;
    const bit = ((w >>> 31) << 5) | ((w >> 19) & 31);
    set(w & 0x01000000 ? 'tbnz' : 'tbz', `${X(w & 31, bit > 31)}, #${bit}, ${h(t)}`, { flow: 'jcc', target: t });
  } else if (M(0xfe000000, 0xd6000000)) { // BR/BLR/RET (+ PAC variants)
    const opc = (w >> 21) & 15, rn = (w >> 5) & 31, op2 = (w >> 10) & 0x3f;
    const pac = op2 === 2 || op2 === 3 ? (op2 === 3 ? 'b' : 'a') : '';
    const z = (w & 31) === 31 && pac ? 'z' : '';
    if (opc === 0) set('br' + (pac ? 'a' + pac + z : ''), X(rn, 1), { flow: 'jmp', indirect: true });
    else if (opc === 1) set('blr' + (pac ? 'a' + pac + z : ''), X(rn, 1), { flow: 'call', indirect: true });
    else if (opc === 2) set(pac ? 'reta' + pac : 'ret', rn === 30 || pac ? '' : X(rn, 1), { flow: 'ret' });
    else if (opc === 4) set('eret', '', { flow: 'ret', privileged: true });
    else if (opc === 8 || opc === 9) set((opc === 8 ? 'bra' : 'blra') + pac, `${X(rn, 1)}, ${X(w & 31, 1, 1)}`, { flow: opc === 8 ? 'jmp' : 'call', indirect: true });
    else set('.inst', h(w >>> 0), { flow: 'invalid', invalid: true });
  } else if (M(0xff000000, 0xd4000000)) { // SVC/HVC/SMC/BRK/HLT
    const imm = (w >> 5) & 0xffff, opc = (w >> 21) & 7, ll = w & 3;
    const name = opc === 0 ? ['', 'svc', 'hvc', 'smc'][ll] : opc === 1 ? 'brk' : opc === 2 ? 'hlt' : '';
    if (name) set(name, '#' + h(imm), { flow: name === 'svc' ? 'syscall' : 'int', imm, privileged: name === 'hvc' || name === 'smc' });
    else set('.inst', h(w >>> 0), { flow: 'invalid', invalid: true });
  } else if (M(0xfffff01f, 0xd503201f)) { // hints
    const k = (w >> 5) & 0x7f;
    const HINT = { 0: 'nop', 1: 'yield', 2: 'wfe', 3: 'wfi', 4: 'sev', 7: 'xpaclri', 8: 'pacia1716', 12: 'autia1716', 24: 'paciaz', 25: 'paciasp', 26: 'pacibz', 27: 'pacibsp', 28: 'autiaz', 29: 'autiasp', 30: 'autibz', 31: 'autibsp', 32: 'bti', 34: 'bti c', 36: 'bti j', 38: 'bti jc', 16: 'esb', 17: 'psb csync', 20: 'csdb' };
    set(HINT[k] || 'hint', HINT[k] ? '' : '#' + k);
  } else if (M(0xffc00000, 0xd5000000) || M(0xffe00000, 0xd5200000) || M(0xffe00000, 0xd5300000) || M(0xffe00000, 0xd5100000)) { // MRS/MSR/SYS/barriers
    const L = (w >> 21) & 1, sr = (w >> 5) & 0xffff, rt = w & 31;
    if (M(0xfffff09f, 0xd503309f)) set(['', '', 'clrex', '', 'dsb', 'dmb', 'isb', 'sb'][(w >> 5) & 7] || 'barrier', '');
    else if ((w >> 20 & 0xfff) === 0xd53) set('mrs', `${X(rt, 1)}, ${SYSREG[sr] || 's' + h(sr)}`, { sysreg: SYSREG[sr] || sr });
    else if ((w >> 20 & 0xfff) === 0xd51) set('msr', `${SYSREG[sr] || 's' + h(sr)}, ${X(rt, 1)}`, { sysreg: SYSREG[sr] || sr });
    else set(L ? 'sysl' : 'sys', h(w >>> 0));
  // ---- PC-relative
  } else if (M(0x1f000000, 0x10000000)) {
    const immlo = (w >> 29) & 3, immhi = sx((w >> 5) & 0x7ffff, 19);
    const imm = (immhi * 4) + immlo;
    if (w & 0x80000000) { const t = Math.floor(addr / 4096) * 4096 + imm * 4096; set('adrp', `${X(w & 31, 1)}, ${h(t)}`, { pcrel: t }); }
    else { const t = addr + imm; set('adr', `${X(w & 31, 1)}, ${h(t)}`, { pcrel: t }); }
  // ---- Data processing immediate
  } else if (M(0x1f000000, 0x11000000)) { // ADD/SUB imm
    const sf = w >>> 31, op = (w >> 30) & 1, S = (w >> 29) & 1, sh = (w >> 22) & 1, imm = ((w >> 10) & 0xfff) << (sh ? 12 : 0);
    const rd = w & 31, rn = (w >> 5) & 31;
    if (!op && !S && !imm && (rd === 31 || rn === 31)) set('mov', `${X(rd, sf, 1)}, ${X(rn, sf, 1)}`);
    else if (S && rd === 31) set(op ? 'cmp' : 'cmn', `${X(rn, sf, 1)}, #${h(imm)}`);
    else set((op ? 'sub' : 'add') + (S ? 's' : ''), `${X(rd, sf, !S)}, ${X(rn, sf, 1)}, #${h(imm)}`, { imm });
  } else if (M(0x1f800000, 0x12000000)) { // logical imm
    const sf = w >>> 31, opc = (w >> 29) & 3, N = (w >> 22) & 1, immr = (w >> 16) & 0x3f, imms = (w >> 10) & 0x3f;
    const v = decodeBitMask(N, imms, immr, sf);
    const rd = w & 31, rn = (w >> 5) & 31;
    if (v === null) set('.inst', h(w >>> 0), { flow: 'invalid', invalid: true });
    else if (opc === 1 && rn === 31) set('mov', `${X(rd, sf, 1)}, #0x${v.toString(16)}`, { imm: v });
    else if (opc === 3 && rd === 31) set('tst', `${X(rn, sf)}, #0x${v.toString(16)}`);
    else set(['and', 'orr', 'eor', 'ands'][opc], `${X(rd, sf, opc !== 3)}, ${X(rn, sf)}, #0x${v.toString(16)}`, { imm: v });
  } else if (M(0x1f800000, 0x12800000)) { // MOVN/MOVZ/MOVK
    const sf = w >>> 31, opc = (w >> 29) & 3, hw = (w >> 21) & 3, imm16 = (w >> 5) & 0xffff;
    const name = ['movn', '', 'movz', 'movk'][opc];
    if (!name) set('.inst', h(w >>> 0), { flow: 'invalid', invalid: true });
    else if (opc === 2) { const v = BigInt(imm16) << BigInt(hw * 16); set('mov', `${X(w & 31, sf)}, #0x${v.toString(16)}`, { imm: v, imm16, hw, wide: 'movz' }); }
    else set(name, `${X(w & 31, sf)}, #${h(imm16)}${hw ? ', lsl #' + hw * 16 : ''}`, { imm16, hw, wide: name });
  } else if (M(0x1f800000, 0x13000000)) { // bitfield
    const sf = w >>> 31, opc = (w >> 29) & 3, immr = (w >> 16) & 0x3f, imms = (w >> 10) & 0x3f;
    const rd = w & 31, rn = (w >> 5) & 31, bits = sf ? 63 : 31;
    if (opc === 2 && imms === bits) set('lsr', `${X(rd, sf)}, ${X(rn, sf)}, #${immr}`);
    else if (opc === 2 && imms + 1 === immr) set('lsl', `${X(rd, sf)}, ${X(rn, sf)}, #${bits - imms}`);
    else if (opc === 0 && imms === bits) set('asr', `${X(rd, sf)}, ${X(rn, sf)}, #${immr}`);
    else set(['sbfm', 'bfm', 'ubfm'][opc] || '.inst', `${X(rd, sf)}, ${X(rn, sf)}, #${immr}, #${imms}`);
  } else if (M(0x1f800000, 0x13800000)) { // EXTR / ROR imm
    const sf = w >>> 31, rd = w & 31, rn = (w >> 5) & 31, rm = (w >> 16) & 31, imms = (w >> 10) & 0x3f;
    set(rn === rm ? 'ror' : 'extr', rn === rm ? `${X(rd, sf)}, ${X(rn, sf)}, #${imms}` : `${X(rd, sf)}, ${X(rn, sf)}, ${X(rm, sf)}, #${imms}`, { rot: imms });
  // ---- Data processing register
  } else if (M(0x1f000000, 0x0a000000)) { // logical shifted reg
    const sf = w >>> 31, opc = (w >> 29) & 3, n = (w >> 21) & 1, rd = w & 31, rn = (w >> 5) & 31, rm = (w >> 16) & 31, amt = (w >> 10) & 0x3f;
    const names = n ? ['bic', 'orn', 'eon', 'bics'] : ['and', 'orr', 'eor', 'ands'];
    if (opc === 1 && !n && rn === 31 && !amt) set('mov', `${X(rd, sf)}, ${X(rm, sf)}`);
    else set(names[opc], `${X(rd, sf)}, ${X(rn, sf)}, ${X(rm, sf)}${amt ? ', ' + ['lsl', 'lsr', 'asr', 'ror'][(w >> 22) & 3] + ' #' + amt : ''}`, { regs: [rd, rn, rm] });
  } else if (M(0x1f000000, 0x0b000000)) { // add/sub shifted/extended reg
    const sf = w >>> 31, op = (w >> 30) & 1, S = (w >> 29) & 1, rd = w & 31, rn = (w >> 5) & 31, rm = (w >> 16) & 31;
    if (S && rd === 31) set(op ? 'cmp' : 'cmn', `${X(rn, sf, 1)}, ${X(rm, sf)}`);
    else set((op ? 'sub' : 'add') + (S ? 's' : ''), `${X(rd, sf, 1)}, ${X(rn, sf, 1)}, ${X(rm, sf)}`);
  } else if (M(0x1fe00000, 0x1a800000)) { // conditional select
    const sf = w >>> 31, op = (w >> 30) & 1, o2 = (w >> 10) & 1;
    set([['csel', 'csinc'], ['csinv', 'csneg']][op][o2], `${X(w & 31, sf)}, ${X((w >> 5) & 31, sf)}, ${X((w >> 16) & 31, sf)}, ${COND[(w >> 12) & 15]}`);
  } else if (M(0x1f000000, 0x1b000000)) { // madd/msub/mul
    const sf = w >>> 31, ra = (w >> 10) & 31, o0 = (w >> 15) & 1;
    set(ra === 31 ? (o0 ? 'mneg' : 'mul') : (o0 ? 'msub' : 'madd'), `${X(w & 31, sf)}, ${X((w >> 5) & 31, sf)}, ${X((w >> 16) & 31, sf)}${ra === 31 ? '' : ', ' + X(ra, sf)}`);
  } else if (M(0x5fe00000, 0x1ac00000)) { // 2-source (udiv, sdiv, lslv, rorv, crc32…)
    const sf = w >>> 31, opc = (w >> 10) & 0x3f;
    const N = { 2: 'udiv', 3: 'sdiv', 8: 'lsl', 9: 'lsr', 10: 'asr', 11: 'ror', 16: 'crc32b', 17: 'crc32h', 18: 'crc32w', 19: 'crc32x', 20: 'crc32cb', 21: 'crc32ch', 22: 'crc32cw', 23: 'crc32cx', 12: 'pacga' }[opc];
    set(N || '.inst', `${X(w & 31, sf)}, ${X((w >> 5) & 31, sf)}, ${X((w >> 16) & 31, sf)}`);
  // ---- Loads / stores
  } else if (M(0x3b000000, 0x39000000)) { // unsigned offset
    const size = w >>> 30, V = (w >> 26) & 1, opc = (w >> 22) & 3, imm = ((w >> 10) & 0xfff) << (V && opc >= 2 ? 4 : size);
    ldst(set, size, V, opc, w & 31, `[${X((w >> 5) & 31, 1, 1)}${imm ? ', #' + h(imm) : ''}]`, { base: (w >> 5) & 31, disp: imm });
  } else if (M(0x3b200000, 0x38000000)) { // unscaled / pre / post
    const size = w >>> 30, V = (w >> 26) & 1, opc = (w >> 22) & 3, imm = sx((w >> 12) & 0x1ff, 9), mode = (w >> 10) & 3;
    const rn = X((w >> 5) & 31, 1, 1);
    const addrTxt = mode === 1 ? `[${rn}], #${h(imm)}` : mode === 3 ? `[${rn}, #${h(imm)}]!` : `[${rn}${imm ? ', #' + h(imm) : ''}]`;
    ldst(set, size, V, opc, w & 31, addrTxt, { base: (w >> 5) & 31, disp: imm }, mode === 0 ? 'u' : '');
  } else if (M(0x3b200c00, 0x38200800)) { // register offset
    const size = w >>> 30, V = (w >> 26) & 1, opc = (w >> 22) & 3;
    ldst(set, size, V, opc, w & 31, `[${X((w >> 5) & 31, 1, 1)}, ${X((w >> 16) & 31, (w >> 13) & 1)}]`, { base: (w >> 5) & 31 });
  } else if (M(0x3a000000, 0x28000000)) { // pairs
    const opc = w >>> 30, V = (w >> 26) & 1, L = (w >> 22) & 1, mode = (w >> 23) & 3;
    const sc = V ? 2 + opc : 2 + (opc >> 1);
    const imm = sx((w >> 15) & 0x7f, 7) << sc;
    const r = (n) => (V ? ['s', 'd', 'q'][opc] + n : X(n, opc >> 1));
    const rn = X((w >> 5) & 31, 1, 1);
    const at = mode === 1 ? `[${rn}], #${h(imm)}` : mode === 3 ? `[${rn}, #${h(imm)}]!` : `[${rn}${imm ? ', #' + h(imm) : ''}]`;
    set(L ? 'ldp' : 'stp', `${r(w & 31)}, ${r((w >> 10) & 31)}, ${at}`, { mem: { base: (w >> 5) & 31, disp: imm }, store: !L });
  } else if (M(0x3b000000, 0x18000000)) { // load literal
    const opc = w >>> 30, V = (w >> 26) & 1, t = addr + sx((w >> 5) & 0x7ffff, 19) * 4;
    set(V ? 'ldr' : opc === 2 ? 'ldrsw' : opc === 3 ? 'prfm' : 'ldr', `${V ? ['s', 'd', 'q'][opc] + (w & 31) : X(w & 31, opc !== 0)}, ${h(t)}`, { pcrel: t, load: true });
  } else if (M(0x3f000000, 0x08000000)) { // exclusive
    set((w >> 22) & 1 ? 'ldxr' : 'stxr', h(w >>> 0));
  } else if (w >>> 16 === 0) {
    set('udf', '#' + w, { flow: 'invalid', invalid: 'udf' });
  } else if (M(0x1fe00800, 0x1a400000)) { // CCMP / CCMN
    const sf = w >>> 31, op = (w >> 30) & 1, rn = (w >> 5) & 31, imm = (w >> 11) & 1;
    set(op ? 'ccmp' : 'ccmn', `${X(rn, sf)}, ${imm ? '#' + ((w >> 16) & 31) : X((w >> 16) & 31, sf)}, #${w & 15}, ${COND[(w >> 12) & 15]}`);
  } else if (M(0x0e000000, 0x0e000000) || M(0x1e000000, 0x1e000000)) {
    set('simd', h(w >>> 0)); // NEON / floating point
  } else {
    set('.inst', h(w >>> 0), { flow: 'invalid', invalid: true });
  }
  ins.text = ins.mnemonic + (ins.opText ? ' ' + ins.opText : '');
  return ins;
}

function ldst(set, size, V, opc, rt, at, mem, u = '') {
  if (V) {
    const reg = ['b', 'h', 's', 'd'][size] + rt;
    set((opc & 1 ? 'ldr' : 'str') + (u ? 'u' : ''), `${opc >= 2 ? 'q' + rt : reg}, ${at}`, { mem, store: !(opc & 1) });
    return;
  }
  const sfx = ['b', 'h', '', ''][size];
  if (opc === 0) set(`st${u ? 'u' : ''}r${sfx}`, `${X(rt, size === 3)}, ${at}`, { mem, store: true, size: 1 << size });
  else if (opc === 1) set(`ld${u ? 'u' : ''}r${sfx}`, `${X(rt, size === 3)}, ${at}`, { mem, load: true, size: 1 << size });
  else if (size === 3 && opc === 2) set('prfm', at, { mem });
  else set(`ld${u ? 'u' : ''}rs${sfx || 'w'}`, `${X(rt, opc === 2)}, ${at}`, { mem, load: true, size: 1 << size });
}

module.exports = { decode };
