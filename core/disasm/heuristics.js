// Creato da anvex2012
'use strict';
/**
 * Behavioural heuristics on machine code. A streaming detector (constant memory) that receives the
 * instructions of a linear sweep and recognizes the building blocks of shellcode and malware loaders:
 *
 *  getpc        call $+5 / pop · fnstenv [esp-0xc] · jmp-call-pop       (position-independent code)
 *  peb          fs:[0x30] / gs:[0x60] / fs:[0x18] / gs:[0x30]           (manual module walking)
 *  hashloop     ror/rol by 13/7/5 + add/xor in a short loop             (API name hashing)
 *  apihash      immediate equal to the hash of a Windows API name       (dictionary in algorithms/apihash)
 *  syscall      syscall / sysenter / int 0x2e / int 0x80 / svc          (direct system calls)
 *  hellsgate    mov r10, rcx ; mov eax, <n> ; syscall                   (EDR evasion stub)
 *  decoder      short backward loop with xor/add/sub/rol on memory      (self-decrypting payload)
 *  stackstr     printable immediates written to the stack / pushed      (hidden strings)
 *  antidebug    rdtsc, int 2d, int1, BeingDebugged (PEB+2), ptrace(PT_DENY_ATTACH)
 *  antivm       cpuid 0x40000000, VMware backdoor 'VMXh', sidt/sgdt/sldt/str (Red Pill)
 *  nopsled      long run of 0x90 or one-byte no-op equivalents
 *  privileged   in/out/cli/hlt/wrmsr/mov crN in user-mode code
 *  crypto       AES-NI / SHA / CRC32 / PCLMULQDQ instructions
 */
const apihash = require('../algorithms/apihash');

const PRINTABLE = (b) => (b >= 0x20 && b < 0x7f) || b === 0;
const ROT_HASH = new Set([13, 7, 5, 11, 19, 0xd]);

class Detector {
  constructor(arch, { windowSize = 48 } = {}) {
    this.arch = arch;
    this.win = [];
    this.windowSize = windowSize;
    this.hits = new Map(); // id → { count, at: [addr…], evidence: Set }
    this.stack = { run: [], lastVa: 0 };
    this.push = { run: [] };
    this.nop = { start: null, bytes: 0 };
    this.armWide = new Map(); // arm64: reg → assembled constant
    this.lastInsVa = null;
    this.stackStrings = [];
    this.count = 0;
    this.invalid = 0;
  }

  hit(id, va, evidence) {
    let h = this.hits.get(id);
    if (!h) { h = { count: 0, at: [], evidence: new Set() }; this.hits.set(id, h); }
    h.count++;
    if (h.at.length < 64) h.at.push(va);
    if (evidence && h.evidence.size < 32) h.evidence.add(evidence);
  }

  /** feed(null) marks a discontinuity (new execution path) */
  feed(ins) {
    if (ins === null) { this.lastInsVa = -1; return; }
    this.count++;
    if (ins.invalid) this.invalid++;
    // A gap in the stream (new region / resync) resets the local state
    if (this.lastInsVa != null && ins.address !== this.lastInsVa) { this.win = []; this.flushStack(); this.flushPush(); this.flushNop(); }
    this.lastInsVa = ins.address + ins.length;
    if (this.arch === 'arm64') this.feedArm(ins); else this.feedX86(ins);
    this.win.push(ins);
    if (this.win.length > this.windowSize) this.win.shift();
  }

  prev(k = 1) { return this.win[this.win.length - k]; }

  /* ------------------------------ x86 / x64 ------------------------------ */
  feedX86(ins) {
    const m = ins.mnemonic, ops = ins.operands || [];
    const p = this.prev();
    // NOP sled (0x90 and other single-byte no-op equivalents commonly used in polymorphic sleds)
    const nopLike = ins.length === 1 && (m === 'nop' || (this.arch === 'x86' && /^(inc|dec)$/.test(m)) || /^(cld|clc|stc|cmc|cwde|cdq|sahf|lahf|wait)$/.test(m));
    if (nopLike) { if (this.nop.start == null) this.nop.start = ins.address; this.nop.bytes++; }
    else this.flushNop();

    // GetPC
    if (m === 'call' && ins.target === ins.address + ins.length) this.getpcPending = ins.address;
    else if (this.getpcPending != null && m === 'pop' && p && p.address === this.getpcPending) { this.hit('getpc', ins.address, `call $+5 ; ${ins.text}`); this.getpcPending = null; }
    else this.getpcPending = null;
    if (m === 'fnstenv' && ops[0] && ops[0].base && /sp$/.test(ops[0].base) && ops[0].disp === -12) this.hit('getpc', ins.address, ins.text);
    if (m === 'call' && ins.target != null && ins.target < ins.address && ins.address - ins.target < 512) {
      // jmp-call-pop: the target must be right after a short forward jmp that lands on this call
      const j = this.win.find((w) => w.mnemonic === 'jmp' && w.target === ins.address && w.address < ins.address);
      if (j) this.hit('getpc', ins.address, 'jmp/call/pop');
    }

    // PEB / TEB access
    for (const o of ops) {
      if (o.type !== 'mem' || !o.seg) continue;
      const d = typeof o.disp === 'bigint' ? Number(o.disp) : o.disp;
      if (!o.index && ((o.seg === 'fs' && (d === 0x30 || d === 0x18)) || (o.seg === 'gs' && (d === 0x60 || d === 0x30)))) {
        this.hit('peb', ins.address, ins.text);
        this.pebReg = ops[0] && ops[0].type === 'reg' ? ops[0].reg : null;
        this.pebAt = this.count;
      }
    }
    // BeingDebugged: byte [peb + 2] shortly after reading the PEB
    if (this.pebReg && this.count - this.pebAt < 6 && ops.some((o) => o.type === 'mem' && o.base === this.pebReg && o.disp === 2 && o.size === 1)) this.hit('antidebug', ins.address, 'PEB.BeingDebugged');

    // API hashing loop (checked on the loop's back edge, see below): rotation by a typical amount of an
    // accumulator that is then combined with a character read byte by byte. A rotation alone is not
    // enough: compilers emit ror/rol for division by constants and bit tricks, and hash/cipher rounds
    // (SHA-2, ChaCha, Murmur…) are full of rotations but do not walk a string a byte at a time.
    // Hash constants (cmp/push/mov imm32)
    for (const o of ops) {
      if (o.type === 'imm' && typeof o.value === 'number' && (o.size === 4 || o.size === 8)) {
        const r = apihash.lookup(o.value >>> 0);
        if (r && /^(cmp|push|mov|sub|xor)$/.test(m)) this.hit('apihash', ins.address, `0x${(o.value >>> 0).toString(16)} = ${r[0].module}!${r[0].api} (${r[0].alg})`);
      }
    }

    // System calls
    if (m === 'syscall' || m === 'sysenter' || (m === 'int' && ops[0] && (ops[0].value === 0x2e || ops[0].value === 0x80))) {
      this.hit('syscall', ins.address, ins.text);
      const w = this.win.slice(-4);
      if (w.some((x) => x.mnemonic === 'mov' && x.operands[0]?.reg === 'r10' && x.operands[1]?.reg === 'rcx') && w.some((x) => x.mnemonic === 'mov' && x.operands[0]?.reg === 'eax' && x.operands[1]?.type === 'imm')) this.hit('hellsgate', ins.address, 'mov r10, rcx ; mov eax, SSN ; syscall');
    }

    // Anti-debug / anti-VM
    if (m === 'rdtsc') this.hit('rdtsc', ins.address);
    if (m === 'int' && ops[0] && ops[0].value === 0x2d) this.hit('antidebug', ins.address, 'int 0x2d');
    if (m === 'int1') this.hit('antidebug', ins.address, 'icebp (int1)');
    if (m === 'cpuid' && p && p.mnemonic === 'mov' && p.operands[0]?.reg === 'eax' && p.operands[1]?.value === 0x40000000) this.hit('antivm', ins.address, 'cpuid 0x40000000 (hypervisor)');
    if (m === 'in' && this.win.slice(-6).some((x) => x.operands?.some((o) => o.type === 'imm' && o.value === 0x564d5868))) this.hit('antivm', ins.address, "backdoor VMware 'VMXh'");
    if (/^(sidt|sgdt|sldt|str)$/.test(m)) this.hit('antivm', ins.address, `${m} (Red Pill)`);
    if (ins.privileged) this.hit('privileged', ins.address, m);
    if (/^v?(aes|sha1|sha256|pclmulqdq|crc32)/.test(m)) this.hit('crypto', ins.address, m.replace(/^v/, ''));

    // Self-decrypting loop: backward branch over a short body that modifies memory with xor/add/sub/rot
    if ((ins.flow === 'jcc' || ins.flow === 'jmp') && ins.target != null && ins.target < ins.address && ins.address - ins.target <= 96) {
      const body = this.win.filter((w) => w.address >= ins.target && w.address < ins.address);
      this.hashLoopX86(body);
      const mod = body.find((w) => /^(xor|add|sub|rol|ror|not|neg|xchg)$/.test(w.mnemonic) && w.operands[0]?.type === 'mem' && !(w.operands[0].base && /[sb]p$/.test(w.operands[0].base)));
      const step = body.some((w) => /^(inc|dec|add|sub|lea|lods|stos|loop)/.test(w.mnemonic) && w !== mod) || /^loop/.test(m);
      const viaReg = body.some((w) => /^lods/.test(w.mnemonic)) && body.some((w) => /^(xor|add|sub|rol|ror)$/.test(w.mnemonic) && w.operands[0]?.reg === 'al') && body.some((w) => /^stos/.test(w.mnemonic));
      if ((mod && step && (!mod.operands[1] || mod.operands[1].type !== 'mem')) || viaReg) this.hit('decoder', ins.target, (mod || body[0]).text);
    }

    // Stack strings: mov byte/word/dword [rsp/rbp/esp/ebp + d], printable imm
    const dst = ops[0];
    if (m === 'mov' && dst && dst.type === 'mem' && dst.base && /^[re]?(sp|bp)$/.test(dst.base) && !dst.index && ops[1]?.type === 'imm' && typeof ops[1].value === 'number' && dst.size <= 8) {
      const size = Math.min(dst.size, 4);
      const v = ops[1].value >>> 0;
      const bytes = []; for (let i = 0; i < size; i++) bytes.push((v >>> (8 * i)) & 0xff);
      if (bytes.every(PRINTABLE)) { this.stack.run.push({ off: dst.disp, bytes, va: ins.address }); return; }
    }
    this.flushStack();
    // push imm32 sequences (classic shellcode: push "exe" ; push "calc." …)
    if (m === 'push' && ops[0]?.type === 'imm' && typeof ops[0].value === 'number') {
      const v = ops[0].value >>> 0;
      const bytes = [0, 1, 2, 3].map((i) => (v >>> (8 * i)) & 0xff);
      if (bytes.every(PRINTABLE) && bytes.some((b) => b)) { this.push.run.push({ bytes, va: ins.address }); return; }
    }
    this.flushPush();
  }

  /** Rotate-and-combine hashing of a string, in the body of a short loop */
  hashLoopX86(body) {
    const rot = (w) => /^(ror|rol)$/.test(w.mnemonic) && w.operands[0]?.type === 'reg' && w.operands[1]?.type === 'imm';
    const rots = body.filter(rot);
    if (rots.length !== 1 || !ROT_HASH.has(rots[0].operands[1].value)) return;
    if (body.some((w) => w.flow === 'call' || /^(shld|shrd|rorx)$/.test(w.mnemonic))) return;
    const acc = rots[0].operands[0].reg.replace(/^r/, 'e');
    const i = body.indexOf(rots[0]);
    const combine = body.some((w, j) => j !== i && /^(add|xor)$/.test(w.mnemonic) && w.operands[0]?.type === 'reg' && w.operands[0].reg.replace(/^r/, 'e') === acc && w.operands[1]?.type === 'reg');
    const byteLoad = body.some((w) => /^lods/.test(w.mnemonic) || (/^(movzx|movsx|mov)$/.test(w.mnemonic) && w.operands[1]?.type === 'mem' && w.operands[1].size === 1));
    if (combine && byteLoad) this.hit('hashloop', rots[0].address, `ror${rots[0].operands[1].value} hashing`);
  }

  flushNop() {
    if (this.nop.bytes >= 16) this.hit('nopsled', this.nop.start, `${this.nop.bytes} byte`);
    if (this.nop.bytes >= 16) { const h = this.hits.get('nopsled'); h.max = Math.max(h.max || 0, this.nop.bytes); }
    this.nop = { start: null, bytes: 0 };
  }

  flushStack() {
    const run = this.stack.run;
    if (run.length >= 3) {
      const map = new Map();
      for (const r of run) r.bytes.forEach((b, i) => map.set(r.off + i, b));
      const offs = [...map.keys()].sort((a, b) => a - b);
      let s = '';
      for (let i = 0; i < offs.length; i++) { if (i && offs[i] !== offs[i - 1] + 1) s += '|'; const b = map.get(offs[i]); s += b ? String.fromCharCode(b) : '\0'; }
      const parts = s.split(/[\0|]+/).filter((x) => x.length >= 4 && /[a-z]{2}/i.test(x));
      for (const part of parts) { this.stackStrings.push(part); this.hit('stackstr', run[0].va, part); }
    }
    this.stack.run = [];
  }

  flushPush() {
    const run = this.push.run;
    if (run.length >= 2) {
      const bytes = [];
      for (let i = run.length - 1; i >= 0; i--) bytes.push(...run[i].bytes);
      const s = Buffer.from(bytes).toString('latin1').split('\0').filter((x) => x.length >= 4 && /[a-z]{2}/i.test(x));
      for (const part of s) { this.stackStrings.push(part); this.hit('stackstr', run[0].va, part); }
    }
    this.push.run = [];
  }

  /* ------------------------------ arm64 ------------------------------ */
  feedArm(ins) {
    const m = ins.mnemonic;
    if (m === 'svc') {
      this.hit('syscall', ins.address, ins.text);
      // macOS ptrace(PT_DENY_ATTACH): x16 = 26 (SYS_ptrace), x0 = 31
      const w = this.win.slice(-8).map((x) => x.text);
      if (w.some((t) => /^mov [wx]16, #0x1a$/.test(t)) && w.some((t) => /^mov [wx]0, #0x1f$/.test(t))) this.hit('antidebug', ins.address, 'ptrace(PT_DENY_ATTACH)');
    }
    if (m === 'mrs' && /cntvct|cntpct/.test(String(ins.sysreg))) this.hit('rdtsc', ins.address);
    if (/^(crc32|aes|sha)/.test(m)) this.hit('crypto', ins.address, m);
    // Wide-move constants (movz/movk) → API hash dictionary and stack strings
    const reg = (ins.opText || '').split(',')[0];
    if (ins.wide === 'movz' || (m === 'mov' && ins.imm != null && ins.imm16 != null)) this.armWide.set(reg.replace(/^w/, 'x'), BigInt(ins.imm16) << BigInt(ins.hw * 16));
    else if (ins.wide === 'movk' && this.armWide.has(reg.replace(/^w/, 'x'))) {
      const r = reg.replace(/^w/, 'x');
      const v = (this.armWide.get(r) & ~(0xffffn << BigInt(ins.hw * 16))) | (BigInt(ins.imm16) << BigInt(ins.hw * 16));
      this.armWide.set(r, v);
      const lo = Number(v & 0xffffffffn) >>> 0;
      const hh = apihash.lookup(lo);
      if (hh) this.hit('apihash', ins.address, `0x${lo.toString(16)} = ${hh[0].module}!${hh[0].api} (${hh[0].alg})`);
    }
    if ((m === 'str' || m === 'stur') && ins.store && /\[(sp|x29)/.test(ins.opText || '')) {
      const r = reg.replace(/^w/, 'x');
      const v = this.armWide.get(r);
      if (v != null) {
        const bytes = []; for (let i = 0; i < (reg.startsWith('x') ? 8 : 4); i++) bytes.push(Number((v >> BigInt(8 * i)) & 0xffn));
        if (bytes.every(PRINTABLE) && bytes.filter(Boolean).length >= 3) { this.stack.run.push({ off: ins.mem ? ins.mem.disp : 0, bytes, va: ins.address }); return; }
      }
    }
    if (ins.flow === 'jcc' || ins.flow === 'jmp') {
      if (ins.target != null && ins.target < ins.address && ins.address - ins.target <= 96) {
        const body = this.win.filter((w) => w.address >= ins.target && w.address < ins.address);
        // byte-wise decryption: ldrb → eor → strb in the same short loop
        const eor = body.find((w) => w.mnemonic === 'eor' && !/sp/.test(w.opText));
        if (eor && body.some((w) => w.mnemonic === 'ldrb') && body.some((w) => w.mnemonic === 'strb')) this.hit('decoder', ins.target, eor.text);
        // ror by a typical hashing amount (immediate or shifted operand "eor w8, w9, w8, ror #13"),
        // a byte load, a combine, a single rotation and no calls (division by constants uses ror #1/#2,
        // cipher rounds use many rotations)
        const amount = (w) => { const mm = /\bror #(0x[0-9a-f]+|\d+)$/.exec(w.opText || ''); return mm ? Number(mm[1]) : (w.mnemonic === 'ror' && w.rot != null ? w.rot : null); };
        const rots = body.filter((w) => amount(w) != null || w.mnemonic === 'extr' || w.mnemonic === 'ror');
        if (rots.length === 1 && ROT_HASH.has(amount(rots[0])) && !body.some((w) => w.flow === 'call')
          && body.some((w) => /^ldrb|^ldrsb/.test(w.mnemonic)) && body.some((w) => w !== rots[0] && /^(add|eor)$/.test(w.mnemonic))) this.hit('hashloop', ins.target, `ror${amount(rots[0])} hashing (arm64)`);
      }
    }
    if (ins.mnemonic === 'nop') { if (this.nop.start == null) this.nop.start = ins.address; this.nop.bytes += 4; } else this.flushNop();
    this.flushStack();
  }

  finish() {
    this.flushNop(); this.flushStack(); this.flushPush();
    const out = {};
    for (const [id, h] of this.hits) out[id] = { count: h.count, at: h.at, evidence: [...h.evidence], max: h.max };
    return out;
  }
}

/** Runs the detector over a linear sweep of [start, end) */
function scanRange(buf, start, end, arch, base, decode, detector, limit = Infinity) {
  const det = detector || new Detector(arch);
  let n = 0;
  for (let off = start; off < end && n < limit; n++) {
    const ins = decode(buf, off, base + (off - start));
    det.feed(ins);
    off += ins.length;
  }
  return det;
}

module.exports = { Detector, scanRange };
