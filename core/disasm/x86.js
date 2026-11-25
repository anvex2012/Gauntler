// Creato da anvex2012
'use strict';
/**
 * x86 / x86-64 disassembler (pure JavaScript, table driven, Intel syntax).
 *
 * Decodes: legacy prefixes, REX, VEX (C4/C5), EVEX (62), ModRM/SIB/displacement, RIP-relative
 * addressing, 16/32/64-bit operand and address sizes, the whole one-byte map, the commonly used
 * two-byte (0F) map, the 0F38/0F3A maps and the x87 escape. Unknown opcodes in the SSE/AVX maps are
 * still decoded with the correct LENGTH (so the instruction stream never desynchronizes).
 *
 * decode(buf, offset, { bits, address }) → instruction object:
 *   { address, offset, length, bytes, mnemonic, operands:[{type,…}], text, flow, target, invalid, privileged }
 *   flow: 'seq' | 'jmp' | 'jcc' | 'call' | 'ret' | 'int' | 'syscall' | 'halt' | 'invalid'
 */

const R8 = ['al', 'cl', 'dl', 'bl', 'ah', 'ch', 'dh', 'bh'];
const R8X = ['al', 'cl', 'dl', 'bl', 'spl', 'bpl', 'sil', 'dil', 'r8b', 'r9b', 'r10b', 'r11b', 'r12b', 'r13b', 'r14b', 'r15b'];
const R16 = ['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di', 'r8w', 'r9w', 'r10w', 'r11w', 'r12w', 'r13w', 'r14w', 'r15w'];
const R32 = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi', 'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d'];
const R64 = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'];
const SEG = ['es', 'cs', 'ss', 'ds', 'fs', 'gs', '?', '?'];
const CC = ['o', 'no', 'b', 'ae', 'e', 'ne', 'be', 'a', 's', 'ns', 'p', 'np', 'l', 'ge', 'le', 'g'];
const ALU = ['add', 'or', 'adc', 'sbb', 'and', 'sub', 'xor', 'cmp'];
const SHIFT = ['rol', 'ror', 'rcl', 'rcr', 'shl', 'shr', 'sal', 'sar'];
const PTR = { 1: 'byte', 2: 'word', 4: 'dword', 8: 'qword', 10: 'tbyte', 16: 'xmmword', 32: 'ymmword', 64: 'zmmword', 6: 'fword' };

/* ---------- one-byte opcode map ----------
 * Operand codes:  Eb Ev Ew Ed Gb Gv Gw Gz Ib Iw Iz Iv Ibs Jb Jz M Mp Sw AL rAX CL DX Zb Zv Ob Ov 1 Ap Ew
 * Flags: i64 = invalid in 64-bit mode; d64 = default 64-bit operand size in 64-bit mode; f64 = forced 64.
 */
const OP1 = new Array(256);
const def = (op, m, ops = [], extra = {}) => { OP1[op] = { m, ops, ...extra }; };
for (let i = 0; i < 8; i++) {
  const b = i * 8;
  def(b, ALU[i], ['Eb', 'Gb']); def(b + 1, ALU[i], ['Ev', 'Gv']); def(b + 2, ALU[i], ['Gb', 'Eb']);
  def(b + 3, ALU[i], ['Gv', 'Ev']); def(b + 4, ALU[i], ['AL', 'Ib']); def(b + 5, ALU[i], ['rAX', 'Iz']);
}
def(0x06, 'push es', [], { i64: 1 }); def(0x07, 'pop es', [], { i64: 1 }); def(0x0e, 'push cs', [], { i64: 1 });
def(0x16, 'push ss', [], { i64: 1 }); def(0x17, 'pop ss', [], { i64: 1 }); def(0x1e, 'push ds', [], { i64: 1 }); def(0x1f, 'pop ds', [], { i64: 1 });
def(0x27, 'daa', [], { i64: 1 }); def(0x2f, 'das', [], { i64: 1 }); def(0x37, 'aaa', [], { i64: 1 }); def(0x3f, 'aas', [], { i64: 1 });
for (let r = 0; r < 8; r++) {
  def(0x40 + r, 'inc', ['Zv'], { i64: 1 }); def(0x48 + r, 'dec', ['Zv'], { i64: 1 });
  def(0x50 + r, 'push', ['Zv'], { d64: 1 }); def(0x58 + r, 'pop', ['Zv'], { d64: 1 });
  def(0x91 + r - 1, r ? 'xchg' : 'nop', r ? ['Zv', 'rAX'] : []);
  def(0xb0 + r, 'mov', ['Zb', 'Ib']); def(0xb8 + r, 'mov', ['Zv', 'Iv']);
}
def(0x60, 'pushad', [], { i64: 1 }); def(0x61, 'popad', [], { i64: 1 }); def(0x62, 'bound', ['Gv', 'M'], { i64: 1 });
def(0x63, 'arpl', ['Ew', 'Gw']);
def(0x68, 'push', ['Iz'], { d64: 1 }); def(0x69, 'imul', ['Gv', 'Ev', 'Iz']); def(0x6a, 'push', ['Ibs'], { d64: 1 }); def(0x6b, 'imul', ['Gv', 'Ev', 'Ibs']);
def(0x6c, 'insb'); def(0x6d, 'insd'); def(0x6e, 'outsb'); def(0x6f, 'outsd');
for (let c = 0; c < 16; c++) def(0x70 + c, 'j' + CC[c], ['Jb'], { flow: 'jcc' });
def(0x80, 'grp1', ['Eb', 'Ib'], { grp: ALU }); def(0x81, 'grp1', ['Ev', 'Iz'], { grp: ALU });
def(0x82, 'grp1', ['Eb', 'Ib'], { grp: ALU, i64: 1 }); def(0x83, 'grp1', ['Ev', 'Ibs'], { grp: ALU });
def(0x84, 'test', ['Eb', 'Gb']); def(0x85, 'test', ['Ev', 'Gv']); def(0x86, 'xchg', ['Eb', 'Gb']); def(0x87, 'xchg', ['Ev', 'Gv']);
def(0x88, 'mov', ['Eb', 'Gb']); def(0x89, 'mov', ['Ev', 'Gv']); def(0x8a, 'mov', ['Gb', 'Eb']); def(0x8b, 'mov', ['Gv', 'Ev']);
def(0x8c, 'mov', ['Ev', 'Sw']); def(0x8d, 'lea', ['Gv', 'M']); def(0x8e, 'mov', ['Sw', 'Ew']); def(0x8f, 'pop', ['Ev'], { d64: 1, grp: ['pop'] });
def(0x98, 'cwde'); def(0x99, 'cdq'); def(0x9a, 'call far', ['Ap'], { i64: 1, flow: 'call' }); def(0x9b, 'wait');
def(0x9c, 'pushfd', [], { d64: 1 }); def(0x9d, 'popfd', [], { d64: 1 }); def(0x9e, 'sahf'); def(0x9f, 'lahf');
def(0xa0, 'mov', ['AL', 'Ob']); def(0xa1, 'mov', ['rAX', 'Ov']); def(0xa2, 'mov', ['Ob', 'AL']); def(0xa3, 'mov', ['Ov', 'rAX']);
def(0xa4, 'movsb'); def(0xa5, 'movsd'); def(0xa6, 'cmpsb'); def(0xa7, 'cmpsd'); def(0xa8, 'test', ['AL', 'Ib']); def(0xa9, 'test', ['rAX', 'Iz']);
def(0xaa, 'stosb'); def(0xab, 'stosd'); def(0xac, 'lodsb'); def(0xad, 'lodsd'); def(0xae, 'scasb'); def(0xaf, 'scasd');
def(0xc0, 'grp2', ['Eb', 'Ib'], { grp: SHIFT }); def(0xc1, 'grp2', ['Ev', 'Ib'], { grp: SHIFT });
def(0xc2, 'ret', ['Iw'], { flow: 'ret' }); def(0xc3, 'ret', [], { flow: 'ret' });
def(0xc4, 'les', ['Gz', 'Mp'], { i64: 1 }); def(0xc5, 'lds', ['Gz', 'Mp'], { i64: 1 });
def(0xc6, 'mov', ['Eb', 'Ib'], { grp: ['mov'] }); def(0xc7, 'mov', ['Ev', 'Iz'], { grp: ['mov'] });
def(0xc8, 'enter', ['Iw', 'Ib']); def(0xc9, 'leave', [], { d64: 1 }); def(0xca, 'retf', ['Iw'], { flow: 'ret' }); def(0xcb, 'retf', [], { flow: 'ret' });
def(0xcc, 'int3', [], { flow: 'int' }); def(0xcd, 'int', ['Ib'], { flow: 'int' }); def(0xce, 'into', [], { i64: 1, flow: 'int' }); def(0xcf, 'iretd', [], { flow: 'ret' });
def(0xd0, 'grp2', ['Eb', '1'], { grp: SHIFT }); def(0xd1, 'grp2', ['Ev', '1'], { grp: SHIFT });
def(0xd2, 'grp2', ['Eb', 'CL'], { grp: SHIFT }); def(0xd3, 'grp2', ['Ev', 'CL'], { grp: SHIFT });
def(0xd4, 'aam', ['Ib'], { i64: 1 }); def(0xd5, 'aad', ['Ib'], { i64: 1 }); def(0xd6, 'salc', [], { i64: 1 }); def(0xd7, 'xlatb');
for (let x = 0xd8; x <= 0xdf; x++) def(x, 'fpu', [], { fpu: 1 });
def(0xe0, 'loopne', ['Jb'], { flow: 'jcc' }); def(0xe1, 'loope', ['Jb'], { flow: 'jcc' }); def(0xe2, 'loop', ['Jb'], { flow: 'jcc' }); def(0xe3, 'jecxz', ['Jb'], { flow: 'jcc' });
def(0xe4, 'in', ['AL', 'Ib'], { priv: 1 }); def(0xe5, 'in', ['eAX', 'Ib'], { priv: 1 }); def(0xe6, 'out', ['Ib', 'AL'], { priv: 1 }); def(0xe7, 'out', ['Ib', 'eAX'], { priv: 1 });
def(0xe8, 'call', ['Jz'], { flow: 'call' }); def(0xe9, 'jmp', ['Jz'], { flow: 'jmp' }); def(0xea, 'jmp far', ['Ap'], { i64: 1, flow: 'jmp' }); def(0xeb, 'jmp', ['Jb'], { flow: 'jmp' });
def(0xec, 'in', ['AL', 'DX'], { priv: 1 }); def(0xed, 'in', ['eAX', 'DX'], { priv: 1 }); def(0xee, 'out', ['DX', 'AL'], { priv: 1 }); def(0xef, 'out', ['DX', 'eAX'], { priv: 1 });
def(0xf1, 'int1', [], { flow: 'int' }); def(0xf4, 'hlt', [], { flow: 'halt', priv: 1 }); def(0xf5, 'cmc');
def(0xf6, 'grp3', ['Eb'], { grp: ['test', 'test', 'not', 'neg', 'mul', 'imul', 'div', 'idiv'], g3: 'Ib' });
def(0xf7, 'grp3', ['Ev'], { grp: ['test', 'test', 'not', 'neg', 'mul', 'imul', 'div', 'idiv'], g3: 'Iz' });
def(0xf8, 'clc'); def(0xf9, 'stc'); def(0xfa, 'cli', [], { priv: 1 }); def(0xfb, 'sti', [], { priv: 1 }); def(0xfc, 'cld'); def(0xfd, 'std');
def(0xfe, 'grp4', ['Eb'], { grp: ['inc', 'dec'] });
def(0xff, 'grp5', ['Ev'], { grp: ['inc', 'dec', 'call', 'call far', 'jmp', 'jmp far', 'push'] });

/* ---------- two-byte opcode map (0F xx) ---------- */
const OP2 = new Array(256);
const def2 = (op, m, ops = [], extra = {}) => { OP2[op] = { m, ops, ...extra }; };
def2(0x00, 'grp6', ['Ew'], { grp: ['sldt', 'str', 'lldt', 'ltr', 'verr', 'verw'] });
def2(0x01, 'grp7', ['M'], { grp7: 1 });
def2(0x02, 'lar', ['Gv', 'Ew']); def2(0x03, 'lsl', ['Gv', 'Ew']);
def2(0x05, 'syscall', [], { flow: 'syscall' }); def2(0x06, 'clts', [], { priv: 1 }); def2(0x07, 'sysret', [], { flow: 'ret', priv: 1 });
def2(0x08, 'invd', [], { priv: 1 }); def2(0x09, 'wbinvd', [], { priv: 1 }); def2(0x0b, 'ud2', [], { flow: 'invalid' });
def2(0x0d, 'prefetchw', ['M']); def2(0x18, 'prefetch', ['M']);
for (let x = 0x19; x <= 0x1f; x++) def2(x, 'nop', ['Ev']);
def2(0x1e, 'nop', ['Ev'], { endbr: 1 });
def2(0x20, 'mov', ['Rd', 'Cd'], { priv: 1 }); def2(0x21, 'mov', ['Rd', 'Dd'], { priv: 1 }); def2(0x22, 'mov', ['Cd', 'Rd'], { priv: 1 }); def2(0x23, 'mov', ['Dd', 'Rd'], { priv: 1 });
def2(0x30, 'wrmsr', [], { priv: 1 }); def2(0x31, 'rdtsc'); def2(0x32, 'rdmsr', [], { priv: 1 }); def2(0x33, 'rdpmc');
def2(0x34, 'sysenter', [], { flow: 'syscall' }); def2(0x35, 'sysexit', [], { flow: 'ret', priv: 1 }); def2(0x37, 'getsec');
for (let c = 0; c < 16; c++) {
  def2(0x40 + c, 'cmov' + CC[c], ['Gv', 'Ev']);
  def2(0x80 + c, 'j' + CC[c], ['Jz'], { flow: 'jcc' });
  def2(0x90 + c, 'set' + CC[c], ['Eb']);
}
def2(0xa0, 'push fs', [], { d64: 1 }); def2(0xa1, 'pop fs', [], { d64: 1 }); def2(0xa2, 'cpuid');
def2(0xa3, 'bt', ['Ev', 'Gv']); def2(0xa4, 'shld', ['Ev', 'Gv', 'Ib']); def2(0xa5, 'shld', ['Ev', 'Gv', 'CL']);
def2(0xa8, 'push gs', [], { d64: 1 }); def2(0xa9, 'pop gs', [], { d64: 1 }); def2(0xaa, 'rsm', [], { priv: 1 });
def2(0xab, 'bts', ['Ev', 'Gv']); def2(0xac, 'shrd', ['Ev', 'Gv', 'Ib']); def2(0xad, 'shrd', ['Ev', 'Gv', 'CL']);
def2(0xae, 'grp15', ['M'], { grp15: 1 }); def2(0xaf, 'imul', ['Gv', 'Ev']);
def2(0xb0, 'cmpxchg', ['Eb', 'Gb']); def2(0xb1, 'cmpxchg', ['Ev', 'Gv']); def2(0xb2, 'lss', ['Gv', 'Mp']); def2(0xb3, 'btr', ['Ev', 'Gv']);
def2(0xb4, 'lfs', ['Gv', 'Mp']); def2(0xb5, 'lgs', ['Gv', 'Mp']); def2(0xb6, 'movzx', ['Gv', 'Eb']); def2(0xb7, 'movzx', ['Gv', 'Ew']);
def2(0xb8, 'popcnt', ['Gv', 'Ev']); def2(0xb9, 'ud1', ['Gv', 'Ev'], { flow: 'invalid' });
def2(0xba, 'grp8', ['Ev', 'Ib'], { grp: [null, null, null, null, 'bt', 'bts', 'btr', 'btc'] });
def2(0xbb, 'btc', ['Ev', 'Gv']); def2(0xbc, 'bsf', ['Gv', 'Ev']); def2(0xbd, 'bsr', ['Gv', 'Ev']);
def2(0xbe, 'movsx', ['Gv', 'Eb']); def2(0xbf, 'movsx', ['Gv', 'Ew']);
def2(0xc0, 'xadd', ['Eb', 'Gb']); def2(0xc1, 'xadd', ['Ev', 'Gv']); def2(0xc3, 'movnti', ['M', 'Gv']);
def2(0xc7, 'grp9', ['M'], { grp9: 1 });
for (let r = 0; r < 8; r++) def2(0xc8 + r, 'bswap', ['Zv']);
def2(0xff, 'ud0', ['Gv', 'Ev'], { flow: 'invalid' });

/* SSE names (no prefix / 66 / F3 / F2) for the most common opcodes: used for readable listings */
const SSE = {
  0x10: ['movups', 'movupd', 'movss', 'movsd'], 0x11: ['movups', 'movupd', 'movss', 'movsd'], 0x12: ['movlps', 'movlpd', 'movsldup', 'movddup'],
  0x13: ['movlps', 'movlpd'], 0x14: ['unpcklps', 'unpcklpd'], 0x15: ['unpckhps', 'unpckhpd'], 0x16: ['movhps', 'movhpd', 'movshdup'], 0x17: ['movhps', 'movhpd'],
  0x28: ['movaps', 'movapd'], 0x29: ['movaps', 'movapd'], 0x2a: ['cvtpi2ps', 'cvtpi2pd', 'cvtsi2ss', 'cvtsi2sd'], 0x2b: ['movntps', 'movntpd'],
  0x2c: ['cvttps2pi', 'cvttpd2pi', 'cvttss2si', 'cvttsd2si'], 0x2d: ['cvtps2pi', 'cvtpd2pi', 'cvtss2si', 'cvtsd2si'], 0x2e: ['ucomiss', 'ucomisd'], 0x2f: ['comiss', 'comisd'],
  0x50: ['movmskps', 'movmskpd'], 0x51: ['sqrtps', 'sqrtpd', 'sqrtss', 'sqrtsd'], 0x54: ['andps', 'andpd'], 0x55: ['andnps', 'andnpd'], 0x56: ['orps', 'orpd'], 0x57: ['xorps', 'xorpd'],
  0x58: ['addps', 'addpd', 'addss', 'addsd'], 0x59: ['mulps', 'mulpd', 'mulss', 'mulsd'], 0x5a: ['cvtps2pd', 'cvtpd2ps', 'cvtss2sd', 'cvtsd2ss'], 0x5b: ['cvtdq2ps', 'cvtps2dq', 'cvttps2dq'],
  0x5c: ['subps', 'subpd', 'subss', 'subsd'], 0x5d: ['minps', 'minpd', 'minss', 'minsd'], 0x5e: ['divps', 'divpd', 'divss', 'divsd'], 0x5f: ['maxps', 'maxpd', 'maxss', 'maxsd'],
  0x60: ['punpcklbw', 'punpcklbw'], 0x61: ['punpcklwd', 'punpcklwd'], 0x62: ['punpckldq', 'punpckldq'], 0x63: ['packsswb', 'packsswb'], 0x64: ['pcmpgtb', 'pcmpgtb'], 0x65: ['pcmpgtw', 'pcmpgtw'],
  0x66: ['pcmpgtd', 'pcmpgtd'], 0x67: ['packuswb', 'packuswb'], 0x68: ['punpckhbw', 'punpckhbw'], 0x69: ['punpckhwd', 'punpckhwd'], 0x6a: ['punpckhdq', 'punpckhdq'], 0x6b: ['packssdw', 'packssdw'],
  0x6c: [null, 'punpcklqdq'], 0x6d: [null, 'punpckhqdq'], 0x6e: ['movd', 'movd'], 0x6f: ['movq', 'movdqa', 'movdqu'], 0x70: ['pshufw', 'pshufd', 'pshufhw', 'pshuflw'],
  0x74: ['pcmpeqb', 'pcmpeqb'], 0x75: ['pcmpeqw', 'pcmpeqw'], 0x76: ['pcmpeqd', 'pcmpeqd'], 0x77: ['emms'], 0x7e: ['movd', 'movd', 'movq'], 0x7f: ['movq', 'movdqa', 'movdqu'],
  0xc2: ['cmpps', 'cmppd', 'cmpss', 'cmpsd'], 0xc4: ['pinsrw', 'pinsrw'], 0xc5: ['pextrw', 'pextrw'], 0xc6: ['shufps', 'shufpd'],
  0xd4: ['paddq', 'paddq'], 0xd5: ['pmullw', 'pmullw'], 0xd6: [null, 'movq', 'movq2dq', 'movdq2q'], 0xd7: ['pmovmskb', 'pmovmskb'], 0xdb: ['pand', 'pand'], 0xdf: ['pandn', 'pandn'],
  0xe7: ['movntq', 'movntdq'], 0xeb: ['por', 'por'], 0xef: ['pxor', 'pxor'], 0xfe: ['paddd', 'paddd'], 0xfa: ['psubd', 'psubd'], 0xfc: ['paddb', 'paddb'], 0xf8: ['psubb', 'psubb'],
};
const SSE_IMM = new Set([0x70, 0x71, 0x72, 0x73, 0xc2, 0xc4, 0xc5, 0xc6]);
const M38 = { 0x00: 'pshufb', 0xdb: 'aesimc', 0xdc: 'aesenc', 0xdd: 'aesenclast', 0xde: 'aesdec', 0xdf: 'aesdeclast', 0xf0: 'movbe', 0xf1: 'movbe', 0x17: 'ptest', 0x2a: 'movntdqa', 0xc8: 'sha1nexte', 0xc9: 'sha1msg1', 0xca: 'sha1msg2', 0xcb: 'sha256rnds2', 0xcc: 'sha256msg1', 0xcd: 'sha256msg2' };
const M3A = { 0x0f: 'palignr', 0x16: 'pextrd', 0x22: 'pinsrd', 0x44: 'pclmulqdq', 0xdf: 'aeskeygenassist', 0x63: 'pcmpistri', 0x61: 'pcmpestri', 0xcc: 'sha1rnds4', 0x0b: 'roundsd', 0x0a: 'roundss' };
const FPU_MEM = {
  0xd8: ['fadd', 'fmul', 'fcom', 'fcomp', 'fsub', 'fsubr', 'fdiv', 'fdivr'], 0xd9: ['fld', null, 'fst', 'fstp', 'fldenv', 'fldcw', 'fnstenv', 'fnstcw'],
  0xda: ['fiadd', 'fimul', 'ficom', 'ficomp', 'fisub', 'fisubr', 'fidiv', 'fidivr'], 0xdb: ['fild', 'fisttp', 'fist', 'fistp', null, 'fld', null, 'fstp'],
  0xdc: ['fadd', 'fmul', 'fcom', 'fcomp', 'fsub', 'fsubr', 'fdiv', 'fdivr'], 0xdd: ['fld', 'fisttp', 'fst', 'fstp', 'frstor', null, 'fnsave', 'fnstsw'],
  0xde: ['fiadd', 'fimul', 'ficom', 'ficomp', 'fisub', 'fisubr', 'fidiv', 'fidivr'], 0xdf: ['fild', 'fisttp', 'fist', 'fistp', 'fbld', 'fild', 'fbstp', 'fistp'],
};
const FPU_SZ = { 0xd8: 4, 0xd9: 4, 0xda: 4, 0xdb: 4, 0xdc: 8, 0xdd: 8, 0xde: 2, 0xdf: 2 };
const FPU_REG = { 0xd9e8: 'fld1', 0xd9ee: 'fldz', 0xd9e0: 'fchs', 0xd9e1: 'fabs', 0xd9e4: 'ftst', 0xd9e5: 'fxam', 0xd9c9: 'fxch', 0xd9d0: 'fnop', 0xdbe3: 'fninit', 0xdbe2: 'fnclex', 0xdfe0: 'fnstsw ax', 0xd9eb: 'fldpi', 0xd9ea: 'fldl2e', 0xd9ec: 'fldlg2', 0xd9ed: 'fldln2', 0xd9f0: 'f2xm1', 0xd9fa: 'fsqrt', 0xd9fe: 'fsin', 0xd9ff: 'fcos', 0xded9: 'fcompp', 0xdae9: 'fucompp' };

const hex = (n) => (n < 0 ? '-0x' + (-n).toString(16) : '0x' + n.toString(16));
const hexU = (n) => '0x' + (typeof n === 'bigint' ? n : BigInt(n)).toString(16);

/** Decoded instruction; the Intel-syntax text is built lazily (only when shown) */
class Ins {
  constructor(address, offset) { this.address = address; this.offset = offset; this.length = 0; this.mnemonic = ''; this.operands = []; this.prefixes = []; this.flow = 'seq'; this._text = null; }
  get text() { if (this._text === null) this._text = format(this); return this._text; }
  set text(v) { this._text = v; }
}

class Reader {
  constructor(buf, off, end) { this.b = buf; this.p = off; this.end = end; this.bad = false; }
  u8() { if (this.p >= this.end) { this.bad = true; return 0; } return this.b[this.p++]; }
  s8() { const v = this.u8(); return v > 127 ? v - 256 : v; }
  u16() { return this.u8() | (this.u8() << 8); }
  s16() { const v = this.u16(); return v > 32767 ? v - 65536 : v; }
  u32() { return (this.u8() | (this.u8() << 8) | (this.u8() << 16) | (this.u8() << 24)) >>> 0; }
  s32() { return this.u32() | 0; }
  u64() { const lo = BigInt(this.u32()), hi = BigInt(this.u32()); return (hi << 32n) | lo; }
}

function regName(n, size, rex) {
  if (size === 1) return rex ? R8X[n] : R8[n] || R8X[n];
  if (size === 2) return R16[n];
  if (size === 4) return R32[n];
  return R64[n];
}

/**
 * Decodes ONE instruction at buf[off].
 * opts: { bits: 32|64, address: virtual address of buf[off] (Number or BigInt-safe Number) }
 */
function decode(buf, off, opts = {}) {
  const bits = opts.bits || 64;
  const x64 = bits === 64;
  const addr = opts.address != null ? opts.address : off;
  const end = Math.min(buf.length, off + 15);
  const rd = new Reader(buf, off, end);
  const ins = new Ins(addr, off);
  let opsize = 0, adsize = 0, rep = 0, lock = 0, seg = null, rex = 0;
  // ---- prefixes
  for (;;) {
    const b = buf[rd.p];
    if (rd.p >= end) break;
    if (b === 0x66) { opsize = 1; rd.p++; ins.prefixes.push('66'); }
    else if (b === 0x67) { adsize = 1; rd.p++; }
    else if (b === 0xf2 || b === 0xf3) { rep = b; rd.p++; }
    else if (b === 0xf0) { lock = 1; rd.p++; }
    else if ([0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65].includes(b)) { seg = { 0x26: 'es', 0x2e: 'cs', 0x36: 'ss', 0x3e: 'ds', 0x64: 'fs', 0x65: 'gs' }[b]; rd.p++; }
    else break;
  }
  if (x64 && rd.p < end && (buf[rd.p] & 0xf0) === 0x40) rex = buf[rd.p++];
  const W = !!(rex & 8), Rx = (rex & 4) ? 8 : 0, Xx = (rex & 2) ? 8 : 0, Bx = (rex & 1) ? 8 : 0;
  const ADDR = x64 ? (adsize ? 4 : 8) : (adsize ? 2 : 4);
  let OPV = x64 ? (W ? 8 : opsize ? 2 : 4) : (opsize ? 2 : 4);
  ins.seg = seg; ins.rep = rep; ins.lock = lock; ins.rex = rex;

  let op = rd.u8();
  let entry, map = 1, vex = null;

  // ---- VEX / EVEX
  const isVex = (op === 0xc4 || op === 0xc5) && rd.p < end && (x64 || (buf[rd.p] & 0xc0) === 0xc0);
  const isEvex = op === 0x62 && rd.p < end && (x64 || (buf[rd.p] & 0xc0) === 0xc0);
  if (isVex || isEvex) {
    let mmmmm = 1, pp = 0, L = 0, vvvv = 0, vR = 0, vB = 0, vW = 0;
    if (op === 0xc5) { const p1 = rd.u8(); vR = p1 & 0x80 ? 0 : 8; vvvv = (~p1 >> 3) & 15; L = (p1 >> 2) & 1; pp = p1 & 3; }
    else if (op === 0xc4) { const p1 = rd.u8(), p2 = rd.u8(); vR = p1 & 0x80 ? 0 : 8; vB = p1 & 0x20 ? 0 : 8; mmmmm = p1 & 31; vW = p2 >> 7; vvvv = (~p2 >> 3) & 15; L = (p2 >> 2) & 1; pp = p2 & 3; }
    else { const p1 = rd.u8(), p2 = rd.u8(), p3 = rd.u8(); vR = p1 & 0x80 ? 0 : 8; vB = p1 & 0x20 ? 0 : 8; mmmmm = p1 & 7; vW = p2 >> 7; vvvv = (~p2 >> 3) & 15; pp = p2 & 3; L = (p3 >> 5) & 3; }
    vex = { evex: op === 0x62, pp, L, vvvv, W: vW };
    map = mmmmm === 2 ? 0x38 : mmmmm === 3 ? 0x3a : 2;
    op = rd.u8();
    const modrm = parseModRM(rd, buf, { x64, ADDR, Rx: vR, Xx: 0, Bx: vB, seg });
    let imm = null;
    if (map === 0x3a || (map === 2 && SSE_IMM.has(op))) imm = rd.u8();
    const vsz = vex.evex ? [16, 32, 64][L] || 64 : L ? 32 : 16;
    const vr = vex.evex ? ['xmm', 'ymm', 'zmm'][L] || 'zmm' : L ? 'ymm' : 'xmm';
    const name = map === 2 ? ((SSE[op] || [])[[0, 1, 2, 3][pp]] || (SSE[op] || [])[0]) : map === 0x38 ? M38[op] : M3A[op];
    ins.mnemonic = 'v' + (name || `${map === 2 ? '' : map.toString(16)}op_${op.toString(16).padStart(2, '0')}`);
    ins.operands.push({ type: 'reg', reg: vr + modrm.reg });
    if (vvvv) ins.operands.push({ type: 'reg', reg: vr + vvvv });
    ins.operands.push(modrm.mod === 3 ? { type: 'reg', reg: vr + modrm.rm } : { ...modrm.mem, size: vsz });
    if (imm !== null) ins.operands.push({ type: 'imm', value: imm, size: 1 });
    ins.vex = vex;
    return finish(ins, rd, buf, off, addr);
  }

  if (op === 0x0f) {
    op = rd.u8();
    if (op === 0x38 || op === 0x3a) { map = op; op = rd.u8(); }
    else { map = 2; }
  }

  if (map === 1) {
    entry = OP1[op];
    if (!entry) return invalid(ins, rd, buf, off, addr, 'prefisso isolato');
    if (x64 && entry.i64) return invalid(ins, rd, buf, off, addr, 'non valida in 64 bit');
    if (x64 && (entry.d64) && !opsize) OPV = 8;
    if (x64 && entry.flow && (entry.m === 'call' || entry.m === 'jmp' || entry.flow === 'jcc')) OPV = 8;
    // special cases
    if (op === 0x90) {
      if (Bx) { ins.mnemonic = 'xchg'; ins.operands.push({ type: 'reg', reg: regName(8, OPV, rex) }, { type: 'reg', reg: regName(0, OPV, rex) }); return finish(ins, rd, buf, off, addr); }
      ins.mnemonic = rep === 0xf3 ? 'pause' : 'nop'; return finish(ins, rd, buf, off, addr);
    }
    if (op === 0x63 && x64) { entry = { m: 'movsxd', ops: ['Gv', 'Ed'] }; }
    if (op === 0x98) ins.mnemonic = OPV === 8 ? 'cdqe' : OPV === 2 ? 'cbw' : 'cwde';
    if (op === 0x99) ins.mnemonic = OPV === 8 ? 'cqo' : OPV === 2 ? 'cwd' : 'cdq';
    if (op === 0xe3) ins.mnemonic = x64 ? (adsize ? 'jecxz' : 'jrcxz') : (adsize ? 'jcxz' : 'jecxz');
    if ([0xa5, 0xa7, 0xab, 0xad, 0xaf, 0x6d, 0x6f].includes(op)) ins.mnemonic = entry.m.slice(0, -1) + (OPV === 8 ? 'q' : OPV === 2 ? 'w' : 'd');
    if (op === 0x9c || op === 0x9d) ins.mnemonic = entry.m.slice(0, -1) + (x64 ? 'q' : 'd');
    if (op === 0xcf) ins.mnemonic = OPV === 8 ? 'iretq' : 'iretd';
    if (entry.fpu) return decodeFpu(ins, rd, buf, off, addr, op, { x64, ADDR, Rx, Xx, Bx, seg });
  } else if (map === 2) {
    entry = OP2[op];
    if (op === 0x1e && rep === 0xf3 && buf[rd.p] === 0xfa) { rd.p++; ins.mnemonic = 'endbr64'; return finish(ins, rd, buf, off, addr); }
    if (op === 0x1e && rep === 0xf3 && buf[rd.p] === 0xfb) { rd.p++; ins.mnemonic = 'endbr32'; return finish(ins, rd, buf, off, addr); }
    if (op === 0xb8 && rep !== 0xf3) return invalid(ins, rd, buf, off, addr, 'jmpe');
    if (op === 0xbc && rep === 0xf3) entry = { m: 'tzcnt', ops: ['Gv', 'Ev'] };
    if (op === 0xbd && rep === 0xf3) entry = { m: 'lzcnt', ops: ['Gv', 'Ev'] };
    if (!entry) {
      // SSE / MMX / other: ModRM + (imm8) — correct length, generic name if unknown
      const modrm = parseModRM(rd, buf, { x64, ADDR, Rx, Xx, Bx, seg });
      const pidx = rep === 0xf3 ? 2 : rep === 0xf2 ? 3 : opsize ? 1 : 0;
      const names = SSE[op];
      ins.mnemonic = (names && (names[pidx] || names[0])) || `op_0f${op.toString(16).padStart(2, '0')}`;
      const mm = op >= 0x60 && op <= 0x7f && !opsize && !rep ? 'mm' : 'xmm';
      const gpForm = (op === 0x6e || op === 0x7e) && rep !== 0xf3;
      if (gpForm) {
        ins.mnemonic = W ? 'movq' : 'movd';
        const gp = modrm.mod === 3 ? { type: 'reg', reg: regName(modrm.rm, W ? 8 : 4, rex) } : { ...modrm.mem, size: W ? 8 : 4 };
        const xr = { type: 'reg', reg: mm + modrm.reg };
        ins.operands.push(...(op === 0x6e ? [xr, gp] : [gp, xr]));
        return finish(ins, rd, buf, off, addr);
      }
      ins.operands.push({ type: 'reg', reg: mm + modrm.reg });
      ins.operands.push(modrm.mod === 3 ? { type: 'reg', reg: mm + modrm.rm } : { ...modrm.mem, size: 16 });
      if (SSE_IMM.has(op) || (op >= 0x71 && op <= 0x73)) ins.operands.push({ type: 'imm', value: rd.u8(), size: 1 });
      return finish(ins, rd, buf, off, addr);
    }
    if (x64 && (entry.d64 || entry.flow === 'jcc') && !opsize) OPV = 8;
  } else {
    // 0F 38 / 0F 3A: always ModRM, 3A has imm8
    const modrm = parseModRM(rd, buf, { x64, ADDR, Rx, Xx, Bx, seg });
    let name = map === 0x38 ? M38[op] : M3A[op];
    if (map === 0x38 && (op === 0xf0 || op === 0xf1) && rep === 0xf2) name = 'crc32';
    ins.mnemonic = name || `op_0f${map.toString(16)}${op.toString(16).padStart(2, '0')}`;
    const gp = name === 'crc32' || name === 'movbe';
    ins.operands.push({ type: 'reg', reg: gp ? regName(modrm.reg, OPV, rex) : 'xmm' + modrm.reg });
    ins.operands.push(modrm.mod === 3 ? { type: 'reg', reg: gp ? regName(modrm.rm, op === 0xf0 ? 1 : OPV, rex) : 'xmm' + modrm.rm } : { ...modrm.mem, size: gp ? (op === 0xf0 ? 1 : OPV) : 16 });
    if (map === 0x3a) ins.operands.push({ type: 'imm', value: rd.u8(), size: 1 });
    return finish(ins, rd, buf, off, addr);
  }

  if (!ins.mnemonic) ins.mnemonic = entry.m;
  if (entry.flow) ins.flow = entry.flow;
  if (entry.priv) ins.privileged = true;
  const needsModrm = entry.grp || entry.grp7 || entry.grp9 || entry.grp15 || entry.ops.some((o) => /^(E|G|M|S|R|C|D)/.test(o));
  let modrm = null;
  if (needsModrm) modrm = parseModRM(rd, buf, { x64, ADDR, Rx, Xx, Bx, seg });

  if (entry.grp7) return decodeGrp7(ins, rd, buf, off, addr, modrm);
  if (entry.grp15) {
    if (modrm.mod === 3) ins.mnemonic = ['rdfsbase', 'rdgsbase', 'wrfsbase', 'wrgsbase', 'incsspq', 'lfence', 'mfence', 'sfence'][modrm.regRaw];
    else { ins.mnemonic = ['fxsave', 'fxrstor', 'ldmxcsr', 'stmxcsr', 'xsave', 'xrstor', 'xsaveopt', 'clflush'][modrm.regRaw]; ins.operands.push(modrm.mem); }
    return finish(ins, rd, buf, off, addr);
  }
  if (entry.grp9) {
    if (modrm.mod === 3) { ins.mnemonic = { 6: 'rdrand', 7: rep === 0xf3 ? 'rdpid' : 'rdseed' }[modrm.regRaw] || 'op_0fc7'; ins.operands.push({ type: 'reg', reg: regName(modrm.rm, OPV, rex) }); }
    else { ins.mnemonic = modrm.regRaw === 1 ? (W ? 'cmpxchg16b' : 'cmpxchg8b') : ['', '', '', 'xrstors', 'xsavec', 'xsaves', 'vmptrld', 'vmptrst'][modrm.regRaw] || 'op_0fc7'; ins.operands.push({ ...modrm.mem, size: W ? 16 : 8 }); }
    return finish(ins, rd, buf, off, addr);
  }
  let ops = entry.ops;
  if (entry.grp) {
    const g = entry.grp[modrm.regRaw];
    if (!g) return invalid(ins, rd, buf, off, addr, 'gruppo non valido');
    ins.mnemonic = g;
    if (op === 0xff && map === 1) {
      if (modrm.regRaw === 2) { ins.flow = 'call'; if (x64) OPV = 8; }
      if (modrm.regRaw === 4) { ins.flow = 'jmp'; if (x64) OPV = 8; }
      if ((modrm.regRaw === 3 || modrm.regRaw === 5) && modrm.mod === 3) return invalid(ins, rd, buf, off, addr, 'far con registro');
      if (modrm.regRaw === 3 || modrm.regRaw === 5) { ins.flow = modrm.regRaw === 3 ? 'call' : 'jmp'; ops = ['Mp']; }
      if (modrm.regRaw === 6 && x64) OPV = 8;
    }
    if (entry.g3 && modrm.regRaw <= 1) ops = [...ops, entry.g3];
  }
  if (entry.endbr) ins.mnemonic = 'nop';

  for (const o of ops) {
    const v = operand(o, { rd, modrm, OPV, ADDR, rex, x64, seg, opcode: op, Bx, addr });
    if (v) ins.operands.push(v);
  }
  return finish(ins, rd, buf, off, addr);
}

function operand(code, s) {
  const { rd, modrm, OPV, ADDR, rex, opcode, Bx } = s;
  switch (code) {
    case 'Eb': return modrm.mod === 3 ? { type: 'reg', reg: regName(modrm.rm, 1, rex) } : { ...modrm.mem, size: 1 };
    case 'Ew': return modrm.mod === 3 ? { type: 'reg', reg: regName(modrm.rm, 2, rex) } : { ...modrm.mem, size: 2 };
    case 'Ed': return modrm.mod === 3 ? { type: 'reg', reg: regName(modrm.rm, 4, rex) } : { ...modrm.mem, size: 4 };
    case 'Ev': return modrm.mod === 3 ? { type: 'reg', reg: regName(modrm.rm, OPV, rex) } : { ...modrm.mem, size: OPV };
    case 'Rd': return { type: 'reg', reg: regName(modrm.rm, s.x64 ? 8 : 4, rex) };
    case 'Cd': return { type: 'reg', reg: 'cr' + modrm.reg };
    case 'Dd': return { type: 'reg', reg: 'dr' + modrm.reg };
    case 'M': return modrm.mod === 3 ? { type: 'reg', reg: regName(modrm.rm, OPV, rex) } : { ...modrm.mem, size: 0 };
    case 'Mp': return { ...modrm.mem, size: OPV === 8 ? 10 : OPV === 2 ? 4 : 6 };
    case 'Gb': return { type: 'reg', reg: regName(modrm.reg, 1, rex) };
    case 'Gw': return { type: 'reg', reg: regName(modrm.reg, 2, rex) };
    case 'Gv': return { type: 'reg', reg: regName(modrm.reg, OPV, rex) };
    case 'Gz': return { type: 'reg', reg: regName(modrm.reg, OPV === 2 ? 2 : 4, rex) };
    case 'Sw': return { type: 'reg', reg: SEG[modrm.regRaw] };
    case 'Ib': return { type: 'imm', value: rd.u8(), size: 1 };
    case 'Ibs': return { type: 'imm', value: rd.s8(), size: OPV };
    case 'Iw': return { type: 'imm', value: rd.u16(), size: 2 };
    case 'Iz': return OPV === 2 ? { type: 'imm', value: rd.u16(), size: 2 } : { type: 'imm', value: rd.s32(), size: OPV };
    case 'Iv': return OPV === 8 ? { type: 'imm', value: rd.u64(), size: 8 } : OPV === 2 ? { type: 'imm', value: rd.u16(), size: 2 } : { type: 'imm', value: rd.u32(), size: 4 };
    case 'Jb': { const d = rd.s8(); return { type: 'rel', disp: d }; }
    case 'Jz': { const d = OPV === 2 && !s.x64 ? rd.s16() : rd.s32(); return { type: 'rel', disp: d }; }
    case 'AL': return { type: 'reg', reg: 'al' };
    case 'eAX': return { type: 'reg', reg: OPV === 2 ? 'ax' : 'eax' };
    case 'rAX': return { type: 'reg', reg: regName(0, OPV, rex) };
    case 'CL': return { type: 'reg', reg: 'cl' };
    case 'DX': return { type: 'reg', reg: 'dx' };
    case '1': return { type: 'imm', value: 1, size: 1 };
    case 'Zb': return { type: 'reg', reg: regName((opcode & 7) + Bx, 1, rex) };
    case 'Zv': return { type: 'reg', reg: regName((opcode & 7) + Bx, OPV, rex) };
    case 'Ob': case 'Ov': {
      const disp = ADDR === 8 ? rd.u64() : ADDR === 4 ? rd.u32() : rd.u16();
      return { type: 'mem', base: null, index: null, scale: 1, disp: typeof disp === 'bigint' ? disp : disp, abs: true, seg: s.seg, size: code === 'Ob' ? 1 : OPV };
    }
    case 'Ap': { const o = OPV === 2 ? rd.u16() : rd.u32(); const sel = rd.u16(); return { type: 'far', sel, off: o }; }
    default: return null;
  }
}

function parseModRM(rd, buf, { x64, ADDR, Rx, Xx, Bx, seg }) {
  const m = rd.u8();
  const mod = m >> 6, regRaw = (m >> 3) & 7, rmRaw = m & 7;
  const r = { mod, regRaw, reg: regRaw + Rx, rm: rmRaw + Bx, mem: null };
  if (mod === 3) return r;
  const mem = { type: 'mem', base: null, index: null, scale: 1, disp: 0, seg };
  if (ADDR === 2) {
    const T = [['bx', 'si'], ['bx', 'di'], ['bp', 'si'], ['bp', 'di'], ['si'], ['di'], ['bp'], ['bx']];
    if (mod === 0 && rmRaw === 6) mem.disp = rd.u16();
    else { const t = T[rmRaw]; mem.base = t[0]; mem.index = t[1] || null; mem.disp = mod === 1 ? rd.s8() : mod === 2 ? rd.s16() : 0; }
    r.mem = mem; return r;
  }
  const RR = ADDR === 8 ? R64 : R32;
  if (rmRaw === 4) {
    const sib = rd.u8();
    const ss = sib >> 6, idx = ((sib >> 3) & 7) + Xx, base = (sib & 7) + Bx;
    if (idx !== 4) { mem.index = RR[idx]; mem.scale = 1 << ss; }
    if ((sib & 7) === 5 && mod === 0) mem.disp = rd.s32();
    else mem.base = RR[base];
  } else if (rmRaw === 5 && mod === 0) {
    mem.disp = rd.s32();
    if (x64) mem.rip = true; else mem.abs = true;
  } else mem.base = RR[rmRaw + Bx];
  if (mod === 1) mem.disp = rd.s8();
  else if (mod === 2) mem.disp = rd.s32();
  r.mem = mem;
  return r;
}

function decodeGrp7(ins, rd, buf, off, addr, modrm) {
  if (modrm.mod === 3) {
    const k = (modrm.regRaw << 3) | (modrm.rm & 7);
    const T = { 0x01: 'vmcall', 0x02: 'vmlaunch', 0x03: 'vmresume', 0x04: 'vmxoff', 0x08: 'monitor', 0x09: 'mwait', 0x0a: 'clac', 0x0b: 'stac', 0x10: 'xgetbv', 0x11: 'xsetbv', 0x15: 'xend', 0x16: 'xtest', 0x18: 'vmrun', 0x19: 'vmmcall', 0x38: 'swapgs', 0x39: 'rdtscp' };
    ins.mnemonic = T[k] || (modrm.regRaw === 4 ? 'smsw' : modrm.regRaw === 6 ? 'lmsw' : 'op_0f01');
    if (/^vm/.test(ins.mnemonic)) ins.privileged = true;
  } else {
    ins.mnemonic = ['sgdt', 'sidt', 'lgdt', 'lidt', 'smsw', null, 'lmsw', 'invlpg'][modrm.regRaw] || 'op_0f01';
    if (/^l|invlpg/.test(ins.mnemonic)) ins.privileged = true;
    ins.operands.push({ ...modrm.mem, size: modrm.regRaw < 4 ? 6 : 2 });
  }
  return finish(ins, rd, buf, off, addr);
}

function decodeFpu(ins, rd, buf, off, addr, op, mctx) {
  const modrm = parseModRM(rd, buf, mctx);
  if (modrm.mod !== 3) {
    const name = FPU_MEM[op][modrm.regRaw];
    ins.mnemonic = name || 'fpu';
    let size = FPU_SZ[op];
    if (op === 0xdb && (modrm.regRaw === 5 || modrm.regRaw === 7)) size = 10;
    if (op === 0xdf && (modrm.regRaw === 5 || modrm.regRaw === 7)) size = 8;
    if (op === 0xdf && (modrm.regRaw === 4 || modrm.regRaw === 6)) size = 10;
    if (op === 0xd9 && modrm.regRaw >= 4) size = modrm.regRaw === 5 || modrm.regRaw === 7 ? 2 : 28;
    if (op === 0xdd && (modrm.regRaw === 4 || modrm.regRaw === 6)) size = 108;
    if (op === 0xdd && modrm.regRaw === 7) size = 2;
    ins.operands.push({ ...modrm.mem, size: PTR[size] ? size : 0 });
  } else {
    const k = (op << 8) | buf[rd.p - 1];
    ins.mnemonic = FPU_REG[k] || ({ 0xd8: 'fadd', 0xd9: 'fld', 0xda: 'fcmovb', 0xdb: 'fcmovnb', 0xdc: 'fadd', 0xdd: 'ffree', 0xde: 'faddp', 0xdf: 'fucomip' }[op]);
    if (!FPU_REG[k]) ins.operands.push({ type: 'reg', reg: `st(${modrm.rm & 7})` });
  }
  return finish(ins, rd, buf, off, addr);
}

function invalid(ins, rd, buf, off, addr, why) {
  ins.mnemonic = '(bad)';
  ins.flow = 'invalid';
  ins.invalid = why || true;
  rd.p = Math.max(rd.p, off + 1);
  return finish(ins, rd, buf, off, addr, true);
}

function finish(ins, rd, buf, off, addr, keepInvalid) {
  if (rd.bad && !keepInvalid) { ins.mnemonic = '(bad)'; ins.flow = 'invalid'; ins.invalid = 'troncata'; ins.operands = []; rd.p = Math.min(buf.length, off + 1); }
  ins.length = Math.max(1, rd.p - off);
  ins.bytes = buf.subarray(off, off + ins.length);
  const next = addr + ins.length;
  for (const o of ins.operands) {
    if (o.type === 'rel') { o.target = next + o.disp; ins.target = o.target; }
    if (o.type === 'mem' && o.rip) o.target = next + o.disp;
  }
  if (ins.lock) ins.prefixText = 'lock ';
  if (ins.rep && /^(movs|stos|lods|scas|cmps|ins|outs)/.test(ins.mnemonic)) ins.prefixText = (ins.rep === 0xf3 ? (/^(scas|cmps)/.test(ins.mnemonic) ? 'repe ' : 'rep ') : 'repne ');
  return ins;
}

function fmtOperand(o) {
  if (o.type === 'reg') return o.reg;
  if (o.type === 'imm') {
    if (typeof o.value === 'bigint') return hexU(o.value);
    return o.value < 0 ? hex(o.value) : '0x' + (o.value >>> 0).toString(16);
  }
  if (o.type === 'rel') return '0x' + (o.target >= 0 ? o.target : o.target >>> 0).toString(16);
  if (o.type === 'far') return `0x${o.sel.toString(16)}:0x${o.off.toString(16)}`;
  if (o.type === 'mem') {
    const parts = [];
    if (o.rip) parts.push('rip');
    if (o.base) parts.push(o.base);
    if (o.index) parts.push(o.index + (o.scale > 1 ? '*' + o.scale : ''));
    let s = parts.join(' + ');
    const d = o.disp;
    if (typeof d === 'bigint') s = s ? `${s} + ${hexU(d)}` : hexU(d);
    else if (d || !s) s = s ? `${s} ${d < 0 ? '-' : '+'} 0x${Math.abs(d).toString(16)}` : '0x' + (d >>> 0).toString(16);
    const ptr = o.size && PTR[o.size] ? PTR[o.size] + ' ptr ' : '';
    return `${ptr}${o.seg ? o.seg + ':' : ''}[${s}]${o.rip ? ` ; 0x${o.target.toString(16)}` : ''}`;
  }
  return '?';
}

function format(ins) {
  const ops = ins.operands.map(fmtOperand);
  // A RIP-relative comment must go at the end of the line
  let comment = '';
  for (let i = 0; i < ops.length; i++) { const k = ops[i].indexOf(' ; '); if (k > 0) { comment = ops[i].slice(k); ops[i] = ops[i].slice(0, k); } }
  return `${ins.prefixText || ''}${ins.mnemonic}${ops.length ? ' ' + ops.join(', ') : ''}${comment}`;
}

/** Linear sweep: decodes a range sequentially. cb(ins) may return false to stop. */
function sweep(buf, start, end, opts, cb) {
  let off = start;
  while (off < end) {
    const ins = decode(buf, off, { ...opts, address: opts.base + (off - start) });
    if (cb(ins) === false) break;
    off += ins.length;
  }
}

module.exports = { decode, sweep, format, regName, R32, R64 };
