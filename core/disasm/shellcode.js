// Creato da anvex2012
'use strict';
/**
 * Shellcode finder for data that is NOT supposed to contain code (documents, images, decoded
 * payloads, unknown binaries, exploit files).
 *
 * 1. Anchor search: byte patterns that start or characterize real shellcode (GetPC, PEB access,
 *    Metasploit/Cobalt Strike prologues, NOP sleds, syscall stubs) found with Buffer.indexOf.
 * 2. For every anchor (both 32 and 64-bit) a short linear sweep is disassembled and fed to the
 *    behavioural Detector; the window is scored on: decodable instruction run length, rate of
 *    invalid/privileged instructions, and the independent behaviours found.
 * 3. Overlapping windows are merged; only windows with ≥ 2 independent behaviours (or one very
 *    strong anchor) are reported, which keeps random data false positives near zero.
 */
const x86 = require('./x86');
const { Detector } = require('./heuristics');

const ANCHORS = [
  { re: 'e800000000', what: 'call $+5 (GetPC)', strong: false },
  { re: 'd97424f4', what: 'fnstenv [esp-0xc] (GetPC)', strong: true },
  { re: '64a130000000', what: 'mov eax, fs:[0x30] (PEB)', strong: false },
  { re: '648b1530000000', what: 'mov edx, fs:[0x30] (PEB)', strong: false },
  { re: '648b3530000000', what: 'mov esi, fs:[0x30] (PEB)', strong: false },
  { re: '648b0d30000000', what: 'mov ecx, fs:[0x30] (PEB)', strong: false },
  { re: '65488b042560000000', what: 'mov rax, gs:[0x60] (PEB)', strong: false },
  { re: '65488b142560000000', what: 'mov rdx, gs:[0x60] (PEB)', strong: false },
  { re: 'fce8', what: 'cld ; call (Metasploit block_api x86)', strong: false },
  { re: 'fc4883e4f0e8', what: 'cld ; and rsp,-16 ; call (stager x64)', strong: true },
  { re: '60e8', what: 'pushad ; call', strong: false },
  { re: '9090909090909090909090909090909090909090', what: 'NOP sled', strong: false },
  { re: '4c8bd1b8', what: 'mov r10, rcx ; mov eax (syscall stub)', strong: false },
  { re: '31c0506a', what: 'xor eax,eax ; push eax ; push', strong: false },
  { re: '31c9f7e1', what: 'xor ecx,ecx ; mul ecx', strong: false },
  { re: 'eb', what: 'jmp short (jmp-call-pop)', jcp: true },
].map((a) => ({ ...a, bytes: Buffer.from(a.re, 'hex') }));

const BEHAVIOURS = ['getpc', 'peb', 'hashloop', 'apihash', 'syscall', 'hellsgate', 'decoder', 'stackstr', 'antidebug', 'antivm', 'nopsled'];
// Behaviours that random bytes practically never produce (x86 is so dense that almost any byte
// sequence decodes: only these are evidence; the others merely add weight)
const STRONG = new Set(['getpc', 'peb', 'hashloop', 'apihash', 'hellsgate', 'stackstr']);

function windowScore(buf, start, bits, maxIns = 160, maxBytes = 1024) {
  const det = new Detector(bits === 64 ? 'x64' : 'x86', { windowSize: 64 });
  let off = start, n = 0, valid = 0, run = 0, bestRun = 0, priv = 0;
  const end = Math.min(buf.length, start + maxBytes);
  while (off < end && n < maxIns) {
    const ins = x86.decode(buf, off, { bits, address: off });
    n++;
    // the first invalid or privileged instruction marks the end of real user-mode code
    if (ins.invalid || ins.privileged) { if (ins.privileged) priv++; break; }
    valid++; run++; bestRun = Math.max(bestRun, run);
    det.feed(ins);
    off += ins.length;
    if (ins.flow === 'ret' && n > 8) break;
  }
  const hits = det.finish();
  const beh = BEHAVIOURS.filter((b) => hits[b]);
  // privileged instructions are almost never in real user-mode shellcode, frequent in random data
  const quality = valid / Math.max(1, n) - priv * 0.08;
  return { start, end: off, bits, n, valid, bestRun, quality, behaviours: beh, hits, stackStrings: det.stackStrings };
}

/**
 * find(buf) → [{ start, end, bits, behaviours, evidence, confidence: 'high'|'medium', anchor }]
 */
function find(buf, { maxAnchors = 20000, maxBytes = 256 * 1024 * 1024 } = {}) {
  const n = Math.min(buf.length, maxBytes);
  const view = n < buf.length ? buf.subarray(0, n) : buf;
  const cands = [];
  for (const a of ANCHORS) {
    let i = -1, k = 0;
    while ((i = view.indexOf(a.bytes, i + 1)) !== -1 && k < maxAnchors) {
      if (a.jcp) {
        // jmp short forward to a call with a backward displacement (jmp-call-pop)
        const t = i + 2 + view[i + 1];
        if (view[i + 1] < 0x80 && view[t] === 0xe8 && t + 5 <= view.length && view.readInt32LE(t + 1) < 0 && view.readInt32LE(t + 1) > -512) { cands.push({ off: i, a }); k++; }
        continue;
      }
      cands.push({ off: Math.max(0, i - (a.re.startsWith('90') ? 0 : 0)), a });
      k++;
      if (a.re.startsWith('9090')) i += 64; // a sled is one candidate
    }
  }
  cands.sort((x, y) => x.off - y.off);
  const results = [];
  let lastEnd = -1;
  for (const c of cands) {
    if (c.off < lastEnd) continue;
    let best = null;
    for (const bits of [32, 64]) {
      const w = windowScore(view, c.off, bits);
      w.strong = w.behaviours.filter((b) => STRONG.has(b));
      const score = w.strong.length * 4 + w.behaviours.length + (c.a.strong ? 2 : 0) + (w.bestRun >= 24 ? 1 : 0);
      if (!best || score > best.score) best = { ...w, score };
    }
    const strongPair = best.strong.length >= 2 && best.bestRun >= 8;
    const strongAnchor = c.a.strong && best.strong.length >= 1 && best.bestRun >= 8;
    if (!strongPair && !strongAnchor) continue;
    const confidence = best.strong.length >= 3 || (c.a.strong && best.strong.length >= 2) ? 'high' : 'medium';
    const evidence = [];
    for (const b of best.behaviours) for (const e of best.hits[b].evidence.slice(0, 3)) evidence.push(`${b}: ${e}`);
    results.push({ start: c.off, end: best.end, bits: best.bits, behaviours: best.behaviours, evidence, confidence, anchor: c.a.what, stackStrings: best.stackStrings, instructions: best.n });
    lastEnd = best.end;
  }
  return results;
}

module.exports = { find, windowScore, ANCHORS };
