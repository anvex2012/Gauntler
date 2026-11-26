// Created by anvex2012
'use strict';
/**
 * Known-plaintext search for content hidden with XOR / ADD keys.
 *
 * Idea (differential cryptanalysis of a repeating key): if c[i] = p[i] ^ k[i mod L] then
 *   c[i] ^ c[i+L] = p[i] ^ p[i+L]
 * which does NOT depend on the key. So we transform the file once per key length L into
 * d_L[i] = c[i] ^ c[i+L] and search for the same transform of each known plaintext with the native
 * Buffer.indexOf (Boyer-Moore-Horspool in C++). When found, the key is recovered directly:
 *   k[(i+j) mod L] = c[i+j] ^ p[j].
 * The same trick works for ADD/SUB keys with d_L[i] = c[i+L] - c[i] (mod 256).
 * Single-byte and multi-byte keys up to 32 bytes are covered in O(n · L) time with no brute force
 * over the 256^L key space.
 */

const PLAINTEXTS = [
  { id: 'pe-stub', text: 'This program cannot be run in DOS mode', what: 'eseguibile Windows (PE)', back: 0x4e },
  { id: 'pe-stub2', text: 'This program must be run under Win32', what: 'eseguibile Windows (PE)', back: 0x50 },
  { id: 'http', text: 'http://', what: 'indirizzo web', min: 1 },
  { id: 'https', text: 'https://', what: 'indirizzo web', min: 1 },
  { id: 'kernel32', text: 'kernel32.dll', what: 'nome di libreria Windows' },
  { id: 'ntdll', text: 'ntdll.dll', what: 'nome di libreria Windows' },
  { id: 'powershell', text: 'powershell', what: 'comando PowerShell' },
  { id: 'cmdexe', text: 'cmd.exe /c', what: 'comando di shell' },
  { id: 'binsh', text: '/bin/sh', what: 'shell Unix' },
  { id: 'useragent', text: 'Mozilla/5.0', what: 'user-agent HTTP (comunicazione C2)' },
  { id: 'elf', text: '\x7fELF\x02\x01\x01', what: 'eseguibile Linux (ELF)', back: 0 },
  { id: 'getproc', text: 'GetProcAddress', what: 'nome di API Windows' },
  { id: 'virtualalloc', text: 'VirtualAlloc', what: 'nome di API Windows' },
];

function diffBuffer(buf, L, op, n) {
  const out = Buffer.allocUnsafe(Math.max(0, n - L));
  if (op === 'xor') for (let i = 0; i < out.length; i++) out[i] = buf[i] ^ buf[i + L];
  else for (let i = 0; i < out.length; i++) out[i] = (buf[i + L] - buf[i]) & 0xff;
  return out;
}

function isTrivialKey(key) { return key.every((k) => k === 0); }

/** Reduces a repeating key to its smallest period ("abab" → "ab") */
function minimalKey(key) {
  for (let p = 1; p < key.length; p++) {
    if (key.length % p) continue;
    let ok = true;
    for (let i = p; i < key.length && ok; i++) if (key[i] !== key[i % p]) ok = false;
    if (ok) return key.subarray(0, p);
  }
  return key;
}

function decrypt(buf, start, end, key, phase, op) {
  const out = Buffer.allocUnsafe(end - start);
  const L = key.length;
  for (let i = start; i < end; i++) {
    const k = key[(i - phase + L * 1e6) % L];
    out[i - start] = op === 'xor' ? buf[i] ^ k : (buf[i] - k) & 0xff;
  }
  return out;
}

/**
 * search(buf) → [{ plaintext, what, op, key (Buffer), keyHex, offset, payloadStart, sample }]
 * maxKey: longest key length; maxBytes: bytes examined (whole file by default up to 128 MB per pass).
 */
function search(buf, { maxKey = 32, maxBytes = 128 * 1024 * 1024, ops = ['xor', 'add'], limit = 50 } = {}) {
  const n = Math.min(buf.length, maxBytes);
  const found = [];
  const seen = new Set();
  for (const op of ops) {
    for (let L = 1; L <= maxKey && found.length < limit; L++) {
      const usable = PLAINTEXTS.filter((p) => p.text.length - L >= 6); // ≥ 6 key-independent bytes: ~2^-48 false matches per position
      if (!usable.length) break;
      const d = diffBuffer(buf, L, op, n);
      for (const p of usable) {
        const pt = Buffer.from(p.text, 'latin1');
        const pd = diffBuffer(pt, L, op, pt.length);
        let i = -1;
        let hits = 0;
        while ((i = d.indexOf(pd, i + 1)) !== -1 && hits < 8) {
          // Recover the key from the first L bytes of the plaintext
          const key = Buffer.alloc(L);
          for (let j = 0; j < L; j++) key[(i + j) % L] = op === 'xor' ? buf[i + j] ^ pt[j] : (buf[i + j] - pt[j]) & 0xff;
          if (isTrivialKey(key)) continue; // plain text, not hidden
          const k = minimalKey(key);
          // Verify the whole plaintext decrypts correctly with the recovered key
          const check = decrypt(buf, i, i + pt.length, k, 0, op);
          let ok = true;
          for (let j = 0; j < pt.length && ok; j++) if (check[j] !== pt[j]) ok = false;
          if (!ok) continue;
          const sig = `${op}:${k.toString('hex')}:${p.id}`;
          if (seen.has(sig)) continue;
          seen.add(sig);
          hits++;
          const payloadStart = p.back != null ? Math.max(0, i - p.back) : i;
          const sampleEnd = Math.min(buf.length, i + 200);
          const sample = decrypt(buf, i, sampleEnd, k, 0, op).toString('latin1').replace(/[^\x20-\x7e]+/g, ' ').slice(0, 160);
          found.push({ plaintext: p.text.replace(/[^\x20-\x7e]/g, '.'), id: p.id, what: p.what, op, key: k, keyHex: k.toString('hex'), offset: i, payloadStart, sample, phase: 0 });
        }
      }
    }
  }
  return found;
}

/** Decrypts the payload found (from payloadStart to the end of the buffer) with its key and phase */
function extractPayload(buf, hit, maxLen = 64 * 1024 * 1024) {
  const end = Math.min(buf.length, hit.payloadStart + maxLen);
  return decrypt(buf, hit.payloadStart, end, hit.key, hit.phase, hit.op);
}

module.exports = { search, extractPayload, decrypt, PLAINTEXTS };
