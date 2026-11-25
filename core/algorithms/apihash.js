// Creato da anvex2012
'use strict';
/**
 * API hashing dictionary.
 * Shellcode and loaders avoid import tables: they walk the loaded modules (PEB → Ldr) and compare
 * a HASH of each export name with constants embedded in the code. We precompute the hashes of the
 * most abused Windows APIs with the algorithms used in the wild and look for those 32-bit constants.
 *
 * Algorithms: ror13 (classic), ror13 Metasploit block_api (module hash + function hash), crc32,
 * djb2, sdbm, fnv-1a, rol5-xor, ror7-xor (Cobalt Strike / custom loaders variants).
 */
const { crc32 } = require('../zip');

const APIS = {
  'kernel32.dll': ['LoadLibraryA', 'LoadLibraryW', 'LoadLibraryExA', 'GetProcAddress', 'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect', 'VirtualFree', 'CreateThread', 'CreateRemoteThread',
    'WriteProcessMemory', 'ReadProcessMemory', 'OpenProcess', 'CreateProcessA', 'CreateProcessW', 'WinExec', 'ExitProcess', 'ExitThread', 'TerminateProcess', 'WaitForSingleObject', 'Sleep',
    'CreateFileA', 'CreateFileW', 'WriteFile', 'ReadFile', 'CloseHandle', 'GetModuleHandleA', 'GetModuleHandleW', 'GetTempPathA', 'GetTempPathW', 'CreateToolhelp32Snapshot', 'Process32First',
    'Process32Next', 'QueueUserAPC', 'ResumeThread', 'SuspendThread', 'GetThreadContext', 'SetThreadContext', 'IsDebuggerPresent', 'GetVersion', 'SetErrorMode', 'DeleteFileA', 'CopyFileA', 'MapViewOfFile', 'CreateFileMappingA', 'GetSystemDirectoryA', 'SetUnhandledExceptionFilter'],
  'ntdll.dll': ['NtAllocateVirtualMemory', 'NtProtectVirtualMemory', 'NtWriteVirtualMemory', 'NtCreateThreadEx', 'NtUnmapViewOfSection', 'NtMapViewOfSection', 'NtCreateSection', 'NtQueueApcThread',
    'NtResumeThread', 'NtQueryInformationProcess', 'NtSetInformationThread', 'RtlMoveMemory', 'RtlCreateUserThread', 'LdrLoadDll', 'LdrGetProcedureAddress', 'NtDelayExecution', 'RtlExitUserThread', 'NtOpenProcess', 'NtClose'],
  'ws2_32.dll': ['WSAStartup', 'WSASocketA', 'WSAConnect', 'socket', 'connect', 'bind', 'listen', 'accept', 'send', 'recv', 'closesocket', 'gethostbyname', 'inet_addr', 'htons'],
  'wininet.dll': ['InternetOpenA', 'InternetOpenW', 'InternetConnectA', 'InternetConnectW', 'HttpOpenRequestA', 'HttpOpenRequestW', 'HttpSendRequestA', 'HttpSendRequestW', 'InternetReadFile', 'InternetOpenUrlA', 'InternetSetOptionA', 'InternetCloseHandle'],
  'winhttp.dll': ['WinHttpOpen', 'WinHttpConnect', 'WinHttpOpenRequest', 'WinHttpSendRequest', 'WinHttpReceiveResponse', 'WinHttpReadData'],
  'urlmon.dll': ['URLDownloadToFileA', 'URLDownloadToFileW'],
  'advapi32.dll': ['RegOpenKeyExA', 'RegSetValueExA', 'RegCreateKeyExA', 'OpenProcessToken', 'AdjustTokenPrivileges', 'LookupPrivilegeValueA', 'CryptAcquireContextA', 'CryptEncrypt', 'CryptDecrypt', 'CreateServiceA', 'StartServiceA', 'OpenSCManagerA'],
  'user32.dll': ['MessageBoxA', 'MessageBoxW', 'SetWindowsHookExA', 'GetAsyncKeyState', 'GetForegroundWindow', 'ShowWindow', 'FindWindowA'],
  'shell32.dll': ['ShellExecuteA', 'ShellExecuteW', 'ShellExecuteExA'],
  'msvcrt.dll': ['system', 'malloc', 'memcpy'],
  'amsi.dll': ['AmsiScanBuffer', 'AmsiInitialize'],
};
const MODULES = Object.keys(APIS);

const ror = (v, n) => ((v >>> n) | (v << (32 - n))) >>> 0;
const rol = (v, n) => ((v << n) | (v >>> (32 - n))) >>> 0;

const ALGS = {
  ror13: (s) => { let h = 0; for (const c of Buffer.from(s, 'latin1')) h = (ror(h, 13) + c) >>> 0; return h; },
  ror13z: (s) => { let h = 0; for (const c of Buffer.from(s + '\0', 'latin1')) h = (ror(h, 13) + c) >>> 0; return h; },
  crc32: (s) => crc32(Buffer.from(s, 'latin1')),
  djb2: (s) => { let h = 5381; for (const c of Buffer.from(s, 'latin1')) h = (Math.imul(h, 33) + c) >>> 0; return h; },
  sdbm: (s) => { let h = 0; for (const c of Buffer.from(s, 'latin1')) h = (c + (h << 6) + (h << 16) - h) >>> 0; return h; },
  fnv1a: (s) => { let h = 0x811c9dc5; for (const c of Buffer.from(s, 'latin1')) h = Math.imul(h ^ c, 0x01000193) >>> 0; return h; },
  rol5xor: (s) => { let h = 0; for (const c of Buffer.from(s, 'latin1')) h = (rol(h, 5) ^ c) >>> 0; return h; },
  ror7xor: (s) => { let h = 0; for (const c of Buffer.from(s, 'latin1')) h = (ror(h, 7) ^ c) >>> 0; return h; },
};

/** Metasploit block_api: ror13 over the UTF-16LE upper-case module name (with terminator) + ror13z(function) */
function msfModuleHash(mod) {
  let h = 0;
  for (const c of Buffer.from(mod.toUpperCase() + '\0', 'utf16le')) h = (ror(h, 13) + c) >>> 0;
  return h;
}

let TABLE = null;
let BITMAP = null;
/** Map uint32 → [{ api, module, alg }] */
function table() {
  if (TABLE) return TABLE;
  TABLE = new Map();
  const add = (h, rec) => {
    if (h < 0x10000) return; // tiny values would collide with ordinary constants
    if (!TABLE.has(h)) TABLE.set(h, []);
    TABLE.get(h).push(rec);
  };
  for (const mod of MODULES) {
    const mh = msfModuleHash(mod);
    for (const api of APIS[mod]) {
      for (const [alg, fn] of Object.entries(ALGS)) add(fn(api), { api, module: mod, alg });
      add((mh + ALGS.ror13z(api)) >>> 0, { api, module: mod, alg: 'metasploit-block_api' });
    }
  }
  return TABLE;
}

const lookup = (v) => table().get(v >>> 0) || null;

/**
 * Scans raw bytes for embedded hash constants (little-endian uint32).
 * Returns clusters: at least `minDistinct` distinct APIs within `window` bytes (random collisions are
 * ~1e-7 per position, a cluster of 2+ within 4 KB is practically never accidental).
 */
function scanBuffer(buf, { window = 4096, minDistinct = 2, maxBytes = 256 * 1024 * 1024 } = {}) {
  const T = table();
  // Fast reject with a 64K bitmap of the low 16 bits (~2% of positions reach the Map lookup)
  if (!BITMAP) { BITMAP = new Uint8Array(65536); for (const k of T.keys()) BITMAP[k & 0xffff] = 1; }
  const hits = [];
  const end = Math.min(buf.length, maxBytes) - 3;
  for (let i = 0; i < end; i++) {
    if (!BITMAP[buf[i] | (buf[i + 1] << 8)]) continue;
    const v = (buf[i] | (buf[i + 1] << 8) | (buf[i + 2] << 16) | (buf[i + 3] << 24)) >>> 0;
    const r = T.get(v);
    if (r) hits.push({ off: i, value: v, matches: r });
  }
  const clusters = [];
  let cur = [];
  const flush = () => {
    const apis = new Set(cur.map((h) => h.matches[0].api));
    if (apis.size >= minDistinct) clusters.push({ start: cur[0].off, end: cur[cur.length - 1].off + 4, hits: cur, apis: [...apis], algs: [...new Set(cur.flatMap((h) => h.matches.map((m) => m.alg)))] });
    cur = [];
  };
  for (const h of hits) {
    if (cur.length && h.off - cur[cur.length - 1].off > window) flush();
    cur.push(h);
  }
  if (cur.length) flush();
  return clusters;
}

module.exports = { lookup, table, scanBuffer, ALGS, msfModuleHash };
