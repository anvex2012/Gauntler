// Creato da anvex2012
'use strict';
const { m: msg } = require('../i18n');
/**
 * Machine code analysis (disassembly).
 *  - Executables (PE/ELF/Mach-O; x86, x86-64, ARM64): recursive-descent disassembly from the entry
 *    point, exports, TLS callbacks and symbols → control-flow graph (functions, basic blocks, loops,
 *    cyclomatic complexity) + behavioural heuristics on the code actually reachable.
 *  - Any binary data (documents, images, decoded payloads, unknown files): shellcode search.
 *  - Everywhere: API-hash constants, content hidden with XOR/ADD keys (key recovered and the
 *    payload decrypted and re-analyzed recursively).
 * The assembly listing (hex + binary) is attached to the report (extra.machineCode).
 */
const D = require('../disasm');
const { Detector } = require('../disasm/heuristics');
const shellcode = require('../disasm/shellcode');
const apihash = require('../algorithms/apihash');
const xorsearch = require('../algorithms/xorsearch');

const NOT_RAW = new Set(['zip', 'jar', 'apk', 'gzip', 'rar', '7z', 'bzip2', 'xz', 'docx', 'xlsx', 'pptx', 'odf', 'dmg', 'cab', 'png', 'mp4', 'mp3', 'ogg', 'flac', 'mkv', 'webp', 'heic', 'kdbx', 'sqlite']);
const SUSPICIOUS_STR = /cmd|powershell|http|\.exe|\.dll|kernel32|ntdll|virtualalloc|loadlibrary|getprocaddress|wscript|\/bin\/|socket|winexec|urlmon|regsvr|rundll|mshta/i;
const LISTING_ROWS = 1500;
const PACKED_ENTROPY = 7.2; // bits/byte: above this the "code" is compressed or encrypted data
const hex = (n) => '0x' + Number(n).toString(16);

function behaviourFindings(h, image, out, C) {
  const pe = image.format === 'PE';
  const user = !(image.native);
  const ev = (id, n = 6) => (h[id] ? h[id].evidence.slice(0, n).concat(h[id].at.slice(0, 3).map((a) => `@ ${hex(a)}`)) : []);

  const apis = h.apihash ? new Set(h.apihash.evidence.map((e) => e.split(' = ')[1].split(' (')[0])) : new Set();
  C('Nessuna risoluzione delle API tramite hash', !apis.size, apis.size ? [...apis].join(', ') : '');
  if (apis.size) out.push({ severity: apis.size >= 2 ? 'high' : 'medium', title: msg('API Windows cercate tramite hash ({n})', { n: apis.size }), detail: 'Il codice confronta valori numerici con gli hash dei nomi di funzioni di sistema invece di importarle: tecnica tipica di shellcode e loader per nascondere cosa fanno.', evidence: ev('apihash', 10) });

  const manual = h.peb && h.hashloop;
  C('Nessuna scansione manuale dei moduli (PEB + hashing)', !manual);
  if (manual) out.push({ severity: 'high', title: 'Ricerca manuale delle librerie di sistema (PEB + hashing)', detail: 'Il codice legge il Process Environment Block e calcola hash dei nomi: è lo schema con cui lo shellcode trova le funzioni di Windows senza import.', evidence: [...ev('peb', 2), ...ev('hashloop', 2)] });
  // Without the PEB walk an isolated rotate-and-add loop is also what string hash tables do: low on
  // Windows (where API hashing is a real technique), informational elsewhere.
  else if (h.hashloop) out.push({ severity: pe ? 'low' : 'info', title: 'Routine di hashing a rotazione (ROR/ROL)', detail: 'Ciclo che legge una stringa byte per byte e la combina con rotazioni tipiche (13, 7, 5): usato per l\'hashing dei nomi delle API, ma anche da normali tabelle hash.', evidence: ev('hashloop', 3) });
  else if (h.peb && pe) out.push({ severity: 'low', title: 'Accesso diretto al PEB/TEB', detail: 'Lettura delle strutture interne del processo tramite fs:/gs:, tipica di codice che evita le API documentate.', evidence: ev('peb', 3) });

  C('Nessun codice indipendente dalla posizione (GetPC)', !h.getpc);
  if (h.getpc) out.push({ severity: image.arch === 'x86' && !pe ? 'low' : 'medium', title: 'Tecnica GetPC (call/pop, fnstenv)', detail: 'Il codice ricava il proprio indirizzo in memoria: caratteristica dello shellcode e dei decodificatori.', evidence: ev('getpc', 4) });

  C('Nessuno stub di syscall diretta (Hell\'s Gate)', !h.hellsgate);
  if (h.hellsgate) out.push({ severity: 'high', title: 'Chiamate di sistema dirette (Hell\'s Gate / SysWhispers)', detail: 'Stub "mov r10, rcx; mov eax, N; syscall" fuori da ntdll: serve a scavalcare i controlli di antivirus ed EDR.', evidence: ev('hellsgate', 4) });
  else if (h.syscall && pe && user) out.push({ severity: 'medium', title: msg('Chiamate di sistema dirette ({n})', { n: h.syscall.count }), detail: 'Un programma Windows normale passa da ntdll: le syscall dirette sono usate per evitare il monitoraggio.', evidence: ev('syscall', 4) });
  else if (h.syscall) C(msg('Chiamate di sistema dirette: {n}', { n: h.syscall.count }), true, 'normale per binari statici Linux/macOS');

  C('Nessun ciclo di auto-decifratura', !h.decoder);
  const strongContext = h.getpc || h.peb || h.apihash || h.hellsgate || h.hashloop;
  if (h.decoder) out.push({ severity: strongContext ? 'medium' : 'info', title: msg('Cicli che modificano dati in memoria ({n})', { n: h.decoder.count }), detail: 'Cicli brevi che applicano XOR/ADD/rotazioni a un buffer: possono decifrare un payload nascosto (ma anche essere codice di crittografia o compressione legittimo).', evidence: ev('decoder', 4) });

  const strs = h.stackstr ? h.stackstr.evidence : [];
  const badStrs = strs.filter((s) => SUSPICIOUS_STR.test(s));
  C('Nessuna stringa sospetta costruita sullo stack', !badStrs.length, strs.slice(0, 8).join(' · '));
  if (badStrs.length) out.push({ severity: 'medium', title: 'Stringhe nascoste costruite sullo stack', detail: 'Testi composti carattere per carattere nel codice per non comparire tra le stringhe del file.', evidence: badStrs.slice(0, 12) });
  else if (strs.length) out.push({ severity: 'info', title: msg('Stringhe costruite sullo stack ({n})', { n: strs.length }), detail: 'Testi composti nel codice a runtime.', evidence: strs.slice(0, 12) });

  C('Nessuna tecnica anti-debug nel codice', !h.antidebug);
  if (h.antidebug) out.push({ severity: 'medium', title: 'Tecniche anti-debug nel codice', detail: 'Istruzioni che rilevano o ostacolano un debugger (usate dai malware per sfuggire all\'analisi).', evidence: ev('antidebug', 6) });
  C('Nessuna tecnica anti-macchina virtuale', !h.antivm);
  if (h.antivm) out.push({ severity: 'medium', title: 'Rilevamento di macchine virtuali / sandbox', detail: 'Istruzioni che verificano se il programma gira in una VM (per non mostrarsi agli analisti).', evidence: ev('antivm', 6) });
  if (h.rdtsc && h.rdtsc.count >= 4) out.push({ severity: 'low', title: msg('Misurazioni del tempo ad alta precisione ({n})', { n: h.rdtsc.count }), detail: 'Usate per accorgersi del rallentamento causato da debugger ed emulatori (ma anche da benchmark e generatori casuali).', evidence: h.rdtsc.at.slice(0, 4).map((a) => `@ ${hex(a)}`) });
  if (h.privileged && user && h.privileged.count >= 2) out.push({ severity: 'info', title: 'Istruzioni privilegiate in un programma utente', detail: 'Istruzioni riservate al kernel (in/out/cli/hlt/wrmsr) raggiungibili nel codice.', evidence: ev('privileged', 5) });
  if (h.nopsled && h.nopsled.max >= 64) out.push({ severity: 'low', title: msg('Sequenza di NOP ({n} byte)', { n: h.nopsled.max }), detail: 'Lunga "slitta" di istruzioni nulle, tipica degli exploit.', evidence: ev('nopsled', 2) });
  if (h.crypto) out.push({ severity: 'info', title: 'Istruzioni crittografiche hardware', detail: 'Il codice usa AES-NI/SHA/CRC32: cifratura o hashing (normale in molti programmi, presente anche nei ransomware).', evidence: [...new Set(h.crypto.evidence)].slice(0, 6) });
}

module.exports = {
  id: 'machinecode',
  name: 'Codice macchina (disassembly)',
  description: 'Disassembla il codice macchina x86, x86-64 e ARM64 (PE, ELF, Mach-O): grafo del flusso di controllo con funzioni, blocchi, cicli e complessità; riconosce shellcode (GetPC, PEB, hashing delle API, syscall dirette, cicli di decifratura, stringhe sullo stack, anti-debug/VM) anche dentro documenti e dati; ritrova contenuti nascosti con chiavi XOR/ADD recuperando la chiave.',
  weight: 2.5,
  applies: (ctx) => !ctx.isText && ctx.size >= 16 && !NOT_RAW.has(ctx.type.id),
  run(ctx) {
    const out = [];
    const checks = [];
    const C = (name, ok, note) => checks.push({ name, ok, note });
    const buf = ctx.buffer;
    const info = {};
    const mc = { format: null, arch: null };
    const isExe = ['pe', 'dll', 'elf', 'macho'].includes(ctx.type.id);
    let execRanges = [];

    /* ---------- 1. Executables: recursive disassembly + CFG + heuristics ---------- */
    if (isExe) {
      let image = null;
      try { image = D.load(buf, ctx.type.id); } catch (e) { C('Struttura del codice leggibile', false, e.message); }
      if (image) {
        mc.format = image.format; mc.arch = image.arch || 'non supportata';
        info['Architettura'] = image.arch || 'non supportata dal disassemblatore';
        if (image.entry != null) info['Punto di avvio'] = hex(image.entry);
        // Every architecture of a universal (fat) binary: the code of the other slices is code, not "data"
        execRanges = (image.slices || [image]).flatMap((sl) => sl.regions.map((r) => [r.off, r.off + r.size]));
        info['Sezioni di codice'] = image.regions.map((r) => `${r.name} (${Math.round(r.size / 1024)} KB)`).join(', ') || 'nessuna';
        if (image.dotnet) info['Codice'] = '.NET (IL) — il codice nativo è solo il caricatore';
        if (image.arch && image.regions.length) {
          const det = new Detector(image.arch);
          const t0 = Date.now();
          // Seeds: entry point, exports/symbols, function-start tables (in the loader) and recognized
          // prologues, so code called only through pointers is disassembled too
          const cfg = D.explore(buf, image, { onIns: (ins) => det.feed(ins), entries: D.prologueStarts(buf, image) });
          const h = det.finish();
          const fns = D.analyzeFunctions(cfg);
          const cov = D.coverage(buf, image, cfg);
          const codeBytes = cov.effective; // alignment padding (int3/nop/zero fill) is not code
          const cyc = fns.map((f) => f.cyclomatic);
          const loops = fns.reduce((a, f) => a + f.loops.length, 0);
          Object.assign(info, {
            'Istruzioni disassemblate': cfg.truncated ? msg('{n} (limite raggiunto)', { n: cfg.insns.size }) : cfg.insns.size,
            Funzioni: cfg.functions.size,
            'Blocchi di base': cfg.blocks.size,
            'Copertura del codice': cov.padding ? msg('{p}% (escluso padding: {n} KB)', { p: Math.round(cov.ratio * 100), n: Math.round(cov.padding / 1024) }) : `${Math.round(cov.ratio * 100)}%`,
            'Complessità ciclomatica (media / max)': cyc.length ? `${(cyc.reduce((a, b) => a + b, 0) / cyc.length).toFixed(1)} / ${Math.max(...cyc)}` : '-',
            Cicli: loops,
            'Tempo di disassemblaggio': `${Date.now() - t0} ms`,
          });
          C('Codice disassemblabile dal punto di avvio', cfg.insns.size > 0, msg('{n} istruzioni', { n: cfg.insns.size }));
          // Low coverage alone is normal (code reached only through pointers the static analysis cannot
          // resolve). It indicates a packer only when the unreached bytes do not look like code at all:
          // compressed/encrypted data has an entropy close to 8 bits/byte, compiled code about 6–6.7.
          if (cov.unreachedEntropy) info['Entropia del codice non raggiunto'] = `${cov.unreachedEntropy.toFixed(2)} bit/byte`;
          const lowCoverage = codeBytes > 64 * 1024 && cov.ratio < 0.05 && !image.dotnet && !cfg.truncated;
          const packedLike = lowCoverage && cov.unreachedEntropy >= PACKED_ENTROPY;
          C('Codice raggiungibile o con struttura normale (nessun codice cifrato non raggiungibile)', !packedLike, cov.unreachedEntropy ? msg('{cov}, entropia {e}', { cov: info['Copertura del codice'], e: cov.unreachedEntropy.toFixed(2) }) : info['Copertura del codice']);
          if (packedLike) out.push({ severity: 'medium', title: 'Codice quasi tutto irraggiungibile', detail: msg('Dal punto di avvio si raggiunge solo il {cov} del codice e il resto ha entropia {e} bit/byte (dati compressi o cifrati, non istruzioni): tipico dei programmi impacchettati che si decomprimono a runtime.', { cov: info['Copertura del codice'], e: cov.unreachedEntropy.toFixed(2) }) });
          else if (lowCoverage) out.push({ severity: 'info', title: 'Codice raggiunto soprattutto tramite puntatori', detail: msg('Copertura statica {cov}: gran parte delle funzioni è chiamata tramite puntatori (callback, tabelle virtuali, metadati del linguaggio). Il codice non raggiunto ha la struttura di normale codice compilato.', { cov: info['Copertura del codice'] }) });
          if (image.entry != null && !cfg.insns.has(image.entry) && !cfg.truncated) {
            C('Punto di avvio dentro una sezione di codice', false, hex(image.entry));
            if (!image.dotnet) out.push({ severity: 'medium', title: 'Punto di avvio fuori dalle sezioni di codice', detail: 'L\'esecuzione inizia in una zona non eseguibile o non presente nel file (programma impacchettato o manipolato).' });
          }
          behaviourFindings(h, image, out, C);
          mc.stats = { instructions: cfg.insns.size, functions: cfg.functions.size, blocks: cfg.blocks.size, coverage: cov.ratio, padding: cov.padding, unreachedEntropy: cov.unreachedEntropy, loops, truncated: cfg.truncated };
          mc.functions = fns.sort((a, b) => b.cyclomatic - a.cyclomatic).slice(0, 50).map((f) => ({ address: hex(f.start), name: image.symbols.get(f.start) || (f.start === image.entry ? 'entry_point' : `sub_${f.start.toString(16)}`), blocks: f.blocks, size: f.size, cyclomatic: f.cyclomatic, loops: f.loops.length }));
          mc.behaviours = h;
          mc.entry = image.entry != null ? hex(image.entry) : null;
          mc.regions = image.regions.map((r) => ({ name: r.name, va: hex(r.va), offset: r.off, size: r.size }));
          if (ctx.options.detail) mc.listing = D.listing(buf, image, cfg, { max: LISTING_ROWS, binary: true, from: image.entry != null && cfg.insns.has(image.entry) ? image.entry : null });
        } else if (!image.arch) C('Architettura supportata dal disassemblatore (x86, x86-64, ARM64)', false, image.machine != null ? String(image.machine) : '');
      }
    }

    /* ---------- 2. Shellcode anywhere outside the executable code ---------- */
    const inExec = (o) => execRanges.some(([a, b]) => o >= a && o < b);
    const sc = shellcode.find(buf).filter((s) => !inExec(s.start));
    C('Nessuno shellcode nei dati', !sc.length, sc.length ? msg('{n} blocchi', { n: sc.length }) : '');
    for (const s of sc.slice(0, 20)) {
      const where = isExe ? 'nei dati del programma (fuori dalle sezioni di codice)' : msg('dentro un file {label}', { label: ctx.type.label });
      const v = { bits: s.bits, at: hex(s.start), where, conf: s.confidence === 'high' ? 'alta' : 'media', anchor: s.anchor, list: s.stackStrings };
      out.push({
        severity: !isExe && s.confidence === 'high' ? 'critical' : 'high',
        title: isExe ? msg('Shellcode {bits}-bit nascosto nei dati @ {at}', v) : msg('Shellcode {bits}-bit nel file @ {at}', v),
        detail: s.stackStrings.length
          ? msg('Codice macchina eseguibile {where} (confidenza {conf}; punto di riconoscimento: {anchor}). Lo shellcode è il cuore degli exploit: viene eseguito sfruttando una vulnerabilità. Stringhe composte: {list}', v)
          : msg('Codice macchina eseguibile {where} (confidenza {conf}; punto di riconoscimento: {anchor}). Lo shellcode è il cuore degli exploit: viene eseguito sfruttando una vulnerabilità.', v),
        evidence: s.evidence.slice(0, 8),
        loc: { offset: s.start },
      });
    }
    if (sc.length) mc.shellcode = sc.slice(0, 20).map((s) => ({ ...s, listing: D.linear(buf, s.start, Math.min(s.end + 16, buf.length), s.bits === 64 ? 'x64' : 'x86', s.start, { binary: true, max: 400 }) }));

    /* ---------- 3. Hash constants in raw bytes (API-hash tables) ---------- */
    const clusters = apihash.scanBuffer(buf).filter((c) => !(mc.behaviours && mc.behaviours.apihash) || !inExec(c.start));
    C('Nessuna tabella di hash di API Windows', !clusters.length);
    for (const c of clusters.slice(0, 5)) {
      out.push({ severity: 'high', title: msg('Tabella di hash di API Windows @ {at}', { at: hex(c.start) }), detail: msg('Valori che corrispondono agli hash ({algs}) di {n} funzioni di sistema: un loader li usa per trovare le API senza nominarle.', { algs: c.algs.join(', '), n: c.apis.length }), evidence: c.apis.slice(0, 12), loc: { offset: c.start } });
    }

    /* ---------- 4. Content hidden with XOR / ADD keys ---------- */
    const big = buf.length > 16 * 1024 * 1024;
    const xs = xorsearch.search(buf, { maxKey: big ? 8 : 32, ops: big ? ['xor'] : ['xor', 'add'] });
    C('Nessun contenuto nascosto con chiave XOR/ADD', !xs.length, xs.length ? msg('{n} trovati', { n: xs.length }) : '');
    const seenPayload = new Set();
    for (const x of xs.slice(0, 20)) {
      const exe = x.id.startsWith('pe') || x.id === 'elf';
      const keyTxt = x.key.length <= 16 ? `0x${x.keyHex}` : `${x.key.length} byte`;
      const v = { op: x.op.toUpperCase(), key: keyTxt, what: x.what, plain: x.plaintext, at: hex(x.offset), len: x.key.length, sample: x.sample };
      out.push({
        severity: exe ? 'critical' : /kernel32|ntdll|getproc|virtualalloc|powershell|cmdexe|binsh/.test(x.id) ? 'high' : 'medium',
        title: exe ? msg('Eseguibile nascosto cifrato con {op} (chiave {key})', v) : msg('Testo nascosto con {op}: {what}', v),
        detail: msg('"{plain}" trovato all\'offset {at} dopo aver recuperato la chiave {op} di {len} byte ({key}) con crittoanalisi differenziale. Anteprima: {sample}', v),
        evidence: [x.sample.slice(0, 120)],
        loc: { offset: x.offset },
      });
      if (exe && !seenPayload.has(x.payloadStart)) {
        seenPayload.add(x.payloadStart);
        ctx.addEmbedded({ name: `decifrato-${x.op}-${x.keyHex.slice(0, 16)}.${x.id === 'elf' ? 'elf' : 'exe'}`, buffer: xorsearch.extractPayload(buf, x), origin: msg('{op} con chiave {key} @ {at}', { ...v, at: hex(x.payloadStart) }) });
      }
    }
    if (xs.length) mc.xor = xs.slice(0, 20).map((x) => ({ op: x.op, key: x.keyHex, plaintext: x.plaintext, offset: x.offset, sample: x.sample }));

    if (!isExe && !sc.length && !clusters.length && !xs.length) {
      if (ctx.type.family === 'media') return { skipped: true, reason: 'nessun codice macchina', findings: [], checks };
    }
    if (mc.format || mc.shellcode || mc.xor) info['Disassemblatore'] = 'Gauntler (x86/x86-64/ARM64, discesa ricorsiva)';
    return { findings: out, checks, info, extra: { machineCode: mc } };
  },
};
