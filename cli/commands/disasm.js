// Creato da anvex2012
'use strict';
/* gauntler disasm: assembly listing (x86 / x86-64 / ARM64) with bytes in hex or binary */
const fs = require('fs');
const path = require('path');
const D = require('../../core/disasm');
const { Detector } = require('../../core/disasm/heuristics');
const shellcode = require('../../core/disasm/shellcode');
const { detectType } = require('../../core/filetype');
const { UsageError } = require('../args');
const ui = require('../ui');
const { c } = ui;

const SPEC = {
  binary: { alias: 'b', type: 'bool' },
  all: { alias: 'a', type: 'bool' },
  max: { alias: 'n', type: 'number' },
  from: { type: 'string' },
  linear: { type: 'bool' },
  raw: { type: 'bool' },
  arch: { type: 'string' },
  offset: { type: 'string' },
  length: { type: 'string' },
  functions: { alias: 'F', type: 'bool' },
  dump: { type: 'bool' },
  out: { alias: 'o', type: 'string' },
  json: { type: 'bool' },
};

const HELP = `
${c.bold('gauntler disasm')} — mostra il codice macchina di un file in assembly e in binario

${c.bold('Uso')}
  gauntler disasm <file> [opzioni]

${c.bold('Opzioni')}
  -b, --binary          Byte di ogni istruzione in binario (0/1) invece che esadecimale
      --dump            Solo il file in codice binario (bit per bit, 8 byte per riga, con offset)
  -a, --all             Tutto il codice, senza limite di righe
  -n, --max <righe>     Numero massimo di righe (predefinito 3000; illimitato con --all o -o)
      --from <indirizzo>  Inizia da un indirizzo (es. 0x401000)
      --linear          Lettura lineare delle sezioni di codice (invece che seguire il flusso)
  -F, --functions       Elenco delle funzioni con blocchi, cicli e complessità ciclomatica
      --raw             Tratta il file come codice grezzo (shellcode); con --arch x86|x64|arm64
      --offset <n> --length <n>   Intervallo di byte per --raw / --dump
  -o, --out <file>      Scrive su file
      --json            Output JSON

${c.bold('Esempi')}
  gauntler disasm programma.exe                  ${c.dim('assembly dal punto di avvio')}
  gauntler disasm /bin/ls -F                     ${c.dim('funzioni e complessità')}
  gauntler disasm payload.bin --raw --arch x86 -b
  gauntler disasm documento.doc                  ${c.dim('trova e disassembla lo shellcode nascosto')}
  gauntler disasm file.bin --dump --length 256   ${c.dim('codice binario puro')}
`;

const num = (v, d) => (v == null ? d : /^0x/i.test(v) ? parseInt(v, 16) : Number(v));

function binaryDump(buf, start, end) {
  const out = [];
  for (let o = start; o < end; o += 8) {
    const row = buf.subarray(o, Math.min(end, o + 8));
    const bits = Array.from(row, (b) => b.toString(2).padStart(8, '0')).join(' ');
    const asc = Array.from(row, (b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '.')).join('');
    out.push(`${o.toString(16).padStart(8, '0')}  ${bits.padEnd(71)}  ${asc}`);
  }
  return out.join('\n');
}

async function run(argv, { parse }) {
  const a = parse(argv, SPEC);
  if (a.help || !a._.length) { console.log(HELP); return a.help ? 0 : 2; }
  const file = a._[0];
  if (!fs.existsSync(file)) throw new UsageError('File non trovato: ' + file);
  const buf = fs.readFileSync(file);
  const type = detectType(buf, path.basename(file));
  const max = a.max != null ? a.max : (a.all || a.out ? Infinity : 3000);
  const emit = (text) => { if (a.out) fs.writeFileSync(a.out, text.endsWith('\n') ? text : text + '\n'); else console.log(text); };

  if (a.dump) {
    const start = num(a.offset, 0), end = Math.min(buf.length, start + num(a.length, buf.length));
    emit(binaryDump(buf, start, end));
    return 0;
  }

  const isExe = ['pe', 'dll', 'elf', 'macho'].includes(type.id) && !a.raw;
  if (isExe) {
    const image = D.load(buf, type.id);
    if (!image.arch) throw new UsageError(`Architettura non supportata dal disassemblatore (supportate: x86, x86-64, ARM64)`);
    const det = new Detector(image.arch);
    const cfg = D.explore(buf, image, { onIns: (i) => det.feed(i) });
    const head = `${c.bold(path.basename(file))} — ${image.format} ${image.arch} · punto di avvio ${image.entry != null ? '0x' + image.entry.toString(16) : 'n/d'} · ${cfg.functions.size} funzioni · ${cfg.blocks.size} blocchi · ${cfg.insns.size} istruzioni${cfg.truncated ? ' (limite)' : ''}`;
    if (a.functions) {
      const fns = D.analyzeFunctions(cfg, Infinity).sort((x, y) => x.start - y.start);
      if (a.json) { emit(JSON.stringify(fns.map((f) => ({ ...f, name: image.symbols.get(f.start) || null, start: '0x' + f.start.toString(16) })), null, 2)); return 0; }
      const rows = fns.slice(0, max).map((f) => [c.cyan('0x' + f.start.toString(16)), image.symbols.get(f.start) || (f.start === image.entry ? 'entry_point' : `sub_${f.start.toString(16)}`), String(f.blocks), String(f.size), String(f.loops.length), f.cyclomatic > 50 ? c.red(String(f.cyclomatic)) : f.cyclomatic > 15 ? c.yellow(String(f.cyclomatic)) : String(f.cyclomatic)]);
      emit(head + '\n\n' + ui.table(rows, ['Indirizzo', 'Nome', 'Blocchi', 'Byte', 'Cicli', 'Complessità']));
      return 0;
    }
    let rows;
    if (a.linear) {
      rows = [];
      for (const r of image.regions) {
        if (rows.length >= max) break;
        rows.push({ gap: true }, { va: r.va, off: r.off, hex: '', text: c.dim(`; sezione ${r.name}`), label: r.name });
        rows.push(...D.linear(buf, r.off, r.off + r.size, image.arch, r.va, { binary: a.binary, max: max - rows.length }));
      }
    } else {
      rows = D.listing(buf, image, cfg, { max, binary: a.binary, from: a.from ? num(a.from) : null });
    }
    if (a.json) { emit(JSON.stringify({ format: image.format, arch: image.arch, entry: image.entry, behaviours: det.finish(), listing: rows }, null, 2)); return 0; }
    emit(`${head}\n${D.formatRows(rows, { binary: a.binary })}`);
    if (rows.length >= max && max !== Infinity) console.error(c.dim(`\n… mostrate ${max} righe: usa --all o -o file per l'elenco completo`));
    return 0;
  }

  // Raw code: explicit range, or shellcode found automatically
  const arch = a.arch || null;
  if (arch && !['x86', 'x64', 'arm64'].includes(arch)) throw new UsageError('--arch deve essere x86, x64 o arm64');
  let ranges;
  if (a.raw || arch || a.offset) {
    const start = num(a.offset, 0);
    ranges = [{ start, end: Math.min(buf.length, start + num(a.length, buf.length)), arch: arch || 'x86', why: 'intervallo richiesto' }];
  } else {
    ranges = shellcode.find(buf).map((s) => ({ start: s.start, end: Math.min(buf.length, s.end + 16), arch: s.bits === 64 ? 'x64' : 'x86', why: `shellcode (${s.behaviours.join(', ')})` }));
    if (!ranges.length) { console.log(`${type.label}: nessun codice macchina riconosciuto. Usa --raw --arch x86|x64|arm64 per forzare il disassemblaggio.`); return 1; }
  }
  const all = [];
  for (const r of ranges) {
    const rows = D.linear(buf, r.start, r.end, r.arch, r.start, { binary: a.binary, max });
    all.push({ ...r, rows });
  }
  if (a.json) { emit(JSON.stringify(all, null, 2)); return 0; }
  emit(all.map((r) => `${c.bold(`; ${r.why} — ${r.arch} — offset 0x${r.start.toString(16)}…0x${r.end.toString(16)}`)}\n${D.formatRows(r.rows, { binary: a.binary })}`).join('\n\n'));
  return 0;
}

module.exports = { run, HELP, SPEC, summary: 'Disassembla il file: assembly x86/x64/ARM64 e codice binario', binaryDump };
