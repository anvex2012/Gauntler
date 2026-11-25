// Creato da anvex2012
'use strict';
const COMPRESSED_FAMILIES = new Set(['media', 'archive']);
const COMPRESSED_IDS = new Set(['pdf', 'docx', 'xlsx', 'pptx', 'odf', 'jar', 'apk', 'kdbx', 'wasm', 'dmg', 'xar', 'one']);

module.exports = {
  id: 'statistics',
  name: 'Analisi statistica (entropia)',
  description: 'Analisi statistica dell\'intero file byte per byte: entropia di Shannon, test chi-quadro con p-value, stima Monte Carlo di π, correlazione seriale, media aritmetica, rapporto di compressione, profilo di entropia e istogramma dei byte; scopre dati cifrati, payload nascosti e file poliglotti.',
  weight: 1,
  applies: (ctx) => ctx.size > 0,
  run(ctx) {
    const out = [], checks = [];
    const C = (n, ok, note) => checks.push({ name: n, ok, note });
    const s = ctx.stats;
    let cls;
    if (s.entropy < 4.5) cls = 'testo/dati strutturati';
    else if (s.entropy < 6.8) cls = 'binario normale';
    else if (s.entropy < 7.6) cls = 'compresso';
    else cls = s.chiP > 0.01 && s.piErr !== null && s.piErr < 0.02 ? 'cifrato/casuale' : 'compresso o cifrato';
    const expectedHigh = COMPRESSED_FAMILIES.has(ctx.type.family) || COMPRESSED_IDS.has(ctx.type.id);
    const unknown = ctx.type.family === 'unknown';

    const enc = cls === 'cifrato/casuale' && unknown && ctx.size > 4096;
    C('Il contenuto non è cifrato senza formato noto', !enc, cls);
    if (enc) out.push({ severity: 'high', title: 'File interamente cifrato di tipo sconosciuto', detail: 'Dati statisticamente indistinguibili da casuali (chi-quadro, Monte Carlo) senza un formato riconoscibile: file preso in ostaggio da ransomware o payload cifrato.' });
    else if (s.entropy > 7.5 && unknown && ctx.size > 4096) out.push({ severity: 'medium', title: 'Dati ad alta entropia senza formato noto', detail: 'Contenuto compresso o cifrato non identificabile.' });
    const encScript = s.entropy > 6.5 && ctx.type.family === 'script';
    C('Entropia coerente con il tipo di file', !encScript && !(s.entropy > 7.2 && ['text', 'markup'].includes(ctx.type.family)), s.entropy.toFixed(3));
    if (encScript) out.push({ severity: 'high', title: 'Script con contenuto cifrato', detail: `Uno script non dovrebbe avere entropia ${s.entropy.toFixed(2)}.` });

    const prof = s.profile;
    let hot = 0, cold = 0;
    if (prof.length >= 8 && !expectedHigh) {
      hot = prof.filter((v) => v > 7.6).length;
      cold = prof.filter((v) => v < 6).length;
    }
    const hidden = hot >= 2 && cold >= prof.length * 0.4 && ctx.type.family !== 'executable';
    C('Nessuna zona cifrata isolata in un file normale', !hidden, `${hot} zone`);
    if (hidden) out.push({ severity: 'low', title: 'Blocco di dati cifrati nascosto', detail: `${hot} zone ad altissima entropia in un file altrimenti normale (possibile payload incorporato o steganografia).` });

    // Data appended after the end of an image / PDF (polyglot files)
    let tailInfo = null;
    const b = ctx.buffer;
    let endIdx = -1;
    if (ctx.type.id === 'jpeg') { endIdx = b.lastIndexOf(Buffer.from([0xff, 0xd9])); if (endIdx >= 0) endIdx += 2; }
    if (ctx.type.id === 'png') { const i = b.lastIndexOf(Buffer.from('IEND')); endIdx = i >= 0 ? i + 8 : -1; }
    if (ctx.type.id === 'gif') { const i = b.lastIndexOf(0x3b); endIdx = i >= 0 ? i + 1 : -1; }
    if (ctx.type.id === 'pdf') { const i = b.lastIndexOf(Buffer.from('%%EOF')); endIdx = i >= 0 ? i + 5 : -1; }
    if (endIdx > 0 && b.length - endIdx > 1024) {
      const tail = b.subarray(endIdx);
      const trimmed = tail.toString('latin1').replace(/^[\s\0]+/, '');
      const hdr = trimmed.slice(0, 4);
      const what = hdr.startsWith('MZ') ? 'un eseguibile Windows' : hdr === 'PK\x03\x04' ? 'un archivio ZIP' : hdr.startsWith('<?ph') ? 'codice PHP' : hdr.startsWith('\x7fELF') ? 'un eseguibile Linux' : /<script|<html/i.test(trimmed.slice(0, 200)) ? 'codice HTML/JavaScript' : `${tail.length} byte di dati extra`;
      tailInfo = what;
      out.push({ severity: /eseguibile|PHP|HTML/.test(what) ? 'critical' : /ZIP/.test(what) ? 'high' : 'low', title: 'Dati nascosti dopo la fine del file', detail: `Dopo la fine del ${ctx.type.label.toLowerCase()} è accodato ${what} (file poliglotta).`, loc: { offset: endIdx } });
      if (/eseguibile|ZIP|PHP|HTML/.test(what)) ctx.embedded.push({ name: 'dati-accodati.bin', buffer: tail, origin: `accodato all'offset 0x${endIdx.toString(16)}` });
    }
    C('Nessun dato accodato dopo la fine del formato', !tailInfo, tailInfo || '');
    C('Distribuzione dei byte non uniforme (non cifrata)', !(s.chiP > 0.01 && s.entropy > 7.9) || expectedHigh, `p=${s.chiP.toFixed(4)}`);
    const nulls = s.nullRatio > 0.9 && ctx.size > 1024 * 1024;
    C('File non composto quasi solo di zeri', !nulls);
    if (nulls) out.push({ severity: 'low', title: 'File quasi vuoto (zeri)', detail: 'Il file è composto quasi interamente da byte nulli (padding per gonfiare la dimensione ed eludere gli antivirus).' });

    return {
      findings: out, checks,
      info: {
        'Byte analizzati': ctx.totals.bytes,
        'Entropia (Shannon)': `${s.entropy.toFixed(4)} / 8`,
        'Chi-quadro': `${Math.round(s.chi)} (p = ${s.chiP < 0.0001 ? '< 0.0001' : s.chiP.toFixed(4)})`,
        'Media aritmetica': `${s.mean.toFixed(3)} (casuale = 127.5)`,
        'Monte Carlo π': s.pi ? `${s.pi.toFixed(6)} (errore ${(s.piErr * 100).toFixed(3)}%)` : 'n/d',
        'Correlazione seriale': s.serial.toFixed(6),
        'Rapporto compressione': `${(s.compression * 100).toFixed(1)}%`,
        'Byte stampabili': `${(s.printableRatio * 100).toFixed(1)}%`,
        'Byte nulli': `${(s.nullRatio * 100).toFixed(1)}%`,
        'Valori di byte distinti': `${s.uniqueBytes} / 256`,
        'Classificazione': cls,
      },
    };
  },
};
