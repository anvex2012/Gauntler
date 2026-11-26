// Creato da anvex2012
'use strict';
const { m: msg } = require('../i18n');
const { EXT_EXPECT, DANGEROUS_EXT } = require('../filetype');

const EXEC_EXT_OK = ['exe', 'dll', 'sys', 'scr', 'so', 'dylib', 'bin', 'elf', 'o', 'out', 'node', 'app', 'efi', 'ocx', 'drv', 'cpl', 'mui', 'class', 'dex', 'wasm', 'x86_64', 'arm64', 'bundle', 'ko', 'axf', 'prx', 'mod', ''];
const DECOY = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'jpg', 'jpeg', 'png', 'gif', 'txt', 'mp3', 'mp4', 'mov', 'zip', 'rtf', 'csv', 'html', 'odt'];
const LURE = /(fattur|invoice|pagament|payment|bonifico|ordine|order|spedizion|shipping|dhl|ups|fedex|scontrino|receipt|contratto|contract|curriculum|resume|cv[_ -]|urgente|urgent|preventivo|quotation|rfq|po[_ -]?\d|swift|estratto|statement|verbale|multa|tax|f24|cud|busta\s?paga|payslip|salary|bank|banca|password|aggiornamento|update|setup|crack|keygen|activator|patch|loader)/i;

module.exports = {
  id: 'identity',
  name: 'Identità & camuffamento',
  description: 'Verifica che il file sia davvero ciò che dichiara: contenuto reale vs estensione, doppie estensioni, caratteri ingannevoli o invisibili nel nome, omoglifi, nomi-esca tipici del phishing.',
  weight: 1.5,
  applies: () => true,
  run(ctx) {
    const out = [];
    const checks = [];
    const name = ctx.name, ext = ctx.ext, t = ctx.type;
    const C = (n, ok, note) => checks.push({ name: n, ok, note });

    const rtlo = /[‪-‮⁦-⁩‎‏]/.test(name);
    C('Nessun carattere di inversione del testo (RTLO) nel nome', !rtlo);
    if (rtlo) out.push({ severity: 'critical', title: 'Carattere di inversione testo nel nome', detail: 'Il nome contiene caratteri Unicode (RTLO) usati per camuffare l\'estensione reale.' });

    const zw = /[​-‍⁠﻿]/.test(name);
    C('Nessun carattere invisibile nel nome', !zw);
    if (zw) out.push({ severity: 'high', title: 'Caratteri invisibili nel nome', detail: 'Il nome contiene caratteri a larghezza zero.' });

    const homo = /[Ѐ-ӿͰ-Ͽ]/.test(name) && /[A-Za-z]/.test(name);
    C('Nessun omoglifo (lettere cirilliche/greche mescolate)', !homo);
    if (homo) out.push({ severity: 'medium', title: 'Lettere straniere che imitano lettere latine', detail: 'Il nome mescola alfabeti diversi per sembrare un altro file.' });

    const parts = name.toLowerCase().split('.');
    const prev = parts.length >= 3 ? parts[parts.length - 2] : '';
    const dbl = DECOY.includes(prev) && DANGEROUS_EXT.has(ext);
    C('Nessuna doppia estensione ingannevole', !dbl, prev ? `.${prev}.${ext}` : '');
    if (dbl) out.push({ severity: 'critical', title: 'Doppia estensione ingannevole', detail: msg('Il file sembra ".{prev}" ma in realtà è ".{ext}".', { prev, ext }) });

    const spaces = /\s{5,}\.[a-z0-9]{2,5}$/i.test(name) || /_{8,}\.[a-z0-9]{2,5}$/i.test(name);
    C('Nessuno spazio/riempitivo prima dell\'estensione', !spaces);
    if (spaces) out.push({ severity: 'high', title: 'Spazi nascosti prima dell\'estensione', detail: 'Molti spazi o trattini nel nome per nascondere l\'estensione reale.' });

    const expected = EXT_EXPECT[ext];
    const mismatch = expected && !expected.includes(t.id) && t.id !== 'empty';
    C('Estensione coerente con il contenuto reale', !mismatch, msg('.{ext} → {label}', { ext: ext || '-', label: t.label }));
    if (mismatch) {
      const sev = t.family === 'executable' || t.family === 'script' ? 'critical' : 'medium';
      out.push({ severity: sev, title: 'Estensione non corrispondente al contenuto', detail: msg('L\'estensione è ".{ext}" ma il contenuto reale è: {label}.', { ext, label: t.label }) });
    }
    const weirdExe = !expected && t.family === 'executable' && !EXEC_EXT_OK.includes(ext);
    C('Eseguibile con estensione appropriata', !weirdExe);
    if (weirdExe) out.push({ severity: 'high', title: 'Eseguibile con estensione insolita', detail: msg('Il file è un {label} ma ha estensione ".{ext}".', { label: t.label, ext }) });

    const danger = DANGEROUS_EXT.has(ext);
    C('Tipo di file non eseguibile', !danger, `.${ext}`);
    if (danger) out.push({ severity: 'low', title: 'Tipo di file che può eseguire codice', detail: msg('I file ".{ext}" possono eseguire codice sul computer. Aprili solo se ti fidi della fonte.', { ext }) });

    const lure = LURE.test(name) && (danger || t.family === 'executable' || t.family === 'script');
    C('Nessun nome-esca su file eseguibile', !lure);
    if (lure) out.push({ severity: 'medium', title: 'Nome-esca su un file eseguibile', detail: 'Nomi come "fattura", "pagamento", "crack", "setup" sono usati per convincere ad aprire malware.' });

    const longName = name.length > 120;
    C('Lunghezza del nome normale', !longName, msg('{n} caratteri', { n: name.length }));
    if (longName) out.push({ severity: 'low', title: 'Nome del file lunghissimo', detail: 'Nomi lunghi nascondono l\'estensione nelle finestre.' });

    const hidden = name.startsWith('.') && !/^\.(env|gitignore|npmrc|editorconfig|prettierrc|eslintrc|DS_Store)/.test(name);
    C('File non nascosto', !hidden);
    if (hidden) out.push({ severity: 'info', title: 'File nascosto', detail: 'Il nome inizia con un punto: non è visibile normalmente.' });

    if (ctx.size === 0) out.push({ severity: 'info', title: 'File vuoto', detail: 'Il file non contiene dati.' });
    return { findings: out, checks, info: { 'Tipo reale': t.label, 'Famiglia': t.family, 'MIME': t.mime, 'Estensione': ext ? '.' + ext : '(nessuna)', 'Codifica': ctx.isText ? (ctx.utf16 ? 'UTF-16' : 'testo') : 'binario' } };
  },
};
