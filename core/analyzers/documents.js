// Created by anvex2012
'use strict';
const { m: msg } = require('../i18n');
const { countMatches, truncate } = require('../utils');

const PDF_KW = {
  '/JavaScript': /\/JavaScript\b/g, '/JS': /\/JS\b/g, '/OpenAction': /\/OpenAction\b/g, '/AA': /\/AA\b/g, '/Launch': /\/Launch\b/g,
  '/EmbeddedFile': /\/EmbeddedFiles?\b/g, '/RichMedia': /\/RichMedia\b/g, '/XFA': /\/XFA\b/g, '/AcroForm': /\/AcroForm\b/g, '/URI': /\/URI\b/g,
  '/SubmitForm': /\/SubmitForm\b/g, '/GoToR': /\/GoToR\b/g, '/GoToE': /\/GoToE\b/g, '/ImportData': /\/ImportData\b/g, '/ObjStm': /\/ObjStm\b/g,
  '/Encrypt': /\/Encrypt\b/g, '/JBIG2Decode': /\/JBIG2Decode\b/g, '/Colors>2^24': /\/Colors\s+\d{8,}/g,
};

function macroFinding(ctx, out, info, checks) {
  const s = ctx.macros.join('\n');
  const autoexec = /\b(AutoOpen|Auto_Open|Document_Open|Workbook_Open|AutoExec|Auto_Close|Document_Close|Workbook_Activate|Workbook_BeforeClose|Document_ContentControlOnEnter|InkPicture1_Painted)\b/i.test(s);
  const shell = /\b(Shell|WScript\.Shell|CreateObject|URLDownloadToFile|XMLHTTP|ADODB\.Stream|PowerShell|cmd\.exe|ShellExecute|CallByName|MacScript|Lib\s+"kernel32)\b/i.test(s);
  const declares = /\bDeclare\s+(PtrSafe\s+)?(Function|Sub)\b[^\n]*Lib\s+"(kernel32|ntdll|user32)/i.test(s);
  const sev = autoexec && (shell || declares) ? 'critical' : autoexec || shell || declares ? 'high' : 'medium';
  info['Moduli macro'] = ctx.macros.length || 'presenti (non decodificati)';
  info['Righe di macro'] = s.split('\n').length;
  checks.push({ name: 'Macro con avvio automatico', ok: !autoexec }, { name: 'Macro che eseguono comandi', ok: !shell }, { name: 'Macro che chiamano API di Windows', ok: !declares });
  out.push({
    severity: sev,
    title: msg('Il documento contiene macro VBA ({n} moduli)', { n: ctx.macros.length || '?' }),
    detail: autoexec && shell ? 'Macro che si avviano da sole ed eseguono comandi: comportamento tipico dei malware.' : 'Le macro possono eseguire codice. Non abilitarle se non sei sicuro della provenienza. Il codice completo è nella scheda "Codice".',
    evidence: [autoexec && 'avvio automatico', shell && 'esecuzione comandi', declares && 'chiamate dirette a DLL di sistema'].filter(Boolean),
  });
}

function analyzePDF(ctx, out, info, checks) {
  const all = [ctx.text, ...ctx.extracted.filter((e) => e.kind !== 'doctext').map((e) => e.text)].join('\n');
  const c = {};
  for (const [k, re] of Object.entries(PDF_KW)) c[k] = countMatches(all, re);
  const hexNames = countMatches(ctx.text, /\/[A-Za-z]*#[0-9a-fA-F]{2}[A-Za-z#0-9]*/g);
  const st = ctx.pdfStats || {};
  Object.assign(info, {
    'Versione': (ctx.text.match(/%PDF-(\d\.\d)/) || [])[1] || '?',
    'Oggetti': countMatches(ctx.text, /\d+\s+\d+\s+obj\b/g), 'Pagine': countMatches(all, /\/Type\s*\/Page\b/g),
    'Flussi totali': st.streams || 0, 'Flussi decompressi': st.decoded || 0, 'Flussi JavaScript': st.js || 0, 'Immagini': st.images || 0,
    'Aggiornamenti incrementali': Math.max(0, countMatches(ctx.text, /%%EOF/g) - 1),
    'Parole chiave': Object.entries(c).filter(([, v]) => v).map(([k, v]) => `${k}:${v}`).join(' ') || 'nessuna',
  });
  const js = c['/JavaScript'] + c['/JS'];
  const auto = c['/OpenAction'] + c['/AA'];
  for (const [k, v] of Object.entries(c)) checks.push({ name: msg('Parola chiave PDF {k}', { k }), ok: !v || ['/URI', '/AcroForm', '/ObjStm'].includes(k), note: String(v) });
  if (js && auto) out.push({ severity: 'high', title: 'JavaScript eseguito all\'apertura del PDF', detail: 'Il PDF esegue codice automaticamente quando viene aperto.' });
  else if (js) out.push({ severity: 'medium', title: 'PDF contiene JavaScript', detail: 'Codice eseguibile dentro il documento (visibile nella scheda "Codice").' });
  if (c['/Launch']) out.push({ severity: 'high', title: 'PDF può avviare programmi', detail: 'L\'azione /Launch può eseguire comandi sul computer.' });
  if (c['/EmbeddedFile']) out.push({ severity: 'medium', title: 'File nascosti dentro il PDF', detail: 'Il PDF contiene allegati incorporati (analizzati nella scheda "Contenuti").' });
  if (c['/RichMedia']) out.push({ severity: 'medium', title: 'Contenuto Flash/multimediale', detail: 'Elementi /RichMedia (storicamente vulnerabili).' });
  if (c['/XFA']) out.push({ severity: 'low', title: 'Moduli XFA', detail: 'Moduli dinamici XFA.' });
  if (c['/GoToR'] || c['/GoToE'] || c['/ImportData']) out.push({ severity: 'medium', title: 'Azioni verso file/documenti esterni', detail: 'Il PDF apre o importa contenuti esterni (possibile furto di hash NTLM).' });
  if (c['/JBIG2Decode'] && js) out.push({ severity: 'high', title: 'Possibile exploit JBIG2', detail: 'Combinazione usata da exploit noti.' });
  if (c['/Colors>2^24']) out.push({ severity: 'high', title: 'Possibile exploit /Colors', detail: 'Valore anomalo usato dall\'exploit CVE-2009-3459.' });
  if (c['/SubmitForm'] && c['/AcroForm']) out.push({ severity: 'low', title: 'Modulo che invia dati', detail: 'Il PDF può inviare i dati inseriti a un server.' });
  if (hexNames > 3) out.push({ severity: 'high', title: 'Nomi PDF offuscati', detail: 'Parole chiave codificate (#xx) per eludere gli scanner.' });
  if (c['/Encrypt']) out.push({ severity: 'info', title: 'PDF cifrato', detail: 'Il contenuto è cifrato: alcuni flussi potrebbero non essere leggibili.' });
  if (st.failed) out.push({ severity: 'low', title: msg('Flussi non decodificabili ({n})', { n: st.failed }), detail: 'Flussi corrotti o con filtri insoliti: possibile tecnica di elusione.' });
  if (info['Aggiornamenti incrementali'] > 3) out.push({ severity: 'low', title: 'Molte revisioni incrementali', detail: 'Il PDF è stato modificato più volte dopo la creazione (contenuti nascosti nelle revisioni precedenti).' });
  for (const e of ctx.extracted.filter((x) => x.kind === 'js')) {
    if (/(eval|unescape|String\.fromCharCode|app\.launchURL|this\.exportDataObject|util\.printf|Collab\.(collectEmailInfo|getIcon)|media\.newPlayer|spell\.customDictionaryOpen|getAnnots)/.test(e.text)) {
      out.push({ severity: 'high', title: 'JavaScript PDF pericoloso', detail: msg('Funzioni usate da exploit PDF in "{label}".', { label: e.label }), evidence: [truncate(e.text.trim(), 140)], loc: { source: e.label, line: 1 } });
    }
  }
}

function analyzeOOXML(ctx, out, info, checks) {
  const parts = ctx.officeParts || [];
  info['Parti del documento'] = parts.length;
  if (ctx.macros.length || parts.some((n) => /vbaProject\.bin$/i.test(n))) macroFinding(ctx, out, info, checks);
  else checks.push({ name: 'Nessuna macro VBA', ok: true });
  const ax = parts.some((n) => /activeX/i.test(n));
  checks.push({ name: 'Nessun controllo ActiveX', ok: !ax });
  if (ax) out.push({ severity: 'medium', title: 'Controlli ActiveX', detail: 'Componenti ActiveX incorporati.' });
  const emb = parts.filter((n) => /oleObject|embeddings\//i.test(n));
  checks.push({ name: 'Nessun oggetto OLE incorporato', ok: !emb.length });
  if (emb.length) out.push({ severity: 'medium', title: 'Oggetti incorporati (OLE)', detail: 'File o programmi incorporati nel documento (analizzati nella scheda "Contenuti").', evidence: emb });
  const ext = new Set(), tmpl = [], dde = [], follina = [];
  for (const e of ctx.extracted.filter((x) => x.kind === 'xml')) {
    for (const m of e.text.matchAll(/Target="([^"]+)"\s+TargetMode="External"|TargetMode="External"[^>]*Target="([^"]+)"/gi)) {
      const t = m[1] || m[2];
      ext.add(t);
      if (/attachedTemplate|oleObject|frame|subDocument/i.test(e.text) && /^https?:|^\\\\|^file:/i.test(t)) tmpl.push(t);
    }
    if (/mhtml:|ms-msdt:|search-ms:|ms-officecmd:|ms-excel:ofe\|/i.test(e.text)) follina.push(e.label);
    if (/DDEAUTO|\bDDE\b\s|<w:fldSimple[^>]*\bDDE/i.test(e.text)) dde.push(e.label);
  }
  info['Collegamenti esterni'] = ext.size;
  checks.push({ name: 'Nessun template/oggetto remoto', ok: !tmpl.length }, { name: 'Nessun exploit di protocollo (Follina…)', ok: !follina.length }, { name: 'Nessun campo DDE', ok: !dde.length });
  if (tmpl.length) out.push({ severity: 'high', title: 'Template remoto (template injection)', detail: 'Il documento scarica contenuti da Internet all\'apertura.', evidence: tmpl.map((t) => truncate(t, 100)) });
  if (follina.length) out.push({ severity: 'critical', title: 'Exploit protocollo Office (es. Follina)', detail: 'Riferimenti a protocolli sfruttati da vulnerabilità note.', evidence: follina });
  if (dde.length) out.push({ severity: 'high', title: 'Campo DDE', detail: 'Comandi eseguiti tramite Dynamic Data Exchange.', evidence: dde });
  if (ext.size && !tmpl.length) out.push({ severity: 'info', title: msg('Collegamenti esterni ({n})', { n: ext.size }), detail: 'Link a risorse esterne.', evidence: [...ext].slice(0, 10).map((t) => truncate(t, 100)) });
}

function analyzeOLE(ctx, out, info, checks) {
  const t = ctx.text;
  if (ctx.macros.length || /_VBA_PROJECT|\x00V\x00B\x00A\x00/.test(t)) macroFinding(ctx, out, info, checks);
  else checks.push({ name: 'Nessuna macro VBA', ok: true });
  const eq = /Equation\.3|\x02\xce\x02\x00/.test(t);
  checks.push({ name: 'Nessun oggetto Equation Editor', ok: !eq });
  if (eq) out.push({ severity: 'high', title: 'Oggetto Equation Editor', detail: 'Componente sfruttato dalla vulnerabilità CVE-2017-11882.' });
  const xlm = /EXEC\(|CALL\(|REGISTER\(/i.test(t) && /Excel|Workbook|\x85\x00/.test(t);
  checks.push({ name: 'Nessuna macro Excel 4.0 (XLM)', ok: !xlm });
  if (xlm) out.push({ severity: 'high', title: 'Macro Excel 4.0 (XLM)', detail: 'Vecchio formato di macro molto usato dai malware.' });
  if (/MsiPackage|Installation Database|\x00M\x00s\x00i/i.test(t)) { info['Tipo'] = 'Pacchetto di installazione MSI'; out.push({ severity: 'low', title: 'Pacchetto di installazione MSI', detail: 'Installa software sul computer.' }); }
  if (/__substg1\.0_|IPM\.Note/.test(t)) info['Tipo'] = 'Email Outlook (.msg)';
}

function analyzeRTF(ctx, out, info, checks) {
  const t = ctx.text;
  const objs = countMatches(t, /\\objdata/gi);
  info['Oggetti incorporati'] = objs;
  checks.push({ name: 'Nessun oggetto incorporato', ok: !objs });
  if (objs) out.push({ severity: 'medium', title: msg('Oggetti incorporati in RTF ({n})', { n: objs }), detail: 'Il documento RTF contiene oggetti (analizzati nella scheda "Contenuti").' });
  if (/\\objupdate/i.test(t)) out.push({ severity: 'high', title: 'Aggiornamento automatico oggetti RTF', detail: 'Gli oggetti si caricano da soli all\'apertura.' });
  if (/0002ce02|equation\.3/i.test(t)) out.push({ severity: 'critical', title: 'Exploit Equation Editor in RTF', detail: 'Tecnica di CVE-2017-11882 / CVE-2018-0802.' });
  if (/\\\*\\template\s+https?:/i.test(t)) out.push({ severity: 'high', title: 'Template RTF remoto', detail: 'Carica contenuti da Internet.' });
  const junk = countMatches(t, /\{\\[a-z]{20,}/g);
  if (junk > 5) out.push({ severity: 'medium', title: 'Parole di controllo RTF anomale', detail: 'RTF deliberatamente malformato per eludere i parser.' });
}

function analyzeLNK(ctx, out, info, checks) {
  const t = ctx.text + '\n' + ctx.buffer.toString('utf16le');
  const target = (t.match(/[A-Za-z]:\\[^\x00\n]{3,260}?\.(?:exe|bat|cmd|ps1|vbs|js|hta|dll|scr)/i) || [])[0];
  if (target) info['Destinazione'] = target;
  const m = t.match(/(powershell|cmd\.exe|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin|curl|conhost)[^\x00]{0,400}/i);
  checks.push({ name: 'Il collegamento non lancia interpreti di comandi', ok: !m });
  if (m) out.push({ severity: /powershell|mshta|certutil|bitsadmin|curl/i.test(m[1]) ? 'critical' : 'high', title: 'Collegamento che esegue comandi', detail: 'Il file .lnk lancia un interprete di comandi.', evidence: [truncate(m[0], 300)] });
  else out.push({ severity: 'low', title: 'Collegamento Windows', detail: 'Verifica la destinazione del collegamento prima di aprirlo.' });
  if (ctx.size > 100 * 1024) out.push({ severity: 'medium', title: 'Collegamento insolitamente grande', detail: msg('{n} KB: un .lnk normale pesa pochi KB (possibile payload incorporato).', { n: Math.round(ctx.size / 1024) }) });
}

module.exports = {
  id: 'documents',
  name: 'Documenti attivi',
  description: 'Contenuti attivi nei documenti: macro VBA (decompresse e lette integralmente), macro XLM, ogni flusso PDF decompresso, JavaScript, azioni automatiche, oggetti OLE, DDE, template remoti, exploit noti (Follina, Equation Editor, JBIG2), collegamenti LNK, OneNote, CHM.',
  weight: 2,
  applies: (ctx) => ['pdf', 'docx', 'xlsx', 'pptx', 'odf', 'ole', 'rtf', 'lnk', 'one', 'chm'].includes(ctx.type.id),
  run(ctx) {
    const out = [], info = {}, checks = [];
    const id = ctx.type.id;
    if (id === 'pdf') analyzePDF(ctx, out, info, checks);
    else if (['docx', 'xlsx', 'pptx', 'odf'].includes(id)) analyzeOOXML(ctx, out, info, checks);
    else if (id === 'ole') analyzeOLE(ctx, out, info, checks);
    else if (id === 'rtf') analyzeRTF(ctx, out, info, checks);
    else if (id === 'lnk') analyzeLNK(ctx, out, info, checks);
    else if (id === 'one') {
      const n = (ctx.buffer.toString('latin1').match(/\.(hta|vbs|js|cmd|bat|wsf|ps1|exe|lnk)\b/gi) || []).length;
      checks.push({ name: 'OneNote senza file eseguibili incorporati', ok: !n });
      if (n) out.push({ severity: 'high', title: 'OneNote con script/eseguibili incorporati', detail: 'Tecnica di phishing del 2023: il documento invita a fare doppio clic su un file nascosto.' });
    } else if (id === 'chm') {
      out.push({ severity: 'medium', title: 'Guida CHM', detail: 'I file CHM possono eseguire script e comandi: formato molto usato per diffondere malware.' });
    }
    info['Contenuti estratti'] = ctx.extracted.length;
    info['File incorporati'] = ctx.embedded.length;
    if (!out.length) out.push({ severity: 'info', title: 'Nessun contenuto attivo', detail: 'Il documento non contiene macro, script o oggetti eseguibili.' });
    return { findings: out, checks, info };
  },
};
