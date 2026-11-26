// Creato da anvex2012
'use strict';
const { t, t: tr } = require('../i18n');
/**
 * Office Open XML (docx/docm, xlsx/xlsm, pptx/pptm) and OpenDocument disarm.
 * The package is rebuilt from scratch keeping only safe parts:
 *  - removed: VBA projects, Excel 4.0 macro sheets, ActiveX controls, embedded OLE objects and
 *    packages, custom UI (ribbon callbacks), attached toolbars, external links (DDE), scripts (ODF)
 *  - relationships pointing outside the document that load content (remote templates — the
 *    "template injection" technique —, OLE links, frames, subdocuments, mhtml:/file:/ms-* schemes)
 *    are removed; normal web hyperlinks are kept
 *  - DDE/DDEAUTO/INCLUDE fields are neutralized, macro-enabled content types become standard ones
 *  - personal metadata (author, last modified by, company) is cleared unless keepMetadata
 */
const { readZip, extract, writeZip } = require('../zip');

const DROP = [
  [/(^|\/)vbaProject\.bin$/i, 'progetto VBA (macro)'],
  [/(^|\/)vbaData\.xml$/i, 'dati VBA'],
  [/(^|\/)vbaProjectSignature[^/]*\.bin$/i, 'firma VBA'],
  [/^xl\/macrosheets\//i, 'foglio macro Excel 4.0 (XLM)'],
  [/(^|\/)activeX\//i, 'controllo ActiveX'],
  [/(^|\/)embeddings\//i, 'oggetto incorporato'],
  [/(^|\/)oleObject[^/]*$/i, 'oggetto OLE'],
  [/^customUI\/|(^|\/)customUI[^/]*\.xml$/i, 'interfaccia personalizzata (callback macro)'],
  [/(^|\/)attachedToolbars\.bin$/i, 'barre degli strumenti con macro'],
  [/^xl\/externalLinks\//i, 'collegamento esterno (DDE)'],
  [/^Basic\/|^Scripts\//i, 'macro/script OpenDocument'],
  [/(^|\/)printerSettings[^/]*\.bin$/i, null], // harmless binary, kept
];
const MACRO_TYPES = [
  ['application/vnd.ms-word.document.macroEnabled.main+xml', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml'],
  ['application/vnd.ms-word.template.macroEnabledTemplate.main+xml', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml'],
  ['application/vnd.ms-excel.sheet.macroEnabled.main+xml', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml'],
  ['application/vnd.ms-excel.template.macroEnabled.main+xml', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml'],
  ['application/vnd.ms-excel.addin.macroEnabled.main+xml', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml'],
  ['application/vnd.ms-powerpoint.presentation.macroEnabled.main+xml', 'application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml'],
  ['application/vnd.ms-powerpoint.slideshow.macroEnabled.main+xml', 'application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml'],
];
const LOADING_REL = /\/(attachedTemplate|oleObject|frame|subDocument|externalLinkPath|externalLink|package|control|activeXControl|aFChunk|vbaProject|customUI|ui\/extensibility|wordVbaData|attachedToolbars)$/i;
const BAD_SCHEME = /^\s*(mhtml:|file:|ms-[\w-]+:|search-ms:|javascript:|vbscript:|\\\\)/i;

const xmlEsc = (s) => s.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');

function disarm(buf, { keepMetadata = false } = {}) {
  const z = readZip(buf);
  if (!z.entries.length) throw new Error('pacchetto Office vuoto o danneggiato');
  const actions = [];
  const files = new Map();
  for (const e of z.entries) {
    if (e.name.endsWith('/')) continue;
    if (e.encrypted) throw new Error('documento protetto da password');
    const r = extract(buf, e);
    if (!r.data) throw new Error(t('parte illeggibile: {name}', { name: e.name }));
    const norm = e.name.replace(/\\/g, '/').replace(/^\/+/, '');
    if (norm.split('/').includes('..')) { actions.push(t('Rimossa parte con percorso anomalo: {name}', { name: e.name })); continue; }
    files.set(norm, r.data);
  }
  const dropped = new Set();
  for (const name of [...files.keys()]) {
    const d = DROP.find(([re]) => re.test(name));
    if (d && d[1]) { files.delete(name); dropped.add(name); actions.push(`Rimosso ${d[1]}: ${name}`); }
  }
  const isDropped = (base, target) => {
    const dir = base.includes('/') ? base.slice(0, base.lastIndexOf('/')) : '';
    const parts = (target.startsWith('/') ? target.slice(1) : (dir ? dir + '/' : '') + target).split('/');
    const out = [];
    for (const p of parts) { if (p === '..') out.pop(); else if (p && p !== '.') out.push(p); }
    return dropped.has(out.join('/'));
  };
  for (const [name, data] of files) {
    if (!/\.(xml|rels|vml)$/i.test(name) && name !== '[Content_Types].xml') continue;
    let x = data.toString('utf8');
    const before = x;
    if (/\.rels$/i.test(name)) {
      const owner = name.replace(/_rels\/([^/]+)\.rels$/i, '$1');
      x = x.replace(/<Relationship\b[^>]*?(?:\/>|>\s*<\/Relationship>)/g, (rel) => {
        const type = (rel.match(/\bType="([^"]*)"/) || [])[1] || '';
        const target = ((rel.match(/\bTarget="([^"]*)"/) || [])[1] || '').replace(/&amp;/g, '&');
        const external = /TargetMode="External"/i.test(rel);
        if (external && (LOADING_REL.test(type) || BAD_SCHEME.test(target) || !/^(https?:|mailto:|#)/i.test(target))) { actions.push(t('Rimosso riferimento esterno ({type}): {target}', { type: type.split('/').pop(), target: target.slice(0, 120) })); return ''; }
        if (external && BAD_SCHEME.test(target)) return '';
        if (!external && isDropped(owner, target)) return '';
        if (!external && LOADING_REL.test(type) && /vbaProject|activeX|oleObject|customUI|attachedToolbars/i.test(type)) return '';
        return rel;
      });
    } else if (name === '[Content_Types].xml') {
      for (const [from, to] of MACRO_TYPES) if (x.includes(from)) { x = x.split(from).join(to); actions.push('Tipo di documento con macro convertito in documento standard'); }
      x = x.replace(/<Override\b[^>]*PartName="\/?([^"]+)"[^>]*\/>/g, (o, part) => (dropped.has(part) ? '' : o));
      x = x.replace(/<Default\b[^>]*ContentType="application\/vnd\.ms-office\.(vbaProject|activeX)[^"]*"[^>]*\/>/g, '');
    } else {
      // DDE / include fields (Word), OLE objects and controls (all applications)
      x = x.replace(/(<w:instrText\b[^>]*>)([^<]*)(<\/w:instrText>)/g, (m, a, t, b) => (/\b(DDE|DDEAUTO|INCLUDETEXT|INCLUDEPICTURE|IMPORT|LINK|QUOTE)\b/i.test(t) ? (actions.push(tr('Neutralizzato campo {f}', { f: t.trim().split(/\s+/)[0] })), a + b) : m));
      x = x.replace(/(<w:fldSimple\b[^>]*\bw:instr=")([^"]*)(")/g, (m, a, t, b) => (/\b(DDE|DDEAUTO|INCLUDETEXT|INCLUDEPICTURE|LINK)\b/i.test(t) ? (actions.push(tr('Neutralizzato campo {f}', { f: t.trim().split(/\s+/)[0] })), a + b) : m));
      x = x.replace(/<o:OLEObject\b[^>]*?(\/>|>[\s\S]*?<\/o:OLEObject>)/g, () => { actions.push('Rimosso riferimento a oggetto OLE'); return ''; });
      x = x.replace(/<(oleObjects|controls)\b[\s\S]*?<\/\1>/g, () => { actions.push('Rimossi oggetti/controlli dal foglio'); return ''; });
      x = x.replace(/<w:control\b[^>]*\/>/g, '');
      x = x.replace(/<ddeLink\b[\s\S]*?<\/ddeLink>/g, () => { actions.push('Rimosso collegamento DDE'); return ''; });
      // ODF: scripts and event listeners
      x = x.replace(/<office:scripts\b[\s\S]*?<\/office:scripts>|<office:event-listeners\b[\s\S]*?<\/office:event-listeners>|<script:event-listener\b[^>]*\/>/g, () => { actions.push('Rimossi script/eventi OpenDocument'); return ''; });
      if (!keepMetadata && /^docProps\/(core|app)\.xml$/.test(name)) {
        x = x.replace(/<(dc:creator|cp:lastModifiedBy|Company|Manager|cp:lastPrinted)>[^<]*<\/\1>/g, (m, tag) => `<${tag}></${tag}>`);
        if (x !== before) actions.push('Rimossi metadati personali (autore, ultimo modificatore, azienda)');
      }
      if (!keepMetadata && name === 'meta.xml') x = x.replace(/<(meta:initial-creator|dc:creator)>[^<]*<\/\1>/g, '<$1></$1>');
    }
    if (x !== before) files.set(name, Buffer.from(x, 'utf8'));
  }
  // OpenDocument: "mimetype" must be the first entry, stored
  const order = [...files.keys()].sort((a, b) => (a === 'mimetype' ? -1 : b === 'mimetype' ? 1 : a === '[Content_Types].xml' ? -1 : b === '[Content_Types].xml' ? 1 : 0));
  const out = writeZip(order.map((n) => ({ name: n, data: files.get(n), store: n === 'mimetype' })));
  return { output: out, actions: [...new Set(actions)] };
}

/** Standard extension for the disarmed document */
const SAFE_EXT = { docm: 'docx', dotm: 'docx', xlsm: 'xlsx', xltm: 'xlsx', xlam: 'xlsx', xlsb: 'xlsx', pptm: 'pptx', potm: 'pptx', ppsm: 'pptx' };

module.exports = { disarm, SAFE_EXT, xmlEsc };
