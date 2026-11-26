// Creato da anvex2012
'use strict';
const { m: msg } = require('../i18n');
const { findAll, truncate, isDoc } = require('../utils');

/** Social engineering / phishing language dictionary (Italian + English) */
const CATS = {
  urgency: { name: 'Urgenza', w: 1, re: /\b(?:urgente|urgentemente|immediatamente|subito|entro\s+(?:24|48|72)\s*ore|entro\s+oggi|ultimo\s+avviso|scadenza\s+imminente|tempo\s+limitato|agisci\s+ora|urgent(?:ly)?|immediately|right\s+away|within\s+(?:24|48|72)\s*hours|final\s+(?:notice|warning)|act\s+now|expires?\s+today|last\s+chance)\b/gi },
  threat: { name: 'Minaccia / blocco', w: 1.5, re: /\b(?:account\s+(?:sospeso|bloccato|limitato|disattivato)|sospensione|verrà\s+(?:chiuso|bloccato|disattivato|cancellato)|accesso\s+non\s+autorizzato|attività\s+sospetta|azioni\s+legali|denuncia|multa|sanzione|pignoramento|account\s+(?:suspended|locked|limited|disabled|terminated)|unauthori[sz]ed\s+(?:access|login|activity)|suspicious\s+activity|legal\s+action|will\s+be\s+(?:closed|deleted|suspended))\b/gi },
  credentials: { name: 'Richiesta di credenziali', w: 2, re: /\b(?:verifica\s+(?:il\s+tuo|i\s+tuoi|la\s+tua)\s+(?:account|dati|identità|password)|conferma\s+(?:i\s+tuoi\s+dati|la\s+password|il\s+tuo\s+account|le\s+credenziali)|inserisci\s+(?:la\s+password|le\s+credenziali|il\s+codice|il\s+pin)|aggiorna\s+(?:i\s+tuoi\s+dati|le\s+informazioni)|codice\s+(?:otp|di\s+verifica|di\s+sicurezza)|verify\s+your\s+(?:account|identity|password|information)|confirm\s+your\s+(?:password|account|details|identity)|update\s+your\s+(?:payment|billing|account)\s+(?:information|details)|enter\s+your\s+(?:password|pin|credentials|otp)|login\s+to\s+(?:verify|confirm|restore))\b/gi },
  money: { name: 'Denaro / pagamenti', w: 1.2, re: /\b(?:bonifico|rimborso|pagamento\s+(?:in\s+sospeso|non\s+riuscito|rifiutato)|fattura\s+(?:scaduta|insoluta|in\s+allegato)|carta\s+(?:scaduta|bloccata)|gift\s*card|buono\s+regalo|criptovalut[ae]|bitcoin|wire\s+transfer|refund|payment\s+(?:failed|declined|pending|overdue)|outstanding\s+(?:invoice|balance)|tax\s+refund|crypto(?:currency)?\s+(?:payment|wallet))\b/gi },
  authority: { name: 'Finta autorità / marchio', w: 1, re: /\b(?:polizia\s+postale|agenzia\s+delle\s+entrate|guardia\s+di\s+finanza|inps|poste\s+italiane|postepay|bancoposta|intesa\s+sanpaolo|unicredit|carabinieri|ministero|servizio\s+clienti|supporto\s+tecnico|microsoft\s+(?:support|security|team)|apple\s+(?:support|id)|paypal|amazon\s+(?:security|support)|netflix|dhl|fedex|irs|fbi|interpol|it\s+department|help\s*desk|helpdesk)\b/gi },
  prize: { name: 'Premi e vincite', w: 1.2, re: /\b(?:hai\s+vinto|congratulazioni|vincitore|premio|estrazione|omaggio\s+gratuito|you(?:'ve|\s+have)?\s+won|congratulations|winner|lottery|claim\s+your\s+(?:prize|reward)|free\s+(?:iphone|gift)|selected\s+to\s+receive)\b/gi },
  action: { name: 'Invito ad agire', w: 1.2, re: /\b(?:clicca\s+(?:qui|sul\s+link|il\s+pulsante)|apri\s+l'allegato|scarica\s+(?:l'allegato|il\s+documento)|abilita\s+(?:il\s+)?(?:contenuto|modifica|macro)|click\s+(?:here|the\s+link|below)|open\s+the\s+attachment|download\s+the\s+(?:attached|document|invoice)|enable\s+(?:content|editing|macros)|scan\s+the\s+qr\s+code|scansiona\s+il\s+(?:codice\s+)?qr)\b/gi },
  secrecy: { name: 'Segretezza / pressione', w: 1, re: /\b(?:non\s+dirlo\s+a\s+nessuno|riservat[oa]|confidenziale|non\s+rispondere\s+a\s+questa\s+email|ceo|amministratore\s+delegato|in\s+riunione|don'?t\s+tell\s+anyone|keep\s+this\s+(?:confidential|between\s+us)|i'?m\s+in\s+a\s+meeting|do\s+not\s+reply)\b/gi },
  sextortion: { name: 'Ricatto / sextortion', w: 2, re: /\b(?:ho\s+(?:hackerato|accesso\s+al)\s+tuo|ti\s+ho\s+registrato|video\s+(?:compromettente|intimo)|webcam|i\s+(?:hacked|have\s+access\s+to)\s+your|recorded\s+you|your\s+(?:contacts|friends)\s+will\s+(?:see|receive)|pay\s+(?:me|in\s+bitcoin))\b/gi },
};
const HEADERS = /^(?:From|Reply-To|Return-Path|Received|Subject|To|Message-ID|DKIM-Signature|Authentication-Results)\s*:/im;

module.exports = {
  id: 'social',
  name: 'Ingegneria sociale (phishing)',
  description: 'Analizza ogni parola del testo visibile (email, documenti, pagine, PDF) alla ricerca del linguaggio tipico di phishing, truffe e ricatti: urgenza, minacce, richiesta di credenziali, denaro, finte autorità, premi; controlla anche le intestazioni email (SPF/DKIM/Reply-To).',
  weight: 1.5,
  textual: true,
  applies: (ctx) => isDoc(ctx.name) ? false : ctx.isText ? ['text', 'markup', 'document'].includes(ctx.type.family) || ctx.type.id === 'eml' : ['document'].includes(ctx.type.family),
  init: () => ({ hits: {}, mail: null }),
  scan(unit, st, ctx) {
    if (unit.kind === 'binary') return;
    if (unit.kind === 'extracted' && !['doctext', 'decoded'].includes(unit.extractedKind)) return;
    const t = unit.text;
    for (const [id, c] of Object.entries(CATS)) {
      for (const m of findAll(t, c.re)) {
        const loc = unit.loc(m.index);
        const h = (st.hits[id] ||= { n: 0, words: new Map(), locs: [] });
        h.n++;
        h.locs.push(loc);
        const w = m[0].toLowerCase();
        h.words.set(w, (h.words.get(w) || 0) + 1);
        ctx.annotate(loc, unit.lineText(m.index), { id: 'soc:' + id, sev: c.w >= 2 ? 'medium' : 'low', label: c.name, desc: msg('Espressione tipica del phishing: "{text}"', { text: m[0] }) });
      }
    }
    // Email headers
    if (unit.kind === 'text' && HEADERS.test(t.slice(0, 20000))) {
      const head = t.slice(0, t.search(/\r?\n\r?\n/) > 0 ? t.search(/\r?\n\r?\n/) : 20000);
      const get = (h) => (head.match(new RegExp(`^${h}:\\s*(.+)$`, 'im')) || [])[1] || '';
      const from = get('From'), reply = get('Reply-To'), ret = get('Return-Path'), auth = get('Authentication-Results');
      const dom = (s) => ((s.match(/@([A-Za-z0-9.-]+)/) || [])[1] || '').toLowerCase();
      st.mail = {
        from, reply, ret, subject: get('Subject'),
        spf: (auth.match(/spf=(\w+)/i) || [])[1] || (head.match(/Received-SPF:\s*(\w+)/i) || [])[1] || 'assente',
        dkim: (auth.match(/dkim=(\w+)/i) || [])[1] || 'assente',
        dmarc: (auth.match(/dmarc=(\w+)/i) || [])[1] || 'assente',
        replyMismatch: reply && dom(reply) && dom(from) && dom(reply) !== dom(from),
        returnMismatch: ret && dom(ret) && dom(from) && dom(ret) !== dom(from),
        displaySpoof: /"[^"]*@[^"]*"\s*</.test(from) && dom(from.replace(/"[^"]*"/, '')) !== dom((from.match(/"([^"]*)"/) || [])[1] || ''),
      };
    }
  },
  finalize(st, ctx) {
    const out = [];
    const present = Object.keys(st.hits);
    let score = 0;
    for (const id of present) score += CATS[id].w * Math.min(3, st.hits[id].n);
    for (const id of present) {
      const h = st.hits[id];
      out.push({ severity: 'info', title: msg('{name}: {n} espressioni', { name: CATS[id].name, n: h.n }), detail: 'Linguaggio tipico dei messaggi di truffa.', evidence: [...h.words.keys()].slice(0, 8), loc: h.locs[0], locs: h.locs });
    }
    const strong = present.filter((id) => ['credentials', 'money', 'sextortion', 'threat'].includes(id)).length;
    if (present.length >= 4 && strong >= 1 || score >= 12) out.unshift({ severity: 'high', title: 'Messaggio con forti caratteristiche di phishing/truffa', detail: msg('Combina {n} tecniche di manipolazione: {list}.', { n: present.length, list: present.map((id) => CATS[id].name.toLowerCase()) }) });
    else if (present.length >= 3 || score >= 6) out.unshift({ severity: 'medium', title: 'Linguaggio di manipolazione', detail: msg('Presenti {n} tecniche tipiche delle truffe: {list}.', { n: present.length, list: present.map((id) => CATS[id].name.toLowerCase()) }) });
    else if (present.length >= 2) out.unshift({ severity: 'low', title: 'Alcune espressioni sospette', detail: 'Il testo contiene espressioni usate anche nelle truffe.' });
    const m = st.mail;
    if (m) {
      if (/fail|softfail/i.test(m.spf)) out.push({ severity: 'high', title: 'SPF fallito', detail: 'Il server che ha inviato l\'email non è autorizzato dal dominio del mittente.', evidence: [m.from] });
      if (/fail/i.test(m.dkim)) out.push({ severity: 'high', title: 'Firma DKIM non valida', detail: 'L\'email è stata alterata o il mittente è falso.' });
      if (/fail/i.test(m.dmarc)) out.push({ severity: 'high', title: 'DMARC fallito', detail: 'Il dominio del mittente non riconosce questa email.' });
      if (m.replyMismatch) out.push({ severity: 'medium', title: 'Reply-To diverso dal mittente', detail: 'Le risposte andranno a un altro indirizzo.', evidence: [`From: ${m.from}`, `Reply-To: ${m.reply}`] });
      if (m.returnMismatch) out.push({ severity: 'low', title: 'Return-Path diverso dal mittente', detail: 'Dominio di invio diverso da quello mostrato.', evidence: [`Return-Path: ${m.ret}`] });
      if (m.displaySpoof) out.push({ severity: 'high', title: 'Mittente falsificato nel nome visualizzato', detail: 'Il nome mostra un indirizzo email diverso da quello reale.', evidence: [m.from] });
    }
    const checks = Object.entries(CATS).map(([id, c]) => ({ name: msg('Linguaggio: {name}', { name: c.name }), ok: !st.hits[id], note: `${st.hits[id]?.n || 0}` }));
    if (m) checks.push({ name: 'SPF', ok: !/fail/i.test(m.spf), note: m.spf }, { name: 'DKIM', ok: !/fail/i.test(m.dkim), note: m.dkim }, { name: 'DMARC', ok: !/fail/i.test(m.dmarc), note: m.dmarc }, { name: 'Reply-To coerente', ok: !m.replyMismatch });
    const info = { 'Tecniche di manipolazione': present.length, 'Punteggio linguistico': Math.round(score) };
    if (m) Object.assign(info, { 'Da': truncate(m.from, 80), 'Oggetto': truncate(m.subject, 80), SPF: m.spf, DKIM: m.dkim, DMARC: m.dmarc });
    return { findings: out, checks, info };
  },
};
