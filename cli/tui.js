// Creato da anvex2012
'use strict';
/*
 * Gauntler — interactive terminal interface (full screen, fixed layout).
 * Started by "gauntler" with no arguments in an interactive terminal (or "gauntler shell").
 *
 *   ┌ header ─────────────────────────────────────────────┐
 *   │ results (scrollable)                                │
 *   │                                    ┌ add menu ┐     │
 *   ├ input box ──────────────────────────────────────────┤
 *   └ [+] footer: shortcuts · session stats ──────────────┘
 *
 * No dependencies: raw mode, ANSI sequences, SGR mouse, bracketed paste.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');
const core = require('../core');
const config = require('../core/config');
const history = require('../core/history');
const report = require('../core/report');
const { ScanPool } = require('../core/pool');
const ui = require('./ui');
const i18n = require('../core/i18n');
const { t } = i18n;

/* ───────────────────────── styles ───────────────────────── */

const TRUE = /truecolor|24bit/i.test(process.env.COLORTERM || '') || /iTerm|WezTerm|vscode|ghostty/i.test(process.env.TERM_PROGRAM || '');
const fg = (hex, x256) => (TRUE ? `38;2;${parseInt(hex.slice(1, 3), 16)};${parseInt(hex.slice(3, 5), 16)};${parseInt(hex.slice(5, 7), 16)}` : `38;5;${x256}`);
const bg = (hex, x256) => (TRUE ? `48;2;${parseInt(hex.slice(1, 3), 16)};${parseInt(hex.slice(3, 5), 16)};${parseInt(hex.slice(5, 7), 16)}` : `48;5;${x256}`);
const S = (...codes) => (s) => `\x1b[${codes.join(';')}m${s}\x1b[0m`;
const T = {
  text: S(fg('#e6e8eb', 254)),
  muted: S(fg('#8b929c', 245)),
  faint: S(fg('#5b616b', 240)),
  line: S(fg('#3a3f47', 238)),
  accent: S(fg('#6b9bf2', 75)),
  accentB: S('1', fg('#6b9bf2', 75)),
  bold: S('1', fg('#f2f4f7', 255)),
  keyRaw: S(fg('#c9ced6', 252), bg('#2b3038', 236)),
  plus: S('1', fg('#0e1116', 233), bg('#6b9bf2', 75)),
  plusOn: S('1', fg('#0e1116', 233), bg('#9dbcf7', 111)),
  sel: S(fg('#f2f4f7', 255), bg('#24406e', 24)),
  safe: S(fg('#4ec98a', 78)), low: S(fg('#56b6c2', 73)), medium: S(fg('#e5b454', 179)), high: S(fg('#ef6b5e', 203)), critical: S('1', fg('#ffffff', 231), bg('#c23b30', 160)),
  ok: S(fg('#4ec98a', 78)), warn: S(fg('#e5b454', 179)), err: S(fg('#ef6b5e', 203)),
};
T.key = (s) => T.keyRaw(s.replace(/ /g, '\u00a0'));
T.plusK = (s) => T.plus(s.replace(/ /g, '\u00a0'));
const scoreStyle = (s) => (s >= 90 ? T.safe : s >= 70 ? T.low : s >= 40 ? T.medium : s >= 15 ? T.high : T.critical);
const SPIN = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

/* ───────────────────────── ANSI-aware text helpers ───────────────────────── */

const ESC_RE = /\x1b\[[0-9;?]*[A-Za-z]/y;
const vlen = (s) => ui.strip(s).length;
/** Visible slice [from, to) that preserves the escape sequences */
function cut(s, from, to = Infinity) {
  let out = '', vis = 0, open = false;
  for (let i = 0; i < s.length;) {
    ESC_RE.lastIndex = i;
    const m = ESC_RE.exec(s);
    if (m) { out += m[0]; open = m[0] !== '\x1b[0m'; i += m[0].length; continue; }
    const ch = String.fromCodePoint(s.codePointAt(i));
    if (vis >= from && vis < to) out += ch;
    vis++; i += ch.length;
    if (vis >= to) break;
  }
  return out + (open ? '\x1b[0m' : '');
}
const fit = (s, w) => { const n = vlen(s); return n > w ? cut(s, 0, Math.max(0, w - 1)) + T.faint('…') : s + ' '.repeat(w - n); };
function wrap(text, w) {
  const out = [];
  for (const para of String(text).split('\n')) {
    let line = '';
    for (const word of para.split(' ')) {
      if (line && vlen(line) + 1 + vlen(word) > w) { out.push(line); line = word; } else line = line ? line + ' ' + word : word;
    }
    out.push(line);
  }
  return out;
}
const home = os.homedir();
const tilde = (p) => (p && p.startsWith(home + path.sep) ? '~' + p.slice(home.length) : p);

/* ───────────────────────── path parsing (drag & drop, paste, typing) ───────────────────────── */

function expandHome(p) { return p === '~' ? home : p.startsWith('~/') ? path.join(home, p.slice(2)) : p; }
function fromUrl(p) { if (!p.startsWith('file://')) return p; try { return decodeURIComponent(new URL(p).pathname); } catch { return p; } }
/** Shell-like tokenizer: quotes, backslash escapes ("My\ File.pdf"), file:// URLs, ~ */
function tokenize(s) {
  const out = []; let cur = '', q = null, any = false;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (q) { if (ch === q) q = null; else if (ch === '\\' && q === '"' && i + 1 < s.length) cur += s[++i]; else cur += ch; continue; }
    if (ch === '\\' && i + 1 < s.length) { cur += s[++i]; any = true; continue; }
    if (ch === '"' || ch === "'") { q = ch; any = true; continue; }
    if (/\s/.test(ch)) { if (cur || any) out.push(cur); cur = ''; any = false; continue; }
    cur += ch;
  }
  if (cur || any) out.push(cur);
  return out.map((t) => path.resolve(expandHome(fromUrl(t))));
}
/** Returns the paths in the text, or null if it does not look like a list of existing paths */
function parsePaths(text) {
  const t = text.trim();
  if (!t) return null;
  const whole = path.resolve(expandHome(fromUrl(t)));
  if (fs.existsSync(whole)) return [whole];
  const toks = tokenize(t);
  return toks.length && toks.every((p) => fs.existsSync(p)) ? toks : null;
}

/* ───────────────────────── native picker (macOS) ───────────────────────── */

function nativePick(kind, onChild = () => {}) {
  if (process.platform !== 'darwin') return Promise.resolve({ unsupported: true, paths: [] });
  const prompt = (kind === 'folder' ? t('Scegli le cartelle da analizzare') : t('Scegli i file da analizzare')).replace(/["\\]/g, '');
  const what = kind === 'folder' ? `choose folder with prompt "${prompt}"` : `choose file with prompt "${prompt}"`;
  const script = [
    'set out to ""',
    'try',
    `  tell application (path to frontmost application as text) to set picked to (${what} with multiple selections allowed)`,
    'on error number -128',
    '  return ""',
    'end try',
    'repeat with f in picked',
    '  set out to out & POSIX path of f & linefeed',
    'end repeat',
    'return out',
  ].join('\n');
  return new Promise((res) => {
    onChild(execFile('osascript', ['-e', script], { timeout: 10 * 60 * 1000 }, (err, stdout) => {
      if (err && err.killed) return res({ paths: [] });
      if (err) return res({ error: err.message.split('\n')[0], paths: [] });
      res({ paths: stdout.split('\n').map((s) => s.trim()).filter(Boolean).map((p) => (p.length > 1 ? p.replace(/\/$/, '') : p)) });
    }));
  });
}

/* ───────────────────────── commands ───────────────────────── */

// Commands: Italian names in Italian, English names in the other languages (both always work)
const CMDS = [
  { id: '/file', it: '/file', en: '/file', d: 'Scegli uno o più file da analizzare' },
  { id: '/cartella', it: '/cartella', en: '/folder', d: 'Scegli una cartella da analizzare' },
  { id: '/report', it: '/report', en: '/report', d: 'Report completo di un risultato: {cmd} 2' },
  { id: '/dettagli', it: '/dettagli', en: '/details', d: 'Report con righe segnalate e controlli: {cmd} 2' },
  { id: '/elenco', it: '/elenco', en: '/list', d: 'Tutti i file analizzati in questa sessione' },
  { id: '/esporta', it: '/esporta', en: '/export', d: 'Salva i risultati: {cmd} report.html (json, sarif, csv, md, html)' },
  { id: '/pulisci', it: '/pulisci', en: '/clear', d: 'Pulisci lo schermo' },
  { id: '/mouse', it: '/mouse', en: '/mouse', d: 'Attiva o disattiva il mouse (per selezionare testo)' },
  { id: '/lingua', it: '/lingua', en: '/language', d: 'Cambia la lingua: {cmd} en (it, en, es, fr, de)' },
  { id: '/aiuto', it: '/aiuto', en: '/help', d: 'Guida e scorciatoie da tastiera' },
  { id: '/esci', it: '/esci', en: '/quit', d: 'Chiudi Gauntler' },
];
const cmdName = (id) => { const c = CMDS.find((x) => x.id === id); return i18n.getLanguage() === 'it' ? c.it : c.en; };
const COMMANDS = () => CMDS.map((c) => { const n = cmdName(c.id); return [n, t(c.d, { cmd: n })]; });
const CMD_ALIAS = { '/help': '/aiuto', '/?': '/aiuto', '/clear': '/pulisci', '/quit': '/esci', '/exit': '/esci', '/q': '/esci', '/folder': '/cartella', '/list': '/elenco', '/export': '/esporta', '/r': '/report', '/d': '/dettagli', '/details': '/dettagli', '/language': '/lingua', '/lang': '/lingua' };
const MENU = [
  { id: 'file', get label() { return t('File…'); }, hint: 'Ctrl+O' },
  { id: 'folder', get label() { return t('Cartella…'); }, hint: 'Ctrl+K' },
  { id: 'type', get label() { return t('Digita un percorso'); }, hint: '' },
];

/* ───────────────────────── application ───────────────────────── */

class Tui {
  constructor() {
    this.out = process.stdout;
    this.in = process.stdin;
    this.cfg = config.load();
    this.blocks = [];          // { render(width) → string[] }
    this.results = [];         // { n, path, name, status, result?, error? }
    this.input = '';
    this.cur = 0;
    this.hist = [];
    this.histIdx = -1;
    this.scroll = 0;           // lines from the bottom
    this.menu = null;          // { sel }
    this.sugSel = 0;
    this.mouse = true;
    this.busy = 0;             // analyses in progress
    this.picking = false;
    this.flash = null;         // { text, until }
    this.frame = 0;
    this.pool = null;
    this.pending = '';         // incomplete escape sequence
    this.pasteBuf = null;
    this.hits = {};            // clickable areas of the last frame
    this.layout = { body: 0 };
    this.env = { clamav: core.clamavAvailable(), sevenZip: false };
    try { this.env.sevenZip = !!require('../core/extract').tools().sevenZip; } catch { /* optional */ }
  }

  /* ── lifecycle ── */
  start() {
    return new Promise((resolve) => {
      this.done = resolve;
      this.in.setRawMode(true);
      this.in.resume();
      this.in.setEncoding('utf8');
      this.write('\x1b[?1049h\x1b[?2004h\x1b[H\x1b[2J');
      this.setMouse(this.mouse);
      this.onData = (d) => this.feed(d);
      this.onResize = () => this.render();
      this.in.on('data', this.onData);
      this.out.on('resize', this.onResize);
      this.restoreOnExit = () => this.restore();
      process.on('exit', this.restoreOnExit);
      this.timer = setInterval(() => { this.frame++; if (this.busy || this.picking || this.flash) this.render(); }, 90);
      this.blocks.push(this.welcomeBlock());
      if (this.firstRun) {
        const f = this.firstRun;
        this.blocks.push({ render: () => ['', `  ${T.ok('✓')} ${T.text(f.installed ? t('Comando "gauntler" installato.') : t('Comando "gauntler" aggiunto al PATH.'))} ${T.muted(t('Da una nuova finestra del terminale basta scrivere'))} ${T.accent('gauntler')}`, ...(f.rc ? [`    ${T.faint(t('PATH aggiornato in {rc}', { rc: tilde(f.rc) }))}`] : [])] });
      }
      this.render();
    });
  }
  setMouse(on) { this.mouse = on; this.write(on ? '\x1b[?1000h\x1b[?1006h' : '\x1b[?1000l\x1b[?1006l'); }
  restore() {
    if (this.restored) return;
    this.restored = true;
    this.write('\x1b[?1000l\x1b[?1006l\x1b[?2004l\x1b[0m\x1b[?25h\x1b[?1049l');
    try { this.in.setRawMode(false); } catch { /* already closed */ }
  }
  async quit() {
    if (this.quitting) return;
    this.quitting = true;
    if (this.picker) try { this.picker.kill(); } catch { /* already closed */ }
    clearInterval(this.timer);
    this.in.off('data', this.onData);
    this.out.off('resize', this.onResize);
    this.in.pause();
    this.restore();
    process.off('exit', this.restoreOnExit);
    const ok = this.results.filter((r) => r.status === 'done');
    if (ok.length) {
      const bad = ok.filter((r) => r.result.overall.score < 40).length;
      console.log(`${T.accentB('◆ Gauntler')} ${T.muted('· ' + t('sessione chiusa') + ' ·')} ${t('{n} file analizzati', { n: ok.length })}${bad ? ' · ' + T.err(bad === 1 ? t('{n} pericoloso', { n: bad }) : t('{n} pericolosi', { n: bad })) : ' · ' + T.ok(t('nessun file pericoloso'))}`);
    }
    if (this.pool) await this.pool.close().catch(() => {});
    this.done(0);
  }
  write(s) { this.out.write(s); }
  note(text, kind = 'info') { this.flash = { text, kind, until: Date.now() + 4000 }; this.render(); }
  push(block) { this.blocks.push(block); this.scroll = 0; this.render(); }
  pushLines(lines) { const l = Array.isArray(lines) ? lines : String(lines).split('\n'); this.push({ render: () => l }); }

  /* ── input decoding ── */
  feed(data) {
    let s = this.pending + data;
    this.pending = '';
    // Fast path: a chunk of plain printable text larger than one key is a drag & drop or a paste without bracketing
    if (this.pasteBuf === null && s.length > 3 && !/[\x00-\x1f\x7f]/.test(s.replace(/\n$/, ''))) { this.onPaste(s.replace(/\n$/, '')); return; }
    let i = 0;
    while (i < s.length) {
      if (this.pasteBuf !== null) {
        const end = s.indexOf('\x1b[201~', i);
        if (end === -1) {
          // keep a possible partial terminator for the next chunk
          const keep = Math.min(5, s.length - i);
          this.pasteBuf += s.slice(i, s.length - keep); this.pending = s.slice(s.length - keep); return;
        }
        this.pasteBuf += s.slice(i, end); i = end + 6;
        const p = this.pasteBuf; this.pasteBuf = null; this.onPaste(p); continue;
      }
      const ch = s[i];
      if (ch === '\x1b') {
        const rest = s.slice(i);
        if (rest.startsWith('\x1b[200~')) { this.pasteBuf = ''; i += 6; continue; }
        let m = /^\x1b\[<(\d+);(\d+);(\d+)([Mm])/.exec(rest);
        if (m) { this.onMouse(+m[1], +m[2], +m[3], m[4] === 'M'); i += m[0].length; continue; }
        m = /^\x1b\[[0-9;]*[A-Za-z~]/.exec(rest) || /^\x1bO[A-Za-z]/.exec(rest) || /^\x1b[bfdy\x7f]/.exec(rest);
        if (m) { this.onKey(m[0]); i += m[0].length; continue; }
        if (rest.length < 6 && /^\x1b(\[[0-9;<]*)?$/.test(rest) && rest.length > 1) { this.pending = rest; break; }
        this.onKey('\x1b'); i++; continue;
      }
      const cp = s.codePointAt(i);
      const c = String.fromCodePoint(cp);
      this.onKey(c); i += c.length;
    }
    this.render();
  }

  onPaste(text) {
    const paths = parsePaths(text.replace(/\r/g, '\n').split('\n').filter(Boolean).join(' '));
    if (paths && !this.input.trim()) { this.menu = null; this.add(paths, 'Trascinato'); return; }
    this.insert(text.replace(/[\r\n]+/g, ' '));
    this.render();
  }

  onMouse(b, x, y, press) {
    if (!press) return;
    if (b === 64) { this.scrollBy(3); return this.render(); }
    if (b === 65) { this.scrollBy(-3); return this.render(); }
    if ((b & 3) !== 0) return;
    const hit = Object.entries(this.hits).find(([, r]) => y === r.y && x >= r.x && x < r.x + r.w);
    if (!hit) { if (this.menu) { this.menu = null; this.render(); } return; }
    const [id] = hit;
    if (id === 'plus') this.menu = this.menu ? null : { sel: 0 };
    else if (id.startsWith('menu:')) { this.menu = null; this.menuAction(id.slice(5)); }
    else if (id.startsWith('sug:')) { this.input = id.slice(4) + ' '; this.cur = this.input.length; }
    this.render();
  }

  insert(t) { this.input = this.input.slice(0, this.cur) + t + this.input.slice(this.cur); this.cur += t.length; this.histIdx = -1; this.sugSel = 0; }
  scrollBy(n) { this.scroll = Math.max(0, Math.min(this.maxScroll || 0, this.scroll + n)); }

  suggestions() {
    if (!this.input.startsWith('/') || this.input.includes(' ')) return [];
    const q = this.input.toLowerCase();
    return COMMANDS().filter(([c]) => c.startsWith(q));
  }

  onKey(k) {
    // Add menu open: it takes the keyboard
    if (this.menu) {
      if (k === '\x1b[A' || k === '\x1bOA' || k === '\x10') this.menu.sel = (this.menu.sel + MENU.length - 1) % MENU.length;
      else if (k === '\x1b[B' || k === '\x1bOB' || k === '\x0e' || k === '\t') this.menu.sel = (this.menu.sel + 1) % MENU.length;
      else if (k === '\r' || k === '\n') { const id = MENU[this.menu.sel].id; this.menu = null; this.menuAction(id); }
      else if (k === 'f' || k === '1') { this.menu = null; this.menuAction('file'); }
      else if (k === 'c' || k === '2') { this.menu = null; this.menuAction('folder'); }
      else if (k === 'd' || k === '3') { this.menu = null; this.menuAction('type'); }
      else if (k === '\x03') this.quit();
      else this.menu = null;
      return;
    }
    const sug = this.suggestions();
    switch (k) {
      case '\x03': if (this.input) { this.input = ''; this.cur = 0; } else this.quit(); return;
      case '\x04': if (!this.input) this.quit(); else this.input = this.input.slice(0, this.cur) + this.input.slice(this.cur + 1); return;
      case '\r': case '\n':
        if (sug.length && this.input !== sug[this.sugSel]?.[0] && sug[this.sugSel]) { this.input = sug[this.sugSel][0]; this.cur = this.input.length; }
        this.submit(); return;
      case '\t':
        if (sug.length) { this.input = sug[this.sugSel][0] + ' '; this.cur = this.input.length; }
        else if (!this.input) this.menu = { sel: 0 };
        return;
      case '\x0f': this.menuAction('file'); return;       // Ctrl+O
      case '\x0b': this.menuAction('folder'); return;     // Ctrl+K
      case '\x0c': this.blocks = []; this.scroll = 0; this.write('\x1b[2J'); return; // Ctrl+L
      case '\x7f': case '\b': if (this.cur > 0) { this.input = this.input.slice(0, this.cur - 1) + this.input.slice(this.cur); this.cur--; this.sugSel = 0; } return;
      case '\x1b[3~': this.input = this.input.slice(0, this.cur) + this.input.slice(this.cur + 1); return;
      case '\x01': case '\x1b[H': case '\x1bOH': case '\x1b[1~': this.cur = 0; return;
      case '\x05': case '\x1b[F': case '\x1bOF': case '\x1b[4~': this.cur = this.input.length; return;
      case '\x15': this.input = this.input.slice(this.cur); this.cur = 0; return;            // Ctrl+U
      case '\x17': case '\x1b\x7f': { const l = this.input.slice(0, this.cur).replace(/\S+\s*$/, ''); this.input = l + this.input.slice(this.cur); this.cur = l.length; return; }
      case '\x1b[D': case '\x1bOD': this.cur = Math.max(0, this.cur - 1); return;
      case '\x1b[C': case '\x1bOC': this.cur = Math.min(this.input.length, this.cur + 1); return;
      case '\x1bb': case '\x1b[1;3D': case '\x1b[1;5D': { const m = /\S+\s*$/.exec(this.input.slice(0, this.cur)); this.cur = m ? m.index : 0; return; }
      case '\x1bf': case '\x1b[1;3C': case '\x1b[1;5C': { const m = /^\s*\S+/.exec(this.input.slice(this.cur)); this.cur += m ? m[0].length : 0; return; }
      case '\x1b[A': case '\x1bOA':
        if (sug.length) { this.sugSel = (this.sugSel + sug.length - 1) % sug.length; return; }
        if (this.hist.length && this.histIdx < this.hist.length - 1) { this.histIdx++; this.input = this.hist[this.hist.length - 1 - this.histIdx]; this.cur = this.input.length; }
        return;
      case '\x1b[B': case '\x1bOB':
        if (sug.length) { this.sugSel = (this.sugSel + 1) % sug.length; return; }
        if (this.histIdx > 0) { this.histIdx--; this.input = this.hist[this.hist.length - 1 - this.histIdx]; } else { this.histIdx = -1; this.input = ''; }
        this.cur = this.input.length; return;
      case '\x1b[5~': this.scrollBy(Math.max(1, this.layout.body - 2)); return;
      case '\x1b[6~': this.scrollBy(-Math.max(1, this.layout.body - 2)); return;
      case '\x1b[1;2A': this.scrollBy(1); return;
      case '\x1b[1;2B': this.scrollBy(-1); return;
      case '\x1b': this.input = ''; this.cur = 0; return;
      default:
        if (k === '+' && !this.input) { this.menu = { sel: 0 }; return; }
        if (k.length === 1 && k < ' ') return;
        if (k.startsWith('\x1b')) return;
        this.insert(k);
    }
  }

  /* ── actions ── */
  async menuAction(id) {
    if (id === 'type') { this.note(t('Digita o incolla il percorso di un file o di una cartella, poi premi Invio')); return; }
    if (this.picking) return;
    this.picking = true; this.render();
    const r = await nativePick(id, (ch) => { this.picker = ch; });
    this.picker = null;
    this.picking = false;
    if (this.restored) return;
    if (r.unsupported) { this.note(t('Il selettore grafico è disponibile solo su macOS: digita il percorso e premi Invio'), 'warn'); return; }
    if (r.error) { this.note(t('Impossibile aprire il selettore: {msg}', { msg: r.error }), 'err'); return; }
    if (!r.paths.length) { this.note(t('Selezione annullata')); return; }
    this.add(r.paths, id === 'folder' ? 'Cartella scelta' : 'File scelto');
  }

  submit() {
    const line = this.input.trim();
    this.input = ''; this.cur = 0; this.histIdx = -1; this.sugSel = 0;
    if (!line) return;
    if (this.hist[this.hist.length - 1] !== line) this.hist.push(line);
    const first = line.split(/\s+/)[0].toLowerCase();
    if (CMDS.some((c) => c.it === first || c.en === first) || CMD_ALIAS[first]) return this.command(line);
    const paths = parsePaths(line);
    if (!paths) {
      const missing = tokenize(line).filter((p) => !fs.existsSync(p));
      this.pushLines(['', `  ${T.err('✗')} ${T.text(t('Percorso non trovato:'))} ${T.muted(tilde(missing[0] || line))}`, `    ${T.faint(t('Suggerimento: premi'))} ${T.key(' + ')} ${T.faint(t('per scegliere il file dal Finder, oppure trascinalo in questa finestra.'))}`]);
      return;
    }
    this.add(paths, 'Percorso');
  }

  command(line) {
    const [raw, ...args] = line.split(/\s+/);
    const low = raw.toLowerCase();
    const name = CMD_ALIAS[low] || (CMDS.find((c) => c.en === low) || {}).id || low;
    const pickN = () => {
      const n = args[0] ? parseInt(args[0].replace('#', ''), 10) : this.results.filter((r) => r.status === 'done').slice(-1)[0]?.n;
      const r = this.results.find((x) => x.n === n);
      if (!r) { this.note(args[0] ? t('Nessun risultato #{n}', { n: args[0] }) : t('Nessun file analizzato: premi + per aggiungerne uno'), 'warn'); return null; }
      if (r.status !== 'done') { this.note(r.status === 'error' ? `#${n}: ${r.error}` : t('#{n} è ancora in analisi', { n }), 'warn'); return null; }
      return r;
    };
    switch (name) {
      case '/file': return this.menuAction('file');
      case '/cartella': return this.menuAction('folder');
      case '/aiuto': return this.push(this.helpBlock());
      case '/pulisci': this.blocks = []; this.scroll = 0; return this.render();
      case '/esci': return this.quit();
      case '/mouse': this.setMouse(!this.mouse); return this.note(this.mouse ? t('Mouse attivo: clic su + e rotella per scorrere') : t('Mouse disattivato: ora puoi selezionare e copiare il testo'));
      case '/lingua': {
        const code = i18n.normalize(args[0]);
        if (!code) {
          const cmd = cmdName('/lingua');
          return this.push({ render: () => ['', `  ${T.bold(t('Lingua'))}  ${T.muted(t('scrivi {cmd} seguito dal codice', { cmd }))}`, ...i18n.LANGUAGES.map((l) => `    ${l.code === i18n.getLanguage() ? T.ok('●') : T.faint('○')} ${T.accent(cmd + ' ' + l.code)}  ${T.text(l.name)}`)] });
        }
        try { require('./language').save(code); } catch (e) { return this.note(t(e.message), 'err'); }
        return this.note(t('Lingua impostata: {name}', { name: i18n.LANGUAGES.find((l) => l.code === code).name }));
      }
      case '/report': case '/dettagli': {
        const r = pickN(); if (!r) return;
        const full = name === '/dettagli';
        const txt = ui.printReport(r.result, { lines: full, checks: full, all: full });
        return this.push({ render: (w) => { const h = `  ── ${t('Report')} #${r.n} · ${r.name} `; return ['', T.faint(h + '─'.repeat(Math.max(0, w - vlen(h) - 2))), ...txt.split('\n').slice(2)]; } });
      }
      case '/elenco': {
        const done = this.results;
        if (!done.length) return this.note(t('Nessun file analizzato: premi + per aggiungerne uno'), 'warn');
        return this.push({ render: (w) => ['', `  ${T.bold(t('File analizzati'))} ${T.muted('· ' + done.length)}`, ...done.map((r) => this.resultLine(r, w))] });
      }
      case '/esporta': {
        const ok = this.results.filter((r) => r.status === 'done').map((r) => r.result);
        if (!ok.length) return this.note(t('Niente da esportare'), 'warn');
        const dest = path.resolve(expandHome(args.join(' ') || `gauntler-report.html`));
        const ext = path.extname(dest).slice(1).toLowerCase();
        const fmt = { htm: 'html', markdown: 'md' }[ext] || ext;
        if (!report.FORMATS[fmt]) return this.note(t('Estensione non supportata: usa .html .json .sarif .csv .md'), 'warn');
        try { fs.writeFileSync(dest, report.render(fmt, ok, {})); this.pushLines(['', `  ${T.ok('✓')} ${T.text(t('Report salvato'))} ${T.muted(tilde(dest))}`]); } catch (e) { this.note(t('Errore: {msg}', { msg: e.message }), 'err'); }
        return;
      }
      default: this.note(t('Comando sconosciuto: {cmd} — digita {help}', { cmd: raw, help: cmdName('/aiuto') }), 'warn');
    }
  }

  /* ── analysis ── */
  getPool() { return this.pool || (this.pool = new ScanPool({ size: this.cfg.jobs, timeoutMs: this.cfg.timeout * 1000 })); }

  add(paths, origin) {
    this.menu = null;
    const files = []; const folders = [];
    for (const p of paths) {
      let st; try { st = fs.statSync(p); } catch { continue; }
      if (st.isDirectory()) folders.push(p); else files.push(p);
    }
    for (const f of files) this.scanOne(f);
    for (const d of folders) this.scanFolder(d);
    if (!files.length && !folders.length) this.note(t('Nessun file valido'), 'warn');
    void origin;
  }

  scanOpts() {
    return { passwords: [], only: null, skip: [], noClamav: false, yara: [], online: false, suppress: [], cache: this.cfg.cache, lang: i18n.getLanguage() };
  }

  track(file) {
    const r = { n: this.results.length + 1, path: file, name: path.basename(file), status: 'scanning', t0: Date.now() };
    this.results.push(r);
    this.busy++;
    return this.getPool().scan(file, this.scanOpts()).then(
      (res) => { r.status = 'done'; r.result = res; r.ms = Date.now() - r.t0; try { if (this.cfg.history !== false) history.record(res); } catch { /* history optional */ } },
      (e) => { r.status = 'error'; r.error = t(e.message); },
    ).finally(() => { this.busy--; this.render(); }).then(() => r);
  }

  scanOne(file) {
    const p = this.track(file);
    const r = this.results[this.results.length - 1];
    this.push({ render: (w) => this.fileBlock(r, w) });
    p.then(() => { if (this.results.filter((x) => x.status === 'done').length === 1 && r.status === 'done') this.pushLines(['', `  ${T.faint(t('Digita'))} ${T.accent('/report ' + r.n)} ${T.faint(t('per il report completo, oppure premi'))} ${T.key(' + ')} ${T.faint(t('per analizzare altri file.'))}`]); });
  }

  scanFolder(dir) {
    const errs = [];
    let files;
    try { files = core.walk(dir, { recursive: true, exclude: this.cfg.exclude, include: [], followSymlinks: false, onError: (d) => errs.push(d) }); } catch (e) { this.note(t('Impossibile leggere la cartella: {msg}', { msg: e.message }), 'err'); return; }
    const uniq = [...new Set(files.map((f) => path.resolve(f)))];
    const g = { dir, items: [], total: uniq.length, t0: Date.now(), errs };
    this.push({ render: (w) => this.folderBlock(g, w) });
    if (!uniq.length) return;
    Promise.all(uniq.map((f) => { const p = this.track(f); g.items.push(this.results[this.results.length - 1]); return p; }))
      .then(() => { g.ms = Date.now() - g.t0; this.render(); });
  }

  /* ── blocks ── */
  welcomeBlock() {
    return {
      render: (W) => {
        const w = Math.min(W - 4, 76);
        if (w < 30) return ['', `  ${T.accentB('◆ Gauntler')}`, `  ${T.muted(t('Premi + per aggiungere un file'))}`];
        const inner = w - 4;
        const row = (s = '') => `  ${T.line('│')} ${fit(s, inner)} ${T.line('│')}`;
        const title = ` ${T.accentB('◆')} ${T.bold('Gauntler')} ${T.muted(core.VERSION)} `;
        const step = (n, text) => wrap(text, inner - 6).map((l, i) => `  ${i ? '  ' : T.accent(n + '.')}  ${l}`);
        return [
          '',
          `  ${T.line('╭─')}${title}${T.line('─'.repeat(Math.max(0, w - 3 - vlen(title))) + '╮')}`,
          row(),
          ...wrap(t('Analisi di sicurezza approfondita di qualsiasi file. Tutto avviene su questo computer: nessun file viene inviato in rete.'), inner - 2).map((l) => row(' ' + T.muted(l))),
          row(),
          row(' ' + T.bold(t('Come aggiungere un file'))),
          row(),
          ...step(1, t('Premi {plus} in basso a sinistra (o il tasto {tab}) e scegli {file} o {folder}: si apre il selettore del Finder.', { plus: T.plusK(' + '), tab: T.key(' Tab '), file: T.text(t('File')), folder: T.text(t('Cartella')) })).map(row),
          ...step(2, t('Trascina un file o una cartella dal Finder dentro questa finestra.')).map(row),
          ...step(3, t('Digita o incolla un percorso, es. {path}, e premi {enter}.', { path: T.accent('~/Downloads/fattura.pdf'), enter: T.key(' ' + t('Invio') + ' ') })).map(row),
          row(),
          row(' ' + T.muted(t('Scorciatoie') + '  ') + `${T.key(' Ctrl+O ')} ${T.muted(t('file'))}   ${T.key(' Ctrl+K ')} ${T.muted(t('cartella'))}   ${T.key(' / ')} ${T.muted(t('comandi'))}`),
          row(),
          `  ${T.line('╰' + '─'.repeat(w - 2) + '╯')}`,
          `  ${T.faint(t(this.env.clamav ? '{n} criteri di analisi · ClamAV attivo · digita {help} per la guida completa' : '{n} criteri di analisi · ClamAV non installato · digita {help} per la guida completa', { n: core.analyzers.length, help: cmdName('/aiuto') }))}`,
        ];
      },
    };
  }

  helpBlock() {
    const k = (a, b) => `    ${fit(T.key(` ${a} `), 18)}${T.muted(b)}`;
    return {
      render: () => [
        '',
        `  ${T.bold(t('Aggiungere file'))}`,
        k('+  /  Tab', t('Apre il menu: File… · Cartella… · Digita un percorso')),
        k('Ctrl+O', t('Selettore di file (selezione multipla)')),
        k('Ctrl+K', t('Selettore di cartelle')),
        `    ${T.muted(t('Puoi anche trascinare file dal Finder o incollare un percorso e premere Invio.'))}`,
        '',
        `  ${T.bold(t('Comandi'))}`,
        ...COMMANDS().map(([c, d]) => `    ${fit(T.accent(c), 16)}${T.muted(d)}`),
        '',
        `  ${T.bold(t('Navigazione'))}`,
        k(t('PagSu / PagGiù'), t('Scorre i risultati (anche rotella del mouse)')),
        k('↑ / ↓', t('Comandi precedenti')),
        k('Esc', t('Cancella la riga · chiude il menu')),
        k('Ctrl+L', t('Pulisce lo schermo')),
        k('Ctrl+C', t('Esce (con la riga vuota)')),
        '',
        `  ${T.bold(t('Punteggio'))}  ${T.muted(t('100 = sicuro · 1 = malevolo'))}`,
        `    ${T.safe('■ 90–100 ' + t('Sicuro'))}   ${T.low('■ 70–89 ' + t('Basso rischio'))}   ${T.medium('■ 40–69 ' + t('Sospetto'))}   ${T.high('■ 15–39 ' + t('Pericoloso'))}   ${T.critical(' 1–14 ' + t('Malevolo') + ' ')}`,
      ],
    };
  }

  resultLine(r, W) {
    const idx = T.faint(('#' + r.n).padStart(4));
    if (r.status === 'scanning') return `  ${idx}  ${T.accent(SPIN[this.frame % SPIN.length])} ${T.muted(t('in analisi').padEnd(17))} ${fit(T.text(r.name), Math.max(10, W - 34))}`;
    if (r.status === 'error') return `  ${idx}  ${T.warn('!')} ${T.warn(t('errore').padEnd(17))} ${fit(T.text(r.name) + '  ' + T.faint(r.error), Math.max(10, W - 34))}`;
    const o = r.result.overall;
    const st = scoreStyle(o.score);
    const top = r.result.findings.find((f) => f.severity !== 'info');
    return `  ${idx}  ${st(String(o.score).padStart(3))} ${fit(st(o.verdict), 16)} ${fit(T.text(r.name) + (top && o.score < 90 ? T.faint('  ' + top.title) : ''), Math.max(10, W - 34))}`;
  }

  fileBlock(r, W) {
    const head = `  ${T.faint('›')} ${T.bold(r.name)}  ${T.faint(tilde(path.dirname(r.path)))}`;
    if (r.status !== 'done') return ['', fit(head, W), this.resultLine(r, W)];
    const res = r.result, o = res.overall, st = scoreStyle(o.score);
    const issues = res.findings.filter((f) => f.severity !== 'info');
    const barW = Math.max(10, Math.min(28, W - 60));
    const lines = ['', fit(head, W),
      `  ${T.faint(('#' + r.n).padStart(4))}  ${st(' ' + String(o.score).padStart(3) + '/100 ')}  ${ui.bar(o.score, barW)}  ${st(o.verdict)}  ${T.faint(`${res.file.type.label} · ${res.file.sizeHuman} · ${ui.fmtDur(r.ms || res.durationMs || 0)}${res.cached ? ' · cache' : ''}`)}`];
    for (const l of wrap(o.advice, Math.max(20, W - 10))) lines.push(`        ${T.muted(l)}`);
    const sevTag = { critical: T.critical(' ' + t('CRIT').slice(0, 5).padEnd(5)), high: T.high(t('ALTO').slice(0, 5).padEnd(6)), medium: T.medium(t('MEDIO').slice(0, 5).padEnd(6)), low: T.low(t('BASSO').slice(0, 5).padEnd(6)) };
    for (const f of issues.slice(0, 5)) lines.push(fit(`        ${sevTag[f.severity] || ''} ${T.text(f.title)} ${T.faint('· ' + f.category)}`, W));
    if (issues.length > 5) lines.push(`        ${T.faint(t('… altri {n} problemi', { n: issues.length - 5 }) + ` · /report ${r.n}`)}`);
    if (!issues.length) lines.push(`        ${T.ok('✓')} ${T.muted(t('Nessun problema rilevato'))}`);
    return lines;
  }

  folderBlock(g, W) {
    const done = g.items.filter((r) => r.status !== 'scanning').length;
    const lines = ['', fit(`  ${T.faint('›')} ${T.bold(path.basename(g.dir) + '/')}  ${T.faint(tilde(path.dirname(g.dir)) + '  ·  ' + g.total + ' file')}`, W)];
    if (!g.total) { lines.push(`        ${T.warn(t('Nessun file da analizzare in questa cartella'))}`); return lines; }
    if (done < g.total) {
      const bw = Math.max(10, Math.min(40, W - 40));
      const n = Math.round((done / g.total) * bw);
      lines.push(`        ${T.accent(SPIN[this.frame % SPIN.length])} ${T.accent('━'.repeat(n))}${T.line('━'.repeat(bw - n))}  ${T.text(done + '/' + g.total)} ${T.faint('· ' + ui.fmtDur(Date.now() - g.t0))}`);
      return lines;
    }
    const ok = g.items.filter((r) => r.status === 'done');
    const by = (l) => ok.filter((r) => r.result.overall.level === l).length;
    lines.push(`        ${T.ok('✓')} ${T.text(t('{n} file analizzati', { n: ok.length }))} ${T.faint(t('in {d}', { d: ui.fmtDur(g.ms || 0) }))}   ` +
      [[by('safe'), T.safe, '{n} sicuri'], [by('low'), T.low, '{n} basso rischio'], [by('medium'), T.medium, '{n} sospetti'], [by('high'), T.high, '{n} pericolosi'], [by('critical'), T.critical, '{n} malevoli']].filter(([n]) => n).map(([n, st, l]) => st(t(l, { n }))).join(T.faint(' · ')));
    const worst = [...g.items].filter((r) => r.status === 'error' || r.result.overall.score < 90).sort((a, b) => (a.result?.overall.score ?? 0) - (b.result?.overall.score ?? 0));
    for (const r of worst.slice(0, 8)) lines.push(this.resultLine(r, W));
    if (worst.length > 8) lines.push(`        ${T.faint(t('… altri {n} · {cmd} per vederli tutti', { n: worst.length - 8, cmd: cmdName('/elenco') }))}`);
    if (!worst.length) lines.push(`        ${T.muted(t('Tutti i file risultano sicuri.'))}`);
    return lines;
  }

  /* ── frame ── */
  render() {
    if (this.restored) return;
    const W = Math.max(20, this.out.columns || 80);
    const H = Math.max(10, this.out.rows || 24);
    if (this.flash && Date.now() > this.flash.until) this.flash = null;
    this.hits = {};
    const rows = [];

    // Header
    const left = ` ${T.accentB('◆')} ${T.bold('Gauntler')} ${T.faint(core.VERSION)}  ${T.line('│')}  ${T.muted(t('Analisi di sicurezza dei file'))}`;
    const dot = (on, name) => `${on ? T.ok('●') : T.faint('○')} ${on ? T.muted(name) : T.faint(name)}`;
    const right = `${dot(this.env.clamav, 'ClamAV')}   ${dot(this.env.sevenZip, '7-Zip')}  `;
    const short = ` ${T.accentB('◆')} ${T.bold('Gauntler')} ${T.faint(core.VERSION)}`;
    const hl = vlen(left) + vlen(right) + 2 <= W ? left : short;
    rows.push(vlen(hl) + vlen(right) + 2 <= W ? hl + ' '.repeat(W - vlen(hl) - vlen(right)) + right : fit(hl, W));
    rows.push(T.line('─'.repeat(W)));

    // Bottom layout: input box (3) + footer (1)
    const bodyH = H - rows.length - 4;
    this.layout.body = bodyH;
    const all = [];
    for (const b of this.blocks) all.push(...b.render(W));
    this.maxScroll = Math.max(0, all.length - bodyH);
    this.scroll = Math.min(this.scroll, this.maxScroll);
    const end = all.length - this.scroll;
    const view = all.slice(Math.max(0, end - bodyH), end).map((l) => fit(l, W));
    while (view.length < bodyH) view.push(' '.repeat(W));
    if (this.scroll > 0) view[view.length - 1] = fit(`  ${T.accent('↓')} ${T.muted(t('{n} righe sotto · PagGiù per tornare in fondo', { n: this.scroll }))}`, W);
    const top = rows.length;

    // Overlay: command suggestions (above the input)
    const sug = this.menu ? [] : this.suggestions();
    if (sug.length) {
      this.sugSel = Math.min(this.sugSel, sug.length - 1);
      const list = sug.slice(0, Math.max(1, bodyH - 1));
      list.forEach(([c, d], i) => {
        const y = view.length - list.length + i;
        const on = i === this.sugSel;
        const line = `  ${on ? T.accent('▸') : ' '} ${fit(on ? T.accentB(c) : T.text(c), 14)} ${T.muted(d)}`;
        view[y] = fit(line, W);
        this.hits['sug:' + c] = { y: top + y + 1, x: 1, w: W };
      });
    }

    // Overlay: add menu (above the + button, at the left)
    if (this.menu) {
      const mw = 40;
      const box = [T.line('╭' + '─'.repeat(mw - 2) + '╮'), `${T.line('│')} ${fit(T.bold(t('Aggiungi da analizzare')), mw - 4)} ${T.line('│')}`, T.line('├' + '─'.repeat(mw - 2) + '┤')];
      MENU.forEach((m, i) => {
        const on = i === this.menu.sel;
        const icon = m.id === 'file' ? '▤' : m.id === 'folder' ? '▣' : '›';
        const body = ` ${icon}  ${m.label}`;
        const inner = fit(body, mw - 4 - m.hint.length) + m.hint;
        box.push(`${T.line('│')} ${on ? T.sel(ui.strip(inner)) : T.text(cut(inner, 0, mw - 4 - m.hint.length)) + T.faint(m.hint)} ${T.line('│')}`);
      });
      box.push(T.line('├' + '─'.repeat(mw - 2) + '┤'));
      box.push(`${T.line('│')} ${fit(T.faint(t('↑↓ scegli · Invio apri · Esc chiudi')), mw - 4)} ${T.line('│')}`);
      box.push(T.line('╰' + '─'.repeat(mw - 2) + '╯'));
      const start = Math.max(0, view.length - box.length);
      box.forEach((b, i) => {
        const y = start + i; if (y >= view.length) return;
        view[y] = ' ' + b + cut(view[y], mw + 1, W);
        if (i >= 3 && i < 3 + MENU.length) this.hits['menu:' + MENU[i - 3].id] = { y: top + y + 1, x: 2, w: mw };
      });
    }
    rows.push(...view);

    // Input box
    const prompt = ` ${T.accent('›')} `;
    const boxW = W - 2;
    const fieldW = boxW - 2 - vlen(prompt) - 1;
    let shown = this.input, curX = this.cur;
    if (shown.length > fieldW) { const off = Math.max(0, Math.min(this.cur - fieldW + 1, shown.length - fieldW)); shown = shown.slice(off, off + fieldW); curX = this.cur - off; }
    const placeholder = this.picking ? T.accent(SPIN[this.frame % SPIN.length] + ' ' + t('Finestra di selezione aperta: scegli i file nel Finder…'))
      : T.faint(t('Trascina qui un file, digita un percorso o un /comando…'));
    const field = this.input ? T.text(shown) : placeholder;
    const focus = this.menu ? T.line : T.accent;
    rows.push(' ' + focus('╭' + '─'.repeat(boxW - 2) + '╮'));
    rows.push(' ' + focus('│') + prompt + fit(field, fieldW + 1) + focus('│'));
    rows.push(' ' + focus('╰' + '─'.repeat(boxW - 2) + '╯'));

    // Footer: + button bottom-left, shortcuts, session stats
    const plus = (this.menu ? T.plusOn : T.plus)(' + ');
    this.hits.plus = { y: H, x: 2, w: 3 };
    let hint;
    if (this.flash) hint = { info: T.muted, warn: T.warn, err: T.err }[this.flash.kind](this.flash.text);
    else {
      const variants = [
        `${T.muted(t('Aggiungi file'))}   ${T.faint('·')}   ${T.faint(t('Invio analizza  ·  / comandi  ·  PagSu/PagGiù scorri  ·  Ctrl+C esci'))}`,
        `${T.muted(t('Aggiungi file'))}   ${T.faint('·')}   ${T.faint(t('/ comandi  ·  Ctrl+C esci'))}`,
        T.muted(t('Aggiungi file')),
      ];
      hint = variants.find((v) => vlen(v) + 30 <= W) || variants[2];
    }
    const ok = this.results.filter((r) => r.status === 'done');
    const risky = ok.filter((r) => r.result.overall.score < 40).length;
    const stats = this.busy ? `${T.accent(SPIN[this.frame % SPIN.length])} ${T.muted(t('{n} in analisi', { n: this.busy }))}  `
      : ok.length ? `${T.muted(t('{n} analizzati', { n: ok.length }))}${risky ? '  ' + T.err('● ' + t('{n} a rischio', { n: risky })) : '  ' + T.ok('●')}  ` : '';
    const footL = ' ' + plus + '  ' + hint;
    rows.push(vlen(footL) + vlen(stats) + 1 <= W ? footL + ' '.repeat(W - vlen(footL) - vlen(stats)) + stats : fit(footL, W));

    // Output: one write, cursor in the input box
    let frame = '\x1b[?25l\x1b[H';
    rows.slice(0, H).forEach((r, i) => { frame += (i ? '\r\n' : '') + r + '\x1b[0m\x1b[K'; });
    const cy = H - 2, cx = 2 + 1 + vlen(prompt) + (this.input ? curX : 0);
    frame += `\x1b[${cy};${cx}H` + (this.menu || this.picking ? '' : '\x1b[?25h');
    this.write(frame);
  }
}

function run(opts = {}) {
  if (!process.stdin.isTTY || !process.stdout.isTTY) throw new Error(t('L\'interfaccia interattiva richiede un terminale. Usa: gauntler <file> (vedi gauntler --help)'));
  const tui = new Tui();
  tui.firstRun = opts.firstRun || null;
  process.on('uncaughtException', (e) => { tui.restore(); console.error(ui.c.red('✖ ' + (e.stack || e.message))); process.exit(3); });
  return tui.start();
}

module.exports = {
  run, parsePaths, tokenize, cut,
  get summary() { return t('Interfaccia interattiva a schermo intero (predefinita senza argomenti)'); },
  get HELP() { return `\n${ui.c.bold('gauntler shell')}\n\n${t('Apre l\'interfaccia interattiva: aggiungi file con il pulsante + in basso a sinistra (o Tab),\ntrascinandoli nella finestra o digitandone il percorso. Si avvia anche con "gauntler" senza argomenti.')}\n`; },
};
