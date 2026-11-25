// Creato da anvex2012
import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import Report from './components/Report.jsx';
import { ScoreRing, ScoreChip, Stat } from './components/ui.jsx';
import Icon, { CatIcon } from './components/Icon.jsx';
import Settings from './components/Settings.jsx';
import logo from './assets/logo.png';
import { LEVEL_COLOR, fmtNum, formatBytes, levelOf } from './lib.js';
import * as prefs from './settings.js';

const LEVELS = [['safe', 'Sicuri'], ['low', 'Basso rischio'], ['medium', 'Sospetti'], ['high', 'Pericolosi'], ['critical', 'Malevoli']];
let nextId = 1;

function Dashboard({ items, onOpen }) {
  const done = items.filter((i) => i.status === 'done').map((i) => ({ ...i, r: i.result }));
  const by = Object.fromEntries(LEVELS.map(([l]) => [l, done.filter((d) => d.r.overall.level === l).length]));
  const avg = done.length ? Math.round(done.reduce((a, d) => a + d.r.overall.score, 0) / done.length) : 0;
  const worst = [...done].sort((a, b) => a.r.overall.score - b.r.overall.score).slice(0, 12);
  const catAgg = {};
  for (const d of done) for (const f of d.r.findings) if (f.severity !== 'info') catAgg[f.categoryId] = (catAgg[f.categoryId] || 0) + 1;
  const catRows = Object.entries(catAgg).sort((a, b) => b[1] - a[1]);
  const maxCat = Math.max(1, ...catRows.map((c) => c[1]));
  const tot = done.reduce((a, d) => ({ lines: a.lines + (d.r.totals.lines || 0), checks: a.checks + d.r.totals.checks, bytes: a.bytes + d.r.file.size, secrets: a.secrets + d.r.findings.filter((f) => f.categoryId === 'secrets' && f.severity !== 'info').length }), { lines: 0, checks: 0, bytes: 0, secrets: 0 });
  return (
    <div className="report">
      <section className="hero" style={{ '--accent': LEVEL_COLOR[levelOf(avg)] }}>
        <ScoreRing score={avg} />
        <div className="hero-text">
          <div className="hero-top"><span className="hero-kicker">Riepilogo analisi</span></div>
          <h1>{fmtNum(done.length)} file analizzati</h1>
          <p className="advice">Punteggio medio {avg} su 100. {by.critical + by.high ? `${by.critical + by.high} ${by.critical + by.high === 1 ? 'file richiede' : 'file richiedono'} attenzione immediata.` : by.medium ? `${by.medium} ${by.medium === 1 ? 'file è sospetto' : 'file sono sospetti'}.` : 'Nessun file pericoloso trovato.'}</p>
          <div className="stack-bar">
            {LEVELS.map(([l, n]) => by[l] > 0 && <span key={l} style={{ flex: by[l], background: LEVEL_COLOR[l] }} title={`${n}: ${by[l]}`} />)}
          </div>
          <div className="legend">{LEVELS.map(([l, n]) => <span key={l}><i className="dot" style={{ '--c': LEVEL_COLOR[l] }} /><b>{by[l]}</b> {n.toLowerCase()}</span>)}</div>
        </div>
      </section>
      <div className="stats">
        <Stat label="file analizzati" value={fmtNum(done.length)} />
        <Stat label="dati analizzati" value={formatBytes(tot.bytes)} />
        <Stat label="righe analizzate" value={fmtNum(tot.lines)} />
        <Stat label="controlli eseguiti" value={fmtNum(tot.checks)} />
        <Stat label="segreti esposti" value={fmtNum(tot.secrets)} />
      </div>
      <div className="two">
        <div className="panel">
          <h3>File con il punteggio più basso</h3>
          <table className="tbl hover plain"><thead><tr><th>Punteggio</th><th>File</th><th>Problema principale</th></tr></thead><tbody>
            {worst.map((d) => <tr key={d.id} className="clickable" onClick={() => onOpen(d.id)}><td><ScoreChip score={d.r.overall.score} /></td><td className="wrap">{d.name}</td><td className="muted small">{d.r.findings.find((f) => f.severity !== 'info')?.title || '—'}</td></tr>)}
          </tbody></table>
        </div>
        <div className="panel">
          <h3>Problemi per criterio</h3>
          {catRows.length === 0 ? <p className="muted">Nessun problema.</p> : catRows.map(([id, n]) => (
            <div key={id} className="hbar"><span className="hbar-l"><CatIcon id={id} /> {done[0]?.r.categories.find((c) => c.id === id)?.name || id}</span><span className="hbar-t"><i style={{ width: `${(n / maxCat) * 100}%` }} /></span><b>{n}</b></div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default function App() {
  const [env, setEnv] = useState(null);
  const [items, setItems] = useState([]);
  const [selected, setSelected] = useState(null);
  const [dragging, setDragging] = useState(false);
  const [filter, setFilter] = useState('');
  const [levelFilter, setLevelFilter] = useState(null);
  const [settings, setSettings] = useState(prefs.load);
  const [sort, setSort] = useState(settings.sort);
  const [showSettings, setShowSettings] = useState(false);
  const dragDepth = useRef(0);
  const searchRef = useRef(null);
  const cfgRef = useRef(settings);
  cfgRef.current = settings;

  // Preferences: applied to the document and the native window, saved on every change
  useEffect(() => { prefs.apply(settings); prefs.save(settings); }, [settings]);
  const setPrefs = useCallback((patch, replace = false) => {
    // Passwords always stay in memory for this session; prefs.save() writes them only when remembered
    setSettings((cur) => prefs.sanitize(replace ? patch : { ...cur, ...patch }));
    if (patch.sort) setSort(patch.sort);
  }, []);
  const ctx = useMemo(() => ({ settings, set: setPrefs }), [settings, setPrefs]);

  useEffect(() => { window.gauntler?.env().then(setEnv); }, []);
  const update = (id, patch) => setItems((list) => list.map((it) => (it.id === id ? { ...it, ...patch } : it)));

  const addPaths = useCallback(async (paths) => {
    if (!paths?.length) return;
    const files = await window.gauntler.expand(paths);
    if (!files.length) return;
    const fresh = files.map((p) => ({ id: nextId++, path: p, name: p.split(/[\\/]/).pop(), status: 'queued', added: Date.now() }));
    setItems((list) => [...fresh, ...list]);
    const cfg = cfgRef.current;
    const showDash = cfg.afterAdd === 'dashboard' || (cfg.afterAdd === 'auto' && fresh.length > 1);
    setSelected(showDash ? 'dashboard' : fresh[0].id);
    let i = 0;
    const opts = { passwords: cfg.passwords.split(/[\n,]/).map((s) => s.trim()).filter(Boolean) };
    const results = [];
    const t0 = Date.now();
    const work = async () => {
      while (i < fresh.length) {
        const it = fresh[i++];
        update(it.id, { status: 'scanning', started: Date.now() });
        const res = await window.gauntler.scanOne(it.path, opts);
        if (res.ok) results.push(res.result);
        update(it.id, res.ok ? { status: 'done', result: res.result } : { status: 'error', error: res.error });
      }
    };
    await Promise.all(Array.from({ length: Math.min(cfg.concurrency, fresh.length) }, work));
    // System notification, only when the window is not in front or the scan took a while
    if (cfgRef.current.notify && (!document.hasFocus() || Date.now() - t0 > 8000) && typeof Notification !== 'undefined') {
      const bad = results.filter((r) => r.overall.level === 'high' || r.overall.level === 'critical');
      const body = fresh.length === 1
        ? `${fresh[0].name}: ${results[0] ? `${results[0].overall.score}/100 — ${results[0].overall.verdict}` : 'errore'}`
        : `${results.length} file analizzati${bad.length ? ` · ${bad.length} pericolos${bad.length === 1 ? 'o' : 'i'}` : ' · nessun file pericoloso'}`;
      try { new Notification(bad.length ? 'Gauntler: attenzione' : 'Gauntler: analisi completata', { body, silent: !bad.length }); } catch { /* notifications disabled */ }
    }
  }, []);
  const addRef = useRef(addPaths);
  addRef.current = addPaths;
  useEffect(() => window.gauntler?.onOpenPaths((p) => addRef.current(p)), []);

  useEffect(() => {
    const prevent = (e) => { e.preventDefault(); e.stopPropagation(); };
    const enter = (e) => { prevent(e); dragDepth.current++; setDragging(true); };
    const leave = (e) => { prevent(e); dragDepth.current = Math.max(0, dragDepth.current - 1); if (!dragDepth.current) setDragging(false); };
    const drop = (e) => {
      prevent(e); dragDepth.current = 0; setDragging(false);
      addPaths([...(e.dataTransfer?.files || [])].map((f) => window.gauntler.pathForFile(f)).filter(Boolean));
    };
    window.addEventListener('dragenter', enter); window.addEventListener('dragover', prevent); window.addEventListener('dragleave', leave); window.addEventListener('drop', drop);
    return () => { window.removeEventListener('dragenter', enter); window.removeEventListener('dragover', prevent); window.removeEventListener('dragleave', leave); window.removeEventListener('drop', drop); };
  }, [addPaths]);

  const pick = async (kind) => addPaths(await window.gauntler.pick(kind));
  const pickRef = useRef(pick);
  pickRef.current = pick;

  // Keyboard shortcuts: ⌘O file, ⇧⌘O folder, ⌘, settings, ⌘F search
  useEffect(() => {
    const onKey = (e) => {
      if (!(e.metaKey || e.ctrlKey) || e.altKey) return;
      const k = e.key.toLowerCase();
      if (k === 'o') { e.preventDefault(); pickRef.current(e.shiftKey ? 'folder' : 'file'); }
      else if (k === ',') { e.preventDefault(); setShowSettings((v) => !v); }
      else if (k === 'f' && searchRef.current) { e.preventDefault(); searchRef.current.focus(); searchRef.current.select(); }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);
  const done = items.filter((i) => i.status === 'done');
  const running = items.filter((i) => i.status === 'scanning' || i.status === 'queued').length;
  const shown = useMemo(() => {
    let l = items.filter((i) => (!filter || i.name.toLowerCase().includes(filter.toLowerCase())) && (!levelFilter || i.result?.overall.level === levelFilter));
    if (sort === 'score') l = [...l].sort((a, b) => (a.result?.overall.score ?? -1) - (b.result?.overall.score ?? -1));
    else if (sort === 'name') l = [...l].sort((a, b) => a.name.localeCompare(b.name));
    return l;
  }, [items, filter, levelFilter, sort]);
  const current = items.find((i) => i.id === selected);
  const finished = items.filter((i) => i.status === 'done' || i.status === 'error').length;
  const levelCounts = useMemo(() => Object.fromEntries(LEVELS.map(([l]) => [l, done.filter((d) => d.result.overall.level === l).length])), [done]);

  const closeSettings = useCallback(() => setShowSettings(false), []);
  if (!window.gauntler) return <div className="fatal">Questa interfaccia va avviata dentro l'app Electron (npm run dev).</div>;

  return (
    <prefs.SettingsContext.Provider value={ctx}>
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <img className="logo" src={logo} alt="" aria-hidden width={30} height={30} />
          Gauntler
          <span className="brand-sep" aria-hidden />
          <span className="brand-sub">Analisi di sicurezza dei file</span>
        </div>
        <div className="top-right">
          {env && <span className={`status ${env.clamav ? 'on' : ''}`} title={env.clamav ? 'ClamAV installato: scansione antivirus attiva' : 'Installa ClamAV per una scansione antivirus aggiuntiva (brew install clamav)'}><i className="dot" />ClamAV</span>}
          {env && <span className={`status ${env.sevenZip ? 'on' : ''}`} title={env.sevenZip ? '7-Zip disponibile per RAR/7z/ISO' : 'Archivi RAR/7z/ISO aperti con bsdtar'}><i className="dot" />{env.sevenZip ? '7-Zip' : 'bsdtar'}</span>}
          <span className="top-div" aria-hidden />
          <button className={`btn btn-quiet btn-icon ${showSettings ? 'on' : ''}`} onClick={() => setShowSettings(true)} title="Impostazioni (⌘,)" aria-label="Impostazioni" aria-haspopup="dialog"><Icon name="settings" size={16} /></button>
          {items.length > 0 && <>
            <button className="btn btn-ghost" onClick={() => pick('folder')}><Icon name="folder" />Cartella</button>
            <button className="btn" onClick={() => pick('file')}><Icon name="plus" />Analizza file</button>
          </>}
        </div>
      </header>

      {items.length === 0 ? (
        <main className="welcome">
          <div className={`drop ${dragging ? 'drop-on' : ''}`}>
            <div className="drop-icon" aria-hidden><Icon name="upload" size={22} /></div>
            <h1>Trascina qui un file o una cartella</h1>
            <p>Programmi, documenti, archivi, script, email e immagini. Ogni riga, ogni stringa e ogni contenuto nascosto viene esaminato. <b>L'analisi avviene interamente sul computer.</b></p>
            <div className="drop-actions">
              <button className="btn btn-lg" onClick={() => pick('file')}><Icon name="file" />Scegli file</button>
              <button className="btn btn-lg btn-ghost" onClick={() => pick('folder')}><Icon name="folder" />Scegli cartella</button>
            </div>
          </div>
          <div className="features-wrap">
            <h2 className="features-title">Cosa viene analizzato</h2>
            <div className="features">
              {[
                ['bug', 'Malware', 'Famiglie note di ransomware, RAT, stealer, botnet, webshell ed exploit; ClamAV se installato'],
                ['binary', 'Codice macchina', 'Disassemblaggio x86/x64/ARM64, shellcode, hash di API, chiavi XOR'],
                ['rows', 'Riga per riga', 'Oltre 200 indicatori su ogni riga e parola, ciascuno spiegato'],
                ['key', 'Segreti esposti', 'Oltre 75 tipi di chiavi, token, password e hash'],
                ['layers', 'Contenuti nascosti', 'Base64, hex e gzip a più livelli, macro, flussi PDF, allegati'],
                ['archive', 'Archivi', 'ZIP anche protetti, RAR, 7z, TAR, ISO: ogni file interno'],
                ['mail', 'Phishing', 'Linguaggio di truffa, mittenti falsificati (SPF/DKIM), link ingannevoli'],
                ['tag', 'Privacy', 'Posizione GPS nelle foto, autori dei documenti, dati personali'],
                ['shieldCheck', 'Copia sicura', 'Ricostruzione del file senza contenuti attivi, con verifica finale'],
              ].map(([i, t, d]) => <div className="feature" key={t}><span className="feature-icon" aria-hidden><Icon name={i} size={15} /></span><div><b>{t}</b><p>{d}</p></div></div>)}
            </div>
          </div>
          {env && <p className="welcome-foot">Gauntler {env.version} · {env.analyzers.length} criteri di analisi</p>}
        </main>
      ) : (
        <div className="layout">
          <aside className="sidebar">
            <div className="side-head">
              <input ref={searchRef} className="search" placeholder="Cerca file…" aria-label="Cerca file" value={filter} onChange={(e) => setFilter(e.target.value)} />
              <div className="lvl-filter" role="group" aria-label="Filtra per livello">
                {LEVELS.map(([l, n]) => (
                  <button key={l} className={levelFilter === l ? 'on' : ''} style={{ '--c': LEVEL_COLOR[l] }} title={`${n}: ${levelCounts[l]}`} aria-pressed={levelFilter === l} onClick={() => setLevelFilter(levelFilter === l ? null : l)}><i className="dot" />{levelCounts[l]}</button>
                ))}
              </div>
              <div className="side-stats">
                {running > 0 ? <span className="side-run"><span className="spin" /> {fmtNum(finished)} di {fmtNum(items.length)}</span> : <span>{fmtNum(done.length)} file</span>}
                <span>
                  <select className="select xs" value={sort} onChange={(e) => setSort(e.target.value)}><option value="score">Per punteggio</option><option value="name">Per nome</option><option value="added">Più recenti</option></select>
                  <button className="btn-mini" onClick={() => { setItems([]); setSelected(null); }} title="Rimuovi tutti i file dall'elenco"><Icon name="trash" />Svuota</button>
                </span>
              </div>
              {running > 0 && <div className="progress" role="progressbar" aria-label="Avanzamento dell'analisi" aria-valuemin={0} aria-valuemax={items.length} aria-valuenow={finished}><i style={{ width: `${(finished / Math.max(1, items.length)) * 100}%` }} /></div>}
            </div>
            <ul className="files">
              {items.length > 1 && (
                <li><button className={`file ${selected === 'dashboard' ? 'file-on' : ''}`} onClick={() => setSelected('dashboard')}><Icon name="grid" /><span className="file-name">Riepilogo</span></button></li>
              )}
              {shown.map((it) => (
                <li key={it.id}>
                  <button className={`file ${selected === it.id ? 'file-on' : ''}`} onClick={() => setSelected(it.id)} title={it.path}>
                    <Icon name="file" />
                    <span className="file-name">{it.name}</span>
                    {it.status === 'done' && <ScoreChip score={it.result.overall.score} />}
                    {(it.status === 'scanning' || it.status === 'queued') && <span className="spin" />}
                    {it.status === 'error' && <span className="chip chip-err">errore</span>}
                  </button>
                </li>
              ))}
            </ul>
          </aside>
          <main className="main">
            {selected === 'dashboard' ? <Dashboard items={items} onOpen={setSelected} />
              : !current ? null
              : current.status === 'done' ? <Report key={current.id} r={current.result} />
              : current.status === 'error' ? <div className="center-msg"><Icon name="alert" size={28} className="err-icon" /><h2>Impossibile analizzare il file</h2><p className="muted">{current.error}</p></div>
              : (
                <div className="center-msg">
                  <div className="scanning-ring"><span className="spin big" /></div>
                  <h2>Analisi in corso</h2>
                  <p className="muted">{current.name}</p>
                  <p className="muted small">Ogni riga, ogni stringa e ogni contenuto nascosto viene esaminato. I file grandi possono richiedere qualche minuto.</p>
                </div>
              )}
          </main>
        </div>
      )}
      {dragging && items.length > 0 && <div className="overlay-drop"><div><Icon name="upload" size={28} />Rilascia per analizzare</div></div>}
      {showSettings && <Settings env={env} onClose={closeSettings} />}
    </div>
    </prefs.SettingsContext.Provider>
  );
}
