// Created by anvex2012
import React, { useMemo, useState } from 'react';
import { ScoreRing, ScoreChip, SevBadge, Radar, EntropyChart, Histogram, HexView, Copy, Stat, KV } from './ui.jsx';
import { CodeViewer, StringsViewer } from './CodeViewer.jsx';
import Disasm from './Disasm.jsx';
import Icon, { CatIcon } from './Icon.jsx';
import { useSettings } from '../settings.js';
import { t, getLanguage } from '../i18n.js';
import { CATEGORY_ADVICE, LEVEL_COLOR, SEVERITY, SEV_RANK, levelOf, formatBytes, fmtNum, fmtMs, fmtLoc } from '../lib.js';

const EXPORTS = { html: 'HTML', json: 'JSON', sarif: 'SARIF', csv: 'CSV', md: 'Markdown' };
const SHORT = { machinecode: 'Assembly', identity: 'Identità', signatures: 'Firme', clamav: 'ClamAV', executable: 'Eseguibile', documents: 'Documenti', code: 'Codice', lines: 'Righe', archive: 'Contenuti', secrets: 'Segreti', privacy: 'Privacy', social: 'Phishing', network: 'Rete', metadata: 'Metadati', statistics: 'Statistica' };

function CategoryCard({ c, active, onClick }) {
  const issues = c.findings.filter((f) => f.severity !== 'info').length;
  const color = LEVEL_COLOR[levelOf(c.score)];
  const passed = (c.checks || []).filter((k) => k.ok).length;
  return (
    <button className={`cat ${active ? 'cat-active' : ''}`} onClick={onClick} title={c.description}>
      <div className="cat-top"><span className="cat-icon" aria-hidden><CatIcon id={c.id} size={14} /></span><span className="cat-name">{c.name}</span><span className="cat-score" style={{ '--c': color }}>{c.score}</span></div>
      <div className="bar"><span style={{ width: `${c.score}%`, background: color }} /></div>
      <div className="cat-foot">
        <span>{issues ? t(issues === 1 ? '{n} problema' : '{n} problemi', { n: issues }) : t('Nessun problema')}</span>
        {c.checks?.length > 0 && <span title={t('Controlli superati')}><Icon name="check" />{passed}/{c.checks.length}</span>}
      </div>
    </button>
  );
}

function Finding({ f, onJump, onChild }) {
  const [open, setOpen] = useState(false);
  const locs = f.locs || (f.loc ? [f.loc] : []);
  return (
    <li className={`finding fsev-${f.severity}`}>
      <button className="finding-head" onClick={() => setOpen(!open)} aria-expanded={open}>
        <SevBadge sev={f.severity} />
        <span className="finding-title">{f.title}</span>
        <span className="finding-cat"><CatIcon id={f.categoryId} />{f.category}</span>
        <span className={`caret ${open ? 'open' : ''}`}><Icon name="chevronRight" /></span>
      </button>
      <p className="finding-detail">{f.detail}{f.where ? <> · <a className="link" onClick={() => onJump(f.loc)}>{f.where}</a></> : null}</p>
      {open && (
        <div className="finding-more">
          {f.evidence?.length > 0 && <div className="evidence">{f.evidence.map((e, i) => <code key={i}>{e}</code>)}</div>}
          {locs.length > 0 && (
            <div className="locs">
              <span className="muted small">{t(locs.length === 1 ? 'Trovato in {n} punto:' : 'Trovato in {n} punti:', { n: fmtNum(locs.length) })}</span>
              {locs.slice(0, 400).map((l, i) => <button key={i} className="loc" onClick={() => onJump(l)}>{fmtLoc(l)}</button>)}
              {locs.length > 400 && <span className="muted small">{t('… e altri {n}', { n: fmtNum(locs.length - 400) })}</span>}
            </div>
          )}
          {f.child && <button className="btn-mini" onClick={() => onChild(f.child)}>{t('Apri il report di {name}', { name: f.child })}<Icon name="arrowRight" /></button>}
          {CATEGORY_ADVICE[f.categoryId] && f.severity !== 'info' && <p className="advice-small"><Icon name="info" />{t(CATEGORY_ADVICE[f.categoryId])}</p>}
        </div>
      )}
    </li>
  );
}

function Issues({ r, cat, setCat, onJump, onChild }) {
  const { settings } = useSettings();
  const [sevs, setSevs] = useState({ critical: true, high: true, medium: true, low: true, info: settings.showInfo });
  const [q, setQ] = useState('');
  const list = useMemo(() => r.findings.filter((f) => sevs[f.severity] && (!cat || f.categoryId === cat) && (!q || (f.title + ' ' + f.detail + ' ' + (f.evidence || []).join(' ')).toLowerCase().includes(q.toLowerCase()))), [r, sevs, cat, q]);
  const counts = useMemo(() => { const c = {}; for (const f of r.findings) if (!cat || f.categoryId === cat) c[f.severity] = (c[f.severity] || 0) + 1; return c; }, [r, cat]);
  return (
    <section>
      <div className="filters">
        {Object.keys(SEVERITY).map((s) => (
          <button key={s} className={`fchip ${sevs[s] ? 'on' : ''}`} aria-pressed={!!sevs[s]} onClick={() => setSevs({ ...sevs, [s]: !sevs[s] })}>
            <i className="dot" style={{ '--c': SEVERITY[s].color }} />{t(SEVERITY[s].label)} <b>{counts[s] || 0}</b>
          </button>
        ))}
        <select className="select" value={cat || ''} onChange={(e) => setCat(e.target.value || null)}>
          <option value="">{t('Tutti i criteri')}</option>
          {r.categories.filter((c) => c.applicable).map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
        </select>
        <input className="search sm" placeholder={t('Cerca nei problemi…')} value={q} onChange={(e) => setQ(e.target.value)} />
      </div>
      {list.length === 0 ? <div className="empty-ok"><Icon name="sparkCheck" size={16} />{t('Nessun problema con questi filtri.')}</div> : (
        <ul className="findings">{list.map((f, i) => <Finding key={i} f={f} onJump={onJump} onChild={onChild} />)}</ul>
      )}
    </section>
  );
}

function Checks({ r }) {
  const [onlyFail, setOnlyFail] = useState(false);
  const cats = r.categories.filter((c) => c.checks?.length);
  return (
    <section>
      <div className="filters">
        <span className="count">{t('{n} controlli eseguiti', { n: fmtNum(r.totals.checks) })}</span>
        <span className="count"><i className="dot" style={{ '--c': 'var(--high)' }} /><b>{fmtNum(r.totals.checksFailed)}</b> {t('non superati')}</span>
        <span className="filters-sep" />
        <label className="toggle"><input type="checkbox" checked={onlyFail} onChange={(e) => setOnlyFail(e.target.checked)} /> {t('Solo non superati')}</label>
      </div>
      <div className="checks-grid">
        {cats.map((c) => {
          const list = c.checks.filter((k) => !onlyFail || !k.ok);
          if (!list.length) return null;
          return (
            <div className="panel" key={c.id}>
              <h3><CatIcon id={c.id} /> {c.name}<span className="grow" />{c.score != null && <ScoreChip score={c.score} />}<span className="muted small num">{c.checks.filter((k) => k.ok).length}/{c.checks.length}</span></h3>
              <ul className="checks">{list.map((k, i) => (
                <li key={i} className={k.ok ? 'ok' : 'ko'}><span className="ck"><Icon name={k.ok ? 'check' : 'x'} /></span><span>{k.name}</span>{k.note ? <span className="note">{k.note}</span> : null}</li>
              ))}</ul>
            </div>
          );
        })}
      </div>
    </section>
  );
}

function Contents({ r, onChild, onJump }) {
  return (
    <section className="tech">
      {r.children?.length > 0 && (
        <div className="panel">
          <h3><Icon name="archive" /> {t('File interni analizzati')} <span className="tab-n">{r.children.length}</span></h3>
          <p className="muted small">{t('Ogni file contenuto nell\'archivio o nascosto nel file è stato analizzato con tutti i criteri. Clicca per aprire il suo report completo.')}</p>
          <table className="tbl hover"><thead><tr><th>{t('File')}</th><th>{t('Tipo')}</th><th>{t('Dimensione')}</th><th>{t('Origine')}</th><th>{t('Punteggio')}</th></tr></thead><tbody>
            {[...r.children].sort((a, b) => a.overall.score - b.overall.score).map((c, i) => (
              <tr key={i} onClick={() => onChild(c)} className="clickable">
                <td className="mono">{c.file.name}</td><td>{c.file.type.label}</td><td>{c.file.sizeHuman}</td><td className="muted small">{c.file.origin}</td><td><ScoreChip score={c.overall.score} /></td>
              </tr>
            ))}
          </tbody></table>
        </div>
      )}
      {r.extracted?.length > 0 && (
        <div className="panel">
          <h3><Icon name="layers" /> {t('Contenuti estratti e decodificati')} <span className="tab-n">{r.extracted.length}</span></h3>
          <p className="muted small">{t('Macro, flussi PDF, parti di documenti e payload decodificati (anche su più livelli): ognuno è stato analizzato riga per riga.')}</p>
          <table className="tbl hover"><thead><tr><th>{t('Contenuto')}</th><th>{t('Tipo')}</th><th>{t('Righe')}</th><th>{t('Livello')}</th><th>{t('Segnalazioni')}</th></tr></thead><tbody>
            {r.extracted.map((e, i) => {
              const n = (r.lines || []).filter((a) => a.source === e.label && a.sev !== 'info').length;
              return (
                <tr key={i} className={e.text != null ? 'clickable' : ''} onClick={() => e.text != null && onJump({ source: e.label, line: 1 })}>
                  <td className="wrap">{e.label}</td><td>{t({ macro: 'Macro VBA', js: 'JavaScript', decoded: 'Decodificato', xml: 'XML', 'pdf-stream': 'Flusso PDF', doctext: 'Testo visibile' }[e.kind] || e.kind)}</td>
                  <td>{fmtNum(e.lines)}</td><td>{e.depth || 0}</td><td>{n ? <span className="chip chip-high">{n}</span> : '—'}</td>
                </tr>
              );
            })}
          </tbody></table>
        </div>
      )}
      {r.archiveEntries?.length > 0 && (
        <div className="panel">
          <h3><Icon name="folderOpen" /> {t('Voci dell\'archivio')} <span className="tab-n">{r.archiveEntries.length}</span></h3>
          <table className="tbl"><thead><tr><th>{t('Nome')}</th><th>{t('Dimensione')}</th><th>{t('Note')}</th></tr></thead><tbody>
            {r.archiveEntries.map((e, i) => <tr key={i}><td className="mono wrap">{e.name}</td><td>{e.size != null ? formatBytes(e.size) : ''}</td><td className="muted small">{[e.encrypted && t('cifrato'), e.special, e.link && t('collegamento a {target}', { target: e.link })].filter(Boolean).join(' ')}</td></tr>)}
          </tbody></table>
        </div>
      )}
      {!r.children?.length && !r.extracted?.length && !r.archiveEntries?.length && <p className="muted">{t('Nessun contenuto nascosto o incorporato.')}</p>}
    </section>
  );
}

function Network({ r }) {
  const i = r.iocs || {};
  const groups = [['URL', i.urls], [t('Domini'), i.domains], [t('IPv4 pubblici'), i.ips], ['IPv6', i.ipv6], ['Tor (.onion)', i.onion], [t('Wallet criptovalute'), i.wallets]].filter(([, l]) => l?.length);
  if (!groups.length) return <p className="muted">{t('Nessun indicatore di rete.')}</p>;
  return (
    <section className="ioc">
      {groups.map(([title, l]) => (
        <div key={title} className="panel">
          <h3><Icon name="globe" /> {title} <span className="tab-n">{fmtNum(l.length)}</span><span className="grow" /><Copy text={l.join('\n')} label={t('Copia tutti')} /></h3>
          <ul>{l.map((x) => <li key={x} className="mono">{x}</li>)}</ul>
        </div>
      ))}
    </section>
  );
}

function Tech({ r }) {
  const ex = r.executable;
  const words = r.wordStats;
  const stat = r.categories.find((c) => c.id === 'statistics');
  return (
    <section className="tech">
      <div className="panel">
        <h3><Icon name="fingerprint" /> {t('Impronte digitali (hash)')}</h3>
        <table className="tbl"><tbody>{Object.entries(r.file.hashes).map(([k, v]) => (
          <tr key={k}><td>{k.toUpperCase()}</td><td className="mono wrap">{v}</td><td><Copy text={v} /></td></tr>
        ))}{ex?.imphash && <tr><td>IMPHASH</td><td className="mono">{ex.imphash}</td><td><Copy text={ex.imphash} /></td></tr>}</tbody></table>
        <p className="muted small">{t('Puoi cercare queste impronte su VirusTotal o MalwareBazaar per sapere se il file è già noto.')}</p>
      </div>
      <div className="two">
        <div className="panel">
          <h3><Icon name="chart" /> {t('Profilo di entropia')}</h3>
          <p className="muted small">{t('Quanto sono "casuali" i dati lungo tutto il file (0–8). Sopra la linea tratteggiata: dati compressi o cifrati.')}</p>
          <EntropyChart profile={r.stats.profile} />
        </div>
        <div className="panel">
          <h3><Icon name="chart" /> {t('Istogramma dei 256 valori di byte')}</h3>
          <p className="muted small">{t('Distribuzione dei byte. Barre uniformi = dati cifrati; picchi nella zona centrale (blu) = testo.')}</p>
          <Histogram data={r.stats.histogram} />
        </div>
      </div>
      {stat?.info && <div className="panel"><h3><Icon name="chart" /> {t('Metriche statistiche')}</h3><KV data={stat.info} /></div>}
      <div className="panel"><h3><Icon name="binary" /> {t('Intestazione del file (esadecimale)')}</h3><HexView b64={r.file.head} /></div>
      {ex?.sections && (
        <div className="panel">
          <h3><Icon name="cpu" /> {t('Sezioni')} <span className="tab-n">{ex.sections.length}</span></h3>
          <table className="tbl"><thead><tr><th>{t('Nome')}</th><th>{t('Dimensione')}</th><th>{t('Entropia')}</th><th>{t('Permessi')}</th></tr></thead><tbody>
            {ex.sections.map((s, i) => <tr key={i}><td className="mono">{s.name || t('(vuoto)')}</td><td>{formatBytes(s.rsize ?? s.size ?? 0)}</td><td style={{ color: s.entropy > 7.2 ? 'var(--high)' : undefined }}>{s.entropy}</td><td className="mono">{s.read !== undefined ? `${s.read ? 'R' : '-'}${s.write ? 'W' : '-'}${s.exec ? 'X' : '-'}` : ''}</td></tr>)}
          </tbody></table>
        </div>
      )}
      {ex?.segments?.length > 0 && typeof ex.segments[0] === 'object' && <div className="panel"><h3>{t('Segmenti')}</h3><KV data={Object.fromEntries(ex.segments.map((s, i) => [`${i}. ${s.type}`, s.flags]))} /></div>}
      {ex?.imports && Object.keys(ex.imports).length > 0 && (
        <div className="panel">
          <h3>{t('Funzioni importate ({n} da {l} librerie)', { n: fmtNum(Object.values(ex.imports).flat().length), l: Object.keys(ex.imports).length })}</h3>
          {Object.entries(ex.imports).map(([dll, fns]) => (
            <details key={dll} className="imp"><summary className="mono">{dll} <span className="muted">({fns.length})</span></summary><div className="mono small wrap">{fns.join(', ')}</div></details>
          ))}
        </div>
      )}
      {ex?.exports?.length > 0 && <div className="panel"><h3>{t('Funzioni esportate ({n})', { n: ex.exports.length })}</h3><div className="mono small wrap">{ex.exports.join(', ')}</div></div>}
      {ex?.entitlements?.length > 0 && <div className="panel"><h3>{t('Entitlement macOS')}</h3><ul className="mono small">{ex.entitlements.map((e) => <li key={e}>{e}</li>)}</ul></div>}
      {ex?.dylibs?.length > 0 && <div className="panel"><h3>{t('Librerie collegate')}</h3><ul className="mono small">{ex.dylibs.map((e) => <li key={e}>{e}</li>)}</ul></div>}
      {r.tokenStats?.length > 0 && (
        <div className="panel">
          <h3><Icon name="rows" /> {t('Indicatori trovati riga per riga')} <span className="tab-n">{r.tokenStats.length}</span></h3>
          <table className="tbl"><thead><tr><th>{t('Indicatore')}</th><th>{t('Categoria')}</th><th>{t('Livello')}</th><th>{t('Occorrenze')}</th></tr></thead><tbody>
            {r.tokenStats.map((x) => <tr key={x.id}><td>{x.label}</td><td className="muted">{x.group}</td><td><SevBadge sev={x.sev} /></td><td>{fmtNum(x.n)}</td></tr>)}
          </tbody></table>
        </div>
      )}
      {words && (
        <div className="panel">
          <h3>{t('Analisi delle parole')}</h3>
          <p className="muted small">{t('{n} parole analizzate, {u} distinte. Le più frequenti:', { n: fmtNum(words.total), u: fmtNum(words.unique) })}</p>
          <div className="words">{words.top.map(([w, n]) => <span key={w} className="word">{w} <b>{fmtNum(n)}</b></span>)}</div>
        </div>
      )}
      {r.categories.filter((c) => c.applicable && c.info && Object.keys(c.info).length && !['statistics', 'metadata'].includes(c.id)).map((c) => (
        <div className="panel" key={c.id}><h3><CatIcon id={c.id} /> {c.name}<span className="grow" /><ScoreChip score={c.score} /><span className="muted small num">{fmtMs(c.ms || 0)}</span></h3><KV data={c.info} /></div>
      ))}
      <p className="muted small">{t('Analisi completata in {d}', { d: fmtMs(r.durationMs) })} · Gauntler {r.scanner.version}</p>
    </section>
  );
}

function Overview({ r, setTab, setCat, onJump, onChild }) {
  const app = r.categories.filter((c) => c.applicable);
  const other = r.categories.filter((c) => !c.applicable);
  const top = r.findings.filter((f) => f.severity !== 'info').slice(0, 6);
  const tt = r.totals;
  const pick = (id) => { setCat(id); setTab('issues'); };
  return (
    <>
      <div className="stats">
        <Stat label={tt.lines ? t('righe analizzate') : t('stringhe analizzate')} value={fmtNum(tt.lines || tt.strings)} />
        <Stat label={t('righe segnalate')} value={fmtNum((r.lines || []).filter((l) => l.sev !== 'info').length)} />
        <Stat label={t('controlli eseguiti')} value={fmtNum(tt.checks)} hint={t('{n} non superati', { n: tt.checksFailed })} />
        <Stat label={t('contenuti estratti')} value={fmtNum(tt.extracted)} />
        <Stat label={t('file interni')} value={fmtNum(tt.children)} />
        <Stat label={t('byte analizzati')} value={formatBytes(tt.bytes)} />
        <Stat label={t('tempo')} value={fmtMs(r.durationMs)} />
      </div>
      <div className="overview">
        <div className="panel radar-panel">
          <h3>{t('Profilo di sicurezza')}<span className="grow" /><span className="hint">{t('per criterio')}</span></h3>
          <Radar cats={app.map((c) => ({ ...c, short: t(SHORT[c.id]) }))} onPick={pick} size={340} />
        </div>
        <div className="panel">
          <h3>{t('Problemi principali')}</h3>
          {top.length === 0 ? <div className="empty-ok"><Icon name="sparkCheck" size={16} />{t('Nessun problema rilevato.')}</div> : (
            <ul className="findings compact">{top.map((f, i) => <Finding key={i} f={f} onJump={onJump} onChild={onChild} />)}</ul>
          )}
          {r.findings.filter((f) => f.severity !== 'info').length > 6 && <button className="btn-mini" onClick={() => setTab('issues')}>{t('Vedi tutti i {n} problemi', { n: r.findings.filter((f) => f.severity !== 'info').length })}<Icon name="arrowRight" /></button>}
        </div>
      </div>
      <section>
        <h2 className="section-title">{t('Punteggi per criterio')} <span className="hint">{t('Seleziona un criterio per vederne i problemi')}</span></h2>
        <div className="cats">{app.map((c) => <CategoryCard key={c.id} c={c} onClick={() => pick(c.id)} />)}</div>
        {other.length > 0 && <p className="na">{t('Non applicabili a questo file:')} {other.map((c) => (c.skipped ? `${c.name} (${c.reason})` : c.name)).join(' · ')}</p>}
      </section>
    </>
  );
}

export default function Report({ r: root }) {
  // Open internal files, by name: the reports follow the root when it is translated again
  const [path, setPath] = useState([]);
  const stack = [root];
  for (const name of path) { const c = stack[stack.length - 1].children?.find((x) => x.file.name === name); if (!c) break; stack.push(c); }
  const setStack = (list) => setPath(list.slice(1).map((x) => x.file.name));
  const r = stack[stack.length - 1];
  const { settings } = useSettings();
  const [tab, setTab] = useState(() => {
    const d = settings.defaultTab;
    if (d === 'issues') return 'issues';
    if (d === 'code' && (root.source != null || (root.extracted || []).some((e) => e.text != null))) return 'code';
    return 'overview';
  });
  const [cat, setCat] = useState(null);
  const [jump, setJump] = useState(null);
  const color = LEVEL_COLOR[r.overall.level];
  const hasText = r.source != null || (r.extracted || []).some((e) => e.text != null);
  const isBin = !!r.strings?.length;
  const flaggedLines = (r.lines || []).filter((l) => l.sev !== 'info').length;

  const onJump = (loc) => {
    if (!loc) return;
    if (loc.line != null && hasText) { setJump({ ...loc, t: Date.now() }); setTab('code'); }
    else if (loc.offset != null && isBin) setTab('strings');
  };
  const onChild = (c) => {
    const child = typeof c === 'string' ? r.children.find((x) => x.file.name === c) : c;
    if (child) { setStack([...stack, child]); setTab('overview'); setCat(null); }
  };
  const [safeMsg, setSafeMsg] = useState(null);
  const sanitize = async () => {
    setSafeMsg({ ok: true, text: t('Disarmo e verifica in corso…') });
    const res = await window.gauntler.sanitize(r.file.path);
    if (!res) { setSafeMsg(null); return; }
    if (!res.ok) setSafeMsg({ ok: false, text: t('Copia sicura non creata: {msg}', { msg: res.error || res.reason }) });
    else setSafeMsg({ ok: true, text: t('Copia sicura salvata in {path}', { path: res.outPath }) + ` (${res.after ? t('{score}/100 dopo la verifica', { score: res.after.score }) : t('verificata')}) — ${res.actions.length ? res.actions.join(' · ') : t('nessun contenuto attivo trovato')}` });
  };
  const save = async (format) => {
    const result = JSON.parse(JSON.stringify(r, (k, v) => (k === 'source' || k === 'strings' ? undefined : v)));
    await window.gauntler.saveReport({ name: r.file.name, result, format });
  };
  const tabs = [
    ['overview', t('Panoramica')],
    ['issues', t('Problemi'), r.findings.filter((f) => f.severity !== 'info').length],
    hasText && ['code', t('Codice'), flaggedLines || null],
    isBin && ['strings', t('Stringhe'), r.strings.length],
    (r.machineCode?.listing?.length || r.machineCode?.shellcode?.length) && ['asm', 'Assembly'],
    ['checks', t('Controlli'), r.totals.checks],
    (r.children?.length || r.extracted?.length || r.archiveEntries?.length) && ['contents', t('Contenuti'), (r.children?.length || 0) + (r.extracted?.length || 0) || null],
    r.iocs && Object.values(r.iocs).some((l) => l.length) && ['network', t('Rete')],
    r.metadata && Object.keys(r.metadata).length && ['meta', t('Metadati')],
    ['tech', t('Dettagli tecnici')],
  ].filter(Boolean);

  return (
    <div className="report">
      {stack.length > 1 && (
        <nav className="crumbs">
          {stack.map((s, i) => (
            <React.Fragment key={i}>
              {i > 0 && <Icon name="chevronRight" />}
              <button className={i === stack.length - 1 ? 'on' : ''} onClick={() => { setStack(stack.slice(0, i + 1)); setTab('overview'); }}>{s.file.name} <ScoreChip score={s.overall.score} /></button>
            </React.Fragment>
          ))}
        </nav>
      )}
      <section className="hero" style={{ '--accent': color }}>
        <ScoreRing score={r.overall.score} />
        <div className="hero-text">
          <div className="hero-top">
            <span className="verdict" style={{ '--c': color }}>{r.overall.verdict}</span>
            <span className="hero-kicker">{t('Valutazione complessiva')}</span>
          </div>
          <h1 title={r.file.path || r.file.name}>{r.file.name}</h1>
          <div className="file-meta">
            <span>{r.file.type.label}</span>
            <span>{r.file.sizeHuman}</span>
            {r.file.origin && <span>{t('origine: {o}', { o: r.file.origin })}</span>}
          </div>
          <p className="advice">{r.overall.advice}</p>
          {['critical', 'high', 'medium', 'low'].some((s) => r.overall.counts[s] > 0) && (
            <div className="counts">
              {['critical', 'high', 'medium', 'low'].map((s) => r.overall.counts[s] > 0 && (
                <button key={s} className="count" onClick={() => setTab('issues')}><i className="dot" style={{ '--c': SEVERITY[s].color }} /><b>{r.overall.counts[s]}</b> {getLanguage() === 'de' ? t(SEVERITY[s].label) : t(SEVERITY[s].label).toLowerCase()}</button>
              ))}
            </div>
          )}
          {safeMsg && <p className={`notice ${safeMsg.ok ? '' : 'danger'}`}><Icon name={safeMsg.ok ? 'shieldCheck' : 'alert'} />{safeMsg.text}</p>}
        </div>
        <div className="hero-actions">
          {r.file.path && stack.length === 1 && <button className="btn" onClick={sanitize} title={t('Ricostruisce il file senza contenuti attivi e lo ri-verifica')}><Icon name="shieldCheck" />{t('Crea copia sicura')}</button>}
          <div className="row">
            <button className="btn btn-ghost" onClick={() => save(settings.exportFormat)} title={t('Esporta il report in {f}', { f: EXPORTS[settings.exportFormat] })}><Icon name="download" />{t('Report')} {EXPORTS[settings.exportFormat]}</button>
            <select className="select" value="" onChange={(e) => e.target.value && save(e.target.value)} title={t('Esporta in altri formati')} aria-label={t('Esporta in altri formati')}>
              <option value="">{t('Altro…')}</option>
              {Object.entries(EXPORTS).filter(([k]) => k !== settings.exportFormat).map(([k, l]) => <option key={k} value={k}>{l}</option>)}
            </select>
          </div>
          {r.file.path && <button className="btn btn-ghost" onClick={() => window.gauntler.reveal(r.file.path)}><Icon name="folder" />{t('Mostra nella cartella')}</button>}
        </div>
      </section>

      <nav className="tabs" role="tablist">
        {tabs.map(([id, label, n]) => <button key={id} role="tab" aria-selected={tab === id} className={tab === id ? 'on' : ''} onClick={() => setTab(id)}>{label}{n != null && <span className="tab-n">{fmtNum(n)}</span>}</button>)}
      </nav>

      {tab === 'overview' && <Overview r={r} setTab={setTab} setCat={setCat} onJump={onJump} onChild={onChild} />}
      {tab === 'issues' && <Issues r={r} cat={cat} setCat={setCat} onJump={onJump} onChild={onChild} />}
      {tab === 'code' && <CodeViewer r={r} jump={jump} />}
      {tab === 'strings' && <StringsViewer r={r} />}
      {tab === 'asm' && <Disasm r={r} />}
      {tab === 'checks' && <Checks r={r} />}
      {tab === 'contents' && <Contents r={r} onChild={onChild} onJump={onJump} />}
      {tab === 'network' && <Network r={r} />}
      {tab === 'meta' && <section className="tech"><div className="panel"><h3><Icon name="tag" /> {t('Metadati e provenienza')}</h3><KV data={r.metadata} /></div></section>}
      {tab === 'tech' && <Tech r={r} />}
    </div>
  );
}
