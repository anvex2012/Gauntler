// Created by anvex2012
import React, { useEffect, useMemo, useRef, useState } from 'react';
import { VirtualList, SevBadge } from './ui.jsx';
import { t } from '../i18n.js';
import Icon from './Icon.jsx';
import { SEV_RANK, SEVERITY, fmtNum } from '../lib.js';
import { codeRow, useSettings } from '../settings.js';

const useRow = () => codeRow(useSettings().settings);
const MAX_COLS = 3000;
const SEV_VAR = { critical: 'var(--critical)', high: 'var(--high)', medium: 'var(--medium)', low: 'var(--low)', info: 'var(--muted)' };

function Heatmap({ total, marks, onJump, view }) {
  const ref = useRef(null);
  useEffect(() => {
    const c = ref.current;
    if (!c) return;
    const h = c.clientHeight, w = c.clientWidth;
    c.width = w * 2; c.height = h * 2;
    const g = c.getContext('2d');
    g.scale(2, 2);
    g.clearRect(0, 0, w, h);
    const css = getComputedStyle(document.documentElement);
    const color = (s) => css.getPropertyValue(`--${s === 'info' ? 'muted' : s}`).trim() || '#888';
    const sorted = [...marks].sort((a, b) => SEV_RANK[b.sev] - SEV_RANK[a.sev]);
    for (const m of sorted) {
      const y = Math.floor((m.i / Math.max(1, total)) * h);
      g.fillStyle = color(m.sev);
      g.fillRect(0, y, w, Math.max(2, h / Math.max(1, total)));
    }
    if (view) {
      g.fillStyle = 'rgba(127,127,127,.18)';
      g.fillRect(0, (view.from / total) * h, w, Math.max(4, ((view.to - view.from) / total) * h));
    }
  }, [total, marks, view]);
  return (
    <canvas ref={ref} className="heatmap" title={t('Mappa del file: ogni tacca è una riga segnalata. Clicca per saltare.')}
      onClick={(e) => { const r = e.currentTarget.getBoundingClientRect(); onJump(Math.floor(((e.clientY - r.top) / r.height) * total)); }} />
  );
}

function TagList({ ann }) {
  if (!ann) return <p className="muted small">{t('Seleziona una riga evidenziata per vedere la spiegazione.')}</p>;
  const tags = [...ann.tags].sort((a, b) => SEV_RANK[a.sev] - SEV_RANK[b.sev]);
  return (
    <div className="taglist">
      <div className="tag-head mono">{ann.line != null ? `Riga ${ann.line}` : `Offset 0x${ann.offset.toString(16)}`}</div>
      <pre className="tag-code mono">{ann.text}</pre>
      {tags.map((t) => (
        <div key={t.id} className="tag">
          <div className="tag-top"><SevBadge sev={t.sev} /><b>{t.label}</b></div>
          {t.group && <div className="tag-group">{t.group}</div>}
          <p>{t.desc}</p>
        </div>
      ))}
    </div>
  );
}

/** Text viewer (file, macros, PDF streams, decoded payloads) with every line annotated */
export function CodeViewer({ r, jump }) {
  const ROW = useRow();
  const sources = useMemo(() => {
    const s = [];
    if (r.source != null) s.push({ key: '', label: `${r.file.name} ${t('(file principale)')}`, text: r.source });
    for (const e of r.extracted || []) if (e.text != null) s.push({ key: e.label, label: e.label, text: e.text, kind: e.kind });
    return s;
  }, [r]);
  const [srcKey, setSrcKey] = useState(sources[0]?.key ?? null);
  const [onlyFlagged, setOnlyFlagged] = useState(false);
  const [minSev, setMinSev] = useState('low');
  const [q, setQ] = useState('');
  const [sel, setSel] = useState(null);
  const [scrollTo, setScrollTo] = useState(null);
  const [view, setView] = useState(null);

  useEffect(() => {
    if (!jump) return;
    const key = jump.source || '';
    if (sources.some((s) => s.key === key)) setSrcKey(key);
    setOnlyFlagged(false);
    setTimeout(() => { setSel(jump.line); setScrollTo({ index: jump.line - 1, t: Date.now() }); }, 30);
  }, [jump, sources]);

  const src = sources.find((s) => s.key === srcKey) || sources[0];
  const lines = useMemo(() => (src ? src.text.split('\n') : []), [src]);
  const ann = useMemo(() => {
    const m = new Map();
    for (const a of r.lines || []) if ((a.source || '') === (src?.key ?? '') && a.line != null) m.set(a.line, a);
    return m;
  }, [r, src]);
  const visibleAnn = useMemo(() => [...ann.values()].filter((a) => SEV_RANK[a.sev] <= SEV_RANK[minSev]), [ann, minSev]);
  const rows = useMemo(() => (onlyFlagged ? visibleAnn.map((a) => a.line - 1).sort((a, b) => a - b) : null), [onlyFlagged, visibleAnn]);
  const count = rows ? rows.length : lines.length;
  const maxLen = useMemo(() => Math.min(MAX_COLS, lines.reduce((a, l) => Math.max(a, l.length), 0)), [lines]);

  const find = (dir = 1) => {
    if (!q) return;
    const ql = q.toLowerCase();
    const cur = sel ? sel - 1 : -1;
    for (let k = 1; k <= lines.length; k++) {
      const i = (cur + dir * k + lines.length) % lines.length;
      if (lines[i].toLowerCase().includes(ql)) { setOnlyFlagged(false); setSel(i + 1); setScrollTo({ index: i, t: Date.now() }); return; }
    }
  };
  const step = (dir) => {
    const list = visibleAnn.map((a) => a.line).sort((a, b) => a - b);
    if (!list.length) return;
    const cur = sel || 0;
    const next = dir > 0 ? list.find((l) => l > cur) ?? list[0] : [...list].reverse().find((l) => l < cur) ?? list[list.length - 1];
    setSel(next);
    setScrollTo({ index: rows ? rows.indexOf(next - 1) : next - 1, t: Date.now() });
  };

  const marks = useMemo(() => visibleAnn.map((a) => ({ i: rows ? rows.indexOf(a.line - 1) : a.line - 1, sev: a.sev })), [visibleAnn, rows]);
  const counts = useMemo(() => { const c = {}; for (const a of ann.values()) c[a.sev] = (c[a.sev] || 0) + 1; return c; }, [ann]);
  if (!sources.length) {
    return <p className="muted">{t('Il testo non è disponibile in questa vista (file binario o troppo grande). Le righe segnalate sono comunque elencate nella scheda "Problemi".')}</p>;
  }

  return (
    <div className="codeview">
      <div className="code-toolbar">
        <select value={src?.key} onChange={(e) => { setSrcKey(e.target.value); setSel(null); }} className="select" title={t('Contenuto da visualizzare')}>
          {sources.map((s) => {
            const n = (r.lines || []).filter((a) => (a.source || '') === s.key && a.sev !== 'info').length;
            return <option key={s.key} value={s.key}>{s.label}{n ? ' — ' + t('{n} righe segnalate', { n }) : ''}</option>;
          })}
        </select>
        <div className="seg">
          {['critical', 'high', 'medium', 'low', 'info'].map((s) => (
            <button key={s} className={SEV_RANK[s] <= SEV_RANK[minSev] ? 'on' : ''} onClick={() => setMinSev(s)} title={t('Mostra fino al livello {s}', { s: t(SEVERITY[s]?.label || s) })}>
              <i style={{ background: SEV_VAR[s] }} />{counts[s] || 0}
            </button>
          ))}
        </div>
        <label className="toggle"><input type="checkbox" checked={onlyFlagged} onChange={(e) => setOnlyFlagged(e.target.checked)} /> {t('Solo righe segnalate')}</label>
        <button className="btn-mini" onClick={() => step(-1)} title={t('Segnalazione precedente')} aria-label={t('Segnalazione precedente')}><Icon name="chevronUp" /></button>
        <button className="btn-mini" onClick={() => step(1)} title={t('Segnalazione successiva')} aria-label={t('Segnalazione successiva')}><Icon name="chevronDown" /></button>
        <input className="search sm" placeholder={t('Cerca nel testo… (Invio)')} value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && find(e.shiftKey ? -1 : 1)} />
        <span className="muted small">{fmtNum(lines.length)} righe</span>
      </div>
      <div className="code-body">
        <div className="code-main">
          <VirtualList
            className="code-list mono"
            count={count}
            rowHeight={ROW}
            scrollTo={scrollTo}
            innerWidth={`calc(${maxLen + 12}ch + 70px)`}
            onScroll={(el) => setView({ from: el.scrollTop / ROW, to: (el.scrollTop + el.clientHeight) / ROW })}
            render={(i, style) => {
              const li = rows ? rows[i] : i;
              const a = ann.get(li + 1);
              const show = a && SEV_RANK[a.sev] <= SEV_RANK[minSev];
              const text = lines[li] ?? '';
              const hit = q && text.toLowerCase().includes(q.toLowerCase());
              return (
                <div key={li} style={style} className={`code-row ${show ? 'flag flag-' + a.sev : ''} ${sel === li + 1 ? 'sel' : ''} ${hit ? 'hit' : ''}`} onClick={() => setSel(li + 1)}>
                  <span className="ln">{li + 1}</span>
                  <span className="gut" style={show ? { background: SEV_VAR[a.sev] } : null} />
                  <span className="code-text">{text.length > MAX_COLS ? text.slice(0, MAX_COLS) + ` … (+${fmtNum(text.length - MAX_COLS)} caratteri)` : text || ' '}</span>
                  {show && <span className="row-tags">{a.tags.slice(0, 3).map((t) => t.label).join(' · ')}{a.tags.length > 3 ? ` +${a.tags.length - 3}` : ''}</span>}
                </div>
              );
            }}
          />
          <Heatmap total={count} marks={marks} view={view} onJump={(i) => setScrollTo({ index: i, t: Date.now() })} />
        </div>
        <aside className="code-side"><TagList ann={sel ? ann.get(sel) : null} /></aside>
      </div>
    </div>
  );
}

/** Every printable string extracted from a binary, with flagged strings highlighted */
export function StringsViewer({ r }) {
  const ROW = useRow();
  const strs = r.strings || [];
  const [q, setQ] = useState('');
  const [onlyFlagged, setOnlyFlagged] = useState(true);
  const [enc, setEnc] = useState('all');
  const [sel, setSel] = useState(null);
  const flagged = useMemo(() => {
    const anns = (r.lines || []).filter((a) => a.offset != null && !a.source).sort((a, b) => a.offset - b.offset);
    const map = new Map();
    let j = 0;
    for (let i = 0; i < strs.length; i++) {
      const s = strs[i];
      const end = s.o + s.s.length * (s.e === 'u' ? 2 : 1);
      while (j < anns.length && anns[j].offset < s.o) j++;
      let k = j;
      while (k < anns.length && anns[k].offset < end) {
        const prev = map.get(i);
        map.set(i, prev ? { ...prev, tags: [...prev.tags, ...anns[k].tags], sev: SEV_RANK[anns[k].sev] < SEV_RANK[prev.sev] ? anns[k].sev : prev.sev } : anns[k]);
        k++;
      }
    }
    return map;
  }, [r, strs]);
  const idx = useMemo(() => {
    const ql = q.toLowerCase();
    const out = [];
    for (let i = 0; i < strs.length; i++) {
      if (onlyFlagged && !flagged.has(i)) continue;
      if (enc !== 'all' && strs[i].e !== enc) continue;
      if (ql && !strs[i].s.toLowerCase().includes(ql)) continue;
      out.push(i);
    }
    return out;
  }, [strs, flagged, q, onlyFlagged, enc]);
  if (!strs.length) return <p className="muted">{t('Nessuna stringa disponibile.')}</p>;
  const cur = sel != null ? flagged.get(sel) : null;
  return (
    <div className="codeview">
      <div className="code-toolbar">
        <input className="search sm" placeholder={t('Filtra stringhe…')} value={q} onChange={(e) => setQ(e.target.value)} />
        <select className="select" value={enc} onChange={(e) => setEnc(e.target.value)}><option value="all">{t('ASCII + UTF-16')}</option><option value="a">{t('Solo ASCII')}</option><option value="u">{t('Solo UTF-16')}</option></select>
        <label className="toggle"><input type="checkbox" checked={onlyFlagged} onChange={(e) => setOnlyFlagged(e.target.checked)} /> {t('Solo stringhe segnalate ({n})', { n: fmtNum(flagged.size) })}</label>
        <span className="muted small">{fmtNum(idx.length)} di {fmtNum(strs.length)} stringhe</span>
      </div>
      <div className="code-body">
        <div className="code-main">
          <VirtualList className="code-list mono" count={idx.length} rowHeight={ROW} render={(i, style) => {
            const k = idx[i], s = strs[k], a = flagged.get(k);
            return (
              <div key={k} style={style} className={`code-row ${a ? 'flag flag-' + a.sev : ''} ${sel === k ? 'sel' : ''}`} onClick={() => setSel(k)}>
                <span className="ln wide">{s.o.toString(16).padStart(8, '0')}</span>
                <span className="gut" style={a ? { background: SEV_VAR[a.sev] } : null} />
                <span className="enc">{s.e === 'u' ? 'U16' : 'ASC'}</span>
                <span className="code-text">{s.s.length > 600 ? s.s.slice(0, 600) + '…' : s.s}</span>
                {a && <span className="row-tags">{[...new Set(a.tags.map((t) => t.label))].slice(0, 3).join(' · ')}</span>}
              </div>
            );
          }} />
        </div>
        <aside className="code-side"><TagList ann={cur ? { ...cur, text: strs[sel].s } : null} /></aside>
      </div>
    </div>
  );
}
