// Creato da anvex2012
import React, { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { LEVEL_COLOR, levelOf, SEVERITY } from '../lib.js';
import Icon from './Icon.jsx';
import { t } from '../i18n.js';

/** Virtualized list: renders only the visible rows (millions of lines without slowdowns) */
export function VirtualList({ count, rowHeight = 20, render, scrollTo, className = '', overscan = 20, onScroll, innerWidth }) {
  const ref = useRef(null);
  const [h, setH] = useState(600);
  const [top, setTop] = useState(0);
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setH(el.clientHeight));
    ro.observe(el);
    setH(el.clientHeight);
    return () => ro.disconnect();
  }, []);
  useEffect(() => {
    if (scrollTo == null || !ref.current) return;
    const el = ref.current;
    const y = scrollTo.index * rowHeight;
    if (y < el.scrollTop || y > el.scrollTop + el.clientHeight - rowHeight * 2) el.scrollTop = Math.max(0, y - el.clientHeight / 3);
  }, [scrollTo, rowHeight]);
  const start = Math.max(0, Math.floor(top / rowHeight) - overscan);
  const end = Math.min(count, Math.ceil((top + h) / rowHeight) + overscan);
  const rows = [];
  for (let i = start; i < end; i++) rows.push(render(i, { position: 'absolute', top: i * rowHeight, height: rowHeight, left: 0, right: innerWidth ? undefined : 0, minWidth: '100%' }));
  return (
    <div ref={ref} className={`vlist ${className}`} onScroll={(e) => { setTop(e.currentTarget.scrollTop); onScroll && onScroll(e.currentTarget); }}>
      <div style={{ height: count * rowHeight, position: 'relative', width: innerWidth }}>{rows}</div>
    </div>
  );
}

export function ScoreRing({ score, size = 112, stroke = 7, label = true }) {
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const color = LEVEL_COLOR[levelOf(score)];
  return (
    <div className="ring" style={{ width: size, height: size }} role="img" aria-label={t('Punteggio {n} su 100', { n: score })}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--track)" strokeWidth={stroke} />
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth={stroke} strokeLinecap="round"
          strokeDasharray={c} strokeDashoffset={c * (1 - score / 100)} transform={`rotate(-90 ${size / 2} ${size / 2})`}
          style={{ transition: 'stroke-dashoffset .8s cubic-bezier(.2,.8,.2,1)' }} />
      </svg>
      {label && (
        <div className="ring-label">
          <span className="ring-score" style={{ fontSize: size * 0.3 }}>{score}</span>
          <span className="ring-max" style={{ fontSize: Math.max(10, size * 0.095) }}>{t('su 100')}</span>
        </div>
      )}
    </div>
  );
}

export function ScoreChip({ score }) {
  return <span className={`chip chip-${levelOf(score)}`} title={t('{n} su 100', { n: score })}>{score}</span>;
}

export function SevBadge({ sev }) {
  const s = SEVERITY[sev] || SEVERITY.info;
  return <span className="sev" style={{ '--c': s.color }}>{t(s.label)}</span>;
}

/** Radar chart of the per-criterion scores */
export function Radar({ cats, size = 300, onPick }) {
  const n = cats.length;
  if (n < 3) return null;
  const c = size / 2, R = size / 2 - 78;
  const pt = (i, v) => {
    const a = -Math.PI / 2 + (i / n) * 2 * Math.PI;
    return [c + Math.cos(a) * R * v, c + Math.sin(a) * R * v];
  };
  const poly = cats.map((k, i) => pt(i, Math.max(0.04, k.score / 100)).join(',')).join(' ');
  return (
    <svg className="radar" viewBox={`-20 0 ${size + 40} ${size}`} style={{ overflow: 'visible' }} role="img" aria-label={t('Grafico radar dei punteggi')}>
      {[0.25, 0.5, 0.75, 1].map((g) => <polygon key={g} points={cats.map((_, i) => pt(i, g).join(',')).join(' ')} className="radar-grid" />)}
      {cats.map((_, i) => { const [x, y] = pt(i, 1); return <line key={i} x1={c} y1={c} x2={x} y2={y} className="radar-grid" />; })}
      <polygon points={poly} className="radar-area" />
      {cats.map((k, i) => {
        const [x, y] = pt(i, Math.max(0.04, k.score / 100));
        const [lx, ly] = pt(i, 1.2);
        return (
          <g key={k.id} onClick={() => onPick && onPick(k.id)} style={{ cursor: 'pointer' }}>
            <circle cx={x} cy={y} r="4.5" fill={LEVEL_COLOR[levelOf(k.score)]} />
            <text x={lx} y={ly} textAnchor={Math.abs(lx - c) < 8 ? 'middle' : lx > c ? 'start' : 'end'} dominantBaseline="middle" className="radar-label">
              {k.short || k.name} <tspan fill={LEVEL_COLOR[levelOf(k.score)]} fontWeight="700">{k.score}</tspan>
            </text>
          </g>
        );
      })}
    </svg>
  );
}

export function EntropyChart({ profile, height = 140 }) {
  if (!profile?.length) return null;
  const W = 800, H = height;
  const pts = profile.map((v, i) => [(i / Math.max(1, profile.length - 1)) * W, H - (v / 8) * H]);
  const line = pts.map((p) => p.join(',')).join(' ');
  return (
    <div className="chart-wrap">
      <div className="chart-y"><span>8</span><span>4</span><span>0</span></div>
      <svg className="entropy" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" role="img" aria-label={t('Profilo di entropia')}>
        <line x1="0" x2={W} y1={H - (7.2 / 8) * H} y2={H - (7.2 / 8) * H} className="entropy-th" />
        <polygon points={`0,${H} ${line} ${W},${H}`} className="entropy-area" />
        <polyline points={line} className="entropy-line" />
      </svg>
    </div>
  );
}

export function Histogram({ data, height = 110 }) {
  if (!data?.length) return null;
  return (
    <div className="histo" style={{ height }} role="img" aria-label={t('Istogramma dei byte')}>
      {data.map((v, i) => <span key={i} style={{ height: `${Math.max(v * 100, v ? 1.5 : 0)}%` }} title={`0x${i.toString(16).padStart(2, '0')} (${i >= 32 && i < 127 ? String.fromCharCode(i) : '·'}): ${t('{p}% del massimo', { p: (v * 100).toFixed(1) })}`} className={i >= 32 && i < 127 ? 'pr' : ''} />)}
    </div>
  );
}

export function HexView({ b64, rows = 32 }) {
  if (!b64) return null;
  const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  const out = [];
  for (let r = 0; r < Math.min(rows, Math.ceil(bytes.length / 16)); r++) {
    const sl = bytes.slice(r * 16, r * 16 + 16);
    out.push(
      <div key={r} className="hexrow">
        <span className="hexoff">{(r * 16).toString(16).padStart(8, '0')}</span>
        <span className="hexbytes">{Array.from(sl, (b) => b.toString(16).padStart(2, '0')).join(' ')}</span>
        <span className="hexasc">{Array.from(sl, (b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '·')).join('')}</span>
      </div>,
    );
  }
  return <div className="hex mono">{out}</div>;
}

export function Copy({ text, label = 'Copia' }) {
  const [ok, setOk] = useState(false);
  return (
    <button className="btn-mini" onClick={() => { navigator.clipboard.writeText(text); setOk(true); setTimeout(() => setOk(false), 1200); }}>
      <Icon name={ok ? 'check' : 'copy'} />{ok ? 'Copiato' : label}
    </button>
  );
}

export function Stat({ label, value, hint }) {
  return (
    <div className="stat" title={hint}>
      <div className="stat-v">{value}</div>
      <div className="stat-l">{label}</div>
    </div>
  );
}

export function KV({ data }) {
  const e = Object.entries(data || {});
  if (!e.length) return <p className="muted small">{t('Nessun dato.')}</p>;
  return (
    <table className="tbl kv"><tbody>
      {e.map(([k, v]) => <tr key={k}><td>{k}</td><td className="wrap">{typeof v === 'object' ? JSON.stringify(v) : String(v)}</td></tr>)}
    </tbody></table>
  );
}
