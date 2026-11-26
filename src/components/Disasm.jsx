// Creato da anvex2012
import React, { useState } from 'react';
import { VirtualList, KV } from './ui.jsx';
import { t } from '../i18n.js';
import Icon from './Icon.jsx';
import { codeRow, useSettings } from '../settings.js';

const hex = (n) => '0x' + Number(n).toString(16).padStart(8, '0');
const BEHAVIOUR = {
  getpc: 'auto-localizzazione', peb: 'ricerca librerie (PEB)', hashloop: 'hash dei nomi', apihash: 'API tramite hash', hellsgate: 'syscall dirette',
  syscall: 'chiamate di sistema', stackstr: 'stringhe sullo stack', decoder: 'ciclo di decifratura', antidebug: 'anti-debug', antivm: 'anti-VM',
  rdtsc: 'controllo dei tempi', nopsled: 'NOP sled', privileged: 'istruzioni privilegiate', crypto: 'istruzioni crittografiche',
};

function Listing({ rows, binary }) {
  const rowHeight = codeRow(useSettings().settings);
  const flat = [];
  for (const r of rows || []) {
    if (r.gap) { flat.push({ sep: true }); continue; }
    if (r.label) flat.push({ label: r.label });
    flat.push({ ...r, label: null });
  }
  const fmt = (r) => (binary && r.bin ? r.bin : r.hex.replace(/(..)/g, '$1 ').trim());
  const width = Math.min(binary ? 72 : 45, flat.reduce((m, r) => (r.hex ? Math.max(m, fmt(r).length) : m), 0));
  return (
    <VirtualList
      className="asm"
      count={flat.length}
      rowHeight={rowHeight}
      render={(i, style) => {
        const r = flat[i];
        if (r.sep) return <div key={i} style={style} className="code-row" />;
        if (r.label) return <div key={i} style={style} className="code-row asm-label">{r.label}:</div>;
        return (
          <div key={i} style={style} className="code-row" title={t('Offset nel file 0x{off}', { off: (r.off || 0).toString(16) })}>
            <span className="asm-addr">{hex(r.va)}  </span>
            <span className="asm-bytes">{fmt(r).padEnd(width)}  </span>
            <span className={r.flow && r.flow !== 'seq' ? `asm-flow-${r.flow}` : undefined}>{r.text}</span>
            {r.note && <span className="asm-note">    ; {r.note}</span>}
          </div>
        );
      }}
    />
  );
}

export default function Disasm({ r }) {
  const mc = r.machineCode || {};
  const [binary, setBinary] = useState(false);
  const [which, setWhich] = useState(mc.listing ? 'main' : 0);
  const rows = which === 'main' ? mc.listing : mc.shellcode?.[which]?.listing;
  const cat = r.categories.find((c) => c.id === 'machinecode');
  return (
    <section className="tech">
      <div className="panel">
        <h3><Icon name="binary" /> {t('Codice macchina')}</h3>
        <KV data={cat?.info || {}} />
      </div>
      {mc.functions?.length > 0 ? (
        <div className="panel">
          <h3><Icon name="cpu" /> {t('Funzioni più complesse')}<span className="grow" /><span className="hint">{t('prime {n}', { n: Math.min(15, mc.functions.length) })}</span></h3>
          <table className="tbl plain">
            <thead><tr><th>{t('Indirizzo')}</th><th>{t('Nome')}</th><th>{t('Blocchi')}</th><th>Byte</th><th>{t('Cicli')}</th><th>{t('Complessità')}</th></tr></thead>
            <tbody>{mc.functions.slice(0, 15).map((f) => (
              <tr key={f.address}><td className="mono">{f.address}</td><td className="mono nowrap" title={f.name}>{f.name}</td><td className="num">{f.blocks}</td><td className="num">{f.size}</td><td className="num">{f.loops}</td><td className="num">{f.cyclomatic}</td></tr>
            ))}</tbody>
          </table>
        </div>
      ) : mc.shellcode?.length > 0 && (
        <div className="panel">
          <h3><Icon name="shieldAlert" /> {t('Shellcode individuato')}</h3>
          <table className="tbl plain">
            <thead><tr><th>{t('Offset')}</th><th>{t('Modo')}</th><th>{t('Affidabilità')}</th><th>{t('Tecniche riconosciute')}</th></tr></thead>
            <tbody>{mc.shellcode.map((s, i) => (
              <tr key={i}><td className="mono">0x{s.start.toString(16)}</td><td>{s.bits}-bit</td><td>{s.confidence === 'high' ? t('Alta') : t('Media')}</td><td className="small">{(s.behaviours || []).map((b) => t(BEHAVIOUR[b] || b)).join(', ')}</td></tr>
            ))}</tbody>
          </table>
        </div>
      )}
      {mc.xor?.length > 0 && (
        <div className="panel">
          <h3><Icon name="key" /> {t('Contenuti cifrati con XOR/ADD')} <span className="hint">{t('chiave recuperata')}</span></h3>
          <table className="tbl plain">
            <thead><tr><th>{t('Operazione')}</th><th>{t('Chiave')}</th><th>{t('Offset')}</th><th>{t('Contenuto riconosciuto')}</th><th>{t('Anteprima')}</th></tr></thead>
            <tbody>{mc.xor.map((x, i) => (
              <tr key={i}><td>{x.op.toUpperCase()}</td><td className="mono">0x{x.key}</td><td className="mono">0x{x.offset.toString(16)}</td><td>{x.plaintext}</td><td className="mono small wrap muted">{x.sample}</td></tr>
            ))}</tbody>
          </table>
        </div>
      )}
      <div className="panel">
        <h3>
          <Icon name="code" /> {t('Listato assembly')}
          <span className="grow" />
          <select className="select" value={which} onChange={(e) => setWhich(e.target.value === 'main' ? 'main' : +e.target.value)} aria-label={t('Codice da visualizzare')}>
            {mc.listing && <option value="main">{t('Dal punto di avvio')}</option>}
            {(mc.shellcode || []).map((s, i) => <option key={i} value={i}>{t('Shellcode a 0x{at} ({bits}-bit)', { at: s.start.toString(16), bits: s.bits })}</option>)}
          </select>
          <div className="seg" role="group" aria-label={t('Formato dei byte')}>
            <button className={!binary ? 'on' : ''} aria-pressed={!binary} onClick={() => setBinary(false)}>{t('Esadecimale')}</button>
            <button className={binary ? 'on' : ''} aria-pressed={binary} onClick={() => setBinary(true)}>{t('Binario')}</button>
          </div>
        </h3>
        {rows?.length ? <Listing rows={rows} binary={binary} /> : <p className="muted">{t('Nessun listato disponibile per questo file.')}</p>}
      </div>
    </section>
  );
}
