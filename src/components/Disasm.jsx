// Creato da anvex2012
import React, { useState } from 'react';
import { VirtualList, KV } from './ui.jsx';
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
          <div key={i} style={style} className="code-row" title={`Offset nel file 0x${(r.off || 0).toString(16)}`}>
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
        <h3><Icon name="binary" /> Codice macchina</h3>
        <KV data={cat?.info || {}} />
      </div>
      {mc.functions?.length > 0 ? (
        <div className="panel">
          <h3><Icon name="cpu" /> Funzioni più complesse<span className="grow" /><span className="hint">prime {Math.min(15, mc.functions.length)}</span></h3>
          <table className="tbl plain">
            <thead><tr><th>Indirizzo</th><th>Nome</th><th>Blocchi</th><th>Byte</th><th>Cicli</th><th>Complessità</th></tr></thead>
            <tbody>{mc.functions.slice(0, 15).map((f) => (
              <tr key={f.address}><td className="mono">{f.address}</td><td className="mono nowrap" title={f.name}>{f.name}</td><td className="num">{f.blocks}</td><td className="num">{f.size}</td><td className="num">{f.loops}</td><td className="num">{f.cyclomatic}</td></tr>
            ))}</tbody>
          </table>
        </div>
      ) : mc.shellcode?.length > 0 && (
        <div className="panel">
          <h3><Icon name="shieldAlert" /> Shellcode individuato</h3>
          <table className="tbl plain">
            <thead><tr><th>Offset</th><th>Modo</th><th>Affidabilità</th><th>Tecniche riconosciute</th></tr></thead>
            <tbody>{mc.shellcode.map((s, i) => (
              <tr key={i}><td className="mono">0x{s.start.toString(16)}</td><td>{s.bits}-bit</td><td>{s.confidence === 'high' ? 'Alta' : 'Media'}</td><td className="small">{(s.behaviours || []).map((b) => BEHAVIOUR[b] || b).join(', ')}</td></tr>
            ))}</tbody>
          </table>
        </div>
      )}
      {mc.xor?.length > 0 && (
        <div className="panel">
          <h3><Icon name="key" /> Contenuti cifrati con XOR/ADD <span className="hint">chiave recuperata</span></h3>
          <table className="tbl plain">
            <thead><tr><th>Operazione</th><th>Chiave</th><th>Offset</th><th>Contenuto riconosciuto</th><th>Anteprima</th></tr></thead>
            <tbody>{mc.xor.map((x, i) => (
              <tr key={i}><td>{x.op.toUpperCase()}</td><td className="mono">0x{x.key}</td><td className="mono">0x{x.offset.toString(16)}</td><td>{x.plaintext}</td><td className="mono small wrap muted">{x.sample}</td></tr>
            ))}</tbody>
          </table>
        </div>
      )}
      <div className="panel">
        <h3>
          <Icon name="code" /> Listato assembly
          <span className="grow" />
          <select className="select" value={which} onChange={(e) => setWhich(e.target.value === 'main' ? 'main' : +e.target.value)} aria-label="Codice da visualizzare">
            {mc.listing && <option value="main">Dal punto di avvio</option>}
            {(mc.shellcode || []).map((s, i) => <option key={i} value={i}>Shellcode a 0x{s.start.toString(16)} ({s.bits}-bit)</option>)}
          </select>
          <div className="seg" role="group" aria-label="Formato dei byte">
            <button className={!binary ? 'on' : ''} aria-pressed={!binary} onClick={() => setBinary(false)}>Esadecimale</button>
            <button className={binary ? 'on' : ''} aria-pressed={binary} onClick={() => setBinary(true)}>Binario</button>
          </div>
        </h3>
        {rows?.length ? <Listing rows={rows} binary={binary} /> : <p className="muted">Nessun listato disponibile per questo file.</p>}
      </div>
    </section>
  );
}
