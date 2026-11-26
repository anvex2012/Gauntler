// Created by anvex2012
import React, { useEffect, useRef, useState } from 'react';
import Icon from './Icon.jsx';
import { OPTIONS, DEFAULTS, useSettings } from '../settings.js';
import { t, useLanguage } from '../i18n.js';

const SECTIONS = [
  ['appearance', 'Aspetto', 'eye'],
  ['text', 'Testo e codice', 'fileText'],
  ['analysis', 'Analisi', 'shieldCheck'],
  ['report', 'Report', 'download'],
  ['system', 'Sistema', 'cpu'],
];
const LEVEL_NAMES = [['safe', 'Sicuro'], ['low', 'Basso'], ['medium', 'Sospetto'], ['high', 'Pericoloso'], ['critical', 'Malevolo']];

/** One labelled setting row: label + description on the left, control on the right */
function Row({ label, hint, children, id, stacked }) {
  return (
    <div className={`set-row ${stacked ? 'stacked' : ''}`}>
      <div className="set-text">
        <label className="set-label" htmlFor={id}>{label}</label>
        {hint && <p className="set-hint">{hint}</p>}
      </div>
      <div className="set-control">{children}</div>
    </div>
  );
}

/** Segmented control with radio semantics (arrow keys move between options) */
function Segmented({ value, options, onChange, label }) {
  const keyNav = (e, i) => {
    const d = e.key === 'ArrowRight' || e.key === 'ArrowDown' ? 1 : e.key === 'ArrowLeft' || e.key === 'ArrowUp' ? -1 : 0;
    if (!d) return;
    e.preventDefault();
    const n = options[(i + d + options.length) % options.length];
    onChange(n[0]);
    e.currentTarget.parentElement.children[(i + d + options.length) % options.length].focus();
  };
  return (
    <div className="seg seg-set" role="radiogroup" aria-label={label}>
      {options.map(([v, l], i) => (
        <button key={String(v)} role="radio" aria-checked={value === v} tabIndex={value === v ? 0 : -1} className={value === v ? 'on' : ''} onClick={() => onChange(v)} onKeyDown={(e) => keyNav(e, i)}>{t(l)}</button>
      ))}
    </div>
  );
}

function Switch({ checked, onChange, id, label }) {
  return (
    <button id={id} role="switch" aria-checked={checked} aria-label={label} className={`switch ${checked ? 'on' : ''}`} onClick={() => onChange(!checked)}>
      <span className="switch-knob" />
    </button>
  );
}

function Select({ id, value, options, onChange }) {
  return (
    <select id={id} className="select" value={String(value)} onChange={(e) => { const o = options.find((x) => String(Array.isArray(x) ? x[0] : x) === e.target.value); onChange(Array.isArray(o) ? o[0] : o); }}>
      {options.map((o) => { const [v, l] = Array.isArray(o) ? o : [o, o]; return <option key={String(v)} value={String(v)}>{typeof l === 'string' ? t(l) : l}</option>; })}
    </select>
  );
}

function Appearance({ s, set }) {
  const { lang, setLang, languages } = useLanguage();
  return (
    <>
      <Row label={t('Lingua')} hint={t('Lingua dell\'app e del comando gauntler nel terminale. I risultati già mostrati vengono tradotti subito.')} id="set-lang">
        <Select id="set-lang" value={lang} options={languages.map((l) => [l.code, l.name])} onChange={setLang} />
      </Row>
      <Row label={t('Tema')} hint={t('Segue il sistema oppure resta sempre chiaro o scuro. Vale anche per la finestra e i menu.')}>
        <Segmented label={t('Tema')} value={s.theme} options={OPTIONS.theme} onChange={(v) => set({ theme: v })} />
      </Row>
      <Row label={t('Colore d\'accento')} hint={t('Selezioni, collegamenti, schede attive e contorno di messa a fuoco.')}>
        <div className="swatches" role="radiogroup" aria-label={t('Colore d\'accento')}>
          {OPTIONS.accent.map(([v, l, hex]) => (
            <button key={v} role="radio" aria-checked={s.accent === v} aria-label={t(l)} title={t(l)} className={`swatch ${s.accent === v ? 'on' : ''}`} style={{ '--sw': hex }} onClick={() => set({ accent: v })}>
              {s.accent === v && <Icon name="check" size={12} strokeWidth={3} />}
            </button>
          ))}
        </div>
      </Row>
      <Row label={t('Pulsanti principali')} hint={t('Grafite sobrio, oppure lo stesso colore d\'accento.')}>
        <Segmented label={t('Pulsanti principali')} value={s.primary} options={OPTIONS.primary} onChange={(v) => set({ primary: v })} />
      </Row>
      <Row label={t('Colori dei livelli di rischio')} hint={t('La tavolozza per daltonici distingue i livelli anche con deuteranopia e protanopia; l\'alto contrasto rende i colori più netti.')} stacked>
        <Segmented label={t('Colori dei livelli')} value={s.levels} options={OPTIONS.levels} onChange={(v) => set({ levels: v })} />
        <div className="level-preview" aria-hidden>
          {LEVEL_NAMES.map(([l, n]) => <span key={l} style={{ '--c': `var(--${l})` }}><i className="dot" />{t(n)}</span>)}
        </div>
      </Row>
      <Row label={t('Densità')} hint={t('Compatta mostra più righe e pannelli nello stesso spazio.')}>
        <Segmented label={t('Densità')} value={s.density} options={OPTIONS.density} onChange={(v) => set({ density: v })} />
      </Row>
      <Row label={t('Animazioni')} hint={t('Ridotte elimina le transizioni non essenziali.')}>
        <Segmented label={t('Animazioni')} value={s.motion} options={OPTIONS.motion} onChange={(v) => set({ motion: v })} />
      </Row>
    </>
  );
}

function Text({ s, set }) {
  return (
    <>
      <Row label={t('Dimensione dell\'interfaccia')} hint={t('Ingrandisce testo, icone e controlli in modo uniforme.')}>
        <Segmented label={t('Dimensione dell\'interfaccia')} value={s.zoom} options={OPTIONS.zoom} onChange={(v) => set({ zoom: v })} />
      </Row>
      <Row label={t('Carattere')} hint={t('Arrotondato e Inter vengono usati solo se presenti nel sistema.')} id="set-font">
        <Select id="set-font" value={s.font} options={OPTIONS.font} onChange={(v) => set({ font: v })} />
      </Row>
      <Row label={t('Carattere del codice')} hint={t('Usato per codice, assembly, impronte e vista esadecimale.')} id="set-mono">
        <Select id="set-mono" value={s.mono} options={OPTIONS.mono} onChange={(v) => set({ mono: v })} />
      </Row>
      <Row label={t('Dimensione del codice')} hint={t('Righe del visualizzatore di codice e dell\'assembly.')} id="set-code">
        <Select id="set-code" value={s.codeSize} options={OPTIONS.codeSize.map((n) => [n, `${n} px`])} onChange={(v) => set({ codeSize: v })} />
      </Row>
      <div className="code-preview mono" aria-hidden>
        <div className="code-row flag-high"><span className="code-ln">12</span><span className="code-text">powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA…</span></div>
        <div className="code-row"><span className="code-ln">13</span><span className="code-text">const url = 'https://example.org/update';</span></div>
        <div className="code-row flag-low"><span className="code-ln">14</span><span className="code-text">require('child_process').execSync(cmd);</span></div>
      </div>
    </>
  );
}

function Analysis({ s, set }) {
  return (
    <>
      <Row label={t('File analizzati in parallelo')} hint={t('Più alto è più veloce sulle cartelle grandi, ma usa più memoria.')} id="set-conc">
        <Select id="set-conc" value={s.concurrency} options={OPTIONS.concurrency.map((n) => [n, String(n)])} onChange={(v) => set({ concurrency: v })} />
      </Row>
      <Row label={t('Dopo aver aggiunto i file, mostra')} id="set-after">
        <Select id="set-after" value={s.afterAdd} options={OPTIONS.afterAdd} onChange={(v) => set({ afterAdd: v })} />
      </Row>
      <Row label={t('Ordine dell\'elenco')} id="set-sort">
        <Select id="set-sort" value={s.sort} options={OPTIONS.sort} onChange={(v) => set({ sort: v })} />
      </Row>
      <Row label={t('Notifica al termine')} hint={t('Avviso di sistema quando finisce un\'analisi, con il numero di file pericolosi.')} id="set-notify">
        <Switch id="set-notify" label={t('Notifica al termine')} checked={s.notify} onChange={(v) => set({ notify: v })} />
      </Row>
      <Row label={t('Password per archivi protetti')} hint={t('Gauntler prova già oltre 30 password comuni (es. "infected"). Aggiungine altre, una per riga o separate da virgola.')} id="set-pw" stacked>
        <textarea id="set-pw" className="textarea" value={s.passwords} onChange={(e) => set({ passwords: e.target.value })} rows={3} placeholder={t('es. fattura2025, 1234abcd')} spellCheck={false} />
        <label className="toggle"><input type="checkbox" checked={s.rememberPasswords} onChange={(e) => set({ rememberPasswords: e.target.checked })} />{t('Ricorda le password tra una sessione e l\'altra (salvate in chiaro su questo computer)')}</label>
      </Row>
    </>
  );
}

function Report({ s, set }) {
  return (
    <>
      <Row label={t('Scheda iniziale del report')} hint={t('La scheda aperta quando selezioni un file.')}>
        <Segmented label={t('Scheda iniziale')} value={s.defaultTab} options={OPTIONS.defaultTab} onChange={(v) => set({ defaultTab: v })} />
      </Row>
      <Row label={t('Mostra le informazioni')} hint={t('Include nell\'elenco dei problemi anche le segnalazioni di livello informativo.')} id="set-info">
        <Switch id="set-info" label={t('Mostra le informazioni')} checked={s.showInfo} onChange={(v) => set({ showInfo: v })} />
      </Row>
      <Row label={t('Formato del pulsante Report')} hint={t('Il formato usato dal pulsante principale di esportazione.')} id="set-fmt">
        <Select id="set-fmt" value={s.exportFormat} options={OPTIONS.exportFormat} onChange={(v) => set({ exportFormat: v })} />
      </Row>
    </>
  );
}

/** Installs / removes the "gauntler" terminal command (~/.local/bin) */
function TerminalCommand() {
  const [st, setSt] = useState(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState(null);
  useEffect(() => { window.gauntler.cliStatus?.().then(setSt); }, []);
  const act = async (fn) => {
    setBusy(true); setMsg(null);
    const r = await fn();
    setBusy(false);
    if (!r.ok) setMsg({ err: true, text: r.error }); else setSt(r);
  };
  const copy = (text) => navigator.clipboard?.writeText(text);
  if (!st) return null;
  return (
    <div className="term-box">
      <div className="term-head">
        <span className="term-icon" aria-hidden><Icon name="code" size={16} /></span>
        <div className="term-text">
          <b>{t('Comando da terminale')} <code>gauntler</code></b>
          <p className="set-hint">
            {st.installed ? <>{t('Installato in')} <code>{st.path}</code>.</> : st.foreign ? <>{t('Esiste già un file')} <code>{st.path}</code> {t('non creato da Gauntler.')}</> : t('Analizza file e cartelle dal terminale con lo stesso motore dell\'app, anche senza Node.js.')}
          </p>
        </div>
        {st.installed
          ? <button className="btn btn-ghost" disabled={busy} onClick={() => act(window.gauntler.cliUninstall)}>{t('Rimuovi')}</button>
          : <button className="btn" disabled={busy || st.foreign} onClick={() => act(window.gauntler.cliInstall)}>{busy ? t('Installazione…') : t('Installa')}</button>}
      </div>
      {st.installed && !st.inPath && (
        <p className="notice danger small"><Icon name="alert" />{t('La cartella')} <code>{st.dir}</code> {t('non è nel PATH: aggiungila al file')} <code>~/.zshrc</code> {t('con la riga')} <code>export PATH="{st.dir}:$PATH"</code>.</p>
      )}
      {st.installed && (
        <div className="term-examples">
          {[['gauntler ~/Downloads/file.pdf', 'analizza un file'], ['gauntler ~/Downloads -q', 'una riga per file'], ['gauntler app file.zip', 'apre l\'app con il file'], ['gauntler --help', 'tutti i comandi']].map(([cmd, d]) => (
            <button key={cmd} className="term-ex" onClick={() => copy(cmd)} title={t('Copia')}><code>{cmd}</code><span>{t(d)}</span><Icon name="copy" size={13} /></button>
          ))}
        </div>
      )}
      {msg && <p className={`notice ${msg.err ? 'danger' : ''}`}><Icon name="alert" />{msg.text}</p>}
    </div>
  );
}

function System({ env, onReset }) {
  const mod = /Mac/.test(navigator.platform) ? '⌘' : 'Ctrl';
  return (
    <>
      {env && (
        <dl className="sys-grid">
          <dt>{t('Motore')}</dt><dd>Gauntler {env.version}</dd>
          <dt>{t('Criteri di analisi')}</dt><dd>{env.analyzers.length}</dd>
          <dt>{t('Antivirus ClamAV')}</dt><dd><span className={`pill ${env.clamav ? 'ok' : ''}`}>{env.clamav ? t('attivo') : t('non installato')}</span></dd>
          <dt>{t('Archivi RAR/7z/ISO')}</dt><dd><span className={`pill ${env.sevenZip ? 'ok' : ''}`}>{env.sevenZip ? '7-Zip' : t('bsdtar (installa 7-Zip per tutti i formati)')}</span></dd>
          <dt>{t('Piattaforma')}</dt><dd>{env.platform}</dd>
        </dl>
      )}
      <TerminalCommand />
      <h4 className="set-sub">{t('Scorciatoie da tastiera')}</h4>
      <dl className="keys">
        <dt><kbd>{mod}</kbd><kbd>O</kbd></dt><dd>{t('Analizza file')}</dd>
        <dt><kbd>{mod}</kbd><kbd>⇧</kbd><kbd>O</kbd></dt><dd>{t('Analizza cartella')}</dd>
        <dt><kbd>{mod}</kbd><kbd>,</kbd></dt><dd>{t('Impostazioni')}</dd>
        <dt><kbd>{mod}</kbd><kbd>F</kbd></dt><dd>{t('Cerca nell\'elenco dei file')}</dd>
        <dt><kbd>Esc</kbd></dt><dd>{t('Chiudi questa finestra')}</dd>
      </dl>
      <div className="set-reset">
        <div><b>{t('Ripristina le impostazioni')}</b><p className="set-hint">{t('Torna ai valori predefiniti. Le password salvate vengono cancellate.')}</p></div>
        <button className="btn btn-ghost" onClick={onReset}>{t('Ripristina')}</button>
      </div>
    </>
  );
}

export default function Settings({ env, onClose }) {
  const { settings: s, set } = useSettings();
  const [section, setSection] = useState('appearance');
  const ref = useRef(null);

  useEffect(() => {
    const prev = document.activeElement;
    ref.current?.focus(); // the dialog itself takes focus; Tab moves into it
    const onKey = (e) => {
      if (e.key === 'Escape') { e.preventDefault(); onClose(); return; }
      if (e.key !== 'Tab' || !ref.current) return;
      // Focus stays inside the dialog
      const f = [...ref.current.querySelectorAll('button, select, textarea, input, [tabindex]:not([tabindex="-1"])')].filter((x) => !x.disabled && x.tabIndex !== -1);
      if (!f.length) return;
      if (e.shiftKey && document.activeElement === f[0]) { e.preventDefault(); f[f.length - 1].focus(); }
      else if (!e.shiftKey && document.activeElement === f[f.length - 1]) { e.preventDefault(); f[0].focus(); }
    };
    window.addEventListener('keydown', onKey);
    return () => { window.removeEventListener('keydown', onKey); prev?.focus?.(); };
  }, [onClose]);

  const Body = { appearance: Appearance, text: Text, analysis: Analysis, report: Report }[section];
  const title = t(SECTIONS.find((x) => x[0] === section)[1]);
  return (
    <div className="modal-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="modal settings-modal" role="dialog" aria-modal="true" aria-labelledby="set-title" ref={ref} tabIndex={-1}>
        <nav className="set-nav" role="tablist" aria-orientation="vertical" aria-label={t('Sezioni delle impostazioni')}>
          <div className="set-nav-title">{t('Impostazioni')}</div>
          {SECTIONS.map(([id, label, icon]) => (
            <button key={id} role="tab" aria-selected={section === id} className={section === id ? 'on' : ''} onClick={() => setSection(id)}><Icon name={icon} size={15} />{t(label)}</button>
          ))}
        </nav>
        <section className="set-body">
          <header className="set-head">
            <h2 id="set-title">{title}</h2>
            <button className="btn btn-quiet btn-icon" onClick={onClose} aria-label={t('Chiudi')} title={t('Chiudi (Esc)')}><Icon name="x" size={16} /></button>
          </header>
          <div className="set-scroll">
            {Body ? <Body s={s} set={set} /> : <System env={env} onReset={() => set({ ...DEFAULTS }, true)} />}
          </div>
        </section>
      </div>
    </div>
  );
}
