// Creato da anvex2012
import React, { useEffect, useRef, useState } from 'react';
import Icon from './Icon.jsx';
import logo from '../assets/logo.png';
import { LANGUAGES } from '../i18n.js';

// Shown before any language is chosen, so every text is written in all the languages
const TITLE = { it: 'Scegli la lingua', en: 'Choose your language', es: 'Elige tu idioma', fr: 'Choisissez votre langue', de: 'Wähle deine Sprache' };
const HINT = {
  it: 'Vale per l\'app e per il comando gauntler nel terminale. Puoi cambiarla quando vuoi nelle Impostazioni.',
  en: 'Used by the app and by the gauntler command in the terminal. You can change it anytime in Settings.',
  es: 'Se usa en la app y en el comando gauntler del terminal. Puedes cambiarlo cuando quieras en Ajustes.',
  fr: 'Utilisée par l\'app et par la commande gauntler du terminal. Modifiable à tout moment dans les Réglages.',
  de: 'Gilt für die App und den Befehl gauntler im Terminal. Jederzeit in den Einstellungen änderbar.',
};
const GO = { it: 'Continua', en: 'Continue', es: 'Continuar', fr: 'Continuer', de: 'Weiter' };

/** First launch: full-window language choice (arrow keys, Enter, or click) */
export default function LanguagePicker({ initial, onChoose }) {
  const [sel, setSel] = useState(LANGUAGES.some((l) => l.code === initial) ? initial : 'en');
  const ref = useRef(null);
  useEffect(() => { ref.current?.querySelector('[aria-checked="true"]')?.focus(); }, []);
  const move = (d) => {
    const i = LANGUAGES.findIndex((l) => l.code === sel);
    const n = LANGUAGES[(i + d + LANGUAGES.length) % LANGUAGES.length].code;
    setSel(n);
    ref.current?.querySelector(`[data-code="${n}"]`)?.focus();
  };
  const onKey = (e) => {
    if (e.key === 'ArrowDown' || e.key === 'ArrowRight') { e.preventDefault(); move(1); }
    else if (e.key === 'ArrowUp' || e.key === 'ArrowLeft') { e.preventDefault(); move(-1); }
    else if (e.key === 'Enter') { e.preventDefault(); onChoose(sel); }
  };
  return (
    <div className="modal-backdrop lang-backdrop">
      <div className="modal lang-modal" role="dialog" aria-modal="true" aria-labelledby="lang-title" onKeyDown={onKey}>
        <img className="lang-logo" src={logo} alt="" aria-hidden width={44} height={44} />
        <h2 id="lang-title" lang={sel}>{TITLE[sel]}</h2>
        <p className="lang-others" aria-hidden>{LANGUAGES.filter((l) => l.code !== sel).map((l) => TITLE[l.code]).join(' · ')}</p>
        <div className="lang-list" role="radiogroup" aria-labelledby="lang-title" ref={ref}>
          {LANGUAGES.map((l) => (
            <button key={l.code} data-code={l.code} role="radio" aria-checked={sel === l.code} tabIndex={sel === l.code ? 0 : -1}
              className={`lang-opt ${sel === l.code ? 'on' : ''}`} lang={l.code} onClick={() => setSel(l.code)} onDoubleClick={() => onChoose(l.code)}>
              <span className="lang-code">{l.code.toUpperCase()}</span>
              <span className="lang-name">{l.name}</span>
              {sel === l.code && <Icon name="check" size={15} strokeWidth={2.5} />}
            </button>
          ))}
        </div>
        <p className="set-hint lang-hint" lang={sel}>{HINT[sel]}</p>
        <button className="btn btn-lg lang-go" onClick={() => onChoose(sel)} lang={sel}>{GO[sel]}<Icon name="arrowRight" /></button>
      </div>
    </div>
  );
}
