<!-- Creato da anvex2012 -->
# Gauntler — Istruzioni

Gauntler analizza la sicurezza di qualsiasi file (programmi, documenti, archivi, script, email, immagini) e assegna un punteggio da **1 a 100** (100 = sicuro). **Tutta l'analisi avviene sul tuo computer**: nessun file viene inviato su Internet.

Puoi usarlo in due modi, con lo stesso motore di analisi:

| | Cosa serve | Come si avvia |
|---|---|---|
| **Terminale** (dallo zip di GitHub) | Node.js | `gauntler` |
| **App desktop macOS** (`.dmg` / `.zip`) | niente | doppio clic su Gauntler, oppure `gauntler` dal terminale |
| **App desktop Windows** (`.zip`) | niente | `Gauntler.exe` |
| **App desktop Linux** (`.tar.gz`) | niente | `./gauntler`, oppure `gauntler` dal terminale dopo `./installa.sh` |

### Dove scaricare
Tutti i file sono nella pagina **[Releases](https://github.com/anvex2012/Gauntler/releases/latest)**:

| Sistema | File |
|---|---|
| macOS (Apple Silicon: M1, M2, M3, M4…) | `Gauntler-<versione>-macOS-arm64.dmg` (oppure il `.zip`) |
| Windows 10/11 (64 bit) | `Gauntler-<versione>-Windows-x64.zip` |
| Linux (64 bit) | `Gauntler-<versione>-Linux-x64.tar.gz` |
| Codice sorgente (uso da terminale) | **Source code (zip)**, oppure su GitHub **Code → Download ZIP** |

`SHA256SUMS.txt` contiene le impronte per verificare i file scaricati (`shasum -a 256 -c SHA256SUMS.txt`).

In entrambi i casi, **dopo il primo avvio il comando `gauntler` funziona da qualsiasi cartella del terminale.**

---

## Lingua

Gauntler è disponibile in **italiano, inglese, spagnolo, francese e tedesco** (interfaccia, terminale e risultati delle analisi).

- **Al primo utilizzo** (app o terminale) viene chiesto di scegliere la lingua; la scelta vale per entrambi.
- **Per cambiarla dopo:**
  - app: **Impostazioni → Aspetto → Lingua** (anche i risultati già mostrati vengono tradotti subito);
  - terminale: `gauntler language` (scelta interattiva) oppure `gauntler language en`;
  - interfaccia interattiva: `/lingua en`;
  - per una sola esecuzione: `gauntler --lang fr file.pdf`.
- La lingua è salvata in `~/.gauntler/config.json` (chiave `language`).

---

## 1. Installazione dal terminale (zip da GitHub)

### Requisiti
- **macOS** o **Linux**
- **Node.js 18 o successivo**: controlla con `node -v`. Se manca, installalo da <https://nodejs.org> oppure con `brew install node`.
- Per l'uso da terminale **non serve `npm install`**: il motore non ha dipendenze esterne.

### Passi
1. Su GitHub premi **Code → Download ZIP** ed estrai lo zip, ad esempio in `~/Coding/Gauntler`.
2. Apri il **Terminale** ed entra nella cartella:
   ```bash
   cd ~/Coding/Gauntler
   ```
3. **Primo avvio**:
   ```bash
   node cli/gauntler.js
   ```
   Al primo avvio Gauntler:
   - crea il comando `gauntler` in `~/.local/bin` (senza password di amministratore);
   - se serve, aggiunge `~/.local/bin` al PATH nel file di avvio della shell (`~/.zshrc` su macOS);
   - ti conferma l'installazione con il messaggio **✔ Comando "gauntler" installato**;
   - installa i componenti aggiuntivi **ClamAV** (antivirus, con le firme) e **bsdtar** se mancano (vedi sezione 5).
4. **Apri una nuova finestra del terminale.** Da ora, ovunque tu sia, basta scrivere:
   ```bash
   gauntler
   ```

> Non spostare né cancellare la cartella del progetto: il comando `gauntler` usa il codice che si trova lì. Se la sposti, ripeti il passo 3 dalla nuova posizione con `node cli/gauntler.js install-command`.

---

## 2. Installazione dell'app desktop (macOS)

### Metodo 1 — dal file `.dmg`, come una normale app (senza terminale)
1. Scarica `Gauntler-<versione>-macOS-arm64.dmg` dalla pagina [Releases](https://github.com/anvex2012/Gauntler/releases/latest) e aprilo con doppio clic.
2. Nella finestra che si apre, **trascina Gauntler sulla cartella Applicazioni**.
3. Apri **Gauntler** da Applicazioni (o dal Launchpad). **Solo la prima volta**, macOS mostra *"Apple non può verificare che Gauntler sia privo di malware"*. Succede perché l'app non è notarizzata da Apple (serve un abbonamento a pagamento Apple Developer). Per sbloccarla:
   1. premi **Fine** (non "Sposta nel Cestino");
   2. apri **Impostazioni di Sistema → Privacy e sicurezza**;
   3. scorri fino a *"Gauntler è stato bloccato…"* e premi **Apri comunque**;
   4. conferma con la password o con Touch ID.

   Dalla volta successiva si apre normalmente. Su macOS 15 e successivi il vecchio "clic destro → Apri" non basta più.
4. **Fine: non devi fare altro.** Al primo avvio l'app installa da sola, in sottofondo:
   - il comando `gauntler` per il terminale;
   - l'antivirus **ClamAV**, con le firme;
   - **bsdtar**.

   L'avanzamento compare in alto nella finestra. Se serve, macOS chiede la password di amministratore con la sua finestra.

### Metodo 2 — con un comando nel Terminale (facoltativo)
Se preferisci il terminale, questo comando installa e apre l'app **senza il blocco del primo avvio**, perché i file scaricati con `curl` non vengono messi in quarantena:
```bash
curl -fsSL https://raw.githubusercontent.com/anvex2012/Gauntler/main/install.sh | sh
```
Lo script:
- scarica l'ultima versione e ne verifica l'impronta SHA-256;
- la installa in **Applicazioni** e la apre.

Serve anche per aggiornare e funziona anche su Linux.

### Dopo l'installazione
- Al primo avvio l'app installa da sola il comando `gauntler` per il terminale e, in sottofondo, **ClamAV** e **bsdtar** (vedi sezione 5).
- **Funziona anche se Node.js non è installato**, perché usa il motore incluso nell'app.
- Apri una **nuova** finestra del terminale e scrivi `gauntler`.

### Se vuoi creare l'app dai sorgenti
Serve Node.js e una sola volta `npm install`:
```bash
cd ~/Coding/Gauntler
npm install
npm run package          # crea release/Gauntler.app
```
Poi segui i passi qui sopra con `release/Gauntler.app`.

Per creare **tutti** i file della release (dmg e zip per macOS, zip per Windows, tar.gz per Linux) in `release/upload/`:
```bash
npm run release:build
```

Per provare l'app senza impacchettarla: `npm start` (oppure `npm run dev` per lo sviluppo).

---

## 2b. Windows

1. Scarica `Gauntler-<versione>-Windows-x64.zip` ed estrai **tutta** la cartella (clic destro → Estrai tutto).
2. Apri **Gauntler.exe**. Se compare "Windows ha protetto il PC" (l'app non ha una firma digitale a pagamento): **Ulteriori informazioni → Esegui comunque**.
3. Trascina file o cartelle nella finestra, oppure usa **Scegli file** / **Scegli cartella**.

Per comodità puoi spostare la cartella in `C:\Programmi\Gauntler` e creare un collegamento a `Gauntler.exe` sul Desktop (clic destro → Invia a → Desktop).

**Terminale su Windows** (facoltativo): installa Node.js, scarica il codice sorgente ed esegui `node cli\gauntler.js` dalla cartella del progetto (es. `node cli\gauntler.js C:\Users\nome\Downloads\file.pdf`). Su Windows il comando `gauntler` non si installa da solo e il pulsante `+` non apre il selettore grafico: trascina il file nella finestra del terminale o scrivine il percorso.

## 2c. Linux

```bash
tar -xzf Gauntler-<versione>-Linux-x64.tar.gz
cd Gauntler-<versione>-Linux-x64
./gauntler              # apre l'app
./installa.sh           # facoltativo: menu delle applicazioni + comando "gauntler" nel terminale
```
Dopo `./installa.sh` apri un nuovo terminale e scrivi `gauntler`: funziona anche senza Node.js. Anche il primo avvio dell'app installa il comando da solo.

Per usare la sandbox di Chromium (consigliato), una volta sola:
```bash
sudo chown root:root chrome-sandbox && sudo chmod 4755 chrome-sandbox
```
Senza questo passaggio l'app parte comunque, ma senza sandbox.

---

## 3. Usare l'interfaccia del terminale

Scrivi `gauntler` senza nient'altro: si apre l'interfaccia a schermo intero.

```
 ◆ Gauntler 2.2.0  │  Analisi di sicurezza dei file          ● ClamAV   ○ 7-Zip
 ──────────────────────────────────────────────────────────────────────────────
   (qui compaiono i risultati)

 ╭────────────────────────────────────────────────────────────────────────────╮
 │ › Trascina qui un file, digita un percorso o un /comando…                  │
 ╰────────────────────────────────────────────────────────────────────────────╯
  +   Aggiungi file  ·  / comandi  ·  Ctrl+C esci
```

### Come aggiungere un file
Hai tre modi:

1. **Pulsante `+`** in basso a sinistra: cliccalo, oppure premi `+` o `Tab`. Si apre un menu:
   - **File…**: apre il selettore del Finder (puoi scegliere più file);
   - **Cartella…**: analizza tutti i file di una cartella e delle sottocartelle;
   - **Digita un percorso**.
2. **Trascina** un file o una cartella dal Finder dentro la finestra del terminale: l'analisi parte subito.
3. **Scrivi o incolla un percorso** e premi `Invio`, ad esempio `~/Downloads/fattura.pdf`.

### Leggere il risultato
Per ogni file vedi il punteggio, il verdetto e i problemi principali:

| Punteggio | Verdetto |
|---|---|
| 90–100 | Sicuro |
| 70–89 | Basso rischio |
| 40–69 | Sospetto |
| 15–39 | Pericoloso |
| 1–14 | Malevolo |

Ogni risultato ha un numero (`#1`, `#2`…), che usi con i comandi qui sotto.

### Comandi (scrivi `/` per vedere i suggerimenti)
| Comando | Cosa fa |
|---|---|
| `/file` | Sceglie uno o più file da analizzare |
| `/cartella` | Sceglie una cartella da analizzare |
| `/report 2` | Report completo del risultato #2 (senza numero: l'ultimo) |
| `/dettagli 2` | Report con le righe segnalate e tutti i controlli |
| `/elenco` | Tutti i file analizzati nella sessione |
| `/esporta report.html` | Salva i risultati (`.html`, `.json`, `.sarif`, `.csv`, `.md`) |
| `/pulisci` | Pulisce lo schermo |
| `/mouse` | Attiva o disattiva il mouse (disattivalo per selezionare e copiare il testo) |
| `/aiuto` | Guida e scorciatoie |
| `/esci` | Chiude Gauntler |

### Tasti
| Tasto | Azione |
|---|---|
| `+` o `Tab` | Menu "Aggiungi" |
| `Ctrl+O` | Selettore di file |
| `Ctrl+K` | Selettore di cartelle |
| `PagSu` / `PagGiù`, rotella | Scorrono i risultati |
| `↑` / `↓` | Comandi scritti in precedenza |
| `Esc` | Cancella la riga o chiude il menu |
| `Ctrl+L` | Pulisce lo schermo |
| `Ctrl+C` | Esce (con la riga vuota) |

---

## 4. Comandi diretti (senza interfaccia)

Utili negli script o per un'analisi veloce:

```bash
gauntler ~/Downloads/fattura.pdf          # analizza un file e stampa il report
gauntler ~/Downloads -q                   # una riga per file, in parallelo
gauntler allegato.zip -l                  # report con le righe segnalate
gauntler sanitize fattura.docm            # crea una copia sicura (fattura.safe.docx)
gauntler watch ~/Downloads --notify       # controlla in tempo reale i nuovi file
gauntler app ~/Downloads/file.zip         # apre l'app desktop con il file
gauntler doctor                           # verifica l'ambiente
gauntler --help                           # tutti i comandi
gauntler <comando> --help                 # aiuto di un comando
```

---

## 5. Componenti aggiuntivi: ClamAV e bsdtar

**Si installano da soli** la prima volta che avvii Gauntler, dal terminale (`gauntler`, oppure `gauntler install-command`) o aprendo l'app desktop.

| Componente | A cosa serve | Come viene installato |
|---|---|---|
| **ClamAV** + firme antivirus | Scansione antivirus aggiuntiva (milioni di firme) | macOS: Homebrew, oppure il pacchetto ufficiale ClamAV se Homebrew manca · Linux: apt / dnf / yum / pacman / zypper · Windows: winget, oppure il pacchetto ufficiale `.msi` |
| **bsdtar** | Archivi RAR, 7z, ISO, CAB | macOS e Windows 10/11: già incluso nel sistema · Linux: `libarchive-tools` / `bsdtar` |

- Può comparire la richiesta della **password di amministratore**. Nel terminale con `sudo`; nell'app con la finestra di sistema (macOS, Linux) o con l'autorizzazione di Windows. Con Homebrew su macOS la password non serve.
- Le **firme antivirus** (circa 200 MB) vengono scaricate in `~/.gauntler/clamav`. Si aggiornano con `gauntler update` e, nell'app, da sole ogni pochi giorni, senza password.
- Nel terminale puoi **saltare** l'installazione con `Ctrl+C`. Nell'app, mentre installa, in alto compare l'avanzamento; se ClamAV manca, il pulsante **Installa ClamAV** in alto la riavvia.

Comandi utili:
```bash
gauntler setup            # installa ciò che manca (puoi ripeterlo quando vuoi)
gauntler setup --status   # mostra cosa è installato
gauntler update           # aggiorna le firme antivirus e gli elenchi di malware
gauntler doctor           # verifica completa dell'ambiente
```

Per non installare nulla in automatico: `GAUNTLER_NO_AUTOINSTALL=1` (vale anche per il comando `gauntler`).

Facoltativo, per gli archivi RAR più recenti: **7-Zip** (`brew install sevenzip` su macOS).

---|---|---|
| ClamAV | Scansione antivirus aggiuntiva | `brew install clamav` |
| 7-Zip | Archivi RAR, 7z, ISO | `brew install sevenzip` |

Usa `gauntler doctor` per vedere cosa è attivo.

---

## 6. Problemi frequenti

**`gauntler: command not found`**
Apri una **nuova** finestra del terminale: il PATH viene letto solo all'apertura. Se il problema resta, esegui dalla cartella del progetto:
```bash
node cli/gauntler.js install-command
```
e apri un nuovo terminale.

**Non riesco a selezionare il testo nell'interfaccia**
Scrivi `/mouse` per disattivare il mouse, poi selezionalo normalmente. Riscrivi `/mouse` per riattivarlo.

**Il pulsante `+` non apre il Finder**
Il selettore grafico c'è solo su macOS. Su Linux e Windows trascina il file nella finestra o scrivine il percorso.

**Su un Mac con processore Intel l'app non si apre**
L'app della release è per Apple Silicon (M1 e successivi). Su un Mac Intel usa la versione da terminale (sezione 1), oppure crea l'app sul tuo Mac con `npm install && npm run package`.

**macOS dice che l'app è danneggiata, che Apple non può verificarla o che non si può aprire**
L'app non è notarizzata da Apple, e macOS blocca le app scaricate dal browser. Hai due soluzioni:
- **Impostazioni di Sistema → Privacy e sicurezza → Apri comunque** (vedi sezione 2, metodo 1);
- oppure reinstalla con il comando del metodo 2, che non viene bloccato:
  ```bash
  curl -fsSL https://raw.githubusercontent.com/anvex2012/Gauntler/main/install.sh | sh
  ```

**Il comando `gauntler` usa una versione vecchia**
Se lo hai installato dai sorgenti, `gauntler` usa sempre il codice della cartella del progetto. Se lo usi tramite l'app, sostituisci l'app in Applicazioni con quella nuova.

---

## 7. Disinstallazione

```bash
gauntler uninstall-command
```
Rimuove il comando `gauntler` e la riga che era stata aggiunta al PATH. Poi:
- **App desktop**: trascina Gauntler.app nel Cestino;
- **Sorgenti**: cancella la cartella del progetto;
- **Dati e impostazioni** (cronologia, quarantena, configurazione): cancella la cartella `~/.gauntler`.

Per evitare che il comando venga installato da solo al primo avvio, imposta `GAUNTLER_NO_AUTOINSTALL=1`.

---

## Licenza

Gauntler è creato da **anvex2012** ed è distribuito con la **Gauntler Custom Source Code License 1.0**: vedi [`licenza-gauntler.txt`](licenza-gauntler.txt).

© 2026 anvex2012
