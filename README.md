<!-- Creato da anvex2012 -->
# Gauntler

Analizzatore di sicurezza per **qualsiasi tipo di file**: app desktop (Electron + React) e tool da terminale.
Tutta l'analisi è **locale**: nessun file viene inviato su Internet.

> **Installazione e uso passo per passo:** vedi [ISTRUZIONI.md](ISTRUZIONI.md).

Ogni file riceve un **punteggio generale da 1 a 100** (100 = sicuro) e un punteggio per ogni criterio.

| Punteggio | Verdetto |
|---|---|
| 90–100 | Sicuro |
| 70–89 | Basso rischio |
| 40–69 | Sospetto |
| 15–39 | Pericoloso |
| 1–14 | Malevolo |

## Analisi approfondita, senza limiti

- **File di qualsiasi dimensione**: analisi a blocchi da 64 MB con sovrapposizione, 100% dei byte (anche file da diversi GB).
- **Ogni riga, ogni parola**: oltre 200 indicatori applicati a ogni riga (o a ogni stringa estratta nei binari), con spiegazione per ogni riga segnalata.
- **Nessun limite di occorrenze**: ogni corrispondenza viene riportata con la sua posizione (riga/offset).
- **Decodifica ricorsiva**: base64, base64 MIME, data URI, hex, charcode, gzip/zlib, PowerShell `-EncodedCommand`, fino a 10 livelli annidati. Ogni payload decodificato viene rianalizzato da tutti i criteri.
- **Estrazione profonda**: macro VBA decompresse (MS-OVBA), ogni flusso PDF decompresso (Flate/ASCIIHex/ASCII85) + testo visibile, parti XML di Office, oggetti RTF, allegati PDF, dati accodati a immagini.
- **Archivi**: ZIP/JAR/APK (anche ZIP64 e protetti da password: oltre 30 password comuni + password personalizzate), TAR, GZIP, RAR/7z/ISO/CAB/PKG/XZ/BZ2 tramite 7-Zip/bsdtar. Ogni file interno viene analizzato con tutti i criteri, ricorsivamente (fino a 12 livelli, contro i "zip quine").
- **Protezione dalle bombe di decompressione** (ZIP, ZIP annidati, voci sovrapposte, GZIP, flussi PDF, payload gzip/zlib codificati, 7-Zip/xz/bzip2): un unico budget per tutta l'analisi di un file, con limiti rigorosi — 256 MB per singolo oggetto, 1 GB decompresso in totale, rapporto di compressione 100:1 (oltre 16 MB), 10.000 file, 2 GB di memoria. Superato un limite, estrazione e analisi si interrompono subito e il file riceve una segnalazione critica. I limiti si cambiano con `"limits"` in `~/.gauntler/config.json` (`maxEntryBytes`, `maxTotalBytes`, `maxRatio`, `ratioMinBytes`, `maxFiles`, `maxMemoryBytes`). Gli archivi aperti con bsdtar vengono convertiti in un flusso tar letto in memoria con tetto esatto (nulla di decompresso finisce su disco); 7-Zip e unar estraggono su disco sotto sorveglianza continua e vengono fermati appena superano il limite.
- **ClamAV senza limiti**: dimensione file, ricorsione, euristiche, macro, archivi cifrati.

## Criteri (17, ciascuno con punteggio 1–100)

| Criterio | Cosa analizza |
|---|---|
| Identità & camuffamento | contenuto reale vs estensione, doppie estensioni, RTLO, omoglifi, nomi-esca |
| Firme malware | impronte note + 56 regole stile YARA (famiglie ransomware/RAT/stealer/botnet, webshell, exploit, tecniche MITRE) |
| ClamAV | motore antivirus, se installato |
| Eseguibile | PE/.NET, ELF, Mach-O: firma, imphash, info versione, finto Microsoft, packer, sezioni/segmenti, API, protezioni, entitlement |
| Codice macchina | disassemblaggio x86/x86-64/ARM64, grafo del flusso di controllo, shellcode in qualsiasi file, hash di API, contenuti nascosti con XOR/ADD |
| Documenti attivi | macro, XLM, JavaScript PDF, azioni automatiche, OLE, DDE, Follina, Equation Editor, LNK, OneNote, CHM |
| Codice & offuscamento | 14 metriche di offuscamento pesate per densità, payload nascosti |
| Riga per riga | oltre 200 indicatori in 20 categorie, Trojan Source, caratteri invisibili, omoglifi, statistiche delle parole |
| Archivi & file incorporati | zip bomb, Zip Slip, link simbolici, cifratura, analisi ricorsiva |
| Password & segreti | 78 rilevatori (cloud, AI, pagamenti, CI/CD, DB, hash di password…) + stringhe ad alta entropia |
| Privacy | carte (Luhn), IBAN (mod-97), codice fiscale (carattere di controllo), P.IVA, documenti, dati sanitari |
| Phishing | linguaggio di manipolazione (IT/EN), SPF/DKIM/DMARC, Reply-To, mittente falsificato |
| Rete & IOC | URL, domini, IPv4/IPv6, .onion, wallet, DGA, punycode, imitazione di marchi |
| Metadati | GPS/EXIF/XMP, autore Office/PDF, provenienza del download, permessi |
| Regole YARA | regole YARA reali (motore ufficiale) da `~/.gauntler/yara`, se YARA è installato |
| Reputazione online | VirusTotal + MalwareBazaar, solo con `--online` (invia solo l'impronta) |
| Statistica | entropia, chi-quadro + p-value, Monte Carlo π, correlazione seriale, istogramma, file poliglotti |

L'app mostra: panoramica con grafico radar, problemi filtrabili (con salto alla riga), **visualizzatore del codice riga per riga** (con evidenziazione, mappa di calore e spiegazioni), stringhe dei binari, elenco di tutti i controlli eseguiti (~200–300 per file), contenuti estratti e file interni (con report navigabile), indicatori di rete, metadati, hash, istogramma, vista esadecimale. Esporta il report in HTML, JSON, SARIF, CSV o Markdown.

**Impostazioni** (icona ingranaggio o `⌘,`): tema chiaro/scuro/sistema, colore d'accento, colori dei livelli di rischio (standard, alto contrasto, per daltonici), dimensione dell'interfaccia, densità, carattere e dimensione del codice, animazioni; file analizzati in parallelo, vista dopo l'aggiunta, ordine dell'elenco, notifica al termine, password per archivi (ricordate solo su richiesta); scheda iniziale del report, segnalazioni informative, formato di esportazione predefinito. Scorciatoie: `⌘O` file, `⇧⌘O` cartella, `⌘F` cerca.

## Codice macchina: assembly e binario

Gauntler contiene un disassemblatore proprio (nessuna dipendenza esterna), verificato contro `objdump`:

- **x86 / x86-64**: prefissi, REX, VEX/EVEX, ModRM/SIB, indirizzamento RIP-relativo, mappe 0F/0F38/0F3A, x87 (lunghezze identiche a objdump su /bin/zsh: 125.000 istruzioni).
- **ARM64**: salti, chiamate, PAC/BTI, syscall, MRS/MSR, ADR/ADRP, immediati logici, load/store e coppie.
- **Discesa ricorsiva** dal punto di avvio, export, callback TLS e simboli → **grafo del flusso di controllo**: funzioni, blocchi di base, cicli (archi all'indietro con DFS), complessità ciclomatica, copertura del codice.
- **Euristiche comportamentali** sul codice raggiungibile: GetPC (call/pop, fnstenv, jmp-call-pop), lettura del PEB/TEB, hashing dei nomi delle API (ROR/ROL), syscall dirette e stub Hell's Gate, cicli di auto-decifratura, stringhe costruite sullo stack, anti-debug (BeingDebugged, int 2d, ptrace PT_DENY_ATTACH), anti-VM (cpuid 0x40000000, backdoor VMware, Red Pill), NOP sled.
- **Shellcode in qualsiasi file** (documenti, immagini, payload decodificati, `%u9090` nei JavaScript): ancore + disassemblaggio a 32 e 64 bit + punteggio su comportamenti indipendenti (0 falsi positivi su 512 MB di dati casuali).

```bash
gauntler disasm programma.exe            # assembly dal punto di avvio (con simboli e riferimenti)
gauntler disasm programma.exe -b         # byte di ogni istruzione in binario (0/1)
gauntler disasm /bin/ls -F               # funzioni: blocchi, cicli, complessità
gauntler disasm documento.doc            # trova e disassembla lo shellcode nascosto
gauntler disasm payload.bin --raw --arch x64
gauntler disasm file.bin --dump          # tutto il file in codice binario
```

## Algoritmi

| Algoritmo | Uso |
|---|---|
| Crittoanalisi differenziale XOR/ADD (`c[i]⊕c[i+L]` non dipende dalla chiave) | recupera chiavi ripetute fino a 32 byte da testo noto (stub PE, URL, nomi di API) e decifra il payload, che viene rianalizzato |
| Dizionario di hash di API (ROR13, Metasploit block_api, CRC32, DJB2, SDBM, FNV-1a, ROL5/ROR7-XOR) | riconosce le costanti con cui shellcode e loader cercano le funzioni di Windows |
| CTPH (spamsum/ssdeep), calcolo multi-livello in un solo passaggio | impronta "fuzzy" per riconoscere varianti dello stesso file |
| DFS iterativa sul grafo del flusso | cicli, complessità ciclomatica, copertura |
| Entropia, chi-quadro, Monte Carlo, correlazione seriale | statistica dei byte (già presenti) |

## File resi sicuri (CDR: Content Disarm & Reconstruction)

`gauntler sanitize` non si limita a dare un voto: **ricostruisce** il file tenendo solo il contenuto sicuro, poi lo **ri-analizza con tutto il motore**. Se dopo il disarmo resta qualcosa di pericoloso, il file viene **bloccato** e non viene prodotto nulla.

| Tipo | Cosa viene rimosso |
|---|---|
| PDF | JavaScript, `/OpenAction`, `/AA`, Launch, SubmitForm, ImportData, GoToE/R, RichMedia, allegati, XFA, dati dopo `%%EOF`; object stream espansi e file riscritto da zero con nuova xref (rendering identico) |
| Word/Excel/PowerPoint (OOXML, ODF) | macro VBA e XLM, ActiveX, oggetti OLE, custom UI, collegamenti DDE, template remoti (template injection), schemi `mhtml:`/`file:`/`ms-*`, metadati personali; `.docm` → `.docx` |
| .doc/.xls/.ppt (OLE) | progetto VBA, oggetti incorporati, Equation Editor (azzerati sul posto) |
| RTF | `\object`, `\objdata`, `\datastore`, campi DDE/INCLUDE, dati dopo la fine |
| HTML/SVG/XML | script, iframe, object/embed, gestori `on…`, URL `javascript:`/`data:`, `foreignObject`, meta refresh, destinazioni dei moduli |
| JPEG/PNG/GIF/WebP/BMP | EXIF/GPS/XMP/commenti/blocchi sconosciuti, dati nascosti dopo la fine dell'immagine (poliglotti) |
| Testo/CSV | caratteri bidirezionali (Trojan Source) e invisibili, formule CSV (`=`, `+`, `-`, `@`) |
| Archivi (ZIP, TAR, GZIP, RAR, 7z) | ogni file disarmato ricorsivamente; eliminati file pericolosi, cifrati, link simbolici, percorsi `../` |
| Programmi, script, immagini disco | non disarmabili: escono solo se l'analisi è pulita (`--strict`: mai) |

```bash
gauntler sanitize fattura.docm               # → fattura.safe.docx
gauntler sanitize ~/Downloads -d ~/Sicuri    # cartella intera
gauntler sanitize allegato.pdf --in-place    # sostituisce l'originale (che va in quarantena)
gauntler watch ~/Downloads --sanitize --quarantine
```

I file prodotti non hanno mai il permesso di esecuzione e sono scritti in modo atomico. Nell'app: pulsante **Crea copia sicura** e scheda **Assembly**.

## Avvio

```bash
npm install
npm run dev        # app con hot reload
npm start          # build + avvio app
npm test           # test su campioni generati (EICAR, dropper, PDF, ZIP…)
```

Puoi anche aprire file direttamente: `npx electron . file1 file2`

**App desktop (macOS)**: `npm run package` crea `release/Gauntler.app` con nome e icona di Gauntler, firmata ad hoc; trascinala in Applicazioni e aprila con doppio clic. Al primo avvio, se macOS la blocca perché non viene da uno sviluppatore identificato: clic destro sull'app → Apri.

**Comando da terminale `gauntler`**: si installa **da solo** al primo avvio, sia dai sorgenti (`node cli/gauntler.js`) sia aprendo l'app desktop; se serve aggiunge `~/.local/bin` al PATH in `~/.zshrc` (blocco marcato `# >>> gauntler >>>`). Si può anche installare a mano: dall'app, Impostazioni → Sistema → Installa; oppure `npm run install-cli`. Insieme al comando si installano anche **ClamAV** (con le firme antivirus in `~/.gauntler/clamav`) e **bsdtar**, se mancano: Homebrew o pacchetto ufficiale su macOS, gestore di pacchetti su Linux, winget/MSI su Windows. Si ripete con `gauntler setup`. Per disattivare l'installazione automatica: `GAUNTLER_NO_AUTOINSTALL=1`. Crea `~/.local/bin/gauntler` (senza sudo) che usa il motore incluso in Gauntler.app, quindi funziona anche senza Node.js. `gauntler app [file…]` apre l'app desktop con i file da analizzare; `gauntler uninstall-command` rimuove il comando.

**Pacchetti per la release**: `npm run release:build` crea in `release/upload/` il `.dmg` e lo `.zip` per macOS, lo `.zip` per Windows (cartella portatile con `Gauntler.exe`) e il `.tar.gz` per Linux, più `SHA256SUMS.txt`. Windows e Linux vengono preparati da macOS con `@electron/packager`, senza Wine.

**Icona dell'app**: il disegno è in `build/icon.svg`; `npm run icon` rigenera `build/icon.png` (Windows/Linux), `build/icon.icns` (macOS) e il logo dell'interfaccia `src/assets/logo.png`.

## Tool da terminale

```bash
npm link                     # installa il comando "gauntler"
gauntler <file|cartella|->   # analizza (equivale a "gauntler scan")
gauntler --help              # tutti i comandi · gauntler <comando> --help per i dettagli
```

| Comando | A cosa serve |
|---|---|
| `scan` | Analisi parallela (un thread per core) con cache, filtri, formati e codici di uscita per CI |
| `sanitize` | Copia sicura dei file: disarmo e ricostruzione + verifica (CDR) |
| `disasm` | Assembly x86/x64/ARM64, funzioni e complessità, codice binario |
| `watch <cartella>` | Protezione in tempo reale: analizza ogni file nuovo (es. Download), notifiche, quarantena e copia sicura automatica (`--sanitize`) |
| `quarantine list/add/restore/delete` | File resi innocui (XOR + sola lettura) e ripristinabili identici |
| `history` | Cronologia delle analisi |
| `config` | Configurazione in `~/.gauntler/config.json` |
| `trust <file>` / `ignore <id>` | File attendibili · segnalazioni da ignorare (supporta `*`) |
| `lookup <file>` | Reputazione su VirusTotal / MalwareBazaar (invia solo l'impronta SHA-256) |
| `update` | Scarica le impronte di malware recenti da abuse.ch (serve Auth-Key gratuita) |
| `hash`, `rules`, `cache`, `doctor`, `completion` | Impronte · regole del motore · cache · verifica ambiente · autocompletamento bash/zsh |

Opzioni principali di `scan`:

| Opzione | |
|---|---|
| `-q` / `-s` / `-v` / `-l` / `-c` | una riga per file / solo riepilogo / tutto / righe segnalate / controlli |
| `-f text\|json\|sarif\|csv\|md\|html`, `-o file` | formato del report (dedotto dall'estensione di `-o`) |
| `-x glob`, `-i glob`, `--max-size 50M` | esclusioni, inclusioni, dimensione massima |
| `-j N`, `--timeout sec` | analisi in parallelo, tempo massimo per file |
| `--only` / `--skip criteri` | scegli i criteri (`gauntler rules analyzers`) |
| `-t N`, `--fail-on high` | exit code 1 sotto soglia o con problemi di quel livello |
| `--quarantine [--quarantine-below N]` | sposta in quarantena i file malevoli |
| `--online`, `--yara dir`, `-p password`, `--ids`, `--no-cache` | reputazione, regole YARA, password archivi, id segnalazioni, rianalisi |

Codici di uscita: `0` ok · `1` file sotto soglia / problemi · `2` uso errato · `3` errori di analisi.

Esempi:

```bash
gauntler ~/Downloads -q
gauntler . -x "**/node_modules/**" -f sarif -o gauntler.sarif --fail-on high   # GitHub code scanning
curl -s https://esempio.it/install.sh | gauntler - --name install.sh -l
gauntler watch ~/Downloads --notify --quarantine
gauntler config add passwords infected2024 && gauntler config add exclude "**/.git/**"
```

## Configurazione e dati (`~/.gauntler`, oppure `GAUNTLER_HOME`)

- `config.json`: soglia, thread, timeout, password archivi, esclusioni, criteri disattivati, pesi, allowlist, suppress, regole YARA, chiavi API.
- `cache/`: risultati per impronta SHA-256 (invalidata automaticamente quando cambia il motore).
- `history.jsonl`, `quarantine/`, `feeds/` (impronte scaricate), `yara/` (regole `.yar` da applicare), `hashes.txt` (impronte personali).

## Estendere

- **Regole YARA della community** (es. YARA-Forge): copia i file `.yar` in `~/.gauntler/yara` (serve `brew install yara`).
- **Impronte malevole personali**: `~/.gauntler/hashes.txt` (una riga: `sha256 nome`).
- **Nuove regole interne**: `core/data/rules.js` (firme) e `core/data/tokens.js` (indicatori riga per riga).
- **Nuovo criterio**: un modulo in `core/analyzers/` (`{ id, name, weight, applies(ctx), run(ctx) }`) registrato in `core/index.js`.
- **Test**: `npm test` (motore + CLI + avanzati), `npm run test:engine`, `npm run test:cli`, `npm run test:advanced` (disassemblatori, algoritmi, shellcode, CDR).

## Limiti

Analisi statica: non esegue il file. Un punteggio alto non garantisce l'assenza di malware sconosciuti o molto offuscati.
Il CDR rende inerti i contenuti attivi conosciuti dei formati supportati; non può correggere vulnerabilità del programma che apre il file (es. un parser di immagini difettoso), né rendere sicuri programmi e script.
Il disassemblatore non supporta MIPS/ARM32/RISC-V; il codice .NET (IL), Java e Python compilato non viene disassemblato.
Per RAR/7z/ISO serve 7-Zip o bsdtar (su macOS bsdtar è già presente; per tutti i formati: `brew install sevenzip`). ZIP con cifratura AES e immagini DMG non vengono aperti.

## Licenza

Gauntler è creato da **anvex2012** ed è distribuito con la **Gauntler Custom Source Code License 1.0** (vedi [`licenza-gauntler.txt`](licenza-gauntler.txt)).

In breve: puoi usare, studiare, modificare e ridistribuire il codice **gratuitamente**, mantenendo il codice sorgente pubblico, includendo la licenza e conservando in ogni file l'attribuzione a `anvex2012`. La vendita del software o di versioni derivate è vietata.

© 2026 anvex2012
