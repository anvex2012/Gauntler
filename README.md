<!-- Created by anvex2012 -->
# Gauntler

Security analyzer for **any kind of file**: desktop app (Electron + React) and terminal tool.
The whole analysis is **local**: no file is ever sent over the Internet.

> **Step-by-step installation and usage:** see [INSTRUCTIONS.md](INSTRUCTIONS.md).
>
> **macOS:** download the `.dmg` from [Releases](https://github.com/anvex2012/Gauntler/releases/latest), drag Gauntler to Applications and open it: on first launch the app installs the `gauntler` command, ClamAV and bsdtar by itself.
>
> **Installation from the terminal (macOS and Linux, optional):**
> ```bash
> curl -fsSL https://raw.githubusercontent.com/anvex2012/Gauntler/main/install.sh | sh
> ```

**Languages:** Italian, English, Spanish, French and German — app, terminal and analysis results. The language is chosen on first use and can be changed at any time (app: Settings → Appearance → Language; terminal: `gauntler language`).

Every file gets an **overall score from 1 to 100** (100 = safe) and a score for each criterion.

| Score | Verdict |
|---|---|
| 90–100 | Safe |
| 70–89 | Low risk |
| 40–69 | Suspicious |
| 15–39 | Dangerous |
| 1–14 | Malicious |

## In-depth analysis, no limits

- **Files of any size**: analysis in 64 MB overlapping blocks, 100% of the bytes (even multi-GB files).
- **Every line, every word**: over 200 indicators applied to every line (or to every string extracted from binaries), with an explanation for each flagged line.
- **No occurrence limit**: every match is reported with its location (line/offset).
- **Recursive decoding**: base64, MIME base64, data URIs, hex, charcodes, gzip/zlib, PowerShell `-EncodedCommand`, up to 10 nested levels. Every decoded payload is re-analyzed by all criteria.
- **Deep extraction**: decompressed VBA macros (MS-OVBA), every decompressed PDF stream (Flate/ASCIIHex/ASCII85) + visible text, Office XML parts, RTF objects, PDF attachments, data appended to images.
- **Archives**: ZIP/JAR/APK (including ZIP64 and password-protected: over 30 common passwords + custom passwords), TAR, GZIP, RAR/7z/ISO/CAB/PKG/XZ/BZ2 through 7-Zip/bsdtar. Every inner file is analyzed with all criteria, recursively (up to 12 levels, against "zip quines").
- **Protection against decompression bombs** (ZIP, nested ZIPs, overlapping entries, GZIP, PDF streams, encoded gzip/zlib payloads, 7-Zip/xz/bzip2): a single budget for the whole analysis of a file, with strict limits — 256 MB per object, 1 GB decompressed in total, 100:1 compression ratio (above 16 MB), 10,000 files, 2 GB of memory. When a limit is exceeded, extraction and analysis stop immediately and the file gets a critical finding. Limits can be changed with `"limits"` in `~/.gauntler/config.json` (`maxEntryBytes`, `maxTotalBytes`, `maxRatio`, `ratioMinBytes`, `maxFiles`, `maxMemoryBytes`). Archives opened with bsdtar are converted into a tar stream read in memory with an exact cap (nothing decompressed touches the disk); 7-Zip and unar extract to disk under continuous monitoring and are stopped as soon as they exceed the limit.
- **ClamAV with no limits**: file size, recursion, heuristics, macros, encrypted archives.

## Criteria (17, each scored 1–100)

| Criterion | What it analyzes |
|---|---|
| Identity & disguise | real content vs extension, double extensions, RTLO, homoglyphs, bait names |
| Malware signatures | known fingerprints + 56 YARA-style rules (ransomware/RAT/stealer/botnet families, webshells, exploits, MITRE techniques) |
| ClamAV | antivirus engine, if installed |
| Executable | PE/.NET, ELF, Mach-O: signature, imphash, version info, fake Microsoft, packers, sections/segments, APIs, protections, entitlements |
| Machine code | x86/x86-64/ARM64 disassembly, control-flow graph, shellcode in any file, API hashes, content hidden with XOR/ADD |
| Active documents | macros, XLM, PDF JavaScript, automatic actions, OLE, DDE, Follina, Equation Editor, LNK, OneNote, CHM |
| Code & obfuscation | 14 density-weighted obfuscation metrics, hidden payloads |
| Line by line | over 200 indicators in 20 categories, Trojan Source, invisible characters, homoglyphs, word statistics |
| Archives & embedded files | zip bombs, Zip Slip, symbolic links, encryption, recursive analysis |
| Passwords & secrets | 78 detectors (cloud, AI, payments, CI/CD, DB, password hashes…) + high-entropy strings |
| Privacy | cards (Luhn), IBAN (mod-97), Italian tax code (check character), VAT numbers, documents, health data |
| Phishing | manipulative language (IT/EN), SPF/DKIM/DMARC, Reply-To, forged sender |
| Network & IOC | URLs, domains, IPv4/IPv6, .onion, wallets, DGA, punycode, brand impersonation |
| Metadata | GPS/EXIF/XMP, Office/PDF author, download origin, permissions |
| YARA rules | real YARA rules (official engine) from `~/.gauntler/yara`, if YARA is installed |
| Online reputation | VirusTotal + MalwareBazaar, only with `--online` (sends only the fingerprint) |
| Statistics | entropy, chi-square + p-value, Monte Carlo π, serial correlation, histogram, polyglot files |

The app shows: overview with radar chart, filterable problems (with jump to the line), **line-by-line code viewer** (with highlighting, heat map and explanations), strings of binaries, list of all checks performed (~200–300 per file), extracted content and inner files (with navigable report), network indicators, metadata, hashes, histogram, hex view. The report can be exported as HTML, JSON, SARIF, CSV or Markdown.

**Settings** (gear icon or `⌘,`): language, light/dark/system theme, accent color, risk level colors (standard, high contrast, color-blind friendly), interface size, density, code font and size, animations; files analyzed in parallel, view after adding files, list order, notification when done, archive passwords (remembered only on request); report start tab, informational findings, default export format. Shortcuts: `⌘O` file, `⇧⌘O` folder, `⌘F` search.

## Machine code: assembly and binary

Gauntler contains its own disassembler (no external dependencies), verified against `objdump`:

- **x86 / x86-64**: prefixes, REX, VEX/EVEX, ModRM/SIB, RIP-relative addressing, 0F/0F38/0F3A maps, x87 (lengths identical to objdump on /bin/zsh: 125,000 instructions).
- **ARM64**: branches, calls, PAC/BTI, syscalls, MRS/MSR, ADR/ADRP, logical immediates, loads/stores and pairs.
- **Recursive descent** from the entry point, exports, TLS callbacks and symbols → **control-flow graph**: functions, basic blocks, loops (back edges with DFS), cyclomatic complexity, code coverage.
- **Behavioral heuristics** on reachable code: GetPC (call/pop, fnstenv, jmp-call-pop), PEB/TEB reads, API name hashing (ROR/ROL), direct syscalls and Hell's Gate stubs, self-decryption loops, stack strings, anti-debug (BeingDebugged, int 2d, ptrace PT_DENY_ATTACH), anti-VM (cpuid 0x40000000, VMware backdoor, Red Pill), NOP sleds.
- **Shellcode in any file** (documents, images, decoded payloads, `%u9090` in JavaScript): anchors + 32- and 64-bit disassembly + scoring on independent behaviors (0 false positives on 512 MB of random data).

```bash
gauntler disasm program.exe            # assembly from the entry point (with symbols and references)
gauntler disasm program.exe -b         # bytes of each instruction in binary (0/1)
gauntler disasm /bin/ls -F             # functions: blocks, loops, complexity
gauntler disasm document.doc           # finds and disassembles hidden shellcode
gauntler disasm payload.bin --raw --arch x64
gauntler disasm file.bin --dump        # the whole file as binary code
```

## Algorithms

| Algorithm | Use |
|---|---|
| Differential XOR/ADD cryptanalysis (`c[i]⊕c[i+L]` does not depend on the key) | recovers repeating keys up to 32 bytes from known plaintext (PE stub, URLs, API names) and decrypts the payload, which is re-analyzed |
| API hash dictionary (ROR13, Metasploit block_api, CRC32, DJB2, SDBM, FNV-1a, ROL5/ROR7-XOR) | recognizes the constants shellcode and loaders use to look up Windows functions |
| CTPH (spamsum/ssdeep), multi-level computation in a single pass | "fuzzy" fingerprint to recognize variants of the same file |
| Iterative DFS on the control-flow graph | loops, cyclomatic complexity, coverage |
| Entropy, chi-square, Monte Carlo, serial correlation | byte statistics |

## Making files safe (CDR: Content Disarm & Reconstruction)

`gauntler sanitize` does more than give a score: it **rebuilds** the file keeping only the safe content, then **re-analyzes it with the whole engine**. If anything dangerous remains after disarming, the file is **blocked** and nothing is produced.

| Type | What is removed |
|---|---|
| PDF | JavaScript, `/OpenAction`, `/AA`, Launch, SubmitForm, ImportData, GoToE/R, RichMedia, attachments, XFA, data after `%%EOF`; object streams expanded and file rewritten from scratch with a new xref (identical rendering) |
| Word/Excel/PowerPoint (OOXML, ODF) | VBA and XLM macros, ActiveX, OLE objects, custom UI, DDE links, remote templates (template injection), `mhtml:`/`file:`/`ms-*` schemes, personal metadata; `.docm` → `.docx` |
| .doc/.xls/.ppt (OLE) | VBA project, embedded objects, Equation Editor (zeroed in place) |
| RTF | `\object`, `\objdata`, `\datastore`, DDE/INCLUDE fields, data after the end |
| HTML/SVG/XML | scripts, iframes, object/embed, `on…` handlers, `javascript:`/`data:` URLs, `foreignObject`, meta refresh, form destinations |
| JPEG/PNG/GIF/WebP/BMP | EXIF/GPS/XMP/comments/unknown chunks, data hidden after the end of the image (polyglots) |
| Text/CSV | bidirectional (Trojan Source) and invisible characters, CSV formulas (`=`, `+`, `-`, `@`) |
| Archives (ZIP, TAR, GZIP, RAR, 7z) | every file disarmed recursively; dangerous files, encrypted files, symbolic links, `../` paths removed |
| Programs, scripts, disk images | cannot be disarmed: they are output only if the analysis is clean (`--strict`: never) |

```bash
gauntler sanitize invoice.docm               # → invoice.safe.docx
gauntler sanitize ~/Downloads -d ~/Safe      # whole folder
gauntler sanitize attachment.pdf --in-place  # replaces the original (which goes to quarantine)
gauntler watch ~/Downloads --sanitize --quarantine
```

Output files never have execute permission and are written atomically. In the app: **Create safe copy** button and **Assembly** tab.

## Getting started

```bash
npm install
npm run dev        # app with hot reload
npm start          # build + start the app
npm test           # tests on generated samples (EICAR, droppers, PDF, ZIP…)
```

You can also open files directly: `npx electron . file1 file2`

**Desktop app (macOS)**: `npm run package` creates `release/Gauntler.app` with Gauntler's name and icon, ad-hoc signed; drag it to Applications and double-click it. On first launch, if macOS blocks it because it does not come from an identified developer: right-click the app → Open.

**`gauntler` terminal command**: it installs **itself** on first launch, both from the sources (`node cli/gauntler.js`) and when opening the desktop app; if needed it adds `~/.local/bin` to the PATH in `~/.zshrc` (block marked `# >>> gauntler >>>`). It can also be installed manually: from the app, Settings → System → Install; or `npm run install-cli`. Together with the command, **ClamAV** (with antivirus signatures in `~/.gauntler/clamav`) and **bsdtar** are installed if missing: Homebrew or the official package on macOS, the package manager on Linux, winget/MSI on Windows. Run it again with `gauntler setup`. To disable automatic installation: `GAUNTLER_NO_AUTOINSTALL=1`. It creates `~/.local/bin/gauntler` (no sudo) which uses the engine included in Gauntler.app, so it also works without Node.js. `gauntler app [file…]` opens the desktop app with the files to analyze; `gauntler uninstall-command` removes the command.

**Release packages**: `npm run release:build` creates in `release/upload/` the `.dmg` and `.zip` for macOS, the `.zip` for Windows (portable folder with `Gauntler.exe`) and the `.tar.gz` for Linux, plus `SHA256SUMS.txt`. Windows and Linux are packaged from macOS with `@electron/packager`, without Wine. The `.dmg` has an installation window with background and instructions (`build/dmg-background.png`, regenerated with `npx electron scripts/build-dmg-background.js`), created with `dmgbuild` (Python 3, installed automatically in `node_modules/.cache`).

**App icon**: the drawing is in `build/icon.svg`; `npm run icon` regenerates `build/icon.png` (Windows/Linux), `build/icon.icns` (macOS) and the interface logo `src/assets/logo.png`.

## Terminal tool

```bash
npm link                     # installs the "gauntler" command
gauntler <file|folder|->     # analyzes (same as "gauntler scan")
gauntler --help              # all commands · gauntler <command> --help for details
```

| Command | What it does |
|---|---|
| `scan` | Parallel analysis (one thread per core) with cache, filters, formats and exit codes for CI |
| `sanitize` | Safe copy of files: disarm and rebuild + verification (CDR) |
| `disasm` | x86/x64/ARM64 assembly, functions and complexity, binary code |
| `watch <folder>` | Real-time protection: analyzes every new file (e.g. Downloads), notifications, quarantine and automatic safe copy (`--sanitize`) |
| `quarantine list/add/restore/delete` | Files made harmless (XOR + read-only) and restorable byte for byte |
| `history` | Analysis history |
| `config` | Configuration in `~/.gauntler/config.json` |
| `language [code]` | Language of the terminal and the app (it, en, es, fr, de) |
| `trust <file>` / `ignore <id>` | Trusted files · findings to ignore (supports `*`) |
| `lookup <file>` | VirusTotal / MalwareBazaar reputation (sends only the SHA-256 fingerprint) |
| `update` | Downloads recent malware fingerprints from abuse.ch (free Auth-Key required) |
| `hash`, `rules`, `cache`, `doctor`, `completion` | Fingerprints · engine rules · cache · environment check · bash/zsh completion |

Main `scan` options:

| Option | |
|---|---|
| `-q` / `-s` / `-v` / `-l` / `-c` | one line per file / summary only / everything / flagged lines / checks |
| `-f text\|json\|sarif\|csv\|md\|html`, `-o file` | report format (inferred from the `-o` extension) |
| `-x glob`, `-i glob`, `--max-size 50M` | exclusions, inclusions, maximum size |
| `-j N`, `--timeout sec` | parallel analyses, maximum time per file |
| `--only` / `--skip criteria` | choose the criteria (`gauntler rules analyzers`) |
| `-t N`, `--fail-on high` | exit code 1 below the threshold or with problems of that level |
| `--quarantine [--quarantine-below N]` | moves malicious files to quarantine |
| `--online`, `--yara dir`, `-p password`, `--ids`, `--no-cache` | reputation, YARA rules, archive passwords, finding ids, re-analysis |
| `--lang xx` | language for this run (it, en, es, fr, de) |

Exit codes: `0` ok · `1` files below threshold / problems · `2` wrong usage · `3` analysis errors.

Examples:

```bash
gauntler ~/Downloads -q
gauntler . -x "**/node_modules/**" -f sarif -o gauntler.sarif --fail-on high   # GitHub code scanning
curl -s https://example.com/install.sh | gauntler - --name install.sh -l
gauntler watch ~/Downloads --notify --quarantine
gauntler config add passwords infected2024 && gauntler config add exclude "**/.git/**"
```

## Configuration and data (`~/.gauntler`, or `GAUNTLER_HOME`)

- `config.json`: language, threshold, threads, timeout, archive passwords, exclusions, disabled criteria, weights, allowlist, suppress, YARA rules, API keys.
- `cache/`: results by SHA-256 fingerprint (invalidated automatically when the engine changes).
- `history.jsonl`, `quarantine/`, `feeds/` (downloaded fingerprints), `yara/` (`.yar` rules to apply), `hashes.txt` (personal fingerprints).

## Extending

- **Community YARA rules** (e.g. YARA-Forge): copy the `.yar` files into `~/.gauntler/yara` (requires `brew install yara`).
- **Personal malicious fingerprints**: `~/.gauntler/hashes.txt` (one line: `sha256 name`).
- **New internal rules**: `core/data/rules.js` (signatures) and `core/data/tokens.js` (line-by-line indicators).
- **New criterion**: a module in `core/analyzers/` (`{ id, name, weight, applies(ctx), run(ctx) }`) registered in `core/index.js`.
- **Translations**: `core/locales/translations.json` maps each Italian text (the key used in the code) to English, Spanish, French and German; texts with variables use `{name}` placeholders.
- **Tests**: `npm test` (engine + CLI + advanced + regression), `npm run test:engine`, `npm run test:cli`, `npm run test:advanced` (disassemblers, algorithms, shellcode, CDR).

## Limitations

Static analysis: the file is never run. A high score does not guarantee the absence of unknown or heavily obfuscated malware.
CDR neutralizes the known active content of the supported formats; it cannot fix vulnerabilities in the program that opens the file (e.g. a faulty image parser), nor make programs and scripts safe.
The disassembler does not support MIPS/ARM32/RISC-V; .NET (IL), Java and compiled Python code is not disassembled.
RAR/7z/ISO require 7-Zip or bsdtar (bsdtar is already included in macOS; for every format: `brew install sevenzip`). ZIP files with AES encryption and DMG images are not opened.

## License

Gauntler is created by **anvex2012** and distributed under the **Gauntler Custom Source Code License 1.0** (see [`LICENSE.txt`](LICENSE.txt)).

In short: you may use, study, modify and redistribute the code **free of charge**, keeping the source code public, including the license and preserving the attribution to `anvex2012` in every file. Selling the software or derived versions is prohibited.

© 2026 anvex2012
