<!-- Created by anvex2012 -->
# Gauntler — Instructions

Gauntler analyzes the security of any file (programs, documents, archives, scripts, emails, images) and gives it a score from **1 to 100** (100 = safe). **The whole analysis happens on your computer**: no file is sent over the Internet.

You can use it in two ways, with the same analysis engine:

| | Requirements | How to start it |
|---|---|---|
| **Terminal** (GitHub source zip) | Node.js | `gauntler` |
| **macOS desktop app** (`.dmg` / `.zip`) | nothing | double-click Gauntler, or `gauntler` in the terminal |
| **Windows desktop app** (`.zip`) | nothing | `Gauntler.exe` |
| **Linux desktop app** (`.tar.gz`) | nothing | `./gauntler`, or `gauntler` in the terminal after `./install.sh` |

### Where to download
All the files are on the **[Releases](https://github.com/anvex2012/Gauntler/releases/latest)** page:

| System | File |
|---|---|
| macOS (Apple silicon: M1, M2, M3, M4…) | `Gauntler-<version>-macOS-arm64.dmg` (or the `.zip`) |
| Windows 10/11 (64-bit) | `Gauntler-<version>-Windows-x64.zip` |
| Linux (64-bit) | `Gauntler-<version>-Linux-x64.tar.gz` |
| Source code (terminal use) | **Source code (zip)**, or on GitHub **Code → Download ZIP** |

`SHA256SUMS.txt` contains the fingerprints to verify the downloaded files (`shasum -a 256 -c SHA256SUMS.txt`).

Either way, **after the first launch the `gauntler` command works from any terminal folder.**

---

## Language

Gauntler is available in **Italian, English, Spanish, French and German** (interface, terminal and analysis results).

- **On first use** (app or terminal) you are asked to choose the language; the choice applies to both.
- **To change it later:**
  - app: **Settings → Appearance → Language** (results already on screen are translated right away);
  - terminal: `gauntler language` (interactive choice) or `gauntler language en`;
  - interactive interface: `/language en`;
  - for a single run: `gauntler --lang fr file.pdf`.
- The language is saved in `~/.gauntler/config.json` (key `language`).

---

## 1. Installation from the terminal (GitHub zip)

### Requirements
- **macOS** or **Linux**
- **Node.js 18 or later**: check with `node -v`. If it is missing, install it from <https://nodejs.org> or with `brew install node`.
- Terminal use **does not need `npm install`**: the engine has no external dependencies.

### Steps
1. On GitHub press **Code → Download ZIP** and extract the zip, for example into `~/Coding/Gauntler`.
2. Open the **Terminal** and go into the folder:
   ```bash
   cd ~/Coding/Gauntler
   ```
3. **First launch**:
   ```bash
   node cli/gauntler.js
   ```
   On first launch Gauntler:
   - asks you to choose the language;
   - creates the `gauntler` command in `~/.local/bin` (no administrator password);
   - if needed, adds `~/.local/bin` to the PATH in the shell startup file (`~/.zshrc` on macOS);
   - confirms the installation with the message **✔ "gauntler" command installed**;
   - installs the additional components **ClamAV** (antivirus, with signatures) and **bsdtar** if missing (see section 5).
4. **Open a new terminal window.** From now on, wherever you are, just type:
   ```bash
   gauntler
   ```

> Do not move or delete the project folder: the `gauntler` command uses the code in it. If you move it, repeat step 3 from the new location with `node cli/gauntler.js install-command`.

---

## 2. Installing the desktop app (macOS)

### Method 1 — from the `.dmg` file, like any other app (no terminal)
1. Download `Gauntler-<version>-macOS-arm64.dmg` from the [Releases](https://github.com/anvex2012/Gauntler/releases/latest) page and double-click it.
2. In the window that opens, **drag Gauntler onto the Applications folder**.
3. Open **Gauntler** from Applications (or Launchpad). **Only the first time**, macOS shows *"Apple could not verify Gauntler is free of malware"*. This happens because the app is not notarized by Apple (that requires a paid Apple Developer membership). To unblock it:
   1. press **Done** (not "Move to Trash");
   2. open **System Settings → Privacy & Security**;
   3. scroll to *"Gauntler was blocked…"* and press **Open Anyway**;
   4. confirm with your password or Touch ID.

   From then on it opens normally. On macOS 15 and later the old "right-click → Open" is no longer enough.
4. **Done: nothing else to do.** On first launch the app asks for the language and then installs, in the background:
   - the `gauntler` terminal command;
   - the **ClamAV** antivirus, with its signatures;
   - **bsdtar**.

   Progress is shown at the top of the window. If needed, macOS asks for the administrator password with its own window.

### Method 2 — with a command in the Terminal (optional)
If you prefer the terminal, this command installs and opens the app **without the first-launch block**, because files downloaded with `curl` are not quarantined:
```bash
curl -fsSL https://raw.githubusercontent.com/anvex2012/Gauntler/main/install.sh | sh
```
The script:
- downloads the latest version and verifies its SHA-256 fingerprint;
- installs it in **Applications** and opens it.

It also works for updating, and on Linux.

### After installation
- On first launch the app installs the `gauntler` terminal command by itself and, in the background, **ClamAV** and **bsdtar** (see section 5).
- **It works even without Node.js**, because it uses the engine included in the app.
- Open a **new** terminal window and type `gauntler`.

### Building the app from the sources
You need Node.js and `npm install` once:
```bash
cd ~/Coding/Gauntler
npm install
npm run package          # creates release/Gauntler.app
```
Then follow the steps above with `release/Gauntler.app`.

To create **all** the release files (dmg and zip for macOS, zip for Windows, tar.gz for Linux) in `release/upload/`:
```bash
npm run release:build
```

To try the app without packaging it: `npm start` (or `npm run dev` for development).

---

## 2b. Windows

1. Download `Gauntler-<version>-Windows-x64.zip` and extract the **whole** folder (right-click → Extract All).
2. Open **Gauntler.exe**. If "Windows protected your PC" appears (the app has no paid digital signature): **More info → Run anyway**.
3. Drag files or folders into the window, or use **Choose files** / **Choose folder**.

For convenience you can move the folder to `C:\Program Files\Gauntler` and create a shortcut to `Gauntler.exe` on the Desktop (right-click → Send to → Desktop).

**Terminal on Windows** (optional): install Node.js, download the source code and run `node cli\gauntler.js` from the project folder (e.g. `node cli\gauntler.js C:\Users\name\Downloads\file.pdf`). On Windows the `gauntler` command does not install itself and the `+` button does not open the graphical picker: drag the file into the terminal window or type its path.

## 2c. Linux

```bash
tar -xzf Gauntler-<version>-Linux-x64.tar.gz
cd Gauntler-<version>-Linux-x64
./gauntler              # opens the app
./install.sh            # optional: applications menu + "gauntler" command in the terminal
```
After `./install.sh` open a new terminal and type `gauntler`: it works even without Node.js. The first launch of the app also installs the command by itself. (Packages up to version 2.4.0 call the installer `installa.sh`.)

To use the Chromium sandbox (recommended), once:
```bash
sudo chown root:root chrome-sandbox && sudo chmod 4755 chrome-sandbox
```
Without this step the app still starts, but without the sandbox.

---

## 3. Using the terminal interface

Type `gauntler` with nothing else: the full-screen interface opens.

```
 ◆ Gauntler 2.4.0  │  File security analysis                 ● ClamAV   ○ 7-Zip
 ──────────────────────────────────────────────────────────────────────────────
   (results appear here)

 ╭────────────────────────────────────────────────────────────────────────────╮
 │ › Drop a file here, type a path or a /command…                             │
 ╰────────────────────────────────────────────────────────────────────────────╯
  +   Add files  ·  / commands  ·  Ctrl+C quit
```

### How to add a file
There are three ways:

1. **`+` button** at the bottom left: click it, or press `+` or `Tab`. A menu opens:
   - **File…**: opens the Finder picker (you can choose several files);
   - **Folder…**: analyzes every file in a folder and its subfolders;
   - **Type a path**.
2. **Drag** a file or folder from the Finder into the terminal window: the analysis starts right away.
3. **Type or paste a path** and press `Enter`, for example `~/Downloads/invoice.pdf`.

### Reading the result
For each file you see the score, the verdict and the main problems:

| Score | Verdict |
|---|---|
| 90–100 | Safe |
| 70–89 | Low risk |
| 40–69 | Suspicious |
| 15–39 | Dangerous |
| 1–14 | Malicious |

Each result has a number (`#1`, `#2`…), used with the commands below.

### Commands (type `/` to see the suggestions)
The names below are shown in English, Spanish, French and German; in Italian the interface shows the Italian names (`/cartella`, `/dettagli`, `/elenco`, `/esporta`, `/pulisci`, `/lingua`, `/aiuto`, `/esci`). Both always work.

| Command | What it does |
|---|---|
| `/file` | Choose one or more files to analyze |
| `/folder` | Choose a folder to analyze |
| `/report 2` | Full report of result #2 (without a number: the last one) |
| `/details 2` | Report with flagged lines and all the checks |
| `/list` | All the files analyzed in the session |
| `/export report.html` | Save the results (`.html`, `.json`, `.sarif`, `.csv`, `.md`) |
| `/clear` | Clear the screen |
| `/mouse` | Turn the mouse on or off (turn it off to select and copy text) |
| `/language en` | Change the language (it, en, es, fr, de) |
| `/help` | Help and shortcuts |
| `/quit` | Close Gauntler |

### Keys
| Key | Action |
|---|---|
| `+` or `Tab` | "Add" menu |
| `Ctrl+O` | File picker |
| `Ctrl+K` | Folder picker |
| `PgUp` / `PgDn`, mouse wheel | Scroll the results |
| `↑` / `↓` | Previously typed commands |
| `Esc` | Clear the line or close the menu |
| `Ctrl+L` | Clear the screen |
| `Ctrl+C` | Quit (with an empty line) |

---

## 4. Direct commands (without the interface)

Useful in scripts or for a quick analysis:

```bash
gauntler ~/Downloads/invoice.pdf          # analyzes a file and prints the report
gauntler ~/Downloads -q                   # one line per file, in parallel
gauntler attachment.zip -l                # report with the flagged lines
gauntler sanitize invoice.docm            # creates a safe copy (invoice.safe.docx)
gauntler watch ~/Downloads --notify       # monitors new files in real time
gauntler app ~/Downloads/file.zip         # opens the desktop app with the file
gauntler language                         # changes the language
gauntler doctor                           # checks the environment
gauntler --help                           # all the commands
gauntler <command> --help                 # help for a command
```

---

## 5. Additional components: ClamAV and bsdtar

**They install themselves** the first time you start Gauntler, from the terminal (`gauntler`, or `gauntler install-command`) or by opening the desktop app.

| Component | What it is for | How it is installed |
|---|---|---|
| **ClamAV** + antivirus signatures | Additional antivirus scan (millions of signatures) | macOS: Homebrew, or the official ClamAV package if Homebrew is missing · Linux: apt / dnf / yum / pacman / zypper · Windows: winget, or the official `.msi` package |
| **bsdtar** | RAR, 7z, ISO, CAB archives | macOS and Windows 10/11: already included in the system · Linux: `libarchive-tools` / `bsdtar` |

- You may be asked for the **administrator password**: in the terminal with `sudo`; in the app with the system window (macOS, Linux) or the Windows permission prompt. With Homebrew on macOS no password is needed.
- The **antivirus signatures** (about 200 MB) are downloaded to `~/.gauntler/clamav`. They are updated with `gauntler update` and, in the app, automatically every few days, without a password.
- In the terminal you can **skip** the installation with `Ctrl+C`. In the app, progress is shown at the top during installation; if ClamAV is missing, the **Install ClamAV** button at the top starts it again.

Useful commands:
```bash
gauntler setup            # installs whatever is missing (run it again whenever you like)
gauntler setup --status   # shows what is installed
gauntler update           # updates antivirus signatures and malware lists
gauntler doctor           # full environment check
```

To install nothing automatically: `GAUNTLER_NO_AUTOINSTALL=1` (also applies to the `gauntler` command).

Optional, for the most recent RAR archives: **7-Zip** (`brew install sevenzip` on macOS). Use `gauntler doctor` to see what is active.

---

## 6. Common problems

**`gauntler: command not found`**
Open a **new** terminal window: the PATH is read only when it opens. If the problem persists, run from the project folder:
```bash
node cli/gauntler.js install-command
```
and open a new terminal.

**I cannot select text in the interface**
Type `/mouse` to turn the mouse off, then select normally. Type `/mouse` again to turn it back on.

**The `+` button does not open the Finder**
The graphical picker exists only on macOS. On Linux and Windows drag the file into the window or type its path.

**The app does not open on a Mac with an Intel processor**
The release app is for Apple silicon (M1 and later). On an Intel Mac use the terminal version (section 1), or build the app on your Mac with `npm install && npm run package`.

**macOS says the app is damaged, that Apple cannot verify it, or that it cannot be opened**
The app is not notarized by Apple, and macOS blocks apps downloaded from the browser. Two solutions:
- **System Settings → Privacy & Security → Open Anyway** (see section 2, method 1);
- or reinstall with the method 2 command, which is not blocked:
  ```bash
  curl -fsSL https://raw.githubusercontent.com/anvex2012/Gauntler/main/install.sh | sh
  ```

**The `gauntler` command uses an old version**
If you installed it from the sources, `gauntler` always uses the code in the project folder. If you use it through the app, replace the app in Applications with the new one.

---

## 7. Uninstalling

```bash
gauntler uninstall-command
```
It removes the `gauntler` command and the line added to the PATH. Then:
- **Desktop app**: drag Gauntler.app to the Trash;
- **Sources**: delete the project folder;
- **Data and settings** (history, quarantine, configuration, language): delete the `~/.gauntler` folder.

To prevent the command from installing itself on first launch, set `GAUNTLER_NO_AUTOINSTALL=1`.

---

## License

Gauntler is created by **anvex2012** and distributed under the **Gauntler Custom Source Code License 1.0**: see [`LICENSE.txt`](LICENSE.txt).

© 2026 anvex2012
