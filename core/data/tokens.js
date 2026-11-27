// Created by anvex2012
'use strict';
/**
 * Catalog of "tokens" checked on EVERY line / string.
 * [id, regex (no capturing groups), severity, group, label, explanation]
 * Severity: info (context only) · low · medium · high · critical
 */
const GROUPS = {
  exec: 'Esecuzione di comandi', net: 'Rete e download', fs: 'File system', persist: 'Persistenza',
  evasion: 'Elusione difese', cred: 'Credenziali', crypto: 'Crittografia', obf: 'Offuscamento',
  inject: 'Iniezione in memoria', priv: 'Privilegi', recon: 'Ricognizione', destroy: 'Distruzione dati',
  exfil: 'Esfiltrazione', web: 'Vulnerabilità web', deser: 'Deserializzazione', mobile: 'Mobile',
  macos: 'macOS', social: 'Ingegneria sociale', dynamic: 'Codice dinamico', sys: 'Sistema',
};

const T = [
  // ---- Code execution ----
  ['ps_iex', String.raw`\b(?:Invoke-Expression|iex)\b\s*[\(\$'"]`, 'medium', 'exec', 'Invoke-Expression', 'PowerShell esegue una stringa come codice: tecnica principale dei loader.'],
  ['ps_start', String.raw`\bStart-Process\b`, 'low', 'exec', 'Start-Process', 'Avvia un altro programma.'],
  ['ps_hidden', String.raw`-(?:w|win|windowstyle)\s+(?:hidden|1)\b`, 'high', 'evasion', 'Finestra nascosta', 'Esegue PowerShell senza mostrare la finestra all\'utente.'],
  ['ps_bypass', String.raw`-(?:ep|exec|executionpolicy)\s+(?:bypass|unrestricted)\b`, 'medium', 'evasion', 'ExecutionPolicy Bypass', 'Disattiva la protezione che impedisce l\'esecuzione di script.'],
  ['ps_enc', String.raw`\s-(?:e|en|enc|enco|encod|encodedcommand)\s+[A-Za-z0-9+/=]{20,}`, 'high', 'obf', 'Comando PowerShell codificato', 'Il comando è nascosto in base64 (-EncodedCommand).'],
  ['ps_nop', String.raw`\s-(?:nop|noprofile)\b`, 'low', 'evasion', 'NoProfile', 'Avvio PowerShell senza profilo (comune negli attacchi).'],
  ['ps_noni', String.raw`\s-(?:noni|noninteractive)\b`, 'low', 'evasion', 'NonInteractive', 'PowerShell senza interazione utente.'],
  ['cmd_c', String.raw`\bcmd(?:\.exe)?\s+/[ck]\b`, 'low', 'exec', 'cmd /c', 'Esegue un comando del prompt di Windows.'],
  ['wscript_shell', String.raw`WScript\.Shell|Shell\.Application`, 'medium', 'exec', 'WScript.Shell', 'Oggetto che permette a script VBS/JS di eseguire programmi.'],
  ['wsh_run', String.raw`\.(?:Run|ShellExecute)\s*\(?\s*["']|\.Exec\s*\(\s*["'](?:cmd|powershell|wscript|cscript|mshta)`, 'low', 'exec', '.Run / .Exec', 'Avvio di un comando da script.'],
  ['vba_shell', String.raw`\bShell\s*\(|\bVBA\.Shell\b|\bCallByName\b`, 'medium', 'exec', 'Shell() VBA', 'La macro esegue un programma esterno.'],
  ['vba_auto', String.raw`\b(?:Auto_?Open|AutoExec|AutoClose|Document_Open|Document_Close|Workbook_Open|Workbook_Activate|Auto_Close)\b`, 'medium', 'exec', 'Macro ad avvio automatico', 'Codice eseguito appena si apre il documento.'],
  ['create_object', String.raw`\bCreateObject\s*\(`, 'low', 'exec', 'CreateObject', 'Crea oggetti COM (accesso a funzioni di sistema).'],
  ['activex', String.raw`\bnew\s+ActiveXObject\b|\bGetObject\s*\(\s*["']winmgmts`, 'medium', 'exec', 'ActiveX / WMI', 'Accesso a componenti di sistema Windows da script.'],
  ['node_cp', String.raw`\brequire\(\s*['"](?:node:)?child_process['"]\s*\)|\bfrom\s+['"](?:node:)?child_process['"]`, 'low', 'exec', 'child_process', 'Il codice Node.js può eseguire comandi di sistema.'],
  ['node_exec', String.raw`\b(?:execSync|spawnSync|execFileSync)\s*\(`, 'low', 'exec', 'exec sincrono Node.js', 'Esecuzione di comandi di sistema.'],
  ['py_system', String.raw`\bos\.(?:system|popen|exec[lv]p?e?)\s*\(`, 'low', 'exec', 'os.system', 'Python esegue un comando di shell.'],
  ['py_subproc_shell', String.raw`subprocess\.\w+\([^)]*shell\s*=\s*True`, 'medium', 'exec', 'subprocess shell=True', 'Esecuzione via shell (rischio di injection).'],
  ['php_exec', String.raw`\b(?:shell_exec|passthru|proc_open|popen|pcntl_exec)\s*\(`, 'medium', 'exec', 'Esecuzione PHP', 'PHP esegue comandi del server.'],
  ['php_system_input', String.raw`\b(?:system|exec|shell_exec|passthru|assert|eval)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)`, 'critical', 'exec', 'Comando dall\'input utente', 'Esegue ciò che arriva dalla richiesta web: webshell.'],
  ['java_runtime', String.raw`Runtime\.getRuntime\(\)\.exec\s*\(|new\s+ProcessBuilder\s*\(`, 'low', 'exec', 'Runtime.exec', 'Java esegue un processo esterno.'],
  ['dotnet_process', String.raw`Process\.Start\s*\(|ProcessStartInfo`, 'low', 'exec', 'Process.Start', '.NET avvia un processo.'],
  ['sh_pipe_shell', String.raw`(?:curl|wget)\s[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b`, 'medium', 'exec', 'Scarica ed esegue (curl | sh)', 'Esegue uno script direttamente da Internet senza controllarlo.'],
  ['b64_pipe_shell', String.raw`base64\s+(?:-d|--decode|-D)[^|\n]*\|\s*(?:ba|z)?sh\b`, 'high', 'obf', 'Decodifica base64 ed esegue', 'Comando nascosto che viene decodificato ed eseguito.'],
  ['osascript', String.raw`\bosascript\s+-e\b`, 'low', 'macos', 'osascript', 'Esecuzione di AppleScript da riga di comando.'],
  ['mshta', String.raw`\bmshta(?:\.exe)?\b`, 'high', 'exec', 'mshta', 'Esegue applicazioni HTA: spesso abusato dai malware.'],
  ['rundll32', String.raw`\brundll32(?:\.exe)?\b`, 'medium', 'exec', 'rundll32', 'Esegue funzioni di DLL (LOLBin abusato).'],
  ['regsvr32', String.raw`\bregsvr32(?:\.exe)?\b[^\n]*/i:`, 'high', 'exec', 'regsvr32 /i', 'Tecnica "Squiblydoo" per eseguire script remoti.'],
  ['certutil', String.raw`\bcertutil(?:\.exe)?\b[^\n]*-(?:urlcache|decode|decodehex)`, 'high', 'net', 'certutil download/decode', 'Uso improprio di certutil per scaricare o decodificare payload.'],
  ['bitsadmin', String.raw`\bbitsadmin(?:\.exe)?\b[^\n]*/transfer`, 'high', 'net', 'bitsadmin', 'Download in background tramite BITS.'],
  ['msiexec_remote', String.raw`\bmsiexec(?:\.exe)?\b[^\n]*https?://`, 'high', 'net', 'msiexec remoto', 'Installa un pacchetto da Internet.'],
  ['wmic_create', String.raw`\bwmic\b[^\n]*process\s+call\s+create`, 'high', 'exec', 'WMIC process create', 'Creazione di processi via WMI (esecuzione/movimento laterale).'],
  ['installutil', String.raw`\b(?:InstallUtil|MSBuild|regasm|regsvcs|cmstp|odbcconf|forfiles|pcalua|scriptrunner)(?:\.exe)?\b`, 'medium', 'evasion', 'LOLBin di esecuzione', 'Programma Microsoft firmato usato per eseguire codice aggirando i controlli.'],

  // ---- Dynamic code ----
  ['js_eval', String.raw`(?<![\w.$-])eval\s*\(`, 'medium', 'dynamic', 'eval()', 'Esegue una stringa come codice.'],
  ['js_function', String.raw`\bnew\s+Function\s*\(`, 'medium', 'dynamic', 'new Function()', 'Crea codice a runtime da una stringa.'],
  ['js_settimeout_str', String.raw`\bset(?:Timeout|Interval)\s*\(\s*["'\x60]`, 'low', 'dynamic', 'setTimeout con stringa', 'Esegue una stringa come codice dopo un ritardo.'],
  ['doc_write', String.raw`document\.write\s*\(`, 'low', 'dynamic', 'document.write', 'Scrive HTML nella pagina in modo dinamico.'],
  ['py_exec', String.raw`(?<![\w.])(?:exec|eval)\s*\(\s*(?:compile|base64|zlib|marshal|codecs|bytes|__import__|requests|urllib)`, 'high', 'dynamic', 'exec di codice decodificato', 'Python esegue codice ottenuto da decodifica o dalla rete.'],
  ['py_import_dyn', String.raw`__import__\s*\(\s*['"](?:os|subprocess|socket|ctypes)['"]\s*\)`, 'medium', 'dynamic', '__import__ dinamico', 'Importazione nascosta di moduli sensibili.'],
  ['ps_scriptblock', String.raw`\[ScriptBlock\]::Create\s*\(`, 'medium', 'dynamic', 'ScriptBlock::Create', 'PowerShell crea codice a runtime.'],
  ['reflection_load', String.raw`\[(?:System\.)?Reflection\.Assembly\]::Load|Assembly\.Load\s*\(`, 'high', 'inject', 'Assembly.Load', 'Carica un programma .NET direttamente in memoria (fileless).'],
  ['vba_execute', String.raw`\bExecuteGlobal\b|\bExecute\s*\(`, 'medium', 'dynamic', 'Execute (VBScript)', 'Esegue codice VBScript da stringa.'],
  ['php_create_function', String.raw`\bcreate_function\s*\(|preg_replace\s*\(\s*['"].*\/e['"]`, 'high', 'dynamic', 'Codice PHP dinamico', 'Esecuzione di codice da stringa in PHP.'],

  // ---- Network ----
  ['ps_webclient', String.raw`Net\.WebClient|DownloadString\s*\(|DownloadFile\s*\(|DownloadData\s*\(`, 'medium', 'net', 'WebClient download', 'Scarica contenuti da Internet.'],
  ['ps_iwr', String.raw`\b(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b\s+[-'"h$]`, 'low', 'net', 'Invoke-WebRequest', 'Richiesta HTTP da PowerShell.'],
  ['xmlhttp', String.raw`MSXML2\.(?:Server)?XMLHTTP|WinHttp\.WinHttpRequest`, 'medium', 'net', 'XMLHTTP', 'Script che scarica dati da Internet.'],
  ['adodb_stream', String.raw`ADODB\.Stream`, 'medium', 'fs', 'ADODB.Stream', 'Scrive su disco dati binari scaricati (dropper).'],
  ['savetofile', String.raw`\.SaveToFile\s*\(?`, 'medium', 'fs', 'SaveToFile', 'Salva un file scaricato.'],
  ['urldownload', String.raw`URLDownloadToFile[AW]?`, 'high', 'net', 'URLDownloadToFile', 'API Windows che scarica un file da Internet.'],
  ['curl_wget', String.raw`\b(?:curl|wget)\s+[^\n]*https?://`, 'low', 'net', 'curl / wget', 'Download da Internet.'],
  ['raw_socket', String.raw`\bsocket\.socket\s*\(|new\s+(?:System\.Net\.Sockets\.)?TcpClient\s*\(|\bnet\.(?:Socket|connect)\s*\(`, 'low', 'net', 'Socket di rete', 'Connessione di rete diretta.'],
  ['dev_tcp', String.raw`/dev/(?:tcp|udp)/`, 'high', 'net', '/dev/tcp', 'Connessione di rete dalla shell (tipica delle reverse shell).'],
  ['nc_exec', String.raw`\b(?:nc|ncat|netcat)\b[^\n]*\s-[a-z]*e\s`, 'critical', 'net', 'netcat -e', 'Apre una shell remota.'],
  ['ngrok', String.raw`\bngrok\b|trycloudflare\.com|serveo\.net|localhost\.run`, 'medium', 'net', 'Tunnel pubblico', 'Espone un servizio locale su Internet o raggiunge un tunnel.'],
  ['pastebin', String.raw`pastebin\.com/raw|paste\.ee/r|hastebin\.com/raw|rentry\.co|ghostbin`, 'medium', 'net', 'Paste site', 'Payload ospitato su siti di "paste".'],
  ['discord_cdn', String.raw`cdn\.discordapp\.com/attachments|media\.discordapp\.net/attachments`, 'medium', 'net', 'Discord CDN', 'File scaricato da Discord (molto usato per distribuire malware).'],
  ['telegram_api', String.raw`api\.telegram\.org/bot`, 'medium', 'exfil', 'API bot Telegram', 'Invio di dati a un bot Telegram.'],
  ['discord_webhook', String.raw`discord(?:app)?\.com/api/webhooks/`, 'medium', 'exfil', 'Webhook Discord', 'Invio di dati a un canale Discord.'],
  ['user_agent', String.raw`Mozilla/[45]\.0 \((?:Windows|compatible|Macintosh|X11)`, 'info', 'net', 'User-Agent fisso', 'Il programma si finge un browser nelle richieste HTTP.'],
  ['ip_port', String.raw`\b(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}\b`, 'info', 'net', 'IP:porta', 'Indirizzo e porta di rete hardcoded.'],
  ['ftp_upload', String.raw`\bSTOR\s|\bftp\.(?:storbinary|upload)|FtpWebRequest`, 'low', 'exfil', 'Upload FTP', 'Invio di file via FTP.'],
  ['smtp_send', String.raw`SmtpClient|smtplib\.SMTP|System\.Net\.Mail|MailMessage\s*\(`, 'low', 'exfil', 'Invio email', 'Il codice invia email (usato da keylogger/stealer per esfiltrare).'],
  ['dns_tunnel', String.raw`nslookup\s+-q(?:uerytype)?=txt|Resolve-DnsName[^\n]*-Type\s+TXT`, 'medium', 'exfil', 'Query DNS TXT', 'Possibile tunnel DNS o payload in record TXT.'],

  // ---- File system ----
  ['temp_path', String.raw`%TEMP%|\$env:TEMP|%APPDATA%|\$env:APPDATA|GetTempPath|/tmp/[\w.-]+`, 'info', 'fs', 'Cartella temporanea', 'Scrittura in cartelle temporanee (dove i dropper salvano i payload).'],
  ['startup_folder', String.raw`\\{1,2}Start Menu\\{1,2}Programs\\{1,2}Startup|shell:startup`, 'high', 'persist', 'Cartella Esecuzione automatica', 'File copiato per avviarsi a ogni accesso.'],
  ['attrib_hide', String.raw`\battrib\s+\+[hs]\b|\.Attributes\s*=\s*['"]?Hidden`, 'medium', 'evasion', 'Nasconde file', 'Rende un file nascosto/di sistema.'],
  // Order matters (one combined regex, the first rule that matches wins): SUID, then world-writable, then +x
  ['chmod_suid', String.raw`\bchmod\s+(?:u\+s|[2467][0-7]{3})\s`, 'high', 'priv', 'SUID', 'Imposta i permessi SUID (escalation di privilegi).'],
  ['chmod_world', String.raw`\bchmod\s+(?:-R\s+)?(?:[0-7]?[0-7][0-7][2367]|[ao]?\+[rx]*w|o\+[rx]*w)\s`, 'medium', 'fs', 'chmod 777', 'Rende un file scrivibile da tutti gli utenti: chiunque può modificarlo o sostituirlo.'],
  ['chmod_x', String.raw`\bchmod\s+(?:-R\s+)?(?:[ugoa]*\+x|[0-7]?7[0-7][0145])\s`, 'low', 'fs', 'chmod +x', 'Rende un file eseguibile.'],
  ['ld_preload', String.raw`/etc/ld\.so\.preload|LD_PRELOAD=`, 'high', 'inject', 'LD_PRELOAD', 'Inietta librerie in tutti i processi (tecnica rootkit).'],
  ['zone_identifier', String.raw`Zone\.Identifier|Unblock-File`, 'medium', 'evasion', 'Rimozione Mark-of-the-Web', 'Rimuove il contrassegno "scaricato da Internet".'],
  ['quarantine_rm', String.raw`xattr\s+-[a-z]*d[a-z]*\s+com\.apple\.quarantine|xattr\s+-c\b`, 'high', 'evasion', 'Rimozione quarantena macOS', 'Aggira Gatekeeper rimuovendo la quarantena.'],

  // ---- Persistence ----
  ['reg_run', String.raw`\\{1,2}CurrentVersion\\{1,2}Run(?:Once|Services)?\b`, 'high', 'persist', 'Chiave Run del registro', 'Avvio automatico a ogni accesso a Windows.'],
  ['reg_add', String.raw`\breg(?:\.exe)?\s+add\b`, 'low', 'persist', 'reg add', 'Modifica del registro di Windows.'],
  ['schtasks', String.raw`\bschtasks(?:\.exe)?\s+/create\b|Register-ScheduledTask|New-ScheduledTaskAction`, 'high', 'persist', 'Operazione pianificata', 'Crea un\'attività che si riavvia periodicamente.'],
  ['new_service', String.raw`\bsc(?:\.exe)?\s+create\b|New-Service\b|CreateService[AW]?\b`, 'medium', 'persist', 'Nuovo servizio', 'Installa un servizio di sistema.'],
  ['wmi_persist', String.raw`__EventFilter|CommandLineEventConsumer|__FilterToConsumerBinding`, 'critical', 'persist', 'Persistenza WMI', 'Tecnica di persistenza fileless tramite eventi WMI.'],
  ['ifeo', String.raw`Image File Execution Options`, 'high', 'persist', 'IFEO', 'Dirottamento dell\'avvio di programmi (debugger hijack).'],
  ['winlogon', String.raw`\\{1,2}Winlogon\\{1,2}(?:Shell|Userinit|Notify)`, 'high', 'persist', 'Winlogon', 'Modifica della shell di accesso di Windows.'],
  ['launch_agent', String.raw`Library/Launch(?:Agents|Daemons)/|launchctl\s+(?:load|bootstrap|submit)`, 'medium', 'persist', 'LaunchAgent macOS', 'Avvio automatico su macOS.'],
  ['login_items', String.raw`login\s+item|LSSharedFileList|SMAppService`, 'low', 'persist', 'Elementi di login macOS', 'Avvio automatico all\'accesso.'],
  ['crontab', String.raw`\bcrontab\s+-|/etc/cron\.|/var/spool/cron`, 'medium', 'persist', 'Cron', 'Attività pianificata Linux/macOS.'],
  ['systemd', String.raw`systemctl\s+enable|/etc/systemd/system/[\w.-]+\.service`, 'low', 'persist', 'Servizio systemd', 'Avvio automatico come servizio Linux.'],
  ['bashrc', String.raw`>>\s*~?/?(?:[\w/]*/)?\.(?:bashrc|bash_profile|zshrc|profile)\b`, 'medium', 'persist', 'Modifica profilo shell', 'Codice aggiunto all\'avvio della shell.'],
  ['ssh_keys', String.raw`>>\s*~?/?(?:[\w/]*/)?\.ssh/authorized_keys`, 'high', 'persist', 'Chiave SSH aggiunta', 'Backdoor: accesso remoto permanente via SSH.'],
  ['rc_local', String.raw`/etc/rc\.local|/etc/init\.d/`, 'low', 'persist', 'Script di avvio', 'Script eseguito all\'avvio del sistema.'],

  // ---- Defense evasion ----
  ['amsi', String.raw`\bAmsi(?:ScanBuffer|InitFailed|Utils|Context|OpenSession)\b`, 'critical', 'evasion', 'Bypass AMSI', 'Disattiva la scansione antimalware di Windows in memoria.'],
  ['etw_patch', String.raw`EtwEventWrite|NtTraceEvent`, 'high', 'evasion', 'Patch ETW', 'Disattiva il monitoraggio degli eventi di Windows.'],
  ['defender_off', String.raw`Set-MpPreference\s+-Disable|DisableRealtimeMonitoring|DisableAntiSpyware|DisableBehaviorMonitoring`, 'critical', 'evasion', 'Disattiva Defender', 'Spegne la protezione di Windows Defender.'],
  ['defender_excl', String.raw`Add-MpPreference\s+-Exclusion(?:Path|Process|Extension)`, 'high', 'evasion', 'Esclusione Defender', 'Esclude file dalla scansione antivirus.'],
  ['clear_logs', String.raw`\bwevtutil(?:\.exe)?\s+(?:cl|clear-log)\b|Clear-EventLog|Remove-EventLog`, 'high', 'evasion', 'Cancella log', 'Cancella i registri eventi per nascondere le tracce.'],
  ['history_wipe', String.raw`history\s+-c\b|unset\s+HISTFILE|HISTFILE=/dev/null|rm\s+[^\n]*\.bash_history`, 'medium', 'evasion', 'Cancella cronologia', 'Elimina la cronologia dei comandi.'],
  ['firewall_off', String.raw`netsh\s+(?:adv)?firewall\s+set\s+[^\n]*(?:off|disable)|ufw\s+disable|iptables\s+-F\b|Set-NetFirewallProfile[^\n]*-Enabled\s+False`, 'high', 'evasion', 'Disattiva firewall', 'Spegne il firewall.'],
  ['uac_off', String.raw`EnableLUA["'\s]*[,/]?\s*(?:/d\s+)?0|ConsentPromptBehaviorAdmin`, 'high', 'priv', 'Disattiva UAC', 'Disabilita il controllo dell\'account utente.'],
  ['gatekeeper_off', String.raw`spctl\s+--master-disable|csrutil\s+disable|spctl\s+--add`, 'high', 'macos', 'Disattiva Gatekeeper/SIP', 'Disattiva le protezioni di macOS.'],
  ['vm_detect', String.raw`\b(?:VBoxService|VBoxTray|vmtoolsd|vmware|qemu-ga|SbieDll|Sandboxie|wireshark|procmon|x64dbg|ollydbg|ida64)\b`, 'low', 'evasion', 'Rilevamento ambiente di analisi', 'Controlla se è in esecuzione in una macchina virtuale o sotto analisi.'],
  ['debugger_check', String.raw`\bIsDebuggerPresent\b|\bCheckRemoteDebuggerPresent\b|ptrace\s*\(\s*PTRACE_TRACEME`, 'low', 'evasion', 'Anti-debug', 'Rileva se viene analizzato con un debugger.'],
  ['sleep_long', String.raw`(?:Start-Sleep|timeout(?:\.exe)?\s+/t|Sleep\s*\(|ping\s+-n)\s*-?\w*\s*(?:\d{4,})`, 'low', 'evasion', 'Attesa lunga', 'Ritardo per eludere le sandbox automatiche.'],
  ['timestomp', String.raw`\.(?:CreationTime|LastWriteTime|LastAccessTime)\s*=|touch\s+-[a-z]*[rt]\s`, 'medium', 'evasion', 'Timestomping', 'Modifica le date dei file per nascondersi.'],

  // ---- Credentials ----
  ['mimikatz', String.raw`sekurlsa::|lsadump::|kerberos::(?:golden|ptt)|privilege::debug|mimikatz`, 'critical', 'cred', 'Mimikatz', 'Strumento per estrarre le password di Windows dalla memoria.'],
  ['lsass', String.raw`\blsass(?:\.exe|\.dmp)?\b`, 'high', 'cred', 'LSASS', 'Accesso al processo che contiene le credenziali di Windows.'],
  ['minidump', String.raw`comsvcs(?:\.dll)?[^\n]*MiniDump|procdump[^\n]*-ma`, 'critical', 'cred', 'Dump della memoria', 'Copia la memoria di un processo (tipicamente LSASS per le password).'],
  ['reg_save_sam', String.raw`reg(?:\.exe)?\s+save\s+hklm\\{1,2}(?:sam|system|security)`, 'critical', 'cred', 'Copia SAM/SYSTEM', 'Estrae il database delle password di Windows.'],
  ['ntds', String.raw`ntds\.dit|ntdsutil`, 'high', 'cred', 'NTDS', 'Database delle password di Active Directory.'],
  ['browser_logins', String.raw`Login Data|logins\.json|key4\.db|signons\.sqlite|Web Data|Local State`, 'medium', 'cred', 'Password del browser', 'Accesso ai file dove i browser salvano password e cookie.'],
  ['dpapi', String.raw`CryptUnprotectData|ProtectedData\.Unprotect|dpapi`, 'medium', 'cred', 'DPAPI', 'Decifra dati protetti dell\'utente (password salvate).'],
  ['keychain', String.raw`security\s+(?:dump-keychain|find-(?:generic|internet)-password)|login\.keychain`, 'high', 'cred', 'Portachiavi macOS', 'Accesso alle password salvate nel Portachiavi.'],
  ['wallets', String.raw`wallet\.dat|Exodus|Electrum|MetaMask|nkbihfbeogaeaoehlefnkodbefgpgknn|Atomic Wallet|Coinomi|Phantom`, 'low', 'cred', 'Wallet di criptovalute', 'Riferimenti a portafogli di criptovalute.'],
  ['shadow_file', String.raw`/etc/shadow\b`, 'medium', 'cred', '/etc/shadow', 'File delle password di Linux.'],
  ['credential_prompt', String.raw`Get-Credential|CredUIPromptForCredentials|display dialog[^\n]*hidden answer`, 'high', 'cred', 'Finta richiesta password', 'Mostra una finestra per farsi dare la password dall\'utente.'],
  ['kerberoast', String.raw`Invoke-Kerberoast|Rubeus\.exe|Rubeus\s+(?:kerberoast|asktgt|asreproast|dump|s4u|tgtdeleg)|GetUserSPNs`, 'critical', 'cred', 'Kerberoasting', 'Attacco alle credenziali di Active Directory.'],
  ['gpp_cpassword', String.raw`cpassword\s*=\s*["'][^"']+`, 'critical', 'cred', 'GPP cpassword', 'Password delle Group Policy decifrabile pubblicamente.'],

  // ---- Memory injection ----
  ['virtualalloc', String.raw`\bVirtualAlloc(?:Ex)?\b`, 'low', 'inject', 'VirtualAlloc', 'Alloca memoria (spesso per eseguire shellcode).'],
  ['writeprocmem', String.raw`\bWriteProcessMemory\b|\bNtWriteVirtualMemory\b`, 'high', 'inject', 'WriteProcessMemory', 'Scrive codice nella memoria di un altro processo.'],
  ['remotethread', String.raw`\bCreateRemoteThread(?:Ex)?\b|\bNtCreateThreadEx\b|\bRtlCreateUserThread\b`, 'high', 'inject', 'CreateRemoteThread', 'Avvia codice dentro un altro processo.'],
  ['hollowing', String.raw`\b(?:Nt|Zw)UnmapViewOfSection\b|\bSetThreadContext\b`, 'high', 'inject', 'Process hollowing', 'Sostituisce il codice di un processo legittimo.'],
  ['apc', String.raw`\bQueueUserAPC\b|\bNtQueueApcThread\b`, 'medium', 'inject', 'APC injection', 'Iniezione tramite chiamate asincrone.'],
  ['virtualprotect', String.raw`\bVirtualProtect(?:Ex)?\b`, 'low', 'inject', 'VirtualProtect', 'Rende eseguibile un\'area di memoria.'],
  ['ctypes_shellcode', String.raw`ctypes\.windll\.kernel32|ctypes\.CDLL|Marshal\.Copy|Marshal\.GetDelegateForFunctionPointer`, 'medium', 'inject', 'Chiamate native', 'Chiama direttamente funzioni di sistema (spesso per eseguire shellcode).'],
  ['shellcode_hex', String.raw`\\xfc\\xe8\\x[0-9a-f]{2}\\x00\\x00\\x00|\\x31\\xc0\\x50\\x68|0xfc,\s*0xe8,\s*0x8[29]`, 'critical', 'inject', 'Shellcode', 'Sequenza tipica di shellcode (es. Metasploit).'],
  ['dll_inject', String.raw`\bLoadLibrary[AW]?\b[^\n]*\bGetProcAddress\b`, 'low', 'inject', 'Caricamento dinamico DLL', 'Carica funzioni a runtime nascondendole dalla tabella import.'],
  ['ptrace_attach', String.raw`PTRACE_ATTACH|PTRACE_POKETEXT|task_for_pid`, 'high', 'inject', 'Iniezione Unix', 'Modifica la memoria di altri processi su Linux/macOS.'],

  // ---- Privileges ----
  ['runas', String.raw`-Verb\s+RunAs|\brunas(?:\.exe)?\s+/`, 'low', 'priv', 'Esecuzione come amministratore', 'Richiede privilegi elevati.'],
  ['uac_bypass', String.raw`fodhelper|computerdefaults|eventvwr\.exe|ms-settings\\{1,2}shell\\{1,2}open\\{1,2}command|sdclt\.exe|slui\.exe`, 'critical', 'priv', 'Bypass UAC', 'Ottiene privilegi di amministratore senza conferma.'],
  ['sedebug', String.raw`SeDebugPrivilege|AdjustTokenPrivileges|SeImpersonatePrivilege`, 'medium', 'priv', 'Privilegi speciali', 'Richiede privilegi per manipolare altri processi.'],
  ['sudo_nopasswd', String.raw`NOPASSWD\s*:\s*ALL|>>\s*/etc/sudoers`, 'critical', 'priv', 'sudoers', 'Concede privilegi root senza password.'],
  ['potato', String.raw`JuicyPotato|PrintSpoofer|RoguePotato|GodPotato|SweetPotato`, 'critical', 'priv', 'Exploit "Potato"', 'Exploit di escalation a SYSTEM.'],

  // ---- Reconnaissance / lateral movement ----
  ['whoami', String.raw`\bwhoami(?:\s+/(?:all|priv|groups))?\b`, 'info', 'recon', 'whoami', 'Raccoglie informazioni sull\'utente.'],
  ['net_user', String.raw`\bnet(?:\.exe)?\s+(?:user|group|localgroup)\b[^\n]*(?:/domain|/add)`, 'medium', 'recon', 'net user/group', 'Enumera o crea account.'],
  ['nltest', String.raw`\bnltest\b[^\n]*(?:domain_trusts|dclist)|Get-ADComputer|Get-ADUser|BloodHound|SharpHound`, 'high', 'recon', 'Ricognizione Active Directory', 'Mappa il dominio aziendale per attacchi successivi.'],
  ['systeminfo', String.raw`\bsysteminfo\b|\bipconfig\s+/all\b|\bGet-ComputerInfo\b|\buname\s+-a\b`, 'info', 'recon', 'Info di sistema', 'Raccoglie informazioni sul computer.'],
  ['portscan', String.raw`\bnmap\b|\bmasscan\b|Test-NetConnection[^\n]*-Port|\bportscan\b`, 'medium', 'recon', 'Scansione porte', 'Cerca servizi aperti in rete.'],
  ['psexec', String.raw`\bpsexec(?:64)?(?:\.exe)?\b|\\\\[\w.-]+\\(?:ADMIN|C|IPC)\$`, 'high', 'recon', 'Movimento laterale', 'Esecuzione di comandi su altri computer della rete.'],
  ['remote_ps', String.raw`Invoke-Command\s+-ComputerName|Enter-PSSession|New-PSSession`, 'medium', 'recon', 'PowerShell remoto', 'Esecuzione su computer remoti.'],
  ['av_enum', String.raw`AntiVirusProduct|root\\SecurityCenter2`, 'medium', 'recon', 'Enumerazione antivirus', 'Verifica quale antivirus è installato.'],
  ['screenshot', String.raw`CopyFromScreen|BitBlt|screencapture\s|ImageGrab\.grab|pyautogui\.screenshot`, 'medium', 'exfil', 'Cattura schermo', 'Fotografa lo schermo dell\'utente.'],
  ['keylog', String.raw`GetAsyncKeyState|SetWindowsHookEx|WH_KEYBOARD_LL|pynput\.keyboard|CGEventTapCreate`, 'high', 'exfil', 'Keylogger', 'Registra i tasti premuti.'],
  ['clipboard', String.raw`GetClipboardData|Get-Clipboard|pbpaste|clipboard\.(?:paste|get)|navigator\.clipboard\.readText`, 'low', 'exfil', 'Lettura appunti', 'Legge il contenuto degli appunti.'],
  ['webcam_mic', String.raw`capCreateCaptureWindow|getUserMedia|AVCaptureDevice|cv2\.VideoCapture|pyaudio`, 'low', 'exfil', 'Webcam/microfono', 'Accesso a webcam o microfono.'],

  // ---- Destruction / ransomware ----
  ['vss_delete', String.raw`vssadmin(?:\.exe)?\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|Win32_ShadowCopy[^\n]*Delete`, 'critical', 'destroy', 'Elimina copie shadow', 'Cancella i backup di Windows (tipico dei ransomware).'],
  ['bcdedit', String.raw`bcdedit(?:\.exe)?\s+/set[^\n]*(?:recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)`, 'critical', 'destroy', 'Disattiva ripristino', 'Impedisce il ripristino del sistema.'],
  ['wbadmin', String.raw`wbadmin\s+delete|cipher(?:\.exe)?\s+/w:`, 'critical', 'destroy', 'Cancella backup', 'Elimina definitivamente i backup.'],
  ['rm_rf_root', String.raw`rm\s+-[a-z]*r[a-z]*f[a-z]*\s+(?:--no-preserve-root\s+)?/(?:\s|\*|$)|rm\s+-[a-z]*f[a-z]*r[a-z]*\s+/(?:\s|\*|$)`, 'critical', 'destroy', 'rm -rf /', 'Cancella l\'intero disco.'],
  ['fork_bomb', String.raw`:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:`, 'critical', 'destroy', 'Fork bomb', 'Blocca il computer creando processi all\'infinito.'],
  ['dd_disk', String.raw`dd\s+if=/dev/(?:zero|urandom)\s+of=/dev/(?:sd|nvme|disk|hd)`, 'critical', 'destroy', 'Sovrascrive il disco', 'Distrugge i dati del disco.'],
  ['physical_drive', String.raw`\\\\\.\\PhysicalDrive\d`, 'high', 'destroy', 'Accesso diretto al disco', 'Scrittura diretta sul disco (wiper/bootkit).'],
  ['format_drive', String.raw`\bformat(?:\.com)?\s+[a-z]:\s*/[qy]|diskpart|mkfs\.\w+\s+/dev/`, 'high', 'destroy', 'Formattazione', 'Formatta un disco.'],
  ['encrypt_loop', String.raw`(?:AES|Rijndael|ChaCha|Salsa20)[^\n]{0,80}(?:GetFiles|EnumerateFiles|os\.walk|readdir|glob)|(?:GetFiles|EnumerateFiles|os\.walk)[^\n]{0,120}(?:Encrypt|AES|cipher)`, 'high', 'destroy', 'Cifratura massiva di file', 'Cifra in serie i file delle cartelle (comportamento ransomware).'],
  ['ransom_ext', String.raw`\.(?:locked|encrypted|crypt|enc|lockbit|conti|ryuk|wncry|cerber|locky)["']`, 'medium', 'destroy', 'Estensione ransomware', 'Rinomina i file con un\'estensione da ransomware.'],
  ['ransom_text', String.raw`(?:your|all)\s+(?:important\s+)?files\s+(?:have\s+been|are|were)\s+encrypted|i\s+tuoi\s+file\s+sono\s+stati\s+(?:criptati|crittografati|cifrati)`, 'critical', 'destroy', 'Messaggio di riscatto', 'Testo di una richiesta di riscatto.'],

  // ---- Crypto ----
  ['crypto_api', String.raw`\b(?:CryptEncrypt|BCryptEncrypt|CryptGenKey|AesManaged|AesCryptoServiceProvider|RijndaelManaged|Cipher\.getInstance|createCipheriv|Fernet|AES\.new)\b`, 'info', 'crypto', 'Cifratura', 'Uso di funzioni di cifratura.'],
  ['rsa_pubkey', String.raw`-----BEGIN (?:RSA )?PUBLIC KEY-----|<RSAKeyValue>`, 'info', 'crypto', 'Chiave pubblica RSA', 'Chiave pubblica incorporata (usata anche dai ransomware).'],
  ['miner', String.raw`stratum\+(?:tcp|ssl)://|\bxmrig\b|cryptonight|randomx|--donate-level|coinhive`, 'high', 'crypto', 'Cryptominer', 'Mining di criptovalute nascosto.'],
  ['xor_loop', String.raw`\^\s*0x[0-9a-f]{2}\b[^\n]{0,40}(?:for|while)|(?:for|while)[^\n]{0,80}\^\s*(?:key|k)\[`, 'low', 'obf', 'Decodifica XOR', 'Decodifica di dati con XOR (offuscamento classico).'],

  // ---- Obfuscation ----
  ['frombase64', String.raw`FromBase64String|atob\s*\(|base64\.b64decode|base64_decode\s*\(|Buffer\.from\([^)]*['"]base64['"]|b64decode`, 'info', 'obf', 'Decodifica base64', 'Decodifica dati nascosti in base64.'],
  ['fromcharcode', String.raw`String\.fromCharCode|\[char\]\s*\d{2,3}|\bChrW?\s*\(\s*\d+`, 'info', 'obf', 'Caratteri da codici numerici', 'Costruisce stringhe da numeri per nasconderle.'],
  ['unescape', String.raw`\bunescape\s*\(|decodeURIComponent\s*\(\s*['"]%`, 'info', 'obf', 'unescape', 'Decodifica stringhe codificate.'],
  ['gzip_b64', String.raw`H4sIA[A-Za-z0-9+/]{20,}`, 'high', 'obf', 'Payload gzip+base64', 'Dati compressi e codificati (tipici dei loader PowerShell).'],
  ['ps_replace_chain', String.raw`(?:-replace\s*['"][^'"]{1,4}['"]\s*,\s*['"][^'"]{0,4}['"][^\n]*){3,}|(?:\.replace\(\s*['"][^'"]{1,4}['"]\s*,\s*['"][^'"]{0,4}['"]\s*\)){3,}`, 'medium', 'obf', 'Catena di sostituzioni', 'Pulisce una stringa offuscata con molte sostituzioni.'],
  ['split_join', String.raw`\.split\(\s*['"][^'"]*['"]\s*\)\.reverse\(\)\.join|-join\s*\(\s*\$\w+\[\s*-1\s*\.\.`, 'medium', 'obf', 'Stringa invertita', 'Inverte una stringa per nasconderla.'],
  ['ps_tick', String.raw`\b\w*(?:\w\x60){2,}\w*\b`, 'medium', 'obf', 'Backtick PowerShell', 'Caratteri ` inseriti per spezzare parole chiave (es. I`E`X).'],
  ['ps_concat_cmd', String.raw`['"](?:I|Ie|In|Inv)['"]\s*\+\s*['"]|&\s*\(\s*['"]\w{1,3}['"]\s*\+`, 'high', 'obf', 'Comando spezzato', 'Il nome del comando è costruito a pezzi per eludere gli antivirus.'],
  ['js_obfuscator', String.raw`_0x[a-f0-9]{4,6}\b`, 'low', 'obf', 'Variabili _0x', 'Codice passato in un offuscatore JavaScript.'],
  ['jsfuck', String.raw`(?:\[\]\+\[\]|!\+\[\]|\(!\[\]\+\[\]\)){4,}`, 'high', 'obf', 'JSFuck', 'Codice scritto solo con []()!+ per nasconderlo.'],
  ['packer_eval', String.raw`eval\(function\(p,a,c,k,e,[dr]\)`, 'medium', 'obf', 'Packer JS', 'Codice compresso con "packer" (molto usato nel malware web).'],
  ['vba_chr_concat', String.raw`(?:Chr[WB]?\$?\(\s*\d+\s*\)\s*&\s*){4,}`, 'high', 'obf', 'Stringa da Chr()', 'Stringa costruita carattere per carattere in VBA.'],
  ['strreverse', String.raw`\bStrReverse\s*\(`, 'medium', 'obf', 'StrReverse', 'Inverte una stringa per nasconderla.'],
  ['caret_obf', String.raw`(?:\w\^){4,}`, 'medium', 'obf', 'Caret in cmd', 'Caratteri ^ per offuscare comandi batch.'],
  ['env_var_slice', String.raw`%[A-Z]+:~-?\d+,-?\d+%`, 'high', 'obf', 'Sottostringhe di variabili', 'Comando batch costruito estraendo lettere da variabili (offuscamento).'],
  ['long_b64_literal', String.raw`['"\x60][A-Za-z0-9+/]{300,}={0,2}['"\x60]`, 'low', 'obf', 'Grosso blocco base64', 'Dati codificati molto lunghi dentro il codice.'],

  // ---- Web vulnerabilities / payloads ----
  ['sqli', String.raw`'\s*or\s+'?1'?\s*=\s*'?1|union\s+(?:all\s+)?select\s|;\s*drop\s+table|xp_cmdshell|information_schema\.tables`, 'medium', 'web', 'SQL injection', 'Payload di SQL injection.'],
  ['xss', String.raw`<script>\s*alert\s*\(|onerror\s*=\s*["']?alert|javascript:\s*alert\(|<svg[^>]*onload\s*=`, 'medium', 'web', 'XSS', 'Payload di cross-site scripting.'],
  ['log4shell', String.raw`\$\{\s*jndi\s*:\s*(?:ldap|rmi|dns|ldaps|iiop)`, 'critical', 'web', 'Log4Shell', 'Exploit della vulnerabilità Log4j (CVE-2021-44228).'],
  ['path_traversal', String.raw`(?:\.\./){4,}|\.\.%2f\.\.%2f|%2e%2e%2f`, 'medium', 'web', 'Path traversal', 'Tentativo di uscire dalla cartella consentita.'],
  ['ssrf_meta', String.raw`169\.254\.169\.254|metadata\.google\.internal`, 'medium', 'web', 'Metadata cloud', 'Accesso alle credenziali del server cloud (SSRF).'],
  ['webshell_upload', String.raw`move_uploaded_file\s*\(\s*\$_FILES|\$_FILES\[[^\]]+\]\[['"]tmp_name`, 'low', 'web', 'Upload di file', 'Caricamento file sul server (verificare i controlli).'],
  ['iframe_hidden', String.raw`<iframe[^>]+(?:width|height)\s*=\s*["']?[01]["'\s>]|<iframe[^>]+(?:display\s*:\s*none|visibility\s*:\s*hidden)`, 'high', 'web', 'Iframe invisibile', 'Carica una pagina nascosta (drive-by download).'],
  ['meta_refresh', String.raw`<meta[^>]+http-equiv\s*=\s*["']?refresh`, 'low', 'web', 'Reindirizzamento automatico', 'La pagina porta altrove automaticamente.'],
  ['form_external', String.raw`<form[^>]+action\s*=\s*["']https?://`, 'low', 'web', 'Modulo verso sito esterno', 'I dati inseriti vengono inviati a un altro sito.'],
  ['password_input', String.raw`<input[^>]+type\s*=\s*["']?password`, 'low', 'social', 'Campo password', 'La pagina chiede una password.'],
  ['html_smuggle', String.raw`msSaveOrOpenBlob|URL\.createObjectURL\s*\(\s*new\s+Blob|\.download\s*=\s*['"][^'"]+\.(?:exe|zip|iso|img|js|hta|lnk|msi|vbs|one)['"]`, 'high', 'web', 'HTML smuggling', 'La pagina genera e scarica un file direttamente nel browser.'],
  ['clickfix', String.raw`(?:Win\s*\+\s*R|Windows\s*\+\s*R|CTRL\s*\+\s*V)[^\n]{0,200}(?:powershell|cmd|mshta|verify|robot|captcha)|navigator\.clipboard\.writeText\([^)]*(?:powershell|mshta|cmd|curl)`, 'critical', 'social', 'Truffa ClickFix', 'Chiede all\'utente di incollare ed eseguire un comando ("verifica di non essere un robot").'],
  ['crypto_drainer', String.raw`setApprovalForAll|eth_sendTransaction|increaseAllowance|signTypedData_v4`, 'low', 'web', 'Operazioni wallet Web3', 'Richiesta di approvazioni/transazioni su wallet (possibile drainer).'],

  // ---- Deserialization ----
  ['py_pickle', String.raw`\bpickle\.loads?\s*\(|\bmarshal\.loads\s*\(|yaml\.load\s*\((?![^)]*Loader\s*=\s*(?:yaml\.)?SafeLoader)`, 'medium', 'deser', 'Deserializzazione insicura', 'Caricare dati non fidati può eseguire codice.'],
  ['java_deser', String.raw`ObjectInputStream|readObject\s*\(\)|XMLDecoder|ysoserial`, 'low', 'deser', 'Deserializzazione Java', 'Possibile vettore di esecuzione remota.'],
  ['dotnet_deser', String.raw`BinaryFormatter|LosFormatter|ObjectStateFormatter|TypeNameHandling\.(?:All|Auto)`, 'medium', 'deser', 'Deserializzazione .NET', 'Serializzatore non sicuro.'],
  ['php_unserialize', String.raw`\bunserialize\s*\(\s*\$_`, 'high', 'deser', 'unserialize su input', 'Deserializzazione di input utente in PHP.'],

  // ---- Mobile ----
  ['android_sms', String.raw`android\.permission\.(?:SEND_SMS|READ_SMS|RECEIVE_SMS)|SmsManager`, 'medium', 'mobile', 'Accesso SMS', 'L\'app può leggere/inviare SMS (furto codici OTP, abbonamenti).'],
  ['android_accessibility', String.raw`BIND_ACCESSIBILITY_SERVICE|AccessibilityService`, 'medium', 'mobile', 'Servizio accessibilità', 'Controllo completo dello schermo (usato dai trojan bancari).'],
  ['android_admin', String.raw`BIND_DEVICE_ADMIN|DevicePolicyManager`, 'medium', 'mobile', 'Amministratore dispositivo', 'L\'app chiede privilegi da amministratore.'],
  ['android_overlay', String.raw`SYSTEM_ALERT_WINDOW|TYPE_APPLICATION_OVERLAY`, 'low', 'mobile', 'Overlay su altre app', 'Può disegnare sopra altre app (phishing di credenziali).'],
  ['android_install', String.raw`REQUEST_INSTALL_PACKAGES|DexClassLoader|PathClassLoader`, 'medium', 'mobile', 'Installa/carica codice', 'Scarica e carica codice aggiuntivo.'],
  ['android_root', String.raw`\bsu\s+-c\b|/system/xbin/su|Superuser\.apk`, 'medium', 'mobile', 'Root', 'Uso dei permessi di root.'],

  // ---- macOS ----
  ['tcc_db', String.raw`TCC\.db|tccutil\s+reset`, 'high', 'macos', 'Database privacy TCC', 'Manipolazione dei permessi privacy di macOS.'],
  ['mac_entitlement_risky', String.raw`com\.apple\.security\.cs\.(?:disable-library-validation|allow-unsigned-executable-memory|allow-dyld-environment-variables|disable-executable-page-protection)`, 'medium', 'macos', 'Entitlement rischioso', 'Disattiva protezioni di sicurezza dell\'app.'],
  ['dyld_insert', String.raw`DYLD_INSERT_LIBRARIES`, 'high', 'inject', 'DYLD_INSERT_LIBRARIES', 'Iniezione di librerie su macOS.'],

  // ---- Supply chain ----
  ['npm_install_script', String.raw`"(?:pre|post)?install"\s*:\s*"[^"]*(?:curl|wget|node\s+-e|powershell|base64|\|\s*sh|http)`, 'high', 'exec', 'Script di installazione npm sospetto', 'Il pacchetto esegue comandi di rete durante l\'installazione.'],
  ['setup_py_net', String.raw`(?:urllib|requests|socket)[^\n]{0,80}(?:setup\(|cmdclass)|cmdclass\s*=\s*\{[^}]*install`, 'medium', 'exec', 'setup.py personalizzato', 'Codice eseguito durante l\'installazione del pacchetto Python.'],

  // ---- Generic / info ----
  ['todo_hack', String.raw`\b(?:backdoor|rootkit|keylogger|ransomware|infostealer|botnet|shellcode|reverse\s*shell|bind\s*shell|c2\s*server)\b`, 'low', 'sys', 'Parola chiave offensiva', 'Termini tipici del codice malevolo.'],
  ['hardcoded_ip_url', String.raw`https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?/`, 'medium', 'net', 'URL con IP diretto', 'Contatta un server tramite indirizzo IP (senza dominio).'],
  ['onion', String.raw`\b[a-z2-7]{16,56}\.onion\b`, 'high', 'net', 'Indirizzo Tor', 'Riferimento al dark web.'],
  ['private_key_marker', String.raw`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY`, 'critical', 'cred', 'Chiave privata', 'Chiave crittografica privata in chiaro.'],
  ['password_word', String.raw`\b(?:password|passwd|pwd|passphrase|parola\s*d'ordine|kennwort|contrase[nñ]a)\b\s*[:=]`, 'info', 'cred', 'Assegnazione password', 'Riga che assegna una password (vedi criterio "Segreti").'],
];

module.exports = { TOKENS: T, GROUPS };
