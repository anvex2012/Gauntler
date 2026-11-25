// Creato da anvex2012
'use strict';
const { mask, findAll, strEntropy, truncate, isDoc } = require('../utils');

// Patterns inspired by gitleaks / trufflehog / detect-secrets. group = which capture group is the secret
const PATTERNS = [
  ['private_key', 'Chiave privata', 'critical', /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED |SSH2 ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g],
  ['putty_key', 'Chiave privata PuTTY', 'critical', /PuTTY-User-Key-File-\d: /g],
  ['aws_access_key', 'AWS Access Key ID', 'high', /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[0-9A-Z]{16}\b/g],
  ['aws_secret', 'AWS Secret Access Key', 'critical', /aws.{0,20}(?:secret|private).{0,20}[:=]\s*['"]?([A-Za-z0-9/+=]{40})\b/gi, 1],
  ['aws_session', 'AWS Session Token', 'high', /aws.{0,20}session.{0,10}token.{0,5}[:=]\s*['"]?([A-Za-z0-9/+=]{100,})/gi, 1],
  ['github_token', 'Token GitHub', 'critical', /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b/g],
  ['gitlab_token', 'Token GitLab', 'critical', /\bgl(?:pat|ptt|dt|rt|soat|cbt|imt|agent)-[A-Za-z0-9_-]{20,}\b/g],
  ['bitbucket', 'App password Bitbucket', 'high', /\bATBB[A-Za-z0-9_=.-]{28,}\b/g],
  ['atlassian', 'Token Atlassian', 'high', /\bATATT3[A-Za-z0-9_=-]{150,}\b/g],
  ['slack_token', 'Token Slack', 'high', /\bxox[baprse]-[A-Za-z0-9-]{10,72}\b/g],
  ['slack_app', 'Token app Slack', 'high', /\bxapp-\d-[A-Z0-9]+-\d+-[a-f0-9]+\b/g],
  ['slack_webhook', 'Webhook Slack', 'medium', /https:\/\/hooks\.slack\.com\/(?:services|workflows)\/[A-Za-z0-9/_-]{20,}/g],
  ['teams_webhook', 'Webhook Microsoft Teams', 'medium', /https:\/\/[a-z0-9-]+\.webhook\.office\.com\/webhookb2\/[A-Za-z0-9@/-]+/g],
  ['discord_webhook', 'Webhook Discord', 'medium', /https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]{60,}/g],
  ['stripe_key', 'Chiave Stripe live', 'critical', /\b(?:sk|rk)_live_[0-9a-zA-Z]{24,99}\b/g],
  ['stripe_test', 'Chiave Stripe di test', 'low', /\b(?:sk|rk)_test_[0-9a-zA-Z]{24,99}\b/g],
  ['paypal_braintree', 'Token PayPal/Braintree', 'critical', /access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/g],
  ['square', 'Token Square', 'high', /\bsq0(?:atp|csp)-[0-9A-Za-z_-]{22,43}\b/g],
  ['shopify', 'Token Shopify', 'high', /\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b/g],
  ['google_api', 'Chiave API Google', 'high', /\bAIza[0-9A-Za-z_-]{35}\b/g],
  ['google_oauth', 'Client secret Google OAuth', 'high', /\bGOCSPX-[A-Za-z0-9_-]{28}\b/g],
  ['gcp_service_account', 'Account di servizio Google Cloud', 'critical', /"type"\s*:\s*"service_account"[\s\S]{0,600}"private_key"/g],
  ['azure_storage', 'Chiave Azure Storage', 'critical', /AccountKey=[A-Za-z0-9+/=]{80,90}/g],
  ['azure_sas', 'Token SAS Azure', 'medium', /[?&]sig=[A-Za-z0-9%+/=]{40,}(?:&|$)/g],
  ['azure_client_secret', 'Client secret Azure AD', 'high', /\b[A-Za-z0-9_~.-]{3}\dQ~[A-Za-z0-9_~.-]{31,34}\b/g],
  ['openai_key', 'Chiave API OpenAI', 'critical', /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b|\bsk-(?:proj|svcacct)-[A-Za-z0-9_-]{40,}\b/g],
  ['anthropic_key', 'Chiave API Anthropic', 'critical', /\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}\b/g],
  ['hf_token', 'Token Hugging Face', 'high', /\bhf_[A-Za-z0-9]{34,}\b/g],
  ['replicate', 'Token Replicate', 'high', /\br8_[A-Za-z0-9]{37}\b/g],
  ['groq', 'Chiave Groq', 'high', /\bgsk_[A-Za-z0-9]{48,}\b/g],
  ['npm_token', 'Token npm', 'high', /\bnpm_[A-Za-z0-9]{36}\b/g],
  ['pypi_token', 'Token PyPI', 'high', /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b/g],
  ['nuget', 'Chiave NuGet', 'high', /\boy2[a-z0-9]{43}\b/g],
  ['rubygems', 'Token RubyGems', 'high', /\brubygems_[a-f0-9]{48}\b/g],
  ['docker_hub', 'Token Docker Hub', 'high', /\bdckr_pat_[A-Za-z0-9_-]{27,}\b/g],
  ['sendgrid', 'Chiave SendGrid', 'high', /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g],
  ['mailgun', 'Chiave Mailgun', 'high', /\bkey-[0-9a-f]{32}\b/g],
  ['mailchimp', 'Chiave Mailchimp', 'high', /\b[0-9a-f]{32}-us\d{1,2}\b/g],
  ['twilio', 'Chiave Twilio', 'high', /\bSK[0-9a-fA-F]{32}\b/g],
  ['telegram_bot', 'Token bot Telegram', 'high', /\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/g],
  ['discord_token', 'Token Discord', 'high', /\b[MNO][A-Za-z\d]{23,25}\.[\w-]{6}\.[\w-]{27,38}\b/g],
  ['facebook', 'Token Facebook', 'high', /\bEAA[A-Za-z0-9]{90,}\b/g],
  ['twitter_bearer', 'Bearer token X/Twitter', 'high', /\bAAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]{30,}\b/g],
  ['dropbox', 'Token Dropbox', 'high', /\bsl\.[A-Za-z0-9_-]{130,}\b/g],
  ['digitalocean', 'Token DigitalOcean', 'high', /\bdo[pro]_v1_[a-f0-9]{64}\b/g],
  ['vault', 'Token HashiCorp Vault', 'high', /\bhvs\.[A-Za-z0-9_-]{24,}\b/g],
  ['doppler', 'Token Doppler', 'high', /\bdp\.(?:pt|st|sa|ct|scim|audit)\.[A-Za-z0-9]{40,44}\b/g],
  ['linear', 'Chiave Linear', 'high', /\blin_api_[A-Za-z0-9]{40}\b/g],
  ['notion', 'Token Notion', 'high', /\b(?:secret_[A-Za-z0-9]{43}|ntn_[A-Za-z0-9]{40,})\b/g],
  ['supabase', 'Token Supabase', 'high', /\bsbp_[a-f0-9]{40}\b/g],
  ['databricks', 'Token Databricks', 'high', /\bdapi[a-f0-9]{32}(?:-\d)?\b/g],
  ['grafana', 'Token Grafana', 'high', /\bgl(?:c|sa)_[A-Za-z0-9+/=_]{32,}\b/g],
  ['newrelic', 'Chiave New Relic', 'high', /\bNRAK-[A-Z0-9]{27}\b/g],
  ['sentry_dsn', 'DSN Sentry', 'low', /https:\/\/[a-f0-9]{32}@[a-z0-9.-]+\.ingest\.(?:[a-z]+\.)?sentry\.io\/\d+/g],
  ['postman', 'Chiave Postman', 'high', /\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b/g],
  ['mapbox', 'Token segreto Mapbox', 'high', /\bsk\.eyJ[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{20,}\b/g],
  ['age_key', 'Chiave privata age', 'critical', /AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}/g],
  ['alibaba', 'Chiave Alibaba Cloud', 'high', /\bLTAI[A-Za-z0-9]{20}\b/g],
  ['tencent', 'Chiave Tencent Cloud', 'high', /\bAKID[A-Za-z0-9]{32}\b/g],
  ['kubeconfig', 'Credenziali Kubernetes', 'critical', /client-key-data:\s*[A-Za-z0-9+/=]{40,}|\btoken:\s*eyJhbGciOiJSUzI1NiIs[A-Za-z0-9._-]{100,}/g],
  ['docker_auth', 'Credenziali registry Docker', 'high', /"auths"\s*:\s*\{[\s\S]{0,300}"auth"\s*:\s*"([A-Za-z0-9+/=]{16,})"/g, 1],
  ['jwt', 'Token JWT', 'medium', /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g],
  ['basic_auth_header', 'Intestazione Authorization Basic', 'high', /Authorization['"]?\s*[:=]\s*['"]?Basic\s+([A-Za-z0-9+/=]{12,})/gi, 1],
  ['bearer_header', 'Intestazione Authorization Bearer', 'medium', /Authorization['"]?\s*[:=]\s*['"]?Bearer\s+([A-Za-z0-9._~+/=-]{20,})/gi, 1],
  ['db_conn', 'Stringa di connessione database con password', 'high', /\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|redis|rediss|amqps?|mssql|sqlserver|clickhouse|cockroachdb):\/\/[^:\s/'"]+:([^@\s'"]{3,})@[^\s'"]+/gi, 1],
  ['jdbc_password', 'Password in stringa JDBC/ODBC', 'high', /(?:jdbc:[a-z]+:|Server=|Data Source=)[^\n"']{0,200}?(?:password|pwd)=([^;&\s"']{3,})/gi, 1],
  ['url_creds', 'Credenziali dentro un URL', 'high', /\b(?:https?|ftp|ftps|smtp|smtps|ssh|sftp):\/\/[^:\s/'"@]{2,}:([^@\s'"/]{3,})@[A-Za-z0-9.-]+/gi, 1],
  ['netrc', 'Credenziali .netrc', 'high', /\bmachine\s+\S+\s+login\s+\S+\s+password\s+(\S+)/g, 1],
  ['xml_password', 'Password in configurazione XML', 'high', /<(?:password|pass|pwd|secret|apikey|api_key)>([^<]{4,})<\/(?:password|pass|pwd|secret|apikey|api_key)>/gi, 1],
  ['unattend', 'Password in file Unattend/Sysprep', 'critical', /<(?:AdministratorPassword|Password)>\s*<Value>([^<]+)<\/Value>/gi, 1],
  ['gpp_cpassword', 'Password Group Policy (cpassword)', 'critical', /cpassword="([^"]{8,})"/gi, 1],
  ['wifi_psk', 'Password Wi-Fi', 'high', /(?:\bpsk|wpa_passphrase|<keyMaterial>)\s*[=>]\s*"?([^"<\s]{8,63})/gi, 1],
  ['shadow_hash', 'Hash di password (formato Unix)', 'high', /\$(?:1|2[abxy]|5|6|y|argon2id?|scrypt|pbkdf2-sha\d+)\$[^\s:$]{1,60}\$[./A-Za-z0-9+=$]{20,}/g],
  ['htpasswd', 'Hash password Apache (htpasswd)', 'high', /^[\w.-]+:\$apr1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$/gm],
  ['ntlm_dump', 'Dump hash NTLM', 'critical', /\b[^\s:]{1,64}:\d{1,6}:[a-f0-9]{32}:[a-f0-9]{32}:::/gi],
  ['firefox_logins', 'Password salvate di Firefox', 'high', /"encryptedPassword"\s*:\s*"[A-Za-z0-9+/=]{20,}"/g],
  ['password_assign', 'Password scritta in chiaro', 'high',
    /\b([A-Za-z0-9_.-]*(?:password|passwd|passwort|pwd|pass|secret|token|api[_-]?key|apikey|access[_-]?key|auth[_-]?token|client[_-]?secret|private[_-]?key|credential)[A-Za-z0-9_.-]*)["']?\s*(?::=|=>|=|:)\s*["']([^"'\s]{6,256})["']/gi, 2, true],
  ['password_env', 'Password in file di configurazione', 'high',
    /^\s*(?:export\s+)?([A-Z0-9_]*(?:PASSWORD|PASSWD|PASS|SECRET|TOKEN|API_?KEY|PRIVATE_KEY|CREDENTIALS?)[A-Z0-9_]*)\s*[=:]\s*([^\s#'"]{6,256})\s*$/gm, 2, true],
  ['password_natural', 'Password scritta in un testo', 'high',
    /\b(?:password|passwd|parola\s*d'ordine|kennwort|contrase[nñ]a|mot\s+de\s+passe|pin|pwd)\s*(?:è|e'|is|:|=|->)\s*["'“]?([^\s"'”,;]{6,64})/gi, 1, true],
];

const PLACEHOLDER = /^(x+|\*+|\.+|<.*>|\$\{.*\}|\{\{.*\}\}|%.*%|your[_-]?|changeme|password\d*|example|sample|dummy|test|null|none|undefined|true|false|process\.env|os\.environ|env\(|getenv|config\.|settings\.|\$[A-Za-z_]|redacted|placeholder|secret|todo|xxx|\.\.\.|required|optional|string|number|boolean)/i;
const BAD_KEY = /(store|type|mode|name|field|label|placeholder|input|length|policy|prompt|hint|url|path|file|count|id|significant|regex|pattern|format|strength|reset|forgot|confirm|class|style|header|selector|param|validator|rule|message|error|text|title|key[_-]?name|endpoint|expiry|expires|ttl|min|max)s?$/i;
const EXAMPLE_HOST = /@(([a-z0-9-]+\.)*example\.(com|org|net)|localhost|127\.0\.0\.1|host(name)?|domain|server|your[-_]?host|db|database|redis|mongo)([:/'"\s]|$)/i;
const EXAMPLE_CREDS = /^(pass(word)?|pwd|secret|xxx+|\*+|<.*>|\$\{.*|user|username|admin|root|guest|test|changeme)$/i;

function looksLikeCredential(v) {
  if (/^[?@#!]/.test(v) || /\s/.test(v)) return false;
  if (/^[A-Za-z]+$/.test(v) && v.length < 20) return false;
  if (/^[a-z]+([A-Z][a-z]+)+$/.test(v)) return false;
  if (/^[a-z0-9]+([-_.][a-z0-9]+)+$/.test(v) && !/\d{3,}/.test(v)) return false;
  if (/^(https?:|\/|\.\/|[a-z]:\\)/i.test(v)) return false;
  if (/^[\w$]+(\.[\w$]+)+[,;)]*$/.test(v) && !/\d{4,}/.test(v)) return false; // object.property references
  if (/^(exports|module|this|self|window|process|require|import|new|function|return)\b/.test(v)) return false;
  if (/^[A-Z][A-Z0-9_]+[,;]?$/.test(v)) return false; // constants
  if (/^[A-Za-z_$][A-Za-z_$]*[;,)]?$/.test(v)) return false; // single identifier without digits
  if (/^\d+$/.test(v) && v.length < 8) return false;
  return strEntropy(v) >= 3.0;
}

const SENSITIVE_NAMES = [
  [/^id_(rsa|dsa|ecdsa|ed25519)$/i, 'Chiave SSH privata', 'critical'],
  [/^\.env(\..+)?$/i, 'File di variabili d\'ambiente (spesso contiene password)', 'medium'],
  [/\.(pem|key|p12|pfx|jks|keystore|ppk|p8|asc|gpg)$/i, 'File di chiave/certificato privato', 'high'],
  [/\.kdbx?$/i, 'Database di password KeePass', 'medium'],
  [/\.(1pux|opvault|agilekeychain|psafe3|bitwarden)$/i, 'Archivio di un password manager', 'medium'],
  [/^(credentials|secrets?|passwords?|password list|passwd)(\.json|\.ya?ml|\.txt|\.csv|\.xlsx?|\.docx?)?$/i, 'File di credenziali', 'high'],
  [/^\.(netrc|pgpass|git-credentials|htpasswd|npmrc|pypirc|s3cfg|boto|dockercfg)$/i, 'File di credenziali di sistema', 'high'],
  [/^(wallet\.dat|keystore|UTC--.*)$/i, 'Wallet di criptovalute', 'high'],
  [/^(shadow|SAM|SYSTEM|SECURITY|NTDS\.dit|lsass\.dmp)$/, 'Database di password del sistema operativo', 'critical'],
  [/^(Login Data|logins\.json|key4\.db|Cookies|login\.keychain(-db)?)$/i, 'Database di password/cookie del browser o del sistema', 'critical'],
  [/^(kubeconfig|config\.json|terraform\.tfstate|\.tfvars)$/i, 'File di configurazione con possibili segreti', 'low'],
];

module.exports = {
  id: 'secrets',
  name: 'Password & segreti esposti',
  description: `${PATTERNS.length} rilevatori (stile gitleaks/trufflehog) per password, chiavi API, token, chiavi private, hash di password e credenziali — applicati a ogni riga, inclusi i contenuti decodificati, più il rilevamento di stringhe casuali ad alta entropia.`,
  weight: 2,
  textual: true,
  applies: () => true,
  init: () => ({ found: new Map(), seen: new Set(), entropy: [], counts: {} }),

  scan(unit, st, ctx) {
    const text = unit.text;
    const naturalText = ctx.isText && ['text', 'markup', 'document'].includes(ctx.type.family) || unit.extractedKind === 'doctext';
    for (const [id, name, sev, re, group, generic] of PATTERNS) {
      if (generic && unit.kind === 'binary') continue;
      if (id === 'password_natural' && !naturalText) continue;
      for (const m of findAll(text, re)) {
        const val = group ? m[group] : m[0];
        if (!val) continue;
        if (generic) {
          const keyName = id === 'password_natural' ? '' : m[1] || '';
          if (PLACEHOLDER.test(val) || !looksLikeCredential(val) || BAD_KEY.test(keyName)) continue;
        }
        if ((id === 'url_creds' || id === 'db_conn') && (EXAMPLE_HOST.test(m[0]) || EXAMPLE_CREDS.test(val))) continue;
        // In binaries: a token embedded in a base64 block is just a random fragment of it
        if (unit.kind === 'binary' && (/[A-Za-z0-9+/]/.test(text[m.index - 1] || '') || /[A-Za-z0-9+/]/.test(text[m.index + m[0].length] || ''))) continue;
        if (unit.kind === 'binary' && ['wifi_psk', 'password_natural', 'jdbc_password', 'xml_password'].includes(id)) continue;
        // Repetitive values or alphabets (AAAA…, 0123…, ABCD…) are not real secrets
        if (val.length > 16 && id !== 'private_key' && id !== 'putty_key' && (strEntropy(val) < 3.2 || /0123456789|abcdefgh|ABCDEFGH|qwertyui/i.test(val))) continue;
        const key = id + ':' + val;
        const loc = unit.loc(m.index);
        st.counts[id] = (st.counts[id] || 0) + 1;
        const tag = { id: 'secret:' + id, sev, label: name, desc: 'Segreto/credenziale in chiaro.' };
        ctx.annotate(loc, maskLine(unit.lineText(m.index), val), tag);
        if (st.seen.has(key)) { st.found.get(key).locs.push(loc); continue; }
        st.seen.add(key);
        st.found.set(key, { id, name, sev, val, loc, locs: [loc], full: id === 'private_key' || id === 'putty_key' });
      }
    }
    // Random high-entropy strings in quotes (possible undeclared secrets)
    if (unit.kind !== 'binary' && !/lock|\.min\.|\.map$|sum$/i.test(ctx.name)) {
      for (const m of findAll(text, /(?<![\w-]|sha\d{3}-|integrity["']?\s*[:=]\s*["'])["'`]([A-Za-z0-9+/=_-]{24,120})["'`]/g)) {
        const v = m[1];
        if (!/[a-z]/.test(v) || !/[A-Z]/.test(v) || !/\d/.test(v)) continue;
        if (strEntropy(v) < 4.5 || /0123456|abcdefg|ABCDEFG|qwerty/i.test(v)) continue;
        const before = text.slice(Math.max(0, m.index - 40), m.index);
        if (/(hash|integrity|checksum|digest|nonce|sha|md5|id|uuid|etag|key\s*=\s*['"]?\w*\s*$|data:)/i.test(before)) continue;
        const k = 'ent:' + v;
        if (st.seen.has(k)) continue;
        st.seen.add(k);
        const loc = unit.loc(m.index);
        st.entropy.push({ val: v, loc });
        ctx.annotate(loc, maskLine(unit.lineText(m.index), v), { id: 'secret:entropy', sev: 'low', label: 'Stringa casuale ad alta entropia', desc: 'Potrebbe essere una chiave o un token non riconosciuto.' });
      }
    }
  },

  finalize(st, ctx) {
    const out = [];
    const doc = isDoc(ctx.name);
    for (const [re, label, sev] of SENSITIVE_NAMES) {
      if (re.test(ctx.name)) out.push({ severity: sev, title: label, detail: `Il nome "${ctx.name}" indica un file che contiene credenziali.` });
    }
    for (const f of st.found.values()) {
      const generic = ['password_assign', 'password_env', 'password_natural'].includes(f.id);
      out.push({
        severity: doc && generic ? 'low' : f.sev,
        title: f.name,
        detail: `Credenziale in chiaro${f.locs.length > 1 ? `, ripetuta ${f.locs.length} volte` : ''}. Va revocata/cambiata se il file è stato condiviso.`,
        evidence: [f.full ? f.val : mask(f.val)],
        loc: f.loc,
        locs: f.locs,
      });
    }
    if (st.entropy.length) {
      out.push({
        severity: st.entropy.length > 10 ? 'medium' : 'low',
        title: `Stringhe casuali ad alta entropia (${st.entropy.length})`,
        detail: 'Valori casuali tra virgolette che potrebbero essere chiavi o token non riconosciuti dai rilevatori specifici.',
        evidence: st.entropy.slice(0, 5).map((e) => mask(e.val)),
        loc: st.entropy[0].loc,
        locs: st.entropy.map((e) => e.loc),
      });
    }
    const checks = PATTERNS.map(([id, name]) => ({ name: `Ricerca: ${name}`, ok: !st.counts[id], note: st.counts[id] ? `${st.counts[id]} trovati` : 'nessuno' }));
    checks.push({ name: 'Nome del file sensibile', ok: !SENSITIVE_NAMES.some(([re]) => re.test(ctx.name)) });
    checks.push({ name: 'Stringhe casuali ad alta entropia (≥ 4.5 bit/carattere)', ok: !st.entropy.length, note: `${st.entropy.length}` });
    return { findings: out, checks, info: { 'Segreti unici trovati': st.found.size, 'Occorrenze totali': Object.values(st.counts).reduce((a, b) => a + b, 0), 'Stringhe ad alta entropia': st.entropy.length, 'Rilevatori': PATTERNS.length } };
  },
};

/** The line shown in the report has the secret masked */
function maskLine(line, val) {
  return truncate(val && val.length > 3 ? line.split(val).join(mask(val)) : line, 600);
}
