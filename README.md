# SMB Files Scanner

A cross-platform SMB share scanner built for security assessments and penetration testing. Enumerates shares, recursively traverses directories, and detects secrets, credentials, and sensitive data — all without downloading full files. Runs natively on macOS, Linux, and Windows via [impacket](https://github.com/fortra/impacket).

> **For authorized security assessments only.** Always obtain written permission before scanning systems you don't own.

---

## Features

### Secret & Credential Detection — 109 patterns across 11 categories

| Category | What it finds |
|---|---|
| **Cloud** | AWS keys (`AKIA`, `ASIA`), Azure client secrets, GCP service account JSON, DigitalOcean tokens, Heroku, Cloudflare |
| **Tokens** | GitHub PATs, GitLab tokens, Slack (`xox*`), Stripe, Twilio, HashiCorp Vault, npm, JWT, OpenAI (`sk-proj-`), SendGrid, Mailgun, Mailchimp, Discord webhooks, Telegram bots, Shopify, Square, New Relic, Doppler, Atlassian PATs, SonarQube, Grafana, PyPI, RubyGems, JFrog Artifactory |
| **AI_Services** | Anthropic Claude (`sk-ant-`), Groq (`gsk_`), Perplexity (`pplx-`), xAI (`xai-`), Replicate (`r8_`), OpenRouter (`sk-or-`), LangSmith (`lsv2__`), Fireworks, Cohere, Mistral, Together AI, ElevenLabs, AssemblyAI, Stability AI, W&B, Pinecone |
| **Secrets** | PEM/PGP private keys, password assignments, `SECRET_KEY`/`API_KEY` env vars, PowerShell credentials, `net use` passwords, LDAP bind passwords |
| **DB_Connection** | MongoDB, PostgreSQL, MySQL, Redis, MSSQL, Oracle, Cassandra, CouchDB, Elasticsearch, Neo4j, AMQP URIs; ADO.NET connection strings; XML `connectionString=` attributes |
| **Git_Credentials** | Embedded tokens in clone URLs (`https://token@github.com`), `.git/config` remote URLs, `.git-credentials` store entries |
| **OfficeMeta_High** | Domain usernames (`CORP\user`), email addresses, internal UNC paths from Office document metadata |
| **OfficeMeta** | Author names, company, manager, Office version, revision count extracted from `.docx`/`.xlsx`/`.pptx` |
| **Domain_Users** | `DOMAIN\user` patterns in config files, UPN-format service accounts |
| **Network_Addresses** | RFC-1918 IPs, internal hostnames (Jenkins, GitLab, Jira, Grafana, Kibana, etc.) |
| **Shadow_Files** | NTDS.dit, LSASS dumps, VSS snapshots, domain controller backup references |

**HIGH** findings (Cloud, Tokens, AI_Services, Secrets, DB_Connection, Git_Credentials, OfficeMeta_High) print immediately to console and are summarized at the end.

### Smart file handling

- **DeepScan** — reads up to 4 MB of text/config/code files and scans content
- **QuickPeek** — extracts metadata from Office OOXML files (`.docx`, `.xlsx`, `.pptx`) without full content scan; reads only `docProps/core.xml` + `docProps/app.xml`
- **ListOnly** — records archives, PST files, VHDs, certificates without reading content
- **Skip** — ignores media, executables, fonts (configurable)

Office metadata extraction is active even in `--quick` mode — the tool reads only 256 KB per file for the ZIP manifest, so it's fast.

### Scale & speed

- **Parallel host scanning** via `--host-threads`
- **Per-host timeout** via `--host-timeout` (prevents getting stuck on massive shares)
- **Quick mode** (`--quick`) — depth 4, 128 KB read limit, 300 files/dir, 120 s per host, metadata-only for Office files
- **CIDR expansion** with parallel TCP 445 probing (100 threads)
- **Guest fallback** — tries `Guest` before null session (many servers block anonymous SRVSVC but allow Guest)
- **Share probing** — when SRVSVC enumeration is denied, probes 80+ common share names (`htdocs`, `jenkins`, `config`, `backup`, etc.)

### Output

- **Live CSV/JSONL** — each finding is written to disk immediately, not just at the end
- **HTML report** — collapsible sections by category, color-coded severity, auto-opens HIGH sections
- **Console** — real-time colored output, HIGH/MED findings printed as found, summary at the end

---

## Requirements

- Python 3.8+
- Works on macOS, Linux, Windows

```bash
pip install -r requirements.txt
```

```
colorama>=0.4.6
tqdm>=4.65.0
impacket>=0.12.0
```

---

## Usage

```
python smb_scanner.py [--target HOST | --targets-file FILE | --mounted-root PATH] [options]
```

### Target

| Flag | Description |
|---|---|
| `--target HOST` | Single IP, hostname, CIDR (`10.0.0.0/24`), or UNC path (`\\host\share`) |
| `--targets-file FILE` | One target per line; `#` = comment |
| `--mounted-root PATH` | Already-mounted CIFS path — no impacket needed |

### Authentication

| Flag | Description |
|---|---|
| `-u`, `--username` | `DOMAIN\user` or `user@domain` |
| `-p`, `--password` | Password (use `""` for blank) |

Without credentials the scanner tries `Guest` first, then null session.

### Share filters

| Flag | Description |
|---|---|
| `--include-shares LIST` | Comma-separated shares to scan |
| `--exclude-shares LIST` | Comma-separated shares to skip |
| `--include-admin-shares` | Include hidden admin shares (`C$`, `ADMIN$`, etc.) |

### Scan tuning

| Flag | Default | Description |
|---|---|---|
| `--max-depth N` | 10 | Max directory recursion depth |
| `--max-files-per-dir N` | 1000 | Cap files processed per directory |
| `--deepscan-max-bytes N` | 4 MB | Max bytes read per DeepScan file |
| `--quickpeek-max-bytes N` | 1 MB | Max bytes read per QuickPeek file |
| `--threads N` | 1 | Parallel share scanners per host |
| `--host-threads N` | 1 | Parallel hosts scanned simultaneously |
| `--host-timeout N` | — | Max seconds per host before moving on |
| `--quick` | off | Fast preset: depth 4, 128 KB, skip junk dirs, 120 s timeout |
| `--no-office` | off | Metadata-only for Office files (skip full content scan) |
| `--no-office-meta` | off | Skip Office files entirely |
| `--no-skip-defaults` | off | Disable built-in junk-path exclusions |

### Directory / file filters

| Flag | Description |
|---|---|
| `--include-dirs PATTERNS` | Only recurse into dirs matching these regex patterns |
| `--exclude-dirs PATTERNS` | Skip dirs matching these regex patterns |
| `--include-ext .ext` | Only process files with these extensions |
| `--exclude-ext .ext` | Skip files with these extensions |

### Output

| Flag | Description |
|---|---|
| `--csv FILE` | Write results to CSV (live, flushed per finding) |
| `--jsonl FILE` | Write results to JSONL (live, flushed per finding) |
| `-v`, `--verbose` | Verbose output |
| `--dry-run` | Parse arguments and exit — no scanning |

---

## Examples

```bash
# Single host — enumerate all accessible shares
python smb_scanner.py --target 10.0.0.5

# With credentials
python smb_scanner.py --target 10.0.0.5 -u CORP\\alice -p 'S3cr3t!'

# Specific share
python smb_scanner.py --target '\\10.0.0.5\Users'

# CIDR scan — auto-discovers hosts with port 445 open
python smb_scanner.py --target 10.0.0.0/24 --quick --host-threads 10

# Large target list, fast mode, live output
python smb_scanner.py --targets-file hosts.txt \
  --quick --host-threads 5 --threads 3 --host-timeout 60 \
  --csv results.csv --jsonl results.jsonl

# Deeper scan with auth, skip known-noisy dirs
python smb_scanner.py --target 10.0.0.5 -u admin -p pass \
  --max-depth 15 --exclude-dirs '^Windows$' '^node_modules$' \
  --include-admin-shares

# Already-mounted share (no impacket needed)
python smb_scanner.py --mounted-root /mnt/smb_share --csv out.csv
```

---

## Output formats

### Console (live)
```
[+] Connected to 10.0.0.5
    Shares found: Users, htdocs, backup
    Scanning: Users, htdocs, backup

[HIGH] \\10.0.0.5\htdocs\.env  (2.1KB)
         Secrets:DB_PASSWORD=Sup3rS3cr3t
         DB_PASSWORD=Sup3rS3cr3t DATABASE_URL=postgres://...

[HIGH] \\10.0.0.5\Users\alice\Documents\config.json  (8.4KB)
         Cloud:AKIA4X7EXAMPLE12345
         AWS_ACCESS_KEY_ID=AKIA4X7EXAMPLE12345
```

### CSV columns

```
target, share, path, size, last_write, action, reason, interesting,
findings, actual_values, content_snippet, ooxml_meta, errors
```

`last_write` is formatted as `YYYY-MM-DD HH:MM`.

### JSONL record

```json
{
  "target": "10.0.0.5",
  "share": "htdocs",
  "path": ".env",
  "size": 2150,
  "last_write": "2024-11-03 14:22",
  "action": "DeepScan",
  "reason": "exact_filename,content:Secrets",
  "interesting": "HIGH",
  "findings": ["Secrets:(?i)(?:password|...)"],
  "actual_values": ["Secrets:DB_PASSWORD=Sup3rS3cr3t"],
  "content_snippet": "DB_PASSWORD=Sup3rS3cr3t DATABASE_URL=postgres://...",
  "ooxml_meta": {},
  "errors": []
}
```

### HTML report (`scan_summary.html`)

Auto-generated at scan end. Includes:
- Stats bar: HIGH / MED / LOW / Office Meta / Total
- Findings grouped by category (Credentials, Network, Office Metadata Intel, Sensitive Files, Folders, Emails)
- HIGH sections auto-expanded
- Per-finding: value, source path, context snippet (or metadata summary for Office files)

---

## How it works

1. **Connect** — tries `Guest` then null session (or supplied credentials)
2. **Enumerate shares** — SRVSVC first; if denied, probes 80+ common share names
3. **Recurse** — `listPath(share, '\\dir\\*')` per directory up to `--max-depth`
4. **Classify each file** — by extension and filename keywords → DeepScan / QuickPeek / ListOnly / Skip
5. **Read** — streams only the configured byte limit via `getFile()` callback
6. **Scan** — 109 regex patterns across 11 categories; Office files get OOXML metadata analysis
7. **Write** — CSV/JSONL flushed immediately per finding; HTML report written at end

Built-in path exclusions skip Windows system directories (`WinSxS`, `SoftwareDistribution`, `MSOCache`, etc.) to avoid scanning gigabytes of OS files. Use `--no-skip-defaults` to override.

---

## High-value filename detection

Beyond content patterns, the scanner flags these filenames unconditionally as HIGH:

```
web.config  ntds.dit  sam  lsass.dmp  id_rsa  id_ed25519
authorized_keys  .env  .netrc  .pgpass  winscp.ini  sitemanager.xml
connectionstrings.config  terraform.tfstate  kubeconfig
.gitconfig  .git-credentials  serviceaccount.json
application_default_credentials.json  docker-compose.yml
.env.production  .env.staging  openai.json  anthropic.json
```

---

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

This tool is for **authorized security assessments only**. Never scan systems without explicit written permission from the system owner. The authors accept no liability for misuse.
