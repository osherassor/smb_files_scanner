<h1 align="center">SMB Files Scanner</h1>

<p align="center">
  <strong>Find the secrets people accidentally left on SMB shares — without downloading half the network.</strong><br>
  Cross-platform, parallel, content-aware. macOS · Linux · Windows.
</p>

<p align="center">
  <img src="https://img.shields.io/github/stars/osherassor/smb_files_scanner?style=for-the-badge&logo=github&color=ffd700" alt="Stars">
  <img src="https://img.shields.io/github/last-commit/osherassor/smb_files_scanner?style=for-the-badge&logo=git&color=00d4aa" alt="Last commit">
  <img src="https://img.shields.io/badge/python-3.8%2B-3776ab?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/license-MIT-informational?style=for-the-badge" alt="License">
</p>

---

> 🛡️ **Authorized assessments only.** Get written permission before scanning anything you don't own.

## What is this?

A Python tool that connects to SMB shares, walks the directory tree, and pulls **109 patterns of secrets** out of files — cloud keys, AI provider tokens, DB connection strings, Office metadata, the works. It's smart about what it reads (deep-scan vs. metadata-only vs. skip), it streams findings to disk live, and it's built for scanning hundreds of hosts in parallel without choking on one.

If you've ever opened a `\fileserver\Public` share on an internal pentest and felt the dread of "where do I even start" — this is the tool.

## 🚀 Quick start

```bash
pip install -r requirements.txt
python smb_scanner.py --target 10.0.0.5
```

That's it. Without creds it tries `Guest`, then null session.

## ✨ What it finds — 109 patterns across 11 categories

| Category | Examples |
|---|---|
| ☁️ **Cloud** | AWS (`AKIA`, `ASIA`), Azure client secrets, GCP service account JSON, DigitalOcean, Heroku, Cloudflare |
| 🎫 **Tokens** | GitHub PATs, GitLab, Slack (`xox*`), Stripe, Twilio, Vault, npm, JWT, OpenAI (`sk-proj-`), SendGrid, Mailgun, Discord webhooks, Telegram bots, Shopify, Atlassian, SonarQube, Grafana, JFrog… |
| 🤖 **AI services** | Anthropic (`sk-ant-`), Groq (`gsk_`), Perplexity (`pplx-`), xAI (`xai-`), Replicate, OpenRouter, LangSmith, Fireworks, Cohere, Mistral, Together, ElevenLabs, AssemblyAI, Stability, W&B, Pinecone |
| 🔑 **Secrets** | PEM/PGP private keys, password assignments, `SECRET_KEY` / `API_KEY` env vars, PowerShell credentials, `net use` passwords, LDAP bind passwords |
| 🗄️ **DB connection strings** | MongoDB, Postgres, MySQL, Redis, MSSQL, Oracle, Cassandra, CouchDB, Elasticsearch, Neo4j, AMQP — plus ADO.NET and XML `connectionString=` attributes |
| 📦 **Git credentials** | Embedded tokens in clone URLs, `.git/config` remotes, `.git-credentials` |
| 📄 **Office metadata (high)** | Domain users (`CORP\user`), email addresses, internal UNC paths from `.docx`/`.xlsx`/`.pptx` |
| 📑 **Office metadata** | Author, company, manager, version, revision count |
| 👥 **Domain users** | `DOMAIN\user` patterns in configs, UPN-format service accounts |
| 🌐 **Network addresses** | RFC-1918 IPs, internal hostnames (Jenkins, GitLab, Jira, Grafana, Kibana…) |
| 🩻 **Shadow files** | NTDS.dit, LSASS dumps, VSS snapshots, DC backup references |

**HIGH** findings (Cloud, Tokens, AI, Secrets, DB, Git, OfficeMeta_High) print the moment they're found and show up in the end-of-run summary.

## 🧠 How it reads files (smartly)

| Mode | What happens |
|---|---|
| **DeepScan** | Reads up to 4 MB of text/config/code and runs the secret patterns |
| **QuickPeek** | For Office files — reads only `docProps/core.xml` + `docProps/app.xml` (256 KB) for metadata |
| **ListOnly** | Records archives, PSTs, VHDs, certs without reading contents |
| **Skip** | Ignores media, executables, fonts (configurable) |

Office metadata extraction stays on even in `--quick` mode because it's cheap.

## ⚙️ Built for scale

- 🧵 **Parallel host scanning** — `--host-threads`
- ⏱️ **Per-host timeout** — `--host-timeout` so one bad share doesn't kill the run
- 🚀 **Quick mode** — `--quick` (depth 4, 128 KB read cap, 300 files/dir, 120 s/host)
- 🌐 **CIDR auto-discovery** — parallel TCP/445 probing across the range
- 👻 **Guest fallback** — many servers block null but allow `Guest`
- 🔍 **Share probing** — when SRVSVC enumeration is denied, probes 80+ common share names

## 🧪 Examples

```bash
# Single host — try everything available
python smb_scanner.py --target 10.0.0.5

# With creds
python smb_scanner.py --target 10.0.0.5 -u CORP\\alice -p 'S3cr3t!'

# Whole subnet — fast preset, 10 hosts at a time
python smb_scanner.py --target 10.0.0.0/24 --quick --host-threads 10

# Big target list, live CSV/JSONL output
python smb_scanner.py --targets-file hosts.txt \
  --quick --host-threads 5 --threads 3 --host-timeout 60 \
  --csv results.csv --jsonl results.jsonl

# Deep auth'd scan, skip noisy dirs
python smb_scanner.py --target 10.0.0.5 -u admin -p pass \
  --max-depth 15 --exclude-dirs '^Windows$' '^node_modules$' \
  --include-admin-shares

# Already-mounted CIFS — no impacket needed
python smb_scanner.py --mounted-root /mnt/smb_share --csv out.csv
```

## 📤 Output

- **Console** — colored, real-time. HIGH / MED findings stream as they're discovered.
- **CSV / JSONL** — `--csv` / `--jsonl` flush after each finding, so even a killed run gives you partial results.
- **HTML** — collapsible by category, color-coded severity, HIGH sections auto-open.

## 🛠️ Requirements

- Python 3.8+
- macOS, Linux, or Windows
- `colorama`, `tqdm`, `impacket>=0.12.0`

```bash
pip install -r requirements.txt
```

## 🤝 Pairs well with

- 🏢 **[AD_Scanner_tool](https://github.com/osherassor/AD_Scanner_tool)** — start there to map the domain and harvest a host list, then feed those hosts into this scanner with `--targets-file`.
- 🔉 **[LANWhisper](https://github.com/osherassor/LANWhisper)** — for the recon step before SMB. Resolve internal asset names (`fileserver`, `dfs`, `backup-01`) and pipe survivors here.
- 📚 **[AwesomeWL — credentials](https://github.com/osherassor/AwesomeWL/blob/main/credentials/default_creds.md)** — when you need default creds to try against authenticated SMB shares.

## ⚖️ Responsible use

Authorized testing only. Don't scan networks you don't own or aren't engaged on.

## 📄 License

MIT
