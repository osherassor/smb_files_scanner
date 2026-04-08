#!/usr/bin/env python3
"""
SMB Sensitive Strings Scanner v2 — impacket edition
Cross-platform SMB share scanner for sensitive files and secrets.
Supports: single IP, CIDR subnet, target file, UNC paths, mounted shares.
"""

import os
import re
import json
import csv
import argparse
import threading
import zipfile
import io
import socket
import ipaddress
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
import time

# ── Optional deps ──────────────────────────────────────────────────────────────

try:
    import msvcrt
    _WINDOWS = True
    KEYBOARD_AVAILABLE = True
except ImportError:
    _WINDOWS = False
    try:
        import tty, termios, select as _select
        KEYBOARD_AVAILABLE = True
    except ImportError:
        KEYBOARD_AVAILABLE = False

try:
    from colorama import init as _cinit, Fore, Style
    _cinit(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    class _Dummy:
        def __getattr__(self, _): return ''
    Fore = Style = _Dummy()

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

try:
    from impacket.smbconnection import SMBConnection
    HAS_IMPACKET = True
except ImportError:
    HAS_IMPACKET = False

# SMB file access constants (fall back to raw values if impacket not present)
try:
    from impacket.smb3structs import (
        FILE_READ_DATA, FILE_SHARE_READ, FILE_SHARE_WRITE,
        FILE_SHARE_DELETE, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
    )
except ImportError:
    FILE_READ_DATA          = 0x00000001
    FILE_SHARE_READ         = 0x00000001
    FILE_SHARE_WRITE        = 0x00000002
    FILE_SHARE_DELETE       = 0x00000004
    FILE_NON_DIRECTORY_FILE = 0x00000040
    FILE_OPEN               = 0x00000001


# ── Enums & dataclasses ────────────────────────────────────────────────────────

class Action(Enum):
    DEEPSCAN  = "DeepScan"
    QUICKPEEK = "QuickPeek"
    LISTONLY  = "ListOnly"
    SKIP      = "Skip"

class Level(Enum):
    HIGH = "HIGH"
    MED  = "MED"
    LOW  = "LOW"

@dataclass
class ScanResult:
    target:          str
    share:           str
    path:            str
    size:            int
    last_write:      str
    action:          str
    reason:          str
    interesting:     str
    findings:        List[str]
    actual_values:   List[str]
    content_snippet: str
    ooxml_meta:      Dict
    errors:          List[str]


# ── Keyboard handler ───────────────────────────────────────────────────────────

class KeyboardHandler:
    def __init__(self):
        self.skip_requested = False

    def check_for_skip(self) -> bool:
        if not KEYBOARD_AVAILABLE:
            return False
        try:
            if _WINDOWS:
                if msvcrt.kbhit():
                    key = msvcrt.getch().decode('utf-8', errors='ignore').upper()
                    if key == 'S':
                        self.skip_requested = True
                        return True
            else:
                if _select.select([sys.stdin], [], [], 0)[0]:
                    old = termios.tcgetattr(sys.stdin)
                    try:
                        tty.setraw(sys.stdin.fileno())
                        key = sys.stdin.read(1).upper()
                        if key == 'S':
                            self.skip_requested = True
                            return True
                    finally:
                        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old)
        except Exception:
            pass
        return False

    def reset(self):
        self.skip_requested = False


# ── Scanner ────────────────────────────────────────────────────────────────────

class SMBScanner:

    # ── Init ──────────────────────────────────────────────────────────────────
    def __init__(self, args):
        self.args      = args
        self.results: List[ScanResult] = []
        self.lock      = threading.Lock()
        self.kb        = KeyboardHandler()
        self.pbar      = None
        self._cnt      = {'HIGH': 0, 'MED': 0, 'LOW': 0}
        self._cnt_lock = threading.Lock()
        self._csv_writer   = None
        self._csv_file     = None
        self._jsonl_file   = None
        self._io_lock      = threading.Lock()  # separate lock for file I/O

        # ── Extension sets (no duplicates, no conflicts) ──────────────────────
        self.quickpeek_ext = {
            '.docx', '.docm', '.xlsx', '.xlsm', '.pptx', '.pptm', '.vsdx', '.one',
        }
        self.listonly_ext = {
            '.zip', '.7z', '.rar', '.tar', '.gz', '.bz2', '.xz',
            '.vhd', '.vhdx', '.vmdk', '.iso',
            '.pst', '.ost', '.mbox',
            '.bak', '.mdf', '.ldf',
            '.pfx', '.p12', '.jks', '.cer', '.crt', '.der',
        }
        self.skip_ext = {
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.psd', '.svg',
            '.mp3', '.wav', '.flac', '.aac', '.ogg',
            '.mp4', '.mkv', '.avi', '.mov', '.wmv', '.webm',
            '.exe', '.dll', '.sys', '.msi', '.cab',
            '.swf', '.fla', '.pdf',
            '.bin', '.obj', '.class', '.jar', '.war', '.ear',
            '.so', '.dylib', '.a', '.lib', '.o', '.pyc', '.pyo',
            '.woff', '.woff2', '.ttf', '.otf', '.eot',
        }
        self.deepscan_ext = {
            '.env', '.ini', '.conf', '.config', '.json', '.yaml', '.yml',
            '.toml', '.properties', '.xml', '.ps1', '.psm1', '.bat', '.cmd',
            '.vbs', '.sh', '.tf', '.tfvars', '.tfstate', '.hcl', '.cfg',
            '.txt', '.csv', '.log', '.md', '.rdp', '.rdg', '.ovpn',
            '.gitconfig', '.npmrc', '.pypirc', '.netrc', '.pgpass',
            '.sql', '.pgsql', '.php', '.py', '.aspx', '.asp', '.jsp',
            '.java', '.c', '.cpp', '.h', '.hpp', '.cs', '.vb', '.rb',
            '.pl', '.pm', '.go', '.rs', '.swift', '.kt', '.scala', '.lua',
            '.r', '.bash', '.zsh', '.fish', '.reg', '.inf', '.mysql',
            '.js', '.ts', '.jsx', '.tsx', '.html', '.htm',
            '.css', '.scss', '.sass', '.less',
            '.sqlite', '.db', '.kube', '.htpasswd',
        } - self.quickpeek_ext - self.listonly_ext - self.skip_ext

        # ── High-value exact filenames ────────────────────────────────────────
        self.high_filenames = {
            'web.config', 'ntds.dit', 'sam', 'system', 'security',
            'lsass.dmp', 'memory.dmp', 'id_rsa', 'id_ed25519', 'id_dsa',
            'id_ecdsa', 'authorized_keys', 'ssh_config', 'sshd_config',
            'known_hosts', 'credentials', 'passwords.txt', 'secrets.txt',
            'tokens.txt', 'auth.json', 'serviceaccount.json', 'sitemanager.xml',
            'winscp.ini', 'confcons.xml', 'connectionstrings.config',
            'database.yml', '.env', '.netrc', '.pgpass',
            'default.rdp', 'gpt.ini', 'registry.pol', 'login.conf',
            # Git credential files
            '.gitconfig', 'config',  # .git/config often has embedded tokens
            '.git-credentials', 'credentials',
            # CI/CD / infra secrets
            'Jenkinsfile', '.travis.yml', '.circleci',
            'terraform.tfstate', 'terraform.tfstate.backup',
            'vault.json', 'vault.hcl',
            # Cloud / k8s
            'kubeconfig', '.kube', 'serviceaccount.json',
            'gcloud_credentials.json', 'application_default_credentials.json',
            # AI service config files
            '.openai', 'openai.json', 'anthropic.json', '.anthropic',
            'claude.json', 'gemini.json', '.gemini',
            'langchain.env', 'llm.env', 'ai.env',
            # Misc high-value
            '.npmrc', '.pypirc', 'pip.conf',
            'docker-compose.yml', 'docker-compose.yaml',
            '.env.local', '.env.production', '.env.staging', '.env.development',
        }

        # ── Folder indicator (single compiled regex) ──────────────────────────
        _folder_pats = [
            r'[/\\]\.ssh[/\\]', r'[/\\]secrets?[/\\]', r'[/\\]credentials?[/\\]',
            r'[/\\]vpn[/\\]', r'[/\\]certs?[/\\]', r'[/\\]\.aws[/\\]',
            r'[/\\]\.azure[/\\]', r'[/\\]\.gcp[/\\]', r'[/\\]\.kube[/\\]',
            r'[/\\]\.docker[/\\]', r'[/\\]keepass[/\\]', r'[/\\]passwords?[/\\]',
            r'[/\\]backups?[/\\]', r'[/\\]rdp[/\\]', r'[/\\]ssh[/\\]',
            r'[/\\]winscp[/\\]', r'[/\\]filezilla[/\\]', r'[/\\]terraform[/\\]',
            r'[/\\]ansible[/\\]', r'[/\\]vault[/\\]', r'[/\\]shadow[/\\]',
            r'[/\\]vss[/\\]', r'[/\\]sysvol[/\\]', r'[/\\]netlogon[/\\]',
            r'[/\\]gpo[/\\]', r'[/\\]dumps?[/\\]', r'[/\\]security[/\\]',
            r'[/\\]auth[/\\]', r'[/\\]configs?[/\\]', r'[/\\]keys?[/\\]',
            r'[/\\]\.git[/\\]',  # .git dir contains config with potential embedded tokens
            r'[/\\]\.gitconfig[/\\]', r'[/\\]repos?[/\\]',
        ]
        self.folder_re = re.compile('|'.join(_folder_pats), re.IGNORECASE)

        # ── Filename keyword (single compiled regex) ──────────────────────────
        self.filename_re = re.compile(
            r'pass(?:word)?|pwd|creds?|credential|secret|token|api[-_]?key|jwt|bearer|'
            r'private[-_]?key|id_rsa|id_ed25519|ovpn|\.rdp|vpn|certificate|'
            r'keepass|kdbx|vault|\.aws|\.azure|kube|'
            r'connection.*string|connectionstring|backup|serviceaccount|shadow|lsass|ntds|'
            r'auth(?:ent)?|login|oauth|saml|'
            r'\.gitconfig|git.?credential|git.?config|\.git-credentials|'
            r'openai|anthropic|claude|gemini|mistral|groq|cohere|replicate|'
            r'langchain|langsmith|wandb|pinecone|weaviate|qdrant|chroma|'
            r'elevenlabs|assemblyai|stability|runway|together|fireworks|perplexity',
            re.IGNORECASE,
        )

        # ── Skip paths (single compiled regex for speed) ──────────────────────
        _skip_pats = [
            r'[/\\]Windows[/\\]WinSxS[/\\]',
            r'[/\\]Windows[/\\]SoftwareDistribution[/\\]',
            r'[/\\]Windows[/\\]Temp[/\\]',
            r'[/\\]Windows[/\\]Installer[/\\]',
            r'[/\\]Program Files(?:\s*\(x86\))?[/\\]',
            r'[/\\]AppData[/\\]Local[/\\]Temp[/\\]',
            r'[/\\]AppData[/\\]Local[/\\]Packages[/\\]',
            r'[/\\]AppData[/\\]Local[/\\]Microsoft[/\\]WindowsApps[/\\]',
            r'[/\\]node_modules[/\\]',
            r'[/\\]\$Recycle\.Bin[/\\]',
            r'[/\\]System Volume Information[/\\]',
            r'[/\\]\.git[/\\]objects[/\\]',
            r'[/\\]__pycache__[/\\]',
            r'[/\\]\.npm[/\\]',
            r'[/\\]bower_components[/\\]',
            r'[/\\]vendor[/\\]bundle[/\\]',
            r'[/\\]Office(?:1[0-6]|[5-9])[/\\]',
            r'[/\\]MSOCache[/\\]',
        ]
        self.skip_path_re = re.compile('|'.join(_skip_pats), re.IGNORECASE)

        # ── Content patterns ──────────────────────────────────────────────────
        _content_patterns: Dict[str, List[str]] = {
            'Cloud': [
                # AWS
                r'(AKIA[0-9A-Z]{16})',
                r'(ASIA[0-9A-Z]{16})',
                r'aws_access_key_id\s*[=:]\s*["\']?([A-Z0-9]{16,20})',
                r'aws_secret_access_key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{30,50})',
                # Azure
                r'(?i)azure[_-]?client[_-]?secret\s*[=:]\s*["\']?([A-Za-z0-9~._\-]{30,})',
                r'(?i)azure[_-]?(?:tenant|subscription)[_-]?id\s*[=:]\s*["\']?([0-9a-f\-]{36})',
                # GCP
                r'(AIza[A-Za-z0-9_\-]{35})',
                r'(?s)("type"\s*:\s*"service_account"[^}]{0,500}"private_key_id"\s*:\s*"([^"]{20,})")',
                # DigitalOcean
                r'(do(?:p|o|a)_v1_[a-f0-9]{64})',
                # Heroku (UUID with context keyword)
                r'(?i)heroku[^"\s]*\s*[=:]\s*["\']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})',
                # Cloudflare
                r'(?i)cloudflare[^"\s]*\s*[=:]\s*["\']?([A-Za-z0-9_\-]{37,40})',
            ],
            'Tokens': [
                # GitHub
                r'(ghp_[A-Za-z0-9]{36})',
                r'(gho_[A-Za-z0-9]{36})',
                r'(ghs_[A-Za-z0-9]{36})',
                r'(ghu_[A-Za-z0-9]{36})',
                r'(github_pat_[A-Za-z0-9_]{82})',
                # GitLab
                r'(glpat-[A-Za-z0-9_\-]{20})',
                # Slack
                r'(xox[baprs]-[0-9A-Za-z\-]{10,})',
                # Stripe
                r'([rs]k_live_[0-9a-zA-Z]{20,247})',
                r'(pk_live_[0-9a-zA-Z]{24,})',
                # Twilio
                r'(AC[0-9a-f]{32})',            # Account SID
                r'(SK[0-9a-fA-F]{32})',         # Auth token / API key
                # HashiCorp Vault
                r'(hvs\.[A-Za-z0-9_\-]{90,})',
                r'(hvb\.[A-Za-z0-9_\-]{90,})',  # batch token
                r'(hvr\.[A-Za-z0-9_\-]{90,})',  # recovery token
                # npm
                r'(npm_[A-Za-z0-9]{36})',
                # JWT
                r'(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})',
                # OpenAI
                r'(sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,})',
                r'(sk-proj-[A-Za-z0-9_\-]{50,})',
                r'(sk-svcacct-[A-Za-z0-9_\-]{50,})',
                # Hugging Face
                r'(hf_[a-zA-Z0-9]{34,})',
                r'(api_org_[a-zA-Z0-9]{34,})',
                # SendGrid
                r'(SG\.[A-Za-z0-9_\-]{20,24}\.[A-Za-z0-9_\-]{39,50})',
                # Mailgun
                r'(key-[a-z0-9]{32})',
                # Mailchimp
                r'([0-9a-f]{32}-us\d{1,2})',
                # Discord
                r'(https?://discord(?:app)?\.com/api/webhooks/\d{17,19}/[A-Za-z0-9_\-]{60,})',
                r'(?i)discord[_-]?(?:bot[_-]?)?token\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]{59,})',
                # Telegram
                r'(\d{8,10}:[A-Za-z0-9_\-]{35})',
                # Shopify
                r'(shp(?:pa|at|ca|ss)_[0-9A-Fa-f]{32})',
                # Square
                r'(EAAA[a-zA-Z0-9\-\+\=]{60})',
                r'(sq0atp-[A-Za-z0-9_\-]{22})',
                r'(sq0csp-[A-Za-z0-9_\-]{43})',
                # New Relic
                r'(NRAK-[A-Z0-9]{27})',
                r'(NRAA-[A-Za-z0-9._\-]{71})',
                r'(NRII-[A-Za-z0-9\-]{32})',
                # Doppler
                r'(dp\.(?:ct|pt|st(?:\.[a-z0-9\-_]{2,35})?|sa|scim|audit)\.[A-Za-z0-9]{36,44})',
                # Atlassian / Jira PAT
                r'(ATATT[A-Za-z0-9_=]{184,})',
                # SonarQube
                r'(squ_[a-f0-9]{40})',
                r'(sqp_[a-f0-9]{40})',  # SonarCloud user token
                # Grafana
                r'(glc_eyJ[A-Za-z0-9+\/=]{60,160})',
                r'(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})',  # Grafana service account token
                # PyPI
                r'(pypi-AgEIcHlwaS5vcmcCJ[A-Za-z0-9\-_]{150,157})',
                # RubyGems
                r'(rubygems_[A-Za-z0-9]{48})',
                # JFrog Artifactory
                r'(AKCp[a-zA-Z0-9]{69})',
                # Generic API key with context
                r'(?i)bearer\s+([A-Za-z0-9_\-\.=+/]{20,})',
                r'(?i)api[_-]?key\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})',
            ],
            'Secrets': [
                # Private keys (PEM)
                r'(-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----)',
                r'(-----BEGIN PGP PRIVATE KEY BLOCK-----)',
                # Password patterns
                r'(?i)(?:password|passwd|pass|pwd)\s*[=:]\s*["\']([^"\']{8,})["\']',
                r'(?i)(?:password|passwd|pass|pwd)\s*=\s*([^;"\s\'<>]{6,})',
                # Secret/token literals
                r'(?i)(?:secret|token)\s*[=:]\s*["\']([^"\']{8,})["\']',
                # Env-var style uppercase assignments
                r'(?i)((?:DB_PASSWORD|DB_PASS|API_KEY|SECRET_KEY|ACCESS_TOKEN|AUTH_TOKEN|PRIVATE_KEY|CLIENT_SECRET|APP_SECRET|MASTER_KEY|ENCRYPTION_KEY)\s*=\s*[^\s\'"]{8,})',
                # PowerShell ConvertTo-SecureString / credential patterns
                r'(?i)ConvertTo-SecureString\s+["\']([^"\']{6,})["\']',
                r'(?i)New-Object\s+System\.Management\.Automation\.PSCredential.{0,80}["\']([^"\']{6,})["\']',
                # net use / Windows CLI credentials
                r'(?i)net\s+use\s+[^\s]+\s+([^\s"\']{6,})\s+/user',
                # LDAP bind password
                r'(?i)(?:ldap|ad)[_-]?(?:bind[_-]?)?(?:password|pass|pwd)\s*[=:]\s*["\']?([^"\';\s]{6,})',
            ],
            'DB_Connection': [
                # URI-style connection strings
                r'(?i)((?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|redis|rediss|mssql|sqlserver|oracle|cassandra|couchdb|elasticsearch|opensearch|neo4j(?:\+s)?|amqp(?:s)?):\/\/[^\'"\s]{10,})',
                # ADO.NET / ODBC key=value chains
                r'(?i)((?:server|host|data\s*source)\s*=[^;]{3,};[^;]*password\s*=[^;]+)',
                r'(?i)(Data Source=[^;]+;[^;]*Password\s*=[^;]+)',
                # XML attribute style (web.config, app.config)
                r'(?i)connectionstrings?\s*=\s*["\']([^"\']{15,})["\']',
                # JSON/YAML key style
                r'(?i)["\']?connectionstrings?["\']?\s*:\s*["\']([^"\']{15,})["\']',
                # Elasticsearch cloud ID
                r'(?i)(?:cloud[_-]?id|elastic[_-]?cloud)\s*[=:]\s*["\']?([A-Za-z0-9_:\-]{20,})',
            ],
            'AI_Services': [
                # Anthropic Claude
                r'(sk-ant-(?:api03|admin01)-[A-Za-z0-9_\-]{80,})',
                # OpenAI  (already in Tokens but also here for category tagging)
                r'(sk-(?:proj|svcacct|service)-[A-Za-z0-9_\-]{50,})',
                # Replicate
                r'(r8_[A-Za-z0-9]{36,})',
                # Groq
                r'(gsk_[A-Za-z0-9]{48,})',
                # Perplexity
                r'(pplx-[a-f0-9]{40,})',
                # xAI (Grok)
                r'(xai-[A-Za-z0-9_\-]{60,})',
                # OpenRouter
                r'(sk-or-(?:v1-)?[A-Za-z0-9_\-]{40,})',
                # LangSmith / LangChain
                r'(ls(?:v2)?__[a-zA-Z0-9_\-]{32,})',
                # Fireworks AI
                r'(fw_[A-Za-z0-9]{32,})',
                # DeepSeek (uses sk- prefix, needs context)
                r'(?i)deepseek[_-]?(?:api[_-]?)?(?:key|token)\s*[=:]\s*["\']?(sk-[A-Za-z0-9]{32,})',
                # Cohere (context-based, no unique prefix)
                r'(?i)cohere[_-]?(?:api[_-]?)?(?:key|token)\s*[=:]\s*["\']?([A-Za-z0-9]{40,})',
                # Mistral AI (context-based)
                r'(?i)mistral[_-]?(?:api[_-]?)?(?:key|token)\s*[=:]\s*["\']?([A-Za-z0-9]{32,})',
                # Together AI
                r'(?i)together(?:ai?)?[_-]?(?:api[_-]?)?(?:key|token)\s*[=:]\s*["\']?([a-f0-9]{64})',
                # ElevenLabs
                r'(?i)elevenlabs?[_-]?(?:api[_-]?)?(?:key|token)\s*[=:]\s*["\']?([a-f0-9]{32})',
                # AssemblyAI
                r'(?i)assemblyai?[_-]?(?:api[_-]?)?(?:key|token)\s*[=:]\s*["\']?([a-f0-9]{32})',
                # Stability AI
                r'(?i)stability[_-]?(?:ai?[_-]?)?(?:api[_-]?)?(?:key|token)\s*[=:]\s*["\']?([A-Za-z0-9\-_]{40,})',
                # Weights & Biases
                r'(?i)(?:wandb|weights[_-]?biases?)[_-]?(?:api[_-]?)?(?:key|token)\s*[=:]\s*["\']?([a-f0-9]{40})',
                # Pinecone
                r'(?i)pinecone[_-]?(?:api[_-]?)?(?:key|token)\s*[=:]\s*["\']?([a-f0-9\-]{32,})',
                # AI21 Labs
                r'(?i)ai21[_-]?(?:api[_-]?)?(?:key|token)\s*[=:]\s*["\']?([A-Za-z0-9]{32,})',
                # RunwayML
                r'(?i)runway(?:ml)?[_-]?(?:api[_-]?)?(?:key|token|secret)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{32,})',
                # Voyage AI (embeddings)
                r'(pa-[A-Za-z0-9_\-]{40,})',
                # Cerebras
                r'(csk-[A-Za-z0-9_\-]{40,})',
            ],
            'Git_Credentials': [
                # Embedded creds in remote URL: https://user:token@github.com
                r'(?i)(https?://[^:@\s"\']{3,}:[^@\s"\']{3,}@(?:github|gitlab|bitbucket|gitea|dev\.azure)[^\s"\']{5,})',
                # git config url = https://token@host
                r'(?i)url\s*=\s*(https?://[A-Za-z0-9_\-\.]+@[^\s"\']{8,})',
                # .git-credentials or git credential store format
                r'(?i)(https?://[^:@\s]+:[^@\s]{6,}@[a-z0-9\.\-]+)',
                # remote = https://...@...
                r'(?i)(?:remote|origin|upstream)\s*=\s*(https?://[^\s"\']*@[^\s"\']+)',
            ],
            'Network_Addresses': [
                r'(\b10\.(?:\d{1,3}\.){2}\d{1,3}\b)',
                r'(\b192\.168\.\d{1,3}\.\d{1,3}\b)',
                r'(\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b)',
                r'(?i)((?:server|host|endpoint|jenkins|gitlab|jira|nexus|artifactory|sonar|grafana|kibana|elasticsearch|redis|mysql|postgres|mongo)\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z]{2,})+)',
            ],
            'Emails': [
                r'(\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b)',
            ],
            'Domain_Users': [
                r'(?i)(?:username|user|login|account)\s*[=:]\s*([A-Za-z0-9_\-]+\\[A-Za-z0-9_\-]+)',
                r'(?i)(?:service\s*account|svc)\s*[=:]\s*([A-Za-z0-9_\-]+\\[A-Za-z0-9_\-]+)',
                # UPN format: user@domain (filtered in post: must look like internal domain)
                r'(?i)(?:username|runas|run[_-]?as|service[_-]?account)\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]+@[A-Za-z0-9_\-]+\.[A-Za-z]{2,})["\']?',
            ],
            'Hebrew': [
                r'((?:סיסמה|סיסמא|שם\s*משתמש|טוקן|אסימון)\s*[=:]\s*[^\s,\'"]{4,})',
            ],
            'Shadow_Files': [
                r'(?i)((?:shadow\s*copy|volume\s*shadow|vssadmin|ntds\.dit|lsass\.dmp))',
                r'(?i)((?:domain\s*controller|dc\s*backup|ad\s*backup|registry\.pol))',
            ],
        }

        self.content_re: Dict[str, List[re.Pattern]] = {
            cat: [re.compile(p) for p in pats]
            for cat, pats in _content_patterns.items()
        }

        self.high_cats = {'Cloud', 'Tokens', 'Secrets', 'OfficeMeta_High', 'Git_Credentials', 'DB_Connection', 'AI_Services'}
        self.med_cats  = {'Network_Addresses', 'Domain_Users', 'OfficeMeta'}

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def format_mtime(mtime) -> str:
        """Convert SMB FILETIME int or local datetime string to 'YYYY-MM-DD HH:MM'."""
        try:
            if isinstance(mtime, int) or (isinstance(mtime, str) and mtime.isdigit()):
                # Windows FILETIME: 100-ns ticks since 1601-01-01
                ft = int(mtime)
                if ft == 0:
                    return ''
                from datetime import timedelta
                dt = datetime(1601, 1, 1) + timedelta(microseconds=ft // 10)
                return dt.strftime('%Y-%m-%d %H:%M')
            elif isinstance(mtime, str):
                # Already a string (local scan isoformat) — reformat
                dt = datetime.fromisoformat(mtime[:19])
                return dt.strftime('%Y-%m-%d %H:%M')
        except Exception:
            pass
        return str(mtime)[:16]

    def format_size(self, b: int) -> str:
        for unit in ('B', 'KB', 'MB', 'GB'):
            if b < 1024:
                return f'{b:.0f}{unit}' if unit == 'B' else f'{b:.1f}{unit}'
            b /= 1024.0
        return f'{b:.1f}TB'

    def should_skip_path(self, path: str) -> bool:
        if getattr(self.args, 'no_skip_defaults', False):
            return False
        return bool(self.skip_path_re.search(path))

    def _get_action(self, filename: str) -> Tuple[Action, str]:
        fn_lower = filename.lower()
        if fn_lower in self.high_filenames:
            return Action.DEEPSCAN, 'exact_filename'
        ext = Path(filename).suffix.lower()
        if ext in self.deepscan_ext:   return Action.DEEPSCAN,  'deepscan_ext'
        if ext in self.quickpeek_ext:  return Action.QUICKPEEK, 'quickpeek_ext'
        if ext in self.listonly_ext:   return Action.LISTONLY,  'listonly_ext'
        if ext in self.skip_ext:       return Action.SKIP,      'skip_ext'
        if self.filename_re.search(filename): return Action.DEEPSCAN, 'filename_kw'
        return Action.SKIP, 'no_indicator'

    def _get_level(self, path: str, filename: str, cats: List[str]) -> Tuple[Level, str]:
        reasons = []
        if self.folder_re.search(path):        reasons.append('folder')
        if self.filename_re.search(filename):  reasons.append('filename')
        if filename.lower() in self.high_filenames: reasons.append('exact_filename')

        for cat in cats:
            if cat in self.high_cats:
                return Level.HIGH, ','.join(reasons + [f'content:{cat}'])
        if filename.lower() in self.high_filenames:
            return Level.HIGH, ','.join(reasons)
        for cat in cats:
            if cat in self.med_cats:
                return Level.MED, ','.join(reasons + [f'content:{cat}'])
        if cats:
            return Level.LOW, ','.join(reasons + ['content:low'])
        if len(reasons) > 1: return Level.MED, ','.join(reasons)
        if reasons:          return Level.LOW, ','.join(reasons)
        return Level.LOW, 'weak'

    # ── Content analysis ──────────────────────────────────────────────────────

    def analyse_bytes(self, data: bytes, max_bytes: int) -> Tuple[List[str], List[str], str]:
        """Return (findings, actual_values, snippet_line_with_match)."""
        data = data[:max_bytes]
        if not data:
            return [], [], ''

        # Binary detection
        sample       = data[:4096]
        null_ratio   = sample.count(b'\x00') / max(len(sample), 1)
        nonpr_ratio  = sum(1 for b in sample if b < 32 and b not in (9, 10, 13)) / max(len(sample), 1)
        if null_ratio > 0.1 or nonpr_ratio > 0.3:
            return [], [], ''

        text = data.decode('utf-8', errors='replace')

        findings: List[str] = []
        values:   List[str] = []
        snippet = ''

        for cat, patterns in self.content_re.items():
            for pat in patterns:
                try:
                    matches = pat.findall(text)
                    if not matches:
                        continue
                    findings.append(f'{cat}:{pat.pattern[:60]}')
                    for m in matches[:5]:
                        val = (m if isinstance(m, str) else m[0] if m else '').strip()
                        if not val or len(val) < 4:
                            continue
                        entry = f'{cat}:{val}'
                        if entry not in values:
                            values.append(entry)
                        # Capture the line that contains this match (first hit wins)
                        if not snippet:
                            for line in text.splitlines():
                                if val in line:
                                    snippet = line.strip()[:200]
                                    break
                except Exception:
                    continue

        return findings, values, snippet

    # Fields we extract from OOXML docProps
    _CORE_FIELDS = {
        'creator', 'lastModifiedBy', 'created', 'modified',
        'lastPrinted', 'revision', 'description', 'subject', 'title',
        'keywords', 'category', 'contentStatus',
    }
    _APP_FIELDS = {
        'Application', 'AppVersion', 'Company', 'Manager',
        'Template', 'DocSecurity', 'TotalTime',
    }

    def extract_ooxml_meta(self, data: bytes) -> Dict:
        """Extract all useful metadata fields from an OOXML (Office) file."""
        meta: Dict = {}
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for xml_path, wanted in (
                    ('docProps/core.xml', self._CORE_FIELDS),
                    ('docProps/app.xml',  self._APP_FIELDS),
                ):
                    try:
                        root = ET.parse(io.BytesIO(z.read(xml_path))).getroot()
                        for el in root.iter():
                            tag = el.tag.split('}')[-1]
                            if tag in wanted and el.text and el.text.strip():
                                meta[tag] = el.text.strip()
                    except Exception:
                        pass
        except Exception:
            pass
        return meta

    def analyse_ooxml_meta(self, meta: Dict, filename: str) -> Tuple[List[str], List[str]]:
        """
        Score OOXML metadata for intelligence value.
        Returns (findings, actual_values) compatible with the main result format.
        """
        findings: List[str] = []
        values:   List[str] = []

        def _add(label: str, val: str, level: str = 'OfficeMeta'):
            entry = f'{level}:{label}={val}'
            if entry not in values:
                values.append(entry)
            tag = f'{level}:{label}'
            if tag not in findings:
                findings.append(tag)

        # ── Usernames ─────────────────────────────────────────────────────────
        for field in ('creator', 'lastModifiedBy'):
            val = meta.get(field, '').strip()
            if not val or val.lower() in ('unknown', 'user', 'admin', 'author'):
                continue
            _add(field, val, 'OfficeMeta')

            # Detect domain\username pattern
            if re.search(r'^[A-Za-z0-9_\-]+\\[A-Za-z0-9_\-\.]+$', val):
                _add('DomainUser', val, 'OfficeMeta_High')
            # Detect email address
            elif re.search(r'@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}', val):
                _add('UserEmail', val, 'OfficeMeta_High')
            # Detect firstname.lastname style → infer email format
            elif re.search(r'^[A-Za-z]+\.[A-Za-z]+$', val):
                _add('UsernameFormat', val, 'OfficeMeta')

        # ── Organisation ──────────────────────────────────────────────────────
        for field in ('Company', 'Manager'):
            val = meta.get(field, '').strip()
            if val and val.lower() not in ('', 'unknown', 'none'):
                _add(field, val, 'OfficeMeta')

        # ── Template — can leak internal UNC paths ────────────────────────────
        tmpl = meta.get('Template', '').strip()
        if tmpl and tmpl not in ('Normal', 'Normal.dotm', 'Normal.dot', ''):
            _add('Template', tmpl, 'OfficeMeta')
            # UNC path in template = internal file server
            if tmpl.startswith('\\\\') or re.search(r'\\\\[A-Za-z0-9_\-]+\\', tmpl):
                _add('InternalServer', tmpl, 'OfficeMeta_High')

        # ── App version — reveals patch level ────────────────────────────────
        app = meta.get('Application', '')
        ver = meta.get('AppVersion', '')
        if app or ver:
            _add('OfficeVersion', f'{app} {ver}'.strip(), 'OfficeMeta')

        # ── Revision count — high revision = actively used doc ────────────────
        rev = meta.get('revision', '')
        try:
            if int(rev) > 20:
                _add('HighRevision', f'rev={rev} file={filename}', 'OfficeMeta')
        except (ValueError, TypeError):
            pass

        # ── Run all metadata text through main content patterns too ──────────
        meta_blob = ' '.join(str(v) for v in meta.values()).encode()
        extra_f, extra_v, _ = self.analyse_bytes(meta_blob, len(meta_blob) + 1)
        findings += [f for f in extra_f if f not in findings]
        values   += [v for v in extra_v if v not in values]

        return findings, values

    # ── SMB operations ────────────────────────────────────────────────────────

    def _smb_connect(self, host: str) -> Optional['SMBConnection']:
        if not HAS_IMPACKET:
            return None
        user   = self.args.username or ''
        passwd = self.args.password or ''
        domain = ''
        if '\\' in user:
            domain, user = user.split('\\', 1)
        elif '@' in user:
            user, domain = user.split('@', 1)

        # Build credential candidates to try
        if user:
            cred_attempts = [(user, passwd, domain)]
        else:
            # No creds — try Guest first (servers often block null-session enum but allow Guest)
            cred_attempts = [('Guest', '', ''), ('guest', '', ''), ('', '', '')]

        for u, p, d in cred_attempts:
            try:
                conn = SMBConnection(host, host, sess_port=445, timeout=15)
                conn.login(u, p, d)
                if u:
                    _write(f'  {Fore.GREEN}[auth] {host} logged in as {u or "null-session"}{Style.RESET_ALL}')
                return conn
            except Exception:
                pass

        _write(f'{Fore.RED}[-] {host}: all login attempts failed{Style.RESET_ALL}')
        return None

    # Common share names to probe when SRVSVC enumeration is denied
    _FALLBACK_SHARES = [
        # Admin / default Windows
        'C$', 'D$', 'E$', 'F$', 'ADMIN$', 'IPC$', 'print$',
        'Users', 'Public', 'Shared', 'Share', 'Shares',
        'SYSVOL', 'NETLOGON',
        # General
        'Data', 'Files', 'Backup', 'Backups', 'Archive', 'Archives',
        'Documents', 'Docs', 'Finance', 'HR', 'IT', 'Dev', 'Development',
        'home', 'homes', 'Upload', 'Uploads', 'Drop', 'Dropbox',
        'Storage', 'NAS', 'Media', 'Temp', 'Transfer',
        # Web roots
        'htdocs', 'wwwroot', 'www', 'web', 'webroot', 'Web',
        'html', 'public_html', 'inetpub', 'sites', 'www-data',
        'srv', 'site', 'root', 'apache', 'nginx',
        # FTP / file transfer
        'ftp', 'ftproot', 'ftp-data',
        # Dev / source control
        'repos', 'git', 'svn', 'code', 'source', 'src',
        # CI/CD & DevOps
        'jenkins', 'jenkins_home', 'jenkins-data',
        'gitlab', 'gitlab-data', 'gitea',
        'nexus', 'artifactory', 'sonar',
        'bamboo', 'teamcity', 'travis',
        'ansible', 'terraform', 'chef', 'puppet',
        # Databases
        'mysql', 'postgres', 'mssql', 'oracle', 'mongo',
        'db', 'database', 'databases',
        # Logs / monitoring
        'logs', 'log', 'audit', 'elk', 'splunk', 'graylog',
        # Docker / k8s
        'docker', 'containers', 'kubernetes', 'k8s',
        # Config / secrets
        'config', 'configs', 'configuration',
        'secrets', 'vault', 'certs', 'keys',
        # App-specific
        'exchange', 'mail', 'email',
        'erp', 'crm', 'sap',
        'jira', 'confluence', 'bitbucket',
        'grafana', 'kibana', 'prometheus',
    ]

    def _list_shares(self, conn: 'SMBConnection') -> List[str]:
        try:
            raw = conn.listShares()
            shares = [s['shi1_netname'].rstrip('\x00') for s in raw]
            if shares:
                return shares
        except Exception as e:
            _write(f'{Fore.YELLOW}[!] SRVSVC share enum denied ({e}), probing common share names...{Style.RESET_ALL}')

        # Fallback: probe common share names by attempting to list their root
        accessible = []
        for share in self._FALLBACK_SHARES:
            try:
                conn.listPath(share, '\\*')
                accessible.append(share)
                _write(f'  {Fore.GREEN}[+] Accessible share: {share}{Style.RESET_ALL}')
            except Exception:
                pass
        if accessible:
            _write(f'  Found {len(accessible)} accessible shares via probing')
        else:
            _write(f'{Fore.YELLOW}  No accessible shares found (try -u/-p for credentials){Style.RESET_ALL}')
        return accessible

    def _read_file_smb(self, conn: 'SMBConnection', share: str, smb_path: str, max_bytes: int) -> bytes:
        """Stream up to max_bytes from a remote file via SMB using getFile."""
        buf = io.BytesIO()

        def _cb(data: bytes):
            remaining = max_bytes - buf.tell()
            if remaining > 0:
                buf.write(data[:remaining])

        try:
            conn.getFile(share, smb_path, _cb)
        except Exception:
            pass  # may raise on EOF or after partial read — that's fine
        return buf.getvalue()

    # ── Single file scan ──────────────────────────────────────────────────────

    def _scan_file(
        self,
        conn: Optional['SMBConnection'],
        target: str,
        share: str,
        smb_path: str,   # leading backslash, e.g. \Users\alice\config.env
        size: int,
        mtime: str,
    ) -> Optional[ScanResult]:
        filename = smb_path.replace('/', '\\').split('\\')[-1]
        action, action_reason = self._get_action(filename)
        if action == Action.SKIP:
            return None
        if size > 50 * 1024 * 1024:
            return None

        findings, values, snippet = [], [], ''
        ooxml: Dict = {}
        max_b = self.args.deepscan_max_bytes if action == Action.DEEPSCAN else self.args.quickpeek_max_bytes

        # meta-only mode: read office files for metadata even when --no-office skips content
        no_office_content = getattr(self.args, 'no_office_content', False)
        meta_only = action == Action.QUICKPEEK and no_office_content

        if conn and action in (Action.DEEPSCAN, Action.QUICKPEEK):
            read_limit = 256 * 1024 if meta_only else max_b
            data = self._read_file_smb(conn, share, smb_path, read_limit)
            if data:
                if not meta_only:
                    findings, values, snippet = self.analyse_bytes(data, read_limit)
                if action == Action.QUICKPEEK:
                    ooxml = self.extract_ooxml_meta(data)
                    if ooxml:
                        mf, mv = self.analyse_ooxml_meta(ooxml, filename)
                        findings += [f for f in mf if f not in findings]
                        values   += [v for v in mv if v not in values]

        level, reason = self._get_level(
            smb_path, filename, [f.split(':')[0] for f in findings]
        )

        return ScanResult(
            target=target, share=share,
            path=smb_path.lstrip('\\').lstrip('/'),
            size=size, last_write=mtime,
            action=action.value,
            reason=f'{action_reason},{reason}',
            interesting=level.value,
            findings=findings, actual_values=values,
            content_snippet=snippet, ooxml_meta=ooxml, errors=[],
        )

    # ── Directory recursion (SMB) ─────────────────────────────────────────────

    def _scan_dir_smb(
        self,
        conn: 'SMBConnection',
        target: str,
        share: str,
        smb_dir: str,   # path within share, no leading slash, e.g. '' or 'Users\\alice'
        depth: int = 0,
    ):
        if depth > self.args.max_depth:
            return
        if self.kb.check_for_skip():
            _write(f'  {Fore.YELLOW}⏭  Skipping: \\\\{target}\\{share}\\{smb_dir}{Style.RESET_ALL}')
            self.kb.reset()
            return

        search = ('\\' + smb_dir + '\\*') if smb_dir else '\\*'
        search = re.sub(r'\\{2,}', '\\\\', search)  # collapse double backslashes

        try:
            entries = conn.listPath(share, search)
        except Exception:
            return

        files:   List[Tuple] = []
        subdirs: List[str]   = []

        for e in entries:
            name = e.get_longname()
            if name in ('.', '..'):
                continue
            child = (smb_dir + '\\' + name) if smb_dir else name

            if e.is_directory():
                # Fixed exclude_dirs: use any() so continue applies to outer loop
                if self.args.exclude_dirs and any(
                    re.search(p, name, re.IGNORECASE) for p in self.args.exclude_dirs
                ):
                    continue
                if self.should_skip_path(child):
                    continue
                # apply include_dirs filter on the directory name
                if self.args.include_dirs and not any(
                    re.search(p, name, re.IGNORECASE) for p in self.args.include_dirs
                ):
                    continue
                subdirs.append(child)
            else:
                ext = Path(name).suffix.lower()
                if self.args.include_ext and ext not in self.args.include_ext:
                    continue
                if self.args.exclude_ext and ext in self.args.exclude_ext:
                    continue
                files.append((e, child))

        max_fpd = getattr(self.args, 'max_files_per_dir', 1000)

        for idx, (entry, fpath) in enumerate(files):
            if idx >= max_fpd:
                _write(f'{Fore.YELLOW}  [!] Dir limit ({max_fpd}) reached in \\{smb_dir}{Style.RESET_ALL}')
                break
            size  = entry.get_filesize()
            mtime = self.format_mtime(entry.get_mtime())
            result = self._scan_file(conn, target, share, '\\' + fpath, size, mtime)
            self._tick(target, result)

        for sub in subdirs:
            self._scan_dir_smb(conn, target, share, sub, depth + 1)

    # ── Directory recursion (local / mounted) ─────────────────────────────────

    def _scan_dir_local(
        self,
        target: str,
        share: str,
        root: str,
        rel: str = '',
        depth: int = 0,
    ):
        if depth > self.args.max_depth:
            return
        full = os.path.join(root, rel) if rel else root
        try:
            entries = list(os.scandir(full))
        except Exception:
            return

        count = 0
        max_fpd = getattr(self.args, 'max_files_per_dir', 1000)

        for entry in entries:
            if self.kb.check_for_skip():
                _write(f'  {Fore.YELLOW}⏭  Skipping: {full}{Style.RESET_ALL}')
                self.kb.reset()
                return

            rel_path = os.path.join(rel, entry.name).replace('/', '\\') if rel else entry.name

            if entry.is_dir(follow_symlinks=False):
                if self.args.exclude_dirs and any(
                    re.search(p, entry.name, re.IGNORECASE) for p in self.args.exclude_dirs
                ):
                    continue
                if self.should_skip_path(rel_path):
                    continue
                self._scan_dir_local(target, share, root, rel_path, depth + 1)
            elif entry.is_file():
                if count >= max_fpd:
                    break
                count += 1
                try:
                    st    = entry.stat()
                    size  = st.st_size
                    mtime = self.format_mtime(datetime.fromtimestamp(st.st_mtime).isoformat())
                    action, action_reason = self._get_action(entry.name)
                    if action == Action.SKIP or size > 50 * 1024 * 1024:
                        self._tick(target, None)
                        continue

                    findings, values, snippet = [], [], ''
                    ooxml: Dict = {}
                    max_b = self.args.deepscan_max_bytes if action == Action.DEEPSCAN else self.args.quickpeek_max_bytes

                    no_office_content = getattr(self.args, 'no_office_content', False)
                    meta_only = action == Action.QUICKPEEK and no_office_content
                    if action in (Action.DEEPSCAN, Action.QUICKPEEK):
                        try:
                            read_limit = 256 * 1024 if meta_only else max_b
                            with open(entry.path, 'rb') as f:
                                data = f.read(read_limit)
                            if not meta_only:
                                findings, values, snippet = self.analyse_bytes(data, read_limit)
                            if action == Action.QUICKPEEK:
                                ooxml = self.extract_ooxml_meta(data)
                                if ooxml:
                                    mf, mv = self.analyse_ooxml_meta(ooxml, entry.name)
                                    findings += [f for f in mf if f not in findings]
                                    values   += [v for v in mv if v not in values]
                        except Exception:
                            pass

                    level, reason = self._get_level(
                        rel_path, entry.name, [f.split(':')[0] for f in findings]
                    )
                    result = ScanResult(
                        target=target, share=share, path=rel_path,
                        size=size, last_write=mtime,
                        action=action.value, reason=f'{action_reason},{reason}',
                        interesting=level.value,
                        findings=findings, actual_values=values,
                        content_snippet=snippet, ooxml_meta=ooxml, errors=[],
                    )
                    self._tick(target, result)
                except Exception:
                    pass

    # ── Live output helpers ───────────────────────────────────────────────────

    def _open_live_outputs(self):
        """Open CSV/JSONL files and write CSV header immediately."""
        if getattr(self.args, 'jsonl', None):
            self._jsonl_file = open(self.args.jsonl, 'w', encoding='utf-8')
        if getattr(self.args, 'csv', None):
            self._csv_file = open(self.args.csv, 'w', newline='', encoding='utf-8')
            # Write header using field names from the dataclass
            from dataclasses import fields as dc_fields
            fieldnames = [f.name for f in dc_fields(ScanResult)]
            self._csv_writer = csv.DictWriter(self._csv_file, fieldnames=fieldnames)
            self._csv_writer.writeheader()
            self._csv_file.flush()

    def _close_live_outputs(self):
        if self._jsonl_file:
            self._jsonl_file.close()
            self._jsonl_file = None
        if self._csv_file:
            self._csv_file.close()
            self._csv_file = None

    def _write_result_live(self, result: ScanResult):
        """Append a single result to open CSV/JSONL files immediately."""
        with self._io_lock:
            if self._jsonl_file:
                self._jsonl_file.write(json.dumps(asdict(result), ensure_ascii=False) + '\n')
                self._jsonl_file.flush()
            if self._csv_writer and self._csv_file:
                row = asdict(result)
                for k in ('findings', 'actual_values', 'errors'):
                    row[k] = '; '.join(row[k])
                row['ooxml_meta'] = json.dumps(row['ooxml_meta'])
                self._csv_writer.writerow(row)
                self._csv_file.flush()

    # ── Progress + result storage ─────────────────────────────────────────────

    def _tick(self, target: str, result: Optional[ScanResult]):
        """Update progress bar and store result."""
        if self.pbar is not None:
            self.pbar.update(1)
        if result:
            with self.lock:
                self.results.append(result)
            with self._cnt_lock:
                self._cnt[result.interesting] += 1
            self._write_result_live(result)
            if result.interesting in ('HIGH', 'MED'):
                self._print_result(result)
            if self.pbar is not None:
                self.pbar.set_postfix(
                    {'H': self._cnt['HIGH'], 'M': self._cnt['MED'], 'host': target[:15]},
                    refresh=False,
                )

    # ── Share & target scanning ───────────────────────────────────────────────

    def _scan_share(self, target: str, share: str):
        conn = self._smb_connect(target)
        if not conn:
            return
        _write(f'{Fore.CYAN}  [*] \\\\{target}\\{share}{Style.RESET_ALL}')
        try:
            self._scan_dir_smb(conn, target, share, '', depth=0)
        finally:
            try:
                conn.logoff()
            except Exception:
                pass

    def _scan_target(self, target_str: str):
        host, spec_share, _subpath = self._parse_target(target_str)

        conn = self._smb_connect(host)
        if not conn:
            return

        _write(f'\n{Fore.GREEN}[+] Connected to {host}{Style.RESET_ALL}')

        if spec_share:
            shares = [spec_share]
        else:
            shares = self._list_shares(conn)
            _write(f'    Shares found: {", ".join(shares) or "(none)"}')

        # Apply share filters
        if self.args.include_shares:
            inc = {s.strip() for s in self.args.include_shares.split(',')}
            shares = [s for s in shares if s in inc]
        if self.args.exclude_shares:
            exc = {s.strip() for s in self.args.exclude_shares.split(',')}
            shares = [s for s in shares if s not in exc]
        if not getattr(self.args, 'include_admin_shares', False):
            shares = [s for s in shares if not s.endswith('$')]

        if not shares:
            _write(f'{Fore.YELLOW}  [!] No shares to scan on {host}{Style.RESET_ALL}')

        try:
            conn.logoff()
        except Exception:
            pass

        if not shares:
            return

        _write(f'    Scanning: {", ".join(shares)}')

        host_timeout = getattr(self.args, 'host_timeout', None)

        def _scan_shares_with_timeout():
            if self.args.threads > 1:
                with ThreadPoolExecutor(max_workers=min(self.args.threads, len(shares))) as ex:
                    futs = {ex.submit(self._scan_share, host, s): s for s in shares}
                    for fut in as_completed(futs):
                        try:
                            fut.result()
                        except Exception as e:
                            _write(f'{Fore.RED}  [!] Error scanning {futs[fut]}: {e}{Style.RESET_ALL}')
            else:
                for s in shares:
                    self._scan_share(host, s)

        if host_timeout:
            import concurrent.futures
            with ThreadPoolExecutor(max_workers=1) as ex:
                fut = ex.submit(_scan_shares_with_timeout)
                try:
                    fut.result(timeout=host_timeout)
                except concurrent.futures.TimeoutError:
                    _write(f'{Fore.YELLOW}  [!] {host} timed out after {host_timeout}s — moving on{Style.RESET_ALL}')
                except Exception as e:
                    _write(f'{Fore.RED}  [!] {host} error: {e}{Style.RESET_ALL}')
        else:
            _scan_shares_with_timeout()

    # ── Target parsing & expansion ────────────────────────────────────────────

    @staticmethod
    def _parse_target(target: str) -> Tuple[str, Optional[str], Optional[str]]:
        t = target.strip().replace('/', '\\')
        if t.startswith('\\\\'):
            parts = t[2:].split('\\')
            host  = parts[0]
            share = parts[1] if len(parts) > 1 and parts[1] else None
            sub   = '\\'.join(parts[2:]) if len(parts) > 2 else None
            return host, share, sub
        return target.strip(), None, None

    @staticmethod
    def _check_port(host: str, port: int = 445, timeout: float = 2.0) -> bool:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except Exception:
            return False

    @staticmethod
    def _expand_cidr(target: str) -> List[str]:
        host, share, _ = SMBScanner._parse_target(target)
        try:
            net = ipaddress.ip_network(host, strict=False)
            if net.num_addresses == 1:
                return [target]
            # Return targets preserving any share/path suffix
            suffix = target[len(host):]
            return [str(ip) + suffix for ip in net.hosts()]
        except ValueError:
            return [target]

    # ── Console output ────────────────────────────────────────────────────────

    def _print_result(self, r: ScanResult):
        color = Fore.RED + Style.BRIGHT if r.interesting == 'HIGH' else Fore.YELLOW
        line  = f'[{r.interesting}] \\\\{r.target}\\{r.share}\\{r.path}  ({self.format_size(r.size)})'
        _write(f'{color}{line}{Style.RESET_ALL}')
        for v in r.actual_values[:3]:
            _write(f'         {Fore.CYAN}{v}{Style.RESET_ALL}')
        if len(r.actual_values) > 3:
            _write(f'         ... +{len(r.actual_values) - 3} more')
        if r.content_snippet:
            _write(f'         {Fore.WHITE}{r.content_snippet[:120]}{Style.RESET_ALL}')

    def _print_high_summary(self):
        high = [r for r in self.results if r.interesting == 'HIGH']
        if not high:
            return
        print(f'\n{"=" * 60}')
        print(f'{Fore.RED}🔥 HIGH PRIORITY FINDINGS SUMMARY{Style.RESET_ALL}')
        print('=' * 60)
        cats: Dict[str, list] = {}
        for r in high:
            for v in r.actual_values:
                if ':' in v:
                    cat, val = v.split(':', 1)
                    cats.setdefault(cat, []).append({
                        'value': val,
                        'source': f'\\\\{r.target}\\{r.share}\\{r.path}',
                        'snippet': self._targeted_snippet(r.content_snippet, val),
                    })
        for cat, items in cats.items():
            print(f'\n{Fore.CYAN}{cat.upper()} ({len(items)}){Style.RESET_ALL}')
            print('-' * 50)
            for i, item in enumerate(items, 1):
                print(f'  {i}. {item["value"]}')
                print(f'     {item["source"]}')
                if item['snippet']:
                    print(f'     {item["snippet"]}')
        print('=' * 60)

    @staticmethod
    def _targeted_snippet(content: str, value: str) -> str:
        if not content or not value:
            return content or ''
        pos = content.find(value.strip())
        if pos == -1:
            return content[:80] + ('...' if len(content) > 80 else '')
        start = max(0, pos - 20)
        end   = min(len(content), pos + len(value) + 20)
        out   = content[start:end]
        if start > 0:  out = '...' + out
        if end < len(content): out += '...'
        return out

    # ── Save results ──────────────────────────────────────────────────────────

    def save_results(self):
        """Live writes already handled by _write_result_live; just print summary."""
        if getattr(self.args, 'jsonl', None):
            print(f'JSONL → {self.args.jsonl} ({len(self.results)} records)')
        if getattr(self.args, 'csv', None):
            print(f'CSV   → {self.args.csv} ({len(self.results)} records)')

    # ── Main run ──────────────────────────────────────────────────────────────

    def run(self):
        print(f'{Fore.CYAN}SMB Sensitive Strings Scanner v2{Style.RESET_ALL}')
        print('=' * 40)

        if not HAS_IMPACKET and not getattr(self.args, 'mounted_root', None):
            print(f'{Fore.RED}ERROR: impacket not installed.{Style.RESET_ALL}')
            print('  pip install impacket')
            sys.exit(1)

        if KEYBOARD_AVAILABLE:
            print("Press 'S' during scan to skip the current directory.")

        pbar_fmt = '{desc}: {n_fmt} {unit} [{elapsed}, {rate_fmt}] {postfix}'
        self.pbar = tqdm(desc='Files', unit='file', dynamic_ncols=True,
                         bar_format=pbar_fmt, total=0) if HAS_TQDM else None

        self._open_live_outputs()

        try:
            if getattr(self.args, 'mounted_root', None):
                target = 'MOUNTED'
                share  = os.path.basename(self.args.mounted_root.rstrip('/\\')) or 'CIFS'
                _write(f'[*] Scanning mounted path: {self.args.mounted_root}')
                self._scan_dir_local(target, share, self.args.mounted_root)

            else:
                raw_targets: List[str] = []
                if getattr(self.args, 'targets_file', None):
                    with open(self.args.targets_file) as f:
                        raw_targets = [l.strip() for l in f if l.strip() and not l.startswith('#')]
                elif getattr(self.args, 'target', None):
                    raw_targets = [self.args.target]

                # Expand CIDRs
                expanded: List[str] = []
                for t in raw_targets:
                    hosts = self._expand_cidr(t)
                    if len(hosts) > 1:
                        _write(f'[*] {t} → {len(hosts)} hosts, probing port 445...')
                        alive: List[str] = []
                        with ThreadPoolExecutor(max_workers=100) as ex:
                            fmap = {ex.submit(self._check_port, h.split('\\')[0].split('/')[0]): h
                                    for h in hosts}
                            for fut in as_completed(fmap):
                                h = fmap[fut]
                                if fut.result():
                                    alive.append(h)
                                    _write(f'  {Fore.GREEN}[+] {h}:445 open{Style.RESET_ALL}')
                        _write(f'  → {len(alive)} hosts with SMB open')
                        expanded.extend(alive)
                    else:
                        expanded.extend(hosts)

                if not expanded:
                    _write(f'{Fore.YELLOW}[!] No targets to scan.{Style.RESET_ALL}')

                # Parallel host scanning
                host_threads = getattr(self.args, 'host_threads', 1)
                if host_threads > 1:
                    _write(f'[*] Scanning {len(expanded)} hosts with {host_threads} parallel host threads')
                    with ThreadPoolExecutor(max_workers=host_threads) as ex:
                        futs = {ex.submit(self._scan_target, t): t for t in expanded}
                        for fut in as_completed(futs):
                            try:
                                fut.result()
                            except Exception as e:
                                _write(f'{Fore.RED}[!] Error: {e}{Style.RESET_ALL}')
                else:
                    for t in expanded:
                        self._scan_target(t)

        finally:
            if self.pbar is not None:
                self.pbar.close()
            self._close_live_outputs()

        self.save_results()
        self.generate_html_summary()

        h, m, l = self._cnt['HIGH'], self._cnt['MED'], self._cnt['LOW']
        print(f'\n{"=" * 40}')
        print(f'Scan complete — {h + m + l} interesting files found.')
        print(f'  {Fore.RED}HIGH: {h}{Style.RESET_ALL}')
        print(f'  {Fore.YELLOW}MED:  {m}{Style.RESET_ALL}')
        print(f'  LOW:  {l}')
        if h:
            self._print_high_summary()

    # ── HTML report ───────────────────────────────────────────────────────────

    def generate_html_summary(self, output_file: str = 'scan_summary.html'):
        if not self.results:
            return

        high_r  = [r for r in self.results if r.interesting == 'HIGH']
        med_r   = [r for r in self.results if r.interesting == 'MED']
        low_r   = [r for r in self.results if r.interesting == 'LOW']
        # Office meta: files with any OfficeMeta finding
        office_meta_r = [r for r in self.results if r.ooxml_meta]
        groups  = self._organize_by_asset_type()
        info    = self._build_scan_info()

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SMB Scanner — {info['target_display']}</title>
    <style>
        body{{font-family:'Segoe UI',sans-serif;margin:0;padding:20px;background:#f5f5f5}}
        .container{{max-width:1200px;margin:0 auto;background:white;border-radius:10px;
                    box-shadow:0 2px 10px rgba(0,0,0,.1);overflow:hidden;display:flex;flex-direction:column}}
        .header{{background:linear-gradient(135deg,#667eea,#764ba2);color:white;padding:30px;text-align:center}}
        .header h1{{margin:0;font-size:2.2em;font-weight:300}}
        .scan-info{{background:#e9ecef;padding:12px 20px;border-bottom:1px solid #dee2e6;
                    font-family:monospace;font-size:.9em}}
        .scan-info .label{{font-weight:bold;color:#495057}}
        .scan-info .value{{color:#6c757d;margin-left:8px}}
        .stats{{display:flex;justify-content:space-around;padding:20px;background:#f8f9fa;
                border-bottom:1px solid #dee2e6}}
        .stat{{text-align:center}}
        .stat-number{{font-size:2em;font-weight:bold}}
        .stat-label{{color:#6c757d;font-size:.85em;text-transform:uppercase;letter-spacing:1px}}
        .content-area{{flex:1;overflow-y:auto;padding:20px}}
        .summary-section{{background:#f8f9fa;border-radius:8px;padding:20px;margin-bottom:30px;
                           border:1px solid #dee2e6}}
        .summary-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px}}
        .summary-item{{text-align:center;padding:15px;background:white;border-radius:6px;
                        box-shadow:0 1px 3px rgba(0,0,0,.1)}}
        .summary-number{{font-size:2em;font-weight:bold;color:#495057}}
        .summary-label{{color:#6c757d;font-size:.85em}}
        .asset-group{{margin:10px 0;border-radius:8px;overflow:hidden;box-shadow:0 2px 5px rgba(0,0,0,.1)}}
        .asset-header{{padding:18px 20px;color:white;font-size:1.3em;font-weight:bold;cursor:pointer;
                        display:flex;justify-content:space-between;align-items:center;transition:opacity .2s}}
        .asset-header:hover{{opacity:.9}}
        .asset-header.network{{background:linear-gradient(135deg,#4facfe,#00f2fe)}}
        .asset-header.credentials{{background:linear-gradient(135deg,#ff6b6b,#ee5a52)}}
        .asset-header.files{{background:linear-gradient(135deg,#feca57,#ff9ff3)}}
        .asset-header.folders{{background:linear-gradient(135deg,#48dbfb,#0abde3)}}
        .asset-header.emails{{background:linear-gradient(135deg,#a8edea,#fed6e3);color:#333}}
        .asset-header.office_meta{{background:linear-gradient(135deg,#fd9644,#e67e22);color:white}}
        .asset-content{{max-height:0;overflow:hidden;transition:max-height .3s ease-out}}
        .asset-content.expanded{{max-height:700px;overflow-y:auto}}
        .priority-section{{margin:15px;border-radius:6px;border:1px solid #e9ecef;overflow:hidden}}
        .priority-header{{padding:10px 15px;font-weight:bold;color:white;font-size:1em}}
        .priority-header.high{{background:#dc3545}}
        .priority-header.med{{background:#ffc107;color:#212529}}
        .priority-header.low{{background:#17a2b8}}
        .finding-item{{padding:14px;border-bottom:1px solid #f1f3f4}}
        .finding-item:hover{{background:#f8f9fa}}
        .finding-item:last-child{{border-bottom:none}}
        .finding-value{{font-weight:bold;color:#2c3e50;margin-bottom:6px;background:#fff3cd;
                         padding:6px 10px;border-radius:4px;border-left:4px solid #ffc107;
                         word-break:break-all}}
        .finding-source{{color:#6c757d;font-family:monospace;font-size:.85em;margin-bottom:4px}}
        .finding-context{{background:#f8f9fa;padding:6px 10px;border-radius:4px;
                           font-family:monospace;font-size:.82em;color:#495057;
                           border-left:3px solid #007bff;white-space:pre-wrap;word-break:break-all}}
        .toggle-icon{{font-size:1.1em;transition:transform .3s}}
        .toggle-icon.expanded{{transform:rotate(180deg)}}
        .timestamp{{text-align:center;padding:16px;color:#6c757d;font-size:.85em;
                     border-top:1px solid #dee2e6}}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>🔍 SMB Scanner Results</h1>
        <div style="margin-top:8px;opacity:.9">{info['target_display']}</div>
    </div>
    <div class="scan-info">
        <div><span class="label">Target:</span><span class="value">{info['target_display']}</span></div>
        <div><span class="label">Command:</span><span class="value">{info['command']}</span></div>
        <div><span class="label">Auth:</span><span class="value">{info['auth_info']}</span></div>
    </div>
    <div class="stats">
        <div class="stat"><div class="stat-number" style="color:#dc3545">{len(high_r)}</div><div class="stat-label">High</div></div>
        <div class="stat"><div class="stat-number" style="color:#ffc107">{len(med_r)}</div><div class="stat-label">Medium</div></div>
        <div class="stat"><div class="stat-number" style="color:#17a2b8">{len(low_r)}</div><div class="stat-label">Low</div></div>
        <div class="stat"><div class="stat-number" style="color:#e67e22">{len(office_meta_r)}</div><div class="stat-label">Office Meta</div></div>
        <div class="stat"><div class="stat-number" style="color:#667eea">{len(self.results)}</div><div class="stat-label">Total</div></div>
    </div>
    <div class="content-area">
        <div class="summary-section">
            <h2>📊 Scan Summary</h2>
            <div class="summary-grid">
                <div class="summary-item"><div class="summary-number">{len(high_r)}</div><div class="summary-label">High Priority</div></div>
                <div class="summary-item"><div class="summary-number">{len(med_r)}</div><div class="summary-label">Medium Priority</div></div>
                <div class="summary-item"><div class="summary-number">{len(low_r)}</div><div class="summary-label">Low Priority</div></div>
                <div class="summary-item"><div class="summary-number">{len(office_meta_r)}</div><div class="summary-label">Office Files w/ Metadata</div></div>
                <div class="summary-item"><div class="summary-number">{len(self.results)}</div><div class="summary-label">Total Files</div></div>
            </div>
        </div>
        <h2>🔍 Findings by Category</h2>
        {self._generate_asset_groups_html(groups)}
    </div>
    <div class="timestamp">Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
</div>
<script>
function toggleAssetGroup(id) {{
    const c = document.getElementById(id+'-content');
    const i = document.getElementById(id+'-icon');
    const expanded = c.classList.toggle('expanded');
    i.classList.toggle('expanded', expanded);
}}
document.addEventListener('DOMContentLoaded', () => {{
    document.querySelectorAll('.asset-group').forEach(g => {{
        if (g.querySelector('.priority-header.high')) {{
            const id = g.querySelector('.asset-header').getAttribute('onclick').match(/'([^']+)'/)[1];
            toggleAssetGroup(id);
        }}
    }});
}});
</script>
</body>
</html>"""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html)
            print(f'HTML report → {output_file}')
        except Exception as e:
            print(f'Error writing HTML: {e}')

    def _build_scan_info(self) -> Dict:
        targets = {r.target for r in self.results}
        shares  = {r.share  for r in self.results}
        t_disp  = list(targets)[0] if len(targets) == 1 else f'Multiple ({len(targets)})'
        cmd     = 'python smb_scanner.py'
        if getattr(self.args, 'target', None):
            cmd += f' --target "{self.args.target}"'
        elif getattr(self.args, 'targets_file', None):
            cmd += f' --targets-file "{self.args.targets_file}"'
        elif getattr(self.args, 'mounted_root', None):
            cmd += f' --mounted-root "{self.args.mounted_root}"'
        if getattr(self.args, 'username', None):
            cmd += f' -u "{self.args.username}"'
        auth = f'User: {self.args.username}' if getattr(self.args, 'username', None) else 'Anonymous'
        return {'target_display': t_disp, 'command': cmd, 'auth_info': auth,
                'scan_path': f'\\\\{t_disp}\\{",".join(sorted(shares))}'}

    def _organize_by_asset_type(self) -> Dict:
        groups = {
            'credentials': {'title': '🔑 Credentials & Tokens', 'results': []},
            'network':     {'title': '🌐 Network Assets',        'results': []},
            'office_meta': {'title': '🏢 Office Metadata Intel', 'results': []},
            'files':       {'title': '📄 Sensitive Files',        'results': []},
            'folders':     {'title': '📁 Sensitive Folders',      'results': []},
            'emails':      {'title': '📧 Email Addresses',        'results': []},
        }
        for r in self.results:
            for v in r.actual_values:
                if ':' not in v:
                    continue
                cat = v.split(':', 1)[0]
                if cat in ('Cloud', 'Tokens', 'Secrets', 'DB_Connection', 'Domain_Users', 'Hebrew', 'Git_Credentials', 'AI_Services'):
                    groups['credentials']['results'].append((v, r))
                elif cat == 'Network_Addresses':
                    groups['network']['results'].append((v, r))
                elif cat == 'Emails':
                    groups['emails']['results'].append((v, r))
                elif cat == 'Shadow_Files':
                    groups['files']['results'].append((v, r))
                elif cat in ('OfficeMeta_High', 'OfficeMeta'):
                    groups['office_meta']['results'].append((v, r))
            if self.folder_re.search(r.path):
                groups['folders']['results'].append((f'Sensitive_Folder:{r.path}', r))
            if self.filename_re.search(r.path.split('\\')[-1]):
                groups['files']['results'].append((f'Sensitive_File:{r.path.split(chr(92))[-1]}', r))
        return groups

    def _generate_asset_groups_html(self, groups: Dict) -> str:
        parts = []
        for key, data in groups.items():
            if not data['results']:
                continue
            high_i = [(v, r) for v, r in data['results'] if r.interesting == 'HIGH']
            med_i  = [(v, r) for v, r in data['results'] if r.interesting == 'MED']
            low_i  = [(v, r) for v, r in data['results'] if r.interesting == 'LOW']
            parts.append(f'''
            <div class="asset-group">
                <div class="asset-header {key}" onclick="toggleAssetGroup('{key}')" id="{key}-header">
                    <span>{data["title"]} ({len(data["results"])})</span>
                    <span class="toggle-icon" id="{key}-icon">▼</span>
                </div>
                <div class="asset-content" id="{key}-content">
            ''')
            for label, cls, items in (('🔥 HIGH', 'high', high_i), ('⚠️ MEDIUM', 'med', med_i), ('ℹ️ LOW', 'low', low_i)):
                if items:
                    parts.append(f'''
                    <div class="priority-section">
                        <div class="priority-header {cls}">{label} ({len(items)})</div>
                        {self._generate_findings_html(items)}
                    </div>''')
            parts.append('</div></div>')
        return ''.join(parts)

    def _generate_findings_html(self, items: List[Tuple]) -> str:
        if not items:
            return '<div style="padding:20px;color:#6c757d;font-style:italic">No findings</div>'
        parts = []
        for val, r in items:
            value_part = val.split(':', 1)[1] if ':' in val else val
            src        = f'\\\\{r.target}\\{r.share}\\{r.path}'
            ctx        = self._targeted_snippet(r.content_snippet, value_part)
            # For office meta findings, show a compact metadata summary if no snippet
            if not ctx and r.ooxml_meta:
                meta_items = [f'{k}: {v}' for k, v in r.ooxml_meta.items()
                              if k in ('creator', 'lastModifiedBy', 'Company', 'Manager',
                                       'Template', 'Application', 'AppVersion', 'revision')]
                if meta_items:
                    ctx = ' | '.join(meta_items)
            parts.append(f'''
            <div class="finding-item">
                <div class="finding-value">🔍 {value_part}</div>
                <div class="finding-source">📁 {src}</div>
                {'<div class="finding-context">' + ctx + '</div>' if ctx else ''}
            </div>''')
        return ''.join(parts)


# ── Shared tqdm-aware print ────────────────────────────────────────────────────

def _write(msg: str):
    if HAS_TQDM:
        tqdm.write(msg)
    else:
        print(msg)


# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='SMB Sensitive Strings Scanner v2 — impacket edition',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single host (enumerate all shares)
  python smb_scanner.py --target 10.0.0.5

  # CIDR subnet — auto-discovers hosts with port 445 open
  python smb_scanner.py --target 10.0.0.0/24

  # With credentials
  python smb_scanner.py --target 10.0.0.5 -u CORP\\\\alice -p 'S3cret!'

  # Specific share
  python smb_scanner.py --target '\\\\\\\\10.0.0.5\\\\Users'

  # Multiple targets from file (one IP or UNC per line, # = comment)
  python smb_scanner.py --targets-file hosts.txt -u admin -p pass

  # Already-mounted path (no impacket needed)
  python smb_scanner.py --mounted-root /mnt/smb_share

  # Parallel scan with threads
  python smb_scanner.py --target 10.0.0.0/24 --threads 10

  # Output reports
  python smb_scanner.py --target 10.0.0.5 --csv out.csv --jsonl out.jsonl
""",
    )

    # Target
    tgt = parser.add_mutually_exclusive_group(required=True)
    tgt.add_argument('--target',       help='IP, CIDR (10.0.0.0/24), hostname, or UNC path')
    tgt.add_argument('--targets-file', help='File with one target per line')
    tgt.add_argument('--mounted-root', help='Already-mounted path (macOS/Linux fallback)')

    # Auth
    parser.add_argument('-u', '--username', help='DOMAIN\\\\user or user@domain')
    parser.add_argument('-p', '--password', help='Password (use "" for blank)')

    # Share filters
    parser.add_argument('--include-shares',       help='Comma-separated shares to include')
    parser.add_argument('--exclude-shares',       help='Comma-separated shares to exclude')
    parser.add_argument('--include-admin-shares', action='store_true',
                        help='Include admin shares (C$, ADMIN$, etc.)')

    # Dir / file filters
    parser.add_argument('--include-dirs',  nargs='+', help='Only recurse dirs matching these regex patterns')
    parser.add_argument('--exclude-dirs',  nargs='+', help='Skip dirs matching these regex patterns')
    parser.add_argument('--include-ext',   nargs='+', help='Only scan files with these extensions (.env .json)')
    parser.add_argument('--exclude-ext',   nargs='+', help='Skip files with these extensions')
    parser.add_argument('--max-depth',     type=int,  default=10,   help='Max directory depth (default: 10)')
    parser.add_argument('--max-files-per-dir', type=int, default=1000, help='Max files per directory (default: 1000)')
    parser.add_argument('--no-skip-defaults', action='store_true',
                        help='Disable built-in skip-path list (scan everything)')

    # Scan settings
    parser.add_argument('--deepscan-max-bytes',  type=int, default=4*1024*1024,
                        help='Max bytes read per DeepScan file (default: 4MB)')
    parser.add_argument('--quickpeek-max-bytes', type=int, default=1*1024*1024,
                        help='Max bytes read per QuickPeek file (default: 1MB)')
    parser.add_argument('--threads', type=int, default=1,
                        help='Parallel share scanners per host (default: 1)')
    parser.add_argument('--host-timeout', type=int, default=None,
                        help='Max seconds to spend on a single host before moving on (e.g. 300)')
    parser.add_argument('--host-threads', type=int, default=1,
                        help='Parallel hosts to scan simultaneously (default: 1)')
    parser.add_argument('--no-office', action='store_true',
                        help='Skip full content scan of Office files; still extract metadata (creator, company, etc.)')
    parser.add_argument('--no-office-meta', action='store_true',
                        help='Skip Office files entirely including metadata extraction')
    parser.add_argument('--quick', action='store_true',
                        help='Quick mode: metadata-only for office files, limit depth to 4, 128KB read limit, skip common junk dirs')

    # Output
    parser.add_argument('--csv',   help='Save results to CSV file')
    parser.add_argument('--jsonl', help='Save results to JSONL file')

    # Misc
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--dry-run',       action='store_true', help='Parse args only, no scanning')

    args = parser.parse_args()

    # Normalise ext lists
    if args.include_ext:
        args.include_ext = {e if e.startswith('.') else '.' + e for e in args.include_ext}
    if args.exclude_ext:
        args.exclude_ext = {e if e.startswith('.') else '.' + e for e in args.exclude_ext}

    # --quick: opinionated fast-scan defaults
    if args.quick:
        args.max_depth             = min(args.max_depth, 4)
        args.deepscan_max_bytes    = min(args.deepscan_max_bytes, 128 * 1024)
        args.quickpeek_max_bytes   = min(args.quickpeek_max_bytes, 64 * 1024)
        args.max_files_per_dir     = min(args.max_files_per_dir, 300)
        args.no_office             = True
        args.no_office_content     = True
        if not args.host_timeout:
            args.host_timeout = 120  # 2 min max per host in quick mode
        # Skip common junk dirs automatically
        junk = [
            r'^Windows$', r'^WinSxS$', r'^SoftwareDistribution$',
            r'^Temp$', r'^Tmp$', r'^Cache$', r'^Installer$',
            r'^MSOCache$', r'^assembly$', r'^GAC_MSIL$',
            r'^en-US$', r'^en$', r'^x86$', r'^x64$',
            r'^fonts$', r'^Fonts$', r'^help$', r'^Help$',
            r'^Sample\s', r'^desktop\.ini$',
        ]
        existing = args.exclude_dirs or []
        args.exclude_dirs = existing + junk

    # --no-office: skip content scan but keep metadata extraction (unless --no-office-meta)
    if getattr(args, 'no_office', False):
        args.no_office_content = True

    # --no-office-meta: skip office files entirely (fastest, no metadata)
    if getattr(args, 'no_office_meta', False):
        if not args.exclude_ext:
            args.exclude_ext = set()
        args.exclude_ext |= {'.docx', '.docm', '.xlsx', '.xlsm', '.pptx', '.pptm', '.vsdx', '.one',
                              '.doc', '.xls', '.ppt'}

    if args.dry_run:
        print('DRY RUN — args parsed OK.')
        return

    scanner = SMBScanner(args)
    scanner.run()


if __name__ == '__main__':
    main()
