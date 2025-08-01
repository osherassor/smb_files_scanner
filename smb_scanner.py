#!/usr/bin/env python3
"""
SMB Sensitive Strings Scanner
A Python-based tool that scans SMB shares for sensitive files and secrets without downloading full files.
"""

import os
import re
import json
import csv
import argparse
import threading
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path, PureWindowsPath
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, asdict
from enum import Enum
import stat
import sys
import time

# Cross-platform keyboard input handling
try:
    import msvcrt  # Windows
    KEYBOARD_AVAILABLE = True
except ImportError:
    try:
        import tty
        import termios
        KEYBOARD_AVAILABLE = True
    except ImportError:
        KEYBOARD_AVAILABLE = False

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False
    Fore = Style = type('Dummy', (), {'__getattr__': lambda self, name: ''})()

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

class Action(Enum):
    DEEPSCAN = "DeepScan"
    QUICKPEEK = "QuickPeek"
    LISTONLY = "ListOnly"
    SKIP = "Skip"

class InterestingLevel(Enum):
    HIGH = "HIGH"
    MED = "MED"
    LOW = "LOW"

@dataclass
class ScanResult:
    target: str
    share: str
    path: str
    size: int
    last_write: str
    action: str
    reason: str
    interesting: str
    findings: List[str]
    actual_values: List[str]
    content_snippet: str
    ooxml_meta: Dict
    errors: List[str]

class KeyboardHandler:
    """Handle keyboard input for interactive features."""
    
    def __init__(self):
        self.skip_requested = False
        self.running = True
    
    def check_for_skip(self):
        """Check if 'S' key was pressed to skip current folder."""
        if not KEYBOARD_AVAILABLE:
            return False
            
        try:
            if os.name == 'nt':  # Windows
                if msvcrt.kbhit():
                    key = msvcrt.getch().decode('utf-8').upper()
                    if key == 'S':
                        self.skip_requested = True
                        return True
            else:  # Unix-like systems
                import tty
                import termios
                import select
                
                # Check if input is available
                if select.select([sys.stdin], [], [], 0)[0]:
                    # Save terminal settings
                    old_settings = termios.tcgetattr(sys.stdin)
                    try:
                        tty.setraw(sys.stdin.fileno())
                        if sys.stdin.readable():
                            key = sys.stdin.read(1).upper()
                            if key == 'S':
                                self.skip_requested = True
                                return True
                    finally:
                        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
        except (UnicodeDecodeError, OSError, ImportError):
            pass
        return False
    
    def reset_skip_flag(self):
        """Reset the skip flag after processing."""
        self.skip_requested = False

class SMBScanner:
    def __init__(self, args):
        self.args = args
        self.results = []
        self.lock = threading.Lock()
        self.keyboard_handler = KeyboardHandler()
        
        # File extension categorizations
        self.deepscan_extensions = {
            '.env', '.ini', '.conf', '.config', '.json', '.yaml', '.yml', '.toml', '.properties', '.xml',
            '.ps1', '.psm1', '.bat', '.cmd', '.vbs', '.sh', '.tf', '.tfvars', '.kube', '.cfg',
            '.txt', '.csv', '.md', '.rdp', '.rdg', '.ovpn', '.dockerfile', '.gitconfig', '.npmrc', '.pypirc',
            '.sql', '.pgsql',
            # Code files - add these to scan for sensitive data
            '.php', '.py', '.aspx', '.asp', '.jsp', '.css', '.scss', '.sass',
            '.java', '.c', '.cpp', '.h', '.hpp', '.cs', '.vb', '.rb', '.pl', '.pm', '.go', '.rs', '.swift',
            '.kt', '.scala', '.clj', '.lua', '.r', '.m', '.mm', '.sh', '.bash', '.zsh', '.fish', '.ps1',
            '.vbs', '.wsf', '.bat', '.cmd', '.reg', '.inf', '.ini', '.cfg', '.conf', '.config',
            '.yml', '.yaml', '.toml', '.json', '.xml', '.csv', '.tsv', '.log', '.md', '.rst',
            '.sql', '.pgsql', '.mysql', '.sqlite', '.db', '.mdb', '.accdb'
        }
        
        self.quickpeek_extensions = {
            '.docx', '.docm', '.xlsx', '.xlsm', '.pptx', '.pptm', '.vsdx', '.one'
        }
        
        self.listonly_extensions = {
            '.zip', '.7z', '.rar', '.tar', '.gz', '.bz2', '.xz',
            '.vhd', '.vhdx', '.vmdk', '.iso',
            '.pst', '.ost', '.olm', '.mbox',
            '.bak', '.mdf', '.ldf', '.sqlite', '.db',
            '.pfx', '.p12', '.jks', '.cer', '.crt', '.der'
        }
        
        self.skip_extensions = {
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.psd', '.svg',
            '.mp3', '.wav', '.flac', '.aac', '.ogg',
            '.mp4', '.mkv', '.avi', '.mov', '.wmv', '.webm',
            '.exe', '.dll', '.sys', '.msi', '.cab',
            # JavaScript files - exclude to avoid false positives
            '.js', '.ts', '.jsx', '.tsx',
            # HTML files - exclude to avoid false positives
            '.html', '.htm', '.xhtml', '.shtml',
            # CSS files - exclude to avoid false positives
            '.css', '.scss', '.sass', '.less',
            # Binary files that should never be scanned
            '.swf', '.fla', '.swc', '.flv', '.f4v', '.f4p', '.f4a', '.f4b',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz',
            '.bin', '.dat', '.obj', '.class', '.jar', '.war', '.ear',
            '.so', '.dylib', '.a', '.lib', '.o', '.pyc', '.pyo',
            '.woff', '.woff2', '.ttf', '.otf', '.eot'
        }
        
        # Folder indicators (regex patterns)
        self.folder_indicators = [
            r'\.ssh\\',
            r'\\secrets?\\',
            r'\\credentials?\\',
            r'\\configs?\\',
            r'\\vpn\\',
            r'\\certs?\\',
            r'\\keys?\\',
            r'\.aws\\',
            r'\.azure\\',
            r'\.gcp\\',
            r'\.kube\\',
            r'\.docker\\',
            r'\.git\\',
            r'\\keepass\\',
            r'\\password\\',
            r'\\backups?\\',
            r'\\dbbackup\\',
            r'\\rdp\\',
            r'\\ssh\\',
            r'\\winscp\\',
            r'\\filezilla\\',
            r'\\terraform\\',
            r'\\ansible\\',
            # Shadow folders and files
            r'\\shadow\\',
            r'\\shadowcopy\\',
            r'\\vss\\',
            r'\\volume\s*shadow\s*copy\\',
            r'\\system\s*volume\s*information\\',
            # Domain and Active Directory files
            r'\\sysvol\\',
            r'\\netlogon\\',
            r'\\policies\\',
            r'\\gpo\\',
            r'\\group\s*policy\\',
            r'\\domain\\',
            r'\\active\s*directory\\',
            r'\\ad\\',
            # Security and authentication files
            r'\\security\\',
            r'\\auth\\',
            r'\\authentication\\',
            r'\\identity\\',
            r'\\identity\s*management\\',
            # Dump files and memory dumps
            r'\\dumps?\\',
            r'\\memory\s*dumps?\\',
            r'\\crash\s*dumps?\\',
            r'\\minidumps?\\',
            # Configuration and policy files
            r'\\policies\\',
            r'\\policy\\',
            r'\\config\\',
            r'\\configuration\\',
            r'\\settings\\',
            # Backup and recovery
            r'\\backup\\',
            r'\\recovery\\',
            r'\\restore\\',
            r'\\snapshots?\\',
            r'\\checkpoints?\\'
        ]
        
        # Filename keywords
        self.filename_keywords = [
            r'pass|password|pwd|creds?|credential|secret|token|api[-_]?key|jwt|bearer',
            r'client[_-]?secret|private[_-]?key|id_rsa|id_ed25519|ovpn|rdp|rdg|vpn',
            r'certificate|keystore?|filezilla|winscp|putty|openvpn|kdbx|keepass|vault',
            r'secret(s)?\.json|\.env(\.|$)|\.env\..*|aws|azure|gcp|kube|config',
            r'connection.*string|db(pass|pwd)|backup|serviceAccount|secrets?-?toml',
            r'secret.*yaml|terraform.*tfvars?|ansible.*vault',
            # Shadow files and VSS
            r'shadow|vss|volume\s*shadow|snapshot|checkpoint',
            # RDP and remote access files
            r'\.rdp$|\.rdg$|remote\s*desktop|rdp\s*config|rdp\s*settings',
            # SSH files
            r'id_rsa|id_ed25519|id_dsa|id_ecdsa|known_hosts|authorized_keys|ssh\s*config',
            # Domain and Active Directory files
            r'ntds\.dit|sam|system|security|gpo|group\s*policy|domain\s*controller',
            # Memory dumps and crash files
            r'lsass\.dmp|memory\.dmp|crash\.dmp|minidump|\.dmp$|\.mdmp$',
            # Authentication and identity files
            r'auth|authentication|identity|login|session|token|jwt|saml|oauth',
            # Configuration and policy files
            r'policy|policies|config|configuration|settings|preferences|profile',
            # Backup and recovery files
            r'backup|restore|recovery|snapshot|checkpoint|archive|dump|export'
        ]
        
        # Exact filename matches
        self.exact_filenames = {
            'web.config', 'sitemanager.xml', 'winscp.ini', 'confCons.xml',
            'connections.xml', 'servers.xml', 'serviceAccount.json',
            'connectionstrings.config', 'database.yml', 'known_hosts',
            # Shadow and VSS files
            'ntds.dit', 'sam', 'system', 'security', 'lsass.dmp', 'memory.dmp',
            'crash.dmp', 'minidump.dmp', 'vssadmin.exe', 'vssvc.exe',
            # RDP files
            'default.rdp', 'remote.rdp', 'connection.rdp', 'rdp.rdg',
            # SSH files
            'id_rsa', 'id_ed25519', 'id_dsa', 'id_ecdsa', 'authorized_keys',
            'ssh_config', 'sshd_config', 'ssh_known_hosts',
            # Domain and Active Directory files
            'gpt.ini', 'registry.pol', 'ntuser.dat', 'usmt3.log', 'migapp.xml',
            'miguser.xml', 'migdocs.xml', 'scanstate.exe', 'loadstate.exe',
            # Authentication files
            'credentials', 'passwords.txt', 'secrets.txt', 'tokens.txt',
            'auth.json', 'auth.xml', 'login.conf', 'session.dat',
            # Configuration files
            'config.ini', 'settings.json', 'preferences.xml', 'profile.dat',
            'policy.xml', 'gpo.xml', 'registry.dat', 'security.dat'
        }
        
        # Skip path patterns
        self.skip_paths = [
            r'\\Windows\\WinSxS\\',
            r'\\Windows\\SoftwareDistribution\\Download\\',
            r'\\Windows\\Temp\\',
            r'\\Windows\\Installer\\',
            r'\\Program Files( \(x86\))?\\',
            r'\\Users\\[^\\]+\\AppData\\Local\\Temp\\',
            r'\\Users\\[^\\]+\\AppData\\Local\\Packages\\',
            r'\\Users\\[^\\]+\\AppData\\Local\\Microsoft\\WindowsApps\\',
            r'\\node_modules\\',
            r'\\\$Recycle\.Bin\\',
            r'\\System Volume Information\\',
            # Skip js and images folders
            r'\\js\\',
            r'\\images\\',
            r'\\img\\',
            r'\\assets\\js\\',
            r'\\assets\\images\\',
            r'\\static\\js\\',
            r'\\static\\images\\',
            # Skip language folders
            r'\\languages\\',
            r'\\lang\\',
            r'\\i18n\\',
            r'\\translations\\'
        ]
        
        # Content regex patterns
        self.content_patterns = {
            'Cloud': [
                r'AKIA[0-9A-Z]{16}',
                r'aws_access_key_id\s*=\s*[A-Z0-9]{16,20}',
                r'aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{30,50}',
                r'(?i)azure[_-]?client[_-]?secret[^A-Za-z0-9]{1,10}[A-Za-z0-9_\-]{20,}',
                r'(?i)google(?:_|-)?api(?:_|-)?key[^A-Za-z0-9]{1,10}[A-Za-z0-9_\-]{20,}'
            ],
            'Secrets': [
                # More specific credential patterns to avoid false positives
                r'(?i)(?:password|pass|pwd|secret|token|bearer)\s*[:=]\s*["\']?[A-Za-z0-9!@#$%^&*()_+\-=\[\]{}|;:,.<>?]{8,}["\']?(?:\s*[,;]|\s*$|\s*\))',
                # JWT tokens
                r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
                # Private keys
                r'-----BEGIN (?:RSA|EC|DSA|OPENSSH|PRIVATE) KEY-----',
                # API keys with specific patterns
                r'(?i)(?:api[_-]?key|access[_-]?key|secret[_-]?key)\s*[:=]\s*["\']?[A-Za-z0-9]{20,}["\']?',
                # Database passwords in connection strings
                r'(?i)(?:password|pwd)\s*[:=]\s*["\']?[A-Za-z0-9!@#$%^&*()_+\-=\[\]{}|;:,.<>?]{6,}["\']?(?:\s*[,;]|\s*$|\s*\))',
                # Environment variable style credentials
                r'(?i)(?:DB_PASSWORD|DB_PASS|DB_PWD|API_KEY|SECRET_KEY|ACCESS_KEY)\s*[:=]\s*["\']?[A-Za-z0-9!@#$%^&*()_+\-=\[\]{}|;:,.<>?]{8,}["\']?',
                # Hardcoded credentials in code (avoiding form fields and variables)
                r'(?i)(?:password|pass|pwd|secret|token)\s*[:=]\s*["\']?[A-Za-z0-9!@#$%^&*()_+\-=\[\]{}|;:,.<>?]{8,}["\']?(?:\s*[,;]|\s*$|\s*\))',
                # Exclude common false positives (PHP variables, form fields, etc.)
                r'(?i)(?:password|pass|pwd|secret|token)\s*[:=]\s*["\']?(?:\$[a-zA-Z_][a-zA-Z0-9_]*|type|text|input|field|required|min|max|placeholder|id|name|class|style|arg_[a-zA-Z_][a-zA-Z0-9_]*)["\']?'
            ],
            'DB_Connection': [
                r'(?i)(server|host|data\s*source)=[^;]{3,};(?:[^;]+;){0,3}user\s*id=[^;]+;[^;]*password=[^;]+;',
                r'(?i)(mongodb|postgres|mysql|mariadb|redis|mssql):\/\/[^\'"\s]{10,}'
            ],
            'Network_Addresses': [
                # Internal IPs (private ranges)
                r'\b10\.(\d{1,3}\.){2}\d{1,3}\b',
                r'\b192\.168\.(\d{1,3})\.\d{1,3}\b',
                r'\b172\.(1[6-9]|2\d|3[0-1])\.(\d{1,3})\.\d{1,3}\b',
                # External IPs (public IP ranges) - only if they look like real IPs
                r'\b(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\b',
                # High-probability hostnames (not random domains)
                r'(?i)(?:server|host|endpoint|api|jenkins|gitlab|github|bitbucket|jira|confluence|nexus|artifactory|sonar|prometheus|grafana|kibana|elasticsearch|redis|mysql|postgres|mongo|oracle|sqlserver)\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,}',
                # CI/CD and cloud asset URLs
                r'(?i)(?:https?://)(?:jenkins|gitlab|github|bitbucket|jira|confluence|nexus|artifactory|sonar|prometheus|grafana|kibana|elasticsearch|aws|azure|gcp|cloudflare|heroku|vercel|netlify)\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,}(?::[0-9]+)?(?:/[^\s]*)?',
                # Database connection strings with hostnames
                r'(?i)(?:mysql|postgres|mongo|redis|oracle|sqlserver)://[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,}(?::[0-9]+)?(?:/[^\s]*)?'
            ],
            'Emails': [
                # Standard email addresses
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                # Email addresses in configuration contexts
                r'(?i)(email|mail|contact|admin|user|username)\s*[:=]\s*[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}',
                # Email addresses in quotes
                r'["\'][A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}["\']',
                # Email addresses in variables
                r'\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*["\'][A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}["\']'
            ],
            'Domain_Users': [
                # Only detect actual domain\username patterns in credential contexts
                r'(?i)(?:username|user|login|account)\s*[:=]\s*[A-Za-z0-9_-]+\\([A-Za-z0-9_-]+)',  # username: domain\user
                r'(?i)(?:password|pass|pwd)\s*[:=]\s*[^,\s\'"]{6,}\s*(?:domain|user)\s*[:=]\s*[A-Za-z0-9_-]+\\([A-Za-z0-9_-]+)',  # password with domain
                r'(?i)(?:auth|authentication)\s*[:=]\s*[A-Za-z0-9_-]+\\([A-Za-z0-9_-]+)',  # auth: domain\user
                r'(?i)(?:service\s*account|svc\s*account)\s*[:=]\s*[A-Za-z0-9_-]+\\([A-Za-z0-9_-]+)',  # service account: domain\user
                # Connection strings with domain users
                r'(?i)(?:server|host)\s*[:=]\s*[^;]+;.*user\s*[:=]\s*[A-Za-z0-9_-]+\\([A-Za-z0-9_-]+)',  # server=...;user=domain\user
                # RDP connection strings
                r'(?i)(?:rdp|remote|desktop)\s*[:=]\s*.*[A-Za-z0-9_-]+\\([A-Za-z0-9_-]+)',  # rdp: ...domain\user
                # Windows authentication patterns
                r'(?i)(?:windows\s*auth|ntlm|kerberos)\s*[:=]\s*[A-Za-z0-9_-]+\\([A-Za-z0-9_-]+)'  # windows auth: domain\user
            ],
            'Hebrew': [
                r'(סיסמה|סיסמא|שם\s*משתמש|טוקן|אסימון)\s*[:=]\s*[^,\s\'"]{4,}'
            ],
            'Shadow_Files': [
                # Shadow copy references
                r'(?i)shadow\s*copy|volume\s*shadow|vss|shadowcopy',
                # VSS commands and references
                r'(?i)vssadmin|vssvc|shadow\s*storage|shadow\s*volume',
                # NTDS.dit references
                r'(?i)ntds\.dit|sam|system|security\s*database',
                # LSASS dump references
                r'(?i)lsass\.dmp|memory\s*dump|crash\s*dump|minidump',
                # Domain controller references
                r'(?i)domain\s*controller|dc\s*backup|ad\s*backup',
                # GPO and policy references
                r'(?i)group\s*policy|gpo|policy\s*backup|registry\.pol',
                # Backup and recovery references
                r'(?i)backup\s*shadow|restore\s*shadow|vss\s*backup'
            ]
        }
        
        # Compile regex patterns
        self.folder_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.folder_indicators]
        self.filename_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.filename_keywords]
        self.skip_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.skip_paths]
        self.content_regex = {}
        for category, patterns in self.content_patterns.items():
            self.content_regex[category] = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]

    def should_skip_path(self, path: str) -> bool:
        """Check if path should be skipped based on skip patterns."""
        if self.args.skip_path_defaults:
            return False
        
        path_lower = path.lower()
        for pattern in self.skip_regex:
            if pattern.search(path_lower):
                return True
        return False

    def get_file_action(self, filepath: str, filename: str) -> Tuple[Action, str]:
        """Determine the action to take for a file based on its extension and name."""
        ext = Path(filename).suffix.lower()
        
        # Check exact filename matches
        if filename in self.exact_filenames:
            return Action.DEEPSCAN, "exact_filename_match"
        
        # Check extension categories
        if ext in self.deepscan_extensions:
            return Action.DEEPSCAN, "deepscan_extension"
        elif ext in self.quickpeek_extensions:
            return Action.QUICKPEEK, "quickpeek_extension"
        elif ext in self.listonly_extensions:
            return Action.LISTONLY, "listonly_extension"
        elif ext in self.skip_extensions:
            return Action.SKIP, "skip_extension"
        
        # Check filename keywords
        for pattern in self.filename_regex:
            if pattern.search(filename):
                return Action.DEEPSCAN, "filename_keyword_match"
        
        return Action.SKIP, "no_indicators"

    def get_interesting_level(self, filepath: str, filename: str, content_matches: List[str]) -> Tuple[InterestingLevel, str]:
        """Determine the interesting level based on path, filename, and content matches."""
        reasons = []
        
        # Check folder indicators
        for pattern in self.folder_regex:
            if pattern.search(filepath):
                reasons.append("folder_indicator")
                break
        
        # Check filename keywords
        for pattern in self.filename_regex:
            if pattern.search(filename):
                reasons.append("filename_match")
                break
        
        # Check exact filename matches
        if filename in self.exact_filenames:
            reasons.append("exact_filename")
        
        # Content matches indicate HIGH level
        if content_matches:
            reasons.append("content_match")
            return InterestingLevel.HIGH, ",".join(reasons)
        
        # Multiple indicators suggest MED level
        if len(reasons) > 1:
            return InterestingLevel.MED, ",".join(reasons)
        elif len(reasons) == 1:
            return InterestingLevel.LOW, ",".join(reasons)
        
        return InterestingLevel.LOW, "weak_indicators"

    def scan_file_content(self, filepath: str, max_bytes: int = None) -> Tuple[List[str], List[str], str]:
        """Scan file content for sensitive patterns."""
        if max_bytes is None:
            max_bytes = self.args.deepscan_max_bytes
        
        findings = []
        actual_values = []
        content_snippet = ""
        
        try:
            with open(filepath, 'rb') as f:
                # Read first max_bytes
                content = f.read(max_bytes)
                
                # Check if file is binary by looking for null bytes or high ratio of non-printable characters
                null_count = content.count(b'\x00')
                non_printable_count = sum(1 for byte in content if byte < 32 and byte != 9 and byte != 10 and byte != 13)
                
                # If more than 10% null bytes or 30% non-printable characters, it's likely binary
                if null_count > len(content) * 0.1 or non_printable_count > len(content) * 0.3:
                    return [], [], "Binary file detected - skipping content scan"
                
                # Try to decode as text
                try:
                    text_content = content.decode('utf-8', errors='ignore')
                except UnicodeDecodeError:
                    text_content = content.decode('latin-1', errors='ignore')
                
                # Additional check: if the decoded text contains mostly non-printable characters, skip
                printable_chars = sum(1 for char in text_content if char.isprintable() or char in '\n\r\t')
                if printable_chars < len(text_content) * 0.7:  # Less than 70% printable characters
                    return [], [], "Binary file detected - skipping content scan"
                
                # Scan for patterns
                for category, patterns in self.content_regex.items():
                    for pattern in patterns:
                        matches = pattern.findall(text_content)
                        if matches:
                            findings.append(f"{category}:{pattern.pattern}")
                            # Store actual matched values, not just patterns
                            for match in matches:
                                if isinstance(match, tuple):
                                    # Handle groups in regex
                                    actual_value = f"{category}:{match[0] if match[0] else ' '.join(match)}"
                                else:
                                    actual_value = f"{category}:{match}"
                                
                                # Filter out false positives for Domain_Users
                                if category == 'Domain_Users':
                                    # Skip if it looks like code (contains common code patterns)
                                    if any(code_pattern in actual_value.lower() for code_pattern in [
                                        'document.', 'window.', 'function', 'var ', 'let ', 'const ',
                                        'if ', 'for ', 'while ', 'return ', 'class ', 'import ',
                                        'require', 'include', 'echo ', 'print ', 'console.',
                                        'http', 'https', '.com', '.org', '.git', '.txt', '.php',
                                        '<?php', '<!--', '//', '/*', '*/', 'function(', '()',
                                        'length', 'push', 'pop', 'replace', 'split', 'join',
                                        'addEventListener', 'onclick', 'onload', 'onchange'
                                    ]):
                                        continue
                                
                                # Only add if not already present (deduplicate)
                                if actual_value not in actual_values:
                                    actual_values.append(actual_value)
                
                # Create snippet
                if findings:
                    lines = text_content.split('\n')[:5]  # First 5 lines
                    content_snippet = " ".join(lines)[:200]  # First 200 chars
                
        except Exception as e:
            return [], [], f"Error reading file: {str(e)}"
        
        return findings, actual_values, content_snippet

    def extract_ooxml_metadata(self, filepath: str) -> Dict:
        """Extract metadata from OOXML files."""
        metadata = {}
        
        try:
            with zipfile.ZipFile(filepath, 'r') as zip_file:
                # Try to read core.xml
                try:
                    with zip_file.open('docProps/core.xml') as core_file:
                        tree = ET.parse(core_file)
                        root = tree.getroot()
                        
                        # Extract common metadata fields
                        for elem in root.iter():
                            tag = elem.tag.split('}')[-1]  # Remove namespace
                            if tag in ['creator', 'lastModifiedBy', 'created', 'modified', 'application', 'company', 'template', 'totalTime']:
                                metadata[tag] = elem.text
                except KeyError:
                    pass
                
                # Try to read app.xml
                try:
                    with zip_file.open('docProps/app.xml') as app_file:
                        tree = ET.parse(app_file)
                        root = tree.getroot()
                        
                        for elem in root.iter():
                            tag = elem.tag.split('}')[-1]
                            if tag in ['Application', 'Company', 'Manager']:
                                metadata[tag.lower()] = elem.text
                except KeyError:
                    pass
                    
        except Exception as e:
            metadata['error'] = str(e)
        
        return metadata

    def scan_file(self, target: str, share: str, filepath: str, relative_path: str) -> Optional[ScanResult]:
        """Scan a single file and return results."""
        try:
            # Get file stats first to check size
            stat_info = os.stat(filepath)
            size = stat_info.st_size
            last_write = datetime.fromtimestamp(stat_info.st_mtime).isoformat()
            
            filename = os.path.basename(filepath)
            
            # Determine action and reason
            action, action_reason = self.get_file_action(relative_path, filename)
            
            # Skip files that should be skipped
            if action == Action.SKIP:
                return None
            
            # Skip very large files to prevent slow scanning
            max_file_size = 50 * 1024 * 1024  # 50MB limit
            if size > max_file_size:
                if self.args.verbose:
                    self.print_status(f"Skipping large file: {relative_path} ({self.format_size(size)})", target, share)
                    self.clear_status()
                return None
            
            # Show current file being scanned
            self.print_status(f"Scanning: {relative_path}", target, share)
            
            # Initialize variables
            findings = []
            actual_values = []
            content_snippet = ""
            ooxml_meta = {}
            errors = []
            
            # Scan content if requested and appropriate
            if self.args.scan_contents and action in [Action.DEEPSCAN, Action.QUICKPEEK]:
                if action == Action.DEEPSCAN:
                    findings, actual_values, content_snippet = self.scan_file_content(
                        filepath, self.args.deepscan_max_bytes
                    )
                elif action == Action.QUICKPEEK and self.args.quickpeek:
                    findings, actual_values, content_snippet = self.scan_file_content(
                        filepath, self.args.quickpeek_max_bytes
                    )
                    ooxml_meta = self.extract_ooxml_metadata(filepath)
            
            # Determine interesting level
            interesting, reason = self.get_interesting_level(relative_path, filename, findings)
            
            # Create result
            result = ScanResult(
                target=target,
                share=share,
                path=relative_path,
                size=size,
                last_write=last_write,
                action=action.value,
                reason=f"{action_reason},{reason}",
                interesting=interesting.value,
                findings=findings,
                actual_values=actual_values,
                content_snippet=content_snippet,
                ooxml_meta=ooxml_meta,
                errors=errors
            )
            
            # Clear status line before printing result
            self.clear_status()
            
            # Print colored output
            self.print_result(result)
            
            return result
            
        except Exception as e:
            self.clear_status()
            if self.args.verbose:
                print(f"Error scanning {filepath}: {str(e)}")
            return None

    def format_size(self, size_bytes: int) -> str:
        """Format file size in human readable format."""
        if size_bytes == 0:
            return "0B"
        
        size_names = ["B", "KB", "MB", "GB", "TB"]
        i = 0
        while size_bytes >= 1024 and i < len(size_names) - 1:
            size_bytes /= 1024.0
            i += 1
        
        if i == 0:
            return f"{size_bytes}B"
        else:
            return f"{size_bytes:.1f}{size_names[i]}"

    def print_result(self, result: ScanResult):
        """Print a scan result with color coding."""
        # Clear any status line before printing result
        self.clear_status()
        
        # Determine color based on interesting level
        if result.interesting == "HIGH":
            color = Fore.RED + Style.BRIGHT
        elif result.interesting == "MED":
            color = Fore.YELLOW
        else:
            color = Fore.WHITE
        
        # Format the output line
        size_str = self.format_size(result.size)
        output_line = f"[{result.interesting}] {result.target}\\{result.share}\\{result.path} {size_str} ({result.action}; {result.reason})"
        
        # Print with color
        print(f"{color}{output_line}{Style.RESET_ALL}")
        
        # Print findings if any
        if result.actual_values:
            print(f"  Found: {', '.join(result.actual_values[:3])}")  # Show first 3 findings
            if len(result.actual_values) > 3:
                print(f"  ... and {len(result.actual_values) - 3} more")
        
        # Print content snippet if available
        if result.content_snippet and len(result.content_snippet.strip()) > 0:
            snippet = result.content_snippet.strip()
            if len(snippet) > 100:
                snippet = snippet[:100] + "..."
            print(f"  Content: {snippet}")

    def print_status(self, message: str, target: str = "", share: str = ""):
        """Print a status message that will be overwritten."""
        # Include server/share info in status if provided
        if target and share:
            full_message = f"🔍 {target}\\{share}\\{message}"
        else:
            full_message = f"🔍 {message}"
        
        # Truncate message if too long to prevent terminal overflow
        max_length = 100  # Reduced from 120 to prevent overflow
        if len(full_message) > max_length:
            full_message = full_message[:max_length-3] + "..."
        
        # Clear the line completely and print status
        print('\r' + ' ' * 120 + '\r', end='', flush=True)  # Reduced from 150
        print(f"\r{full_message}", end='', flush=True)
    
    def clear_status(self):
        """Clear the status line."""
        # Clear with fewer spaces to reduce blank lines
        print('\r' + ' ' * 120 + '\r', end='', flush=True)  # Reduced from 150
    
    def clear_and_print(self, message: str):
        """Clear the current line and print a new message."""
        self.clear_status()
        print(message)
    
    def print_skip_message(self, directory: str, target: str = "", share: str = ""):
        """Print skip message and ensure it stays at the bottom."""
        # Clear the status line completely first
        self.clear_status()
        
        # Print the skip message
        if target and share:
            print(f"⏭️  Skipping directory: {target}\\{share}\\{directory}")
        else:
            print(f"⏭️  Skipping directory: {directory}")
        
        # Don't add extra newline to reduce blank spaces

    def scan_directory(self, target: str, share: str, root_path: str, current_path: str = "", depth: int = 0):
        """Recursively scan a directory."""
        if depth > self.args.max_depth:
            return
        
        full_path = os.path.join(root_path, current_path)
        
        # Show current directory being scanned
        showing_directory_status = False
        if current_path:
            self.print_status(f"Scanning directory: {current_path} (Press 'S' to skip)", target, share)
            showing_directory_status = True
        
        try:
            with os.scandir(full_path) as entries:
                for entry in entries:
                    # Check for skip request (always interactive)
                    if self.keyboard_handler.check_for_skip():
                        self.print_skip_message(current_path, target, share)
                        self.keyboard_handler.reset_skip_flag()
                        return
                    
                    try:
                        # Skip if should be excluded
                        if self.args.exclude_dirs:
                            for pattern in self.args.exclude_dirs:
                                if re.search(pattern, entry.name, re.IGNORECASE):
                                    continue
                        
                        # Include only if specified
                        if self.args.include_dirs:
                            include_match = False
                            for pattern in self.args.include_dirs:
                                if re.search(pattern, entry.name, re.IGNORECASE):
                                    include_match = True
                                    break
                            if not include_match:
                                continue
                        
                        relative_path = os.path.join(current_path, entry.name).replace('/', '\\')
                        
                        # Check if path should be skipped
                        if self.should_skip_path(relative_path):
                            continue
                        
                        if entry.is_file():
                            # Check file extension filters
                            ext = Path(entry.name).suffix.lower()
                            if self.args.include_ext and ext not in self.args.include_ext:
                                continue
                            if self.args.exclude_ext and ext in self.args.exclude_ext:
                                continue
                            
                            # Clear directory status before scanning file
                            if showing_directory_status:
                                self.clear_status()
                                showing_directory_status = False
                            
                            # Scan the file
                            result = self.scan_file(target, share, entry.path, relative_path)
                            if result:
                                with self.lock:
                                    self.results.append(result)
                        
                        elif entry.is_dir() and not entry.is_symlink():
                            # Recursively scan subdirectories
                            self.scan_directory(target, share, root_path, relative_path, depth + 1)
                    
                    except PermissionError:
                        if self.args.verbose:
                            print(f"Permission denied: {entry.path}")
                    except Exception as e:
                        if self.args.verbose:
                            print(f"Error processing {entry.path}: {str(e)}")
        
        except PermissionError:
            if self.args.verbose:
                print(f"Permission denied accessing directory: {full_path}")
        except Exception as e:
            if self.args.verbose:
                print(f"Error scanning directory {full_path}: {str(e)}")
        
        # Clear directory status at the end if it was showing
        if showing_directory_status:
            self.clear_status()

    def net_use(self, host: str, username: str = None, password: str = None) -> bool:
        """Establish SMB connection using net use command."""
        if not username:
            return True  # No authentication needed
        
        cmd = f'net use \\\\{host}'
        if username:
            cmd += f' /user:{username}'
        if password:
            cmd += f' {password}'
        
        try:
            result = os.system(cmd)
            return result == 0
        except Exception as e:
            if self.args.verbose:
                print(f"Error establishing SMB connection: {str(e)}")
            return False

    def net_view(self, host: str) -> List[str]:
        """Get list of shares from a host using net view command."""
        try:
            import subprocess
            # Run net view command
            result = subprocess.run(
                ['net', 'view', f'\\\\{host}'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if self.args.verbose:
                print(f"Net view output for \\\\{host}:")
                print(f"Return code: {result.returncode}")
                print(f"Stdout:\n{result.stdout}")
                print(f"Stderr:\n{result.stderr}")
            
            shares = []
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                
                # Skip header lines and look for actual share names
                for line in lines:
                    line = line.strip()
                    # Skip empty lines, headers, and separator lines
                    if not line or line.startswith('Shared resources') or line.startswith('Share name') or line.startswith('---') or line.startswith('\\\\'):
                        continue
                    
                    # Extract share name (first word before spaces)
                    parts = line.split()
                    if parts:
                        share_name = parts[0]
                        # Skip if it looks like a header or system info
                        if share_name.lower() in ['samba', 'type', 'used', 'comment', 'name']:
                            continue
                        shares.append(share_name)
            
            if self.args.verbose:
                print(f"Found shares: {shares}")
            
            return shares
            
        except subprocess.TimeoutExpired:
            print(f"Timeout getting shares from {host}")
            return []
        except Exception as e:
            print(f"Error getting shares from {host}: {e}")
            return []

    def scan_share(self, target: str, share: str, subpath: str = ""):
        """Scan a specific SMB share."""
        if self.args.path_unc:
            # Direct UNC path scanning
            root_path = self.args.path_unc
        else:
            # Construct UNC path
            root_path = f"\\\\{target}\\{share}"
            if subpath:
                root_path = os.path.join(root_path, subpath)
        
        print(f"Scanning: {root_path}")
        
        if not os.path.exists(root_path):
            print(f"Path does not exist: {root_path}")
            return
        
        self.scan_directory(target, share, root_path)

    def save_results(self):
        """Save results to JSONL and CSV files."""
        if not self.results:
            print("No results to save.")
            return
        
        # Save JSONL
        if self.args.jsonl:
            with open(self.args.jsonl, 'w', encoding='utf-8') as f:
                for result in self.results:
                    f.write(json.dumps(asdict(result), ensure_ascii=False) + '\n')
            print(f"Results saved to {self.args.jsonl}")
        
        # Save CSV
        if self.args.csv:
            with open(self.args.csv, 'w', newline='', encoding='utf-8') as f:
                if self.results:
                    fieldnames = asdict(self.results[0]).keys()
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    for result in self.results:
                        # Convert lists to semicolon-separated strings for CSV
                        row = asdict(result)
                        row['findings'] = ';'.join(row['findings'])
                        row['actual_values'] = ';'.join(row['actual_values'])
                        row['errors'] = ';'.join(row['errors'])
                        writer.writerow(row)
            print(f"Results saved to {self.args.csv}")

    def parse_target(self, target: str) -> Tuple[str, Optional[str], Optional[str]]:
        """Parse target string to extract host, share, and subpath."""
        target = target.strip()
        
        # Handle different formats
        if target.startswith('\\\\'):
            # UNC path format: \\host\share\path
            parts = target[2:].split('\\')
            host = parts[0]
            if len(parts) > 1 and parts[1]:
                share = parts[1]
                subpath = '\\'.join(parts[2:]) if len(parts) > 2 else None
                return host, share, subpath
            else:
                # \\host\ or \\host format - no specific share
                return host, None, None
        else:
            # Just hostname/IP
            return target, None, None

    def run(self):
        """Main execution method."""
        print("SMB Sensitive Strings Scanner")
        print("=" * 40)
        
        # Always show interactive message
        if KEYBOARD_AVAILABLE:
            print("🔧 Interactive mode enabled - Press 'S' to skip current folder")
        else:
            print("⚠️  Interactive mode not available on this platform")
            print("   Continuing in non-interactive mode")
        
        if self.args.dry_run:
            print("DRY RUN MODE - No actual scanning will be performed")
            return
        
        if self.args.path_unc:
            # Scan specific UNC path
            target = "LOCAL"
            share = "UNC"
            self.scan_share(target, share)
        elif self.args.mounted_root:
            # Scan mounted CIFS path
            target = "MOUNTED"
            share = "CIFS"
            self.scan_share(target, share, self.args.mounted_root)
        else:
            # Scan targets from file or command line
            targets = []
            if self.args.targets_file:
                with open(self.args.targets_file, 'r') as f:
                    targets = [line.strip() for line in f if line.strip()]
            elif self.args.target:
                targets = [self.args.target]
            
            for target_str in targets:
                # Parse target to extract host, share, and subpath
                host, specific_share, subpath = self.parse_target(target_str)
                
                print(f"\nScanning target: {target_str}")
                print(f"Parsed: Host={host}, Share={specific_share}, Subpath={subpath}")
                
                # Establish connection
                if not self.net_use(host, self.args.username, self.args.password):
                    print(f"Failed to connect to {host}")
                    continue
                
                if specific_share:
                    # Specific share was provided in target
                    print(f"Scanning specific share: {specific_share}")
                    self.scan_share(host, specific_share, subpath or "")
                else:
                    # No specific share - enumerate all shares
                    shares = self.net_view(host)
                    
                    # If no shares found and include_shares is specified, use those
                    if not shares and self.args.include_shares:
                        print(f"No shares found via net view, using specified shares: {self.args.include_shares}")
                        shares = [s.strip() for s in self.args.include_shares.split(',')]
                    elif not shares:
                        print(f"No shares found for {host}. Try using --include-shares to specify shares manually.")
                        print("Example: --include-shares 'C$,Users,Public'")
                        continue
                    
                    # Filter shares
                    if self.args.include_shares:
                        include_list = [s.strip() for s in self.args.include_shares.split(',')]
                        shares = [s for s in shares if s in include_list]
                    
                    if self.args.exclude_shares:
                        exclude_list = [s.strip() for s in self.args.exclude_shares.split(',')]
                        shares = [s for s in shares if s not in exclude_list]
                    
                    if not self.args.include_admin_shares:
                        shares = [s for s in shares if not s.endswith('$')]
                    
                    print(f"Found shares: {', '.join(shares)}")
                    
                    if not shares:
                        print(f"No shares to scan for {host} after filtering.")
                        continue
                    
                    # Scan each share
                    for share in shares:
                        self.scan_share(host, share)
        
        # Save results
        self.save_results()
        
        # Print summary
        print(f"\nScan completed. Found {len(self.results)} interesting files.")
        
        # Count by interesting level
        high_count = sum(1 for r in self.results if r.interesting == "HIGH")
        med_count = sum(1 for r in self.results if r.interesting == "MED")
        low_count = sum(1 for r in self.results if r.interesting == "LOW")
        
        print(f"  HIGH: {high_count}")
        print(f"  MED:  {med_count}")
        print(f"  LOW:  {low_count}")
        
        # Print detailed HIGH priority summary
        if high_count > 0:
            self.print_high_priority_summary()
        
        # Generate HTML summary
        self.generate_html_summary()

    def print_high_priority_summary(self):
        """Print a detailed summary of all HIGH priority findings grouped by category."""
        print(f"\n{'='*60}")
        print("🔥 HIGH PRIORITY FINDINGS SUMMARY")
        print(f"{'='*60}")
        
        # Get all HIGH priority results
        high_results = [r for r in self.results if r.interesting == "HIGH"]
        
        # Group by category
        categories = {}
        for result in high_results:
            for actual_value in result.actual_values:
                # Extract category from actual_value (format: "Category:value")
                if ':' in actual_value:
                    category, value = actual_value.split(':', 1)
                    if category not in categories:
                        categories[category] = []
                    
                    # Create a more targeted content snippet
                    targeted_content = self.create_targeted_snippet(result.content_snippet, value)
                    
                    categories[category].append({
                        'value': value,
                        'source': f"{result.target}\\{result.share}\\{result.path}",
                        'content_snippet': targeted_content
                    })
        
        if not categories:
            print("No categorized HIGH priority findings found.")
            return
        
        # Print each category
        for category, findings in categories.items():
            print(f"\n🔍 {category.upper()} FINDINGS ({len(findings)} items):")
            print("-" * 50)
            
            for i, finding in enumerate(findings, 1):
                print(f"{i}. {finding['value']}")
                print(f"   📁 Source: {finding['source']}")
                if finding['content_snippet']:
                    print(f"   📄 Context: {finding['content_snippet']}")
                print()
        
        print(f"{'='*60}")
        print(f"Total HIGH priority findings: {len(high_results)} files with {sum(len(findings) for findings in categories.values())} sensitive items")
        print(f"{'='*60}")

    def create_targeted_snippet(self, content_snippet: str, found_value: str) -> str:
        """Create a targeted snippet showing the context around the found sensitive data."""
        if not content_snippet or not found_value:
            return content_snippet
        
        content = content_snippet.strip()
        value_clean = found_value.strip()
        
        pos = content.find(value_clean)
        if pos == -1:
            for word in value_clean.split():
                pos = content.find(word)
                if pos != -1:
                    value_clean = word
                    break
        
        if pos != -1:
            start = max(0, pos - 20)
            end = min(len(content), pos + len(value_clean) + 20)
            context = content[start:end]
            if start > 0:
                context = "..." + context
            if end < len(content):
                context = context + "..."
            return context
        
        return content_snippet[:80] + "..." if len(content_snippet) > 80 else content_snippet

    def generate_html_summary(self, output_file: str = "scan_summary.html"):
        """Generate an HTML summary report with collapsible groups organized by asset types."""
        if not self.results:
            print("No results to generate HTML summary.")
            return
        
        # Group results by priority level
        high_results = [r for r in self.results if r.interesting == "HIGH"]
        med_results = [r for r in self.results if r.interesting == "MED"]
        low_results = [r for r in self.results if r.interesting == "LOW"]
        
        # Organize findings by asset type
        asset_groups = self._organize_by_asset_type()
        
        # Build command and scan path information
        scan_info = self._build_scan_info()
        
        # Generate HTML
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SMB Scanner - {scan_info['target_display']}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
            font-weight: 300;
        }}
        .header .subtitle {{
            margin-top: 10px;
            opacity: 0.9;
            font-size: 1.1em;
        }}
        .scan-info {{
            background: #e9ecef;
            padding: 15px 20px;
            border-bottom: 1px solid #dee2e6;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }}
        .scan-info .label {{
            font-weight: bold;
            color: #495057;
        }}
        .scan-info .value {{
            color: #6c757d;
            margin-left: 10px;
        }}
        .stats {{
            display: flex;
            justify-content: space-around;
            padding: 20px;
            background: #f8f9fa;
            border-bottom: 1px solid #dee2e6;
        }}
        .stat {{
            text-align: center;
        }}
        .stat-number {{
            font-size: 2em;
            font-weight: bold;
            color: #495057;
        }}
        .stat-label {{
            color: #6c757d;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .asset-group {{
            margin: 20px;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        .asset-header {{
            padding: 20px;
            color: white;
            font-size: 1.4em;
            font-weight: bold;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: background-color 0.3s;
        }}
        .asset-header:hover {{
            opacity: 0.9;
        }}
        .asset-header.network {{
            background: linear-gradient(135deg, #4facfe, #00f2fe);
        }}
        .asset-header.credentials {{
            background: linear-gradient(135deg, #ff6b6b, #ee5a52);
        }}
        .asset-header.files {{
            background: linear-gradient(135deg, #feca57, #ff9ff3);
        }}
        .asset-header.folders {{
            background: linear-gradient(135deg, #48dbfb, #0abde3);
        }}
        .asset-header.emails {{
            background: linear-gradient(135deg, #a8edea, #fed6e3);
        }}
        .asset-content {{
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease-out;
        }}
        .asset-content.expanded {{
            max-height: 2000px;
        }}
        .priority-section {{
            margin: 15px;
            border-radius: 6px;
            overflow: hidden;
            border: 1px solid #e9ecef;
        }}
        .priority-header {{
            padding: 12px 15px;
            font-weight: bold;
            color: white;
            font-size: 1.1em;
        }}
        .priority-header.high {{
            background: #dc3545;
        }}
        .priority-header.med {{
            background: #ffc107;
            color: #212529;
        }}
        .priority-header.low {{
            background: #17a2b8;
        }}
        .finding-item {{
            padding: 15px;
            border-bottom: 1px solid #f1f3f4;
            transition: background-color 0.2s;
        }}
        .finding-item:hover {{
            background-color: #f8f9fa;
        }}
        .finding-item:last-child {{
            border-bottom: none;
        }}
        .finding-value {{
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 8px;
            font-size: 1.1em;
            background: #fff3cd;
            padding: 8px 12px;
            border-radius: 4px;
            border-left: 4px solid #ffc107;
            word-break: break-all;
        }}
        .finding-source {{
            color: #6c757d;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            margin-bottom: 5px;
        }}
        .finding-context {{
            background: #f8f9fa;
            padding: 8px 12px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
            color: #495057;
            border-left: 3px solid #007bff;
        }}
        .empty-section {{
            padding: 40px;
            text-align: center;
            color: #6c757d;
            font-style: italic;
        }}
        .timestamp {{
            text-align: center;
            padding: 20px;
            color: #6c757d;
            font-size: 0.9em;
            border-top: 1px solid #dee2e6;
        }}
        .toggle-icon {{
            font-size: 1.2em;
            transition: transform 0.3s;
        }}
        .toggle-icon.expanded {{
            transform: rotate(180deg);
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 SMB Scanner Results</h1>
            <div class="subtitle">Sensitive Data Discovery Report</div>
        </div>
        
        <div class="scan-info">
            <div><span class="label">Target:</span><span class="value">{scan_info['target_display']}</span></div>
            <div><span class="label">Command:</span><span class="value">{scan_info['command']}</span></div>
            <div><span class="label">Scan Path:</span><span class="value">{scan_info['scan_path']}</span></div>
            <div><span class="label">Authentication:</span><span class="value">{scan_info['auth_info']}</span></div>
        </div>
        
        <div class="stats">
            <div class="stat">
                <div class="stat-number" style="color: #ff6b6b;">{len(high_results)}</div>
                <div class="stat-label">High Priority</div>
            </div>
            <div class="stat">
                <div class="stat-number" style="color: #feca57;">{len(med_results)}</div>
                <div class="stat-label">Medium Priority</div>
            </div>
            <div class="stat">
                <div class="stat-number" style="color: #48dbfb;">{len(low_results)}</div>
                <div class="stat-label">Low Priority</div>
            </div>
            <div class="stat">
                <div class="stat-number" style="color: #667eea;">{len(self.results)}</div>
                <div class="stat-label">Total Files</div>
            </div>
        </div>
        
        {self._generate_asset_groups_html(asset_groups)}
        
        <div class="timestamp">
            Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        </div>
    </div>
    
    <script>
        function toggleAssetGroup(groupId) {{
            const content = document.getElementById(groupId + '-content');
            const icon = document.getElementById(groupId + '-icon');
            const header = document.getElementById(groupId + '-header');
            
            if (content.classList.contains('expanded')) {{
                content.classList.remove('expanded');
                icon.classList.remove('expanded');
                header.style.borderRadius = '8px';
            }} else {{
                content.classList.add('expanded');
                icon.classList.add('expanded');
                header.style.borderRadius = '8px 8px 0 0';
            }}
        }}
        
        // Auto-expand high priority groups
        document.addEventListener('DOMContentLoaded', function() {{
            const highPriorityGroups = document.querySelectorAll('.asset-group');
            highPriorityGroups.forEach(group => {{
                const hasHighPriority = group.querySelector('.priority-header.high');
                if (hasHighPriority) {{
                    const groupId = group.querySelector('.asset-header').getAttribute('onclick').match(/toggleAssetGroup\('([^']+)'\)/)[1];
                    toggleAssetGroup(groupId);
                }}
            }});
        }});
    </script>
</body>
</html>
        """
        
        # Write HTML file
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            print(f"\n📄 HTML Summary generated: {output_file}")
        except Exception as e:
            print(f"Error generating HTML summary: {e}")

    def _build_scan_info(self):
        """Build scan information for the HTML report."""
        # Get unique targets and shares from results
        targets = set()
        shares = set()
        for result in self.results:
            targets.add(result.target)
            shares.add(result.share)
        
        # Build target display
        if len(targets) == 1:
            target_display = list(targets)[0]
        else:
            target_display = f"Multiple targets: {', '.join(sorted(targets))}"
        
        # Build scan path
        if len(shares) == 1:
            scan_path = f"\\\\{list(targets)[0]}\\{list(shares)[0]}"
        else:
            scan_path = f"\\\\{list(targets)[0]}\\Multiple shares: {', '.join(sorted(shares))}"
        
        # Build command
        command_parts = ["python smb_scanner.py"]
        
        if self.args.target:
            command_parts.append(f'--target "{self.args.target}"')
        elif self.args.targets_file:
            command_parts.append(f'--targets-file "{self.args.targets_file}"')
        elif self.args.path_unc:
            command_parts.append(f'--path-unc "{self.args.path_unc}"')
        elif self.args.mounted_root:
            command_parts.append(f'--mounted-root "{self.args.mounted_root}"')
        
        if self.args.username:
            command_parts.append(f'-u "{self.args.username}"')
        if self.args.password:
            command_parts.append(f'-p "{self.args.password}"')
        
        if self.args.scan_contents:
            command_parts.append('--scan-contents')
        
        if self.args.include_shares:
            command_parts.append(f'--include-shares "{self.args.include_shares}"')
        if self.args.exclude_shares:
            command_parts.append(f'--exclude-shares "{self.args.exclude_shares}"')
        
        command = ' '.join(command_parts)
        
        # Build authentication info
        if self.args.username:
            auth_info = f"Username: {self.args.username}"
            if self.args.password:
                auth_info += " (with password)"
        else:
            auth_info = "Anonymous access"
        
        return {
            'target_display': target_display,
            'command': command,
            'scan_path': scan_path,
            'auth_info': auth_info
        }

    def _organize_by_asset_type(self):
        """Organize findings by asset type categories."""
        asset_groups = {
            'network': {'title': '🌐 Network Assets (IP Addresses)', 'icon': '🌐', 'results': []},
            'credentials': {'title': '🔑 Passwords & Tokens', 'icon': '🔑', 'results': []},
            'files': {'title': '📄 Sensitive Files', 'icon': '📄', 'results': []},
            'folders': {'title': '📁 Sensitive Folders', 'icon': '📁', 'results': []},
            'emails': {'title': '📧 Email Addresses', 'icon': '📧', 'results': []}
        }
        
        for result in self.results:
            # Categorize by content patterns
            for actual_value in result.actual_values:
                if ':' in actual_value:
                    category = actual_value.split(':', 1)[0]
                    
                    if category in ['Network_Addresses']:
                        asset_groups['network']['results'].append((actual_value, result))
                    elif category in ['Secrets', 'Cloud', 'DB_Connection', 'Domain_Users']:
                        asset_groups['credentials']['results'].append((actual_value, result))
                    elif category in ['Emails']:
                        asset_groups['emails']['results'].append((actual_value, result))
                    elif category in ['Shadow_Files']:
                        asset_groups['files']['results'].append((actual_value, result))
            
            # Categorize by folder indicators (sensitive folders)
            if any(pattern.search(result.path) for pattern in self.folder_regex):
                asset_groups['folders']['results'].append(('Sensitive_Folder:' + result.path, result))
            
            # Categorize by filename keywords (sensitive files)
            if any(pattern.search(result.path.split('\\')[-1]) for pattern in self.filename_regex):
                asset_groups['files']['results'].append(('Sensitive_File:' + result.path.split('\\')[-1], result))
        
        return asset_groups

    def _generate_asset_groups_html(self, asset_groups):
        """Generate HTML for asset groups."""
        html_parts = []
        
        for group_key, group_data in asset_groups.items():
            if not group_data['results']:
                continue
                
            # Group by priority
            high_items = [(v, r) for v, r in group_data['results'] if r.interesting == "HIGH"]
            med_items = [(v, r) for v, r in group_data['results'] if r.interesting == "MED"]
            low_items = [(v, r) for v, r in group_data['results'] if r.interesting == "LOW"]
            
            html_parts.append(f'''
            <div class="asset-group">
                <div class="asset-header {group_key}" onclick="toggleAssetGroup('{group_key}')" id="{group_key}-header">
                    <span>{group_data['title']} ({len(group_data['results'])} items)</span>
                    <span class="toggle-icon" id="{group_key}-icon">▼</span>
                </div>
                <div class="asset-content" id="{group_key}-content">
            ''')
            
            # High priority section
            if high_items:
                html_parts.append(f'''
                    <div class="priority-section">
                        <div class="priority-header high">🔥 HIGH PRIORITY ({len(high_items)} items)</div>
                        {self._generate_findings_html(high_items)}
                    </div>
                ''')
            
            # Medium priority section
            if med_items:
                html_parts.append(f'''
                    <div class="priority-section">
                        <div class="priority-header med">⚠️ MEDIUM PRIORITY ({len(med_items)} items)</div>
                        {self._generate_findings_html(med_items)}
                    </div>
                ''')
            
            # Low priority section
            if low_items:
                html_parts.append(f'''
                    <div class="priority-section">
                        <div class="priority-header low">ℹ️ LOW PRIORITY ({len(low_items)} items)</div>
                        {self._generate_findings_html(low_items)}
                    </div>
                ''')
            
            html_parts.append('</div></div>')
        
        return ''.join(html_parts)

    def _generate_findings_html(self, items):
        """Generate HTML for findings list."""
        if not items:
            return '<div class="empty-section">No findings</div>'
        
        html_parts = []
        for actual_value, result in items:
            # Extract the actual sensitive value
            if ':' in actual_value:
                value_part = actual_value.split(':', 1)[1]
            else:
                value_part = actual_value
            
            source_path = f"{result.target}\\{result.share}\\{result.path}"
            file_path = f"file:///{result.target}/{result.share}/{result.path}".replace('\\', '/')
            context = self.create_targeted_snippet(result.content_snippet, value_part)
            
            html_parts.append(f'''
            <div class="finding-item">
                <div class="finding-value">🔍 {value_part}</div>
                <div class="finding-source">
                    📁 Source: <a href="{file_path}" target="_blank">{source_path}</a>
                </div>
                <div class="finding-context">{context}</div>
            </div>
            ''')
        
        return ''.join(html_parts)

def main():
    parser = argparse.ArgumentParser(
        description="SMB Sensitive Strings Scanner - Scan SMB shares for sensitive files and secrets (Interactive mode always enabled - Press 'S' to skip folders)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan all shares on a host
  python smb_scanner.py --target 10.0.0.5 --scan-contents
  python smb_scanner.py --target \\\\10.0.0.5 --scan-contents
  
  # Scan specific share
  python smb_scanner.py --target \\\\10.0.0.5\\Users --scan-contents
  
  # Scan specific path within a share
  python smb_scanner.py --target \\\\10.0.0.5\\Users\\Public --scan-contents
  
  # With authentication
  python smb_scanner.py --target 10.0.0.5 -u CORP\\alice -p "S3cret!" --scan-contents
  
  # Direct UNC path (alternative)
  python smb_scanner.py --path-unc "\\\\10.0.0.5\\Users\\Public" --scan-contents
  
  # Multiple targets from file
  python smb_scanner.py --targets-file hosts.txt --include-shares "Users,Shared"
  
Note: Interactive mode is always enabled. Press 'S' during scanning to skip the current folder.
        """
    )
    
    # Target specification
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('--target', help='Target host or UNC path. Examples: 10.0.0.5, \\\\10.0.0.5, \\\\10.0.0.5\\Share, \\\\10.0.0.5\\Share\\path')
    target_group.add_argument('--targets-file', help='File containing list of target hosts')
    target_group.add_argument('--path-unc', help='Direct UNC path to scan (alternative to --target)')
    target_group.add_argument('--mounted-root', help='Mounted CIFS path for Linux/Mac')
    
    # Authentication
    parser.add_argument('-u', '--username', help='Username (DOMAIN\\user or user@domain)')
    parser.add_argument('-p', '--password', help='Password (use empty quotes for blank password)')
    
    # Share filtering
    parser.add_argument('--include-shares', help='Comma-separated list of shares to include')
    parser.add_argument('--exclude-shares', help='Comma-separated list of shares to exclude')
    parser.add_argument('--include-admin-shares', action='store_true', help='Include admin shares (C$, ADMIN$, etc.)')
    
    # Directory and file filtering
    parser.add_argument('--include-dirs', nargs='+', help='Regex patterns for directories to include')
    parser.add_argument('--exclude-dirs', nargs='+', help='Regex patterns for directories to exclude')
    parser.add_argument('--include-ext', nargs='+', help='File extensions to include')
    parser.add_argument('--exclude-ext', nargs='+', help='File extensions to exclude')
    parser.add_argument('--max-depth', type=int, default=10, help='Maximum directory depth to scan')
    
    # Content scanning
    parser.add_argument('--scan-contents', action='store_true', help='Scan file contents for sensitive patterns')
    parser.add_argument('--deepscan-max-bytes', type=int, default=4*1024*1024, help='Maximum bytes to read for deep scan (default: 4MB)')
    parser.add_argument('--quickpeek', action='store_true', help='Enable quick peek for OOXML files')
    parser.add_argument('--quickpeek-max-bytes', type=int, default=8*1024*1024, help='Maximum bytes to read for quick peek (default: 8MB)')
    
    # Output options
    parser.add_argument('--jsonl', help='Output file for JSONL format')
    parser.add_argument('--csv', help='Output file for CSV format')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be scanned without actually scanning')
    
    # Performance
    parser.add_argument('--threads', type=int, default=1, help='Number of threads (default: 1)')
    parser.add_argument('--skip-path-defaults', action='store_true', help='Skip default path exclusions')
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.include_ext:
        args.include_ext = [ext.lower() if not ext.startswith('.') else ext.lower() for ext in args.include_ext]
    if args.exclude_ext:
        args.exclude_ext = [ext.lower() if not ext.startswith('.') else ext.lower() for ext in args.exclude_ext]
    
    # Create scanner and run
    scanner = SMBScanner(args)
    scanner.run()

if __name__ == "__main__":
    main() 