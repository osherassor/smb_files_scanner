# 🔍 SMB Sensitive Data Scanner

A powerful Python-based tool for scanning SMB shares to discover sensitive files and secrets without downloading full files. Perfect for security assessments, penetration testing, and compliance audits.

## ✨ Features

### 🔐 **Sensitive Data Detection**
- **Cloud Credentials**: AWS, Azure, GCP API keys and secrets
- **Passwords & Tokens**: JWT tokens, bearer tokens, API keys
- **Database Connections**: Connection strings with credentials
- **Network Assets**: IP addresses, hostnames, CI/CD URLs
- **Email Addresses**: Email addresses in various contexts
- **Domain Users**: Domain authentication credentials
- **Shadow Files**: NTDS.dit, LSASS dumps, VSS snapshots
- **RDP Files**: Remote Desktop connection files
- **SSH Keys**: SSH private keys and configuration files

### 🎯 **Smart File Categorization**
- **DeepScan**: Text files, config files, code files
- **QuickPeek**: OOXML documents (metadata only)
- **ListOnly**: Archives, databases, binary files
- **Skip**: Media files, executables, irrelevant files

### 🚀 **Interactive Features**
- **Live Status Updates**: Real-time scanning progress
- **Interactive Skip**: Press 'S' to skip current folder
- **Smart Path Parsing**: Supports various UNC path formats
- **Binary Detection**: Automatically skips binary files

### 📊 **Comprehensive Reporting**
- **Console Output**: Colored, real-time results
- **CSV Export**: Structured data for analysis
- **JSONL Export**: Detailed findings with metadata
- **HTML Report**: Beautiful, collapsible summary with navigation

## 🛠️ Installation

### Prerequisites
- Python 3.7+
- Windows (for SMB access) or Linux/Mac (with mounted CIFS)

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Requirements
```
colorama>=0.4.6
tqdm>=4.65.0
```

## 🚀 Quick Start

### Basic Scan
```bash
# Scan all shares on a host
python smb_scanner.py --target 10.0.0.5

# Scan specific share
python smb_scanner.py --target \\10.0.0.5\Users

# Scan specific path
python smb_scanner.py --target \\10.0.0.5\Users\Public
```

### With Authentication
```bash
# Domain authentication
python smb_scanner.py --target 10.0.0.5 -u CORP\alice -p "S3cret!"

# Local authentication
python smb_scanner.py --target 10.0.0.5 -u administrator -p "password123"
```

### Export Results
```bash
# Export to CSV and JSONL
python smb_scanner.py --target \\10.0.0.5\Share --csv results.csv --jsonl results.jsonl

# Generate HTML report (automatic)
python smb_scanner.py --target \\10.0.0.5\Share
```

## 📖 Usage Examples

### 1. **Network Discovery Scan**
```bash
# Scan multiple hosts from file
echo "10.0.0.5" > hosts.txt
echo "10.0.0.10" >> hosts.txt
python smb_scanner.py --targets-file hosts.txt
```

### 2. **Targeted Share Scan**
```bash
# Scan only specific shares
python smb_scanner.py --target 10.0.0.5 --include-shares "Users,Shared,Public"

# Exclude admin shares
python smb_scanner.py --target 10.0.0.5 --exclude-shares "C$,ADMIN$,IPC$"
```

### 3. **Deep Content Analysis**
```bash
# Increase scan depth and file size limits
python smb_scanner.py --target \\10.0.0.5\Share --max-depth 15 --deepscan-max-bytes 10485760
```

### 4. **Linux/Mac with Mounted CIFS**
```bash
# Mount SMB share first
sudo mount -t cifs //10.0.0.5/Share /mnt/smb -o username=user,password=pass

# Scan mounted path
python smb_scanner.py --mounted-root /mnt/smb
```

## 🎮 Interactive Features

### Live Status Updates
The scanner provides real-time status updates:
```
🔍 Scanning: \\10.0.0.5\Users\alice\Documents\config.env
[HIGH] \\10.0.0.5\Users\alice\Documents\config.env 1.2KB (DeepScan; content_match)
```

### Interactive Skip
Press **'S'** during scanning to skip the current folder:
```
🔍 Scanning directory: \\10.0.0.5\Users\alice\Downloads (Press 'S' to skip)
⏭️  Skipping directory: \\10.0.0.5\Users\alice\Downloads
```

## 📊 Output Formats

### 1. **Console Output**
```
[HIGH] \\10.0.0.5\Users\config.env 1.2KB (DeepScan; content_match)
   🔑 AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF
   📁 Source: \\10.0.0.5\Users\config.env
   📄 Context: AWS_ACCESS_KEY_ID=**AKIA1234567890ABCDEF**...
```

### 2. **CSV Export**
```csv
target,share,path,size,last_write,action,reason,interesting,findings,actual_values
10.0.0.5,Users,config.env,1234,2024-01-15T10:30:00,DeepScan,content_match,HIGH,"Cloud:AKIA","Cloud:AKIA1234567890ABCDEF"
```

### 3. **JSONL Export**
```json
{
  "target": "10.0.0.5",
  "share": "Users",
  "path": "config.env",
  "size": 1234,
  "last_write": "2024-01-15T10:30:00",
  "action": "DeepScan",
  "reason": "content_match",
  "interesting": "HIGH",
  "findings": ["Cloud:AKIA"],
  "actual_values": ["Cloud:AKIA1234567890ABCDEF"],
  "content_snippet": "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF..."
}
```

### 4. **HTML Report**
- **Collapsible sections** by asset type
- **Clickable navigation** to categories
- **Color-coded priority** levels
- **Direct file links** for easy access
- **Scan information** and command used

## 🔧 Advanced Configuration

### File Type Categories

#### DeepScan Extensions
Text and configuration files that are fully scanned:
```
.env, .ini, .conf, .json, .yaml, .xml, .txt, .csv, .md
.php, .py, .java, .c, .cpp, .sh, .ps1, .bat
```

#### QuickPeek Extensions
OOXML documents (metadata only):
```
.docx, .xlsx, .pptx, .docm, .xlsm, .pptm
```

#### ListOnly Extensions
Archives and databases (indexed only):
```
.zip, .rar, .7z, .tar, .sqlite, .db, .bak
```

#### Skip Extensions
Media and binary files:
```
.jpg, .png, .mp4, .exe, .dll, .swf, .css, .html
```

### Content Pattern Categories

#### Cloud Credentials
- AWS Access Keys: `AKIA[0-9A-Z]{16}`
- Azure Client Secrets: `azure_client_secret`
- GCP API Keys: `google_api_key`

#### Secrets & Tokens
- JWT Tokens: `eyJ[A-Za-z0-9_-]{10,}...`
- API Keys: `api_key`, `access_key`
- Private Keys: `-----BEGIN RSA PRIVATE KEY-----`

#### Network Assets
- Internal IPs: `10.x.x.x`, `192.168.x.x`
- CI/CD URLs: Jenkins, GitLab, GitHub
- Database URLs: MySQL, PostgreSQL, MongoDB

## 🛡️ Security Considerations

### Safe Scanning
- **No file downloads**: Only streams file content
- **Size limits**: Configurable maximum file sizes
- **Binary detection**: Automatically skips binary files
- **Error handling**: Graceful handling of permission errors

### Best Practices
- **Use dedicated accounts**: Don't use admin credentials
- **Limit scope**: Scan specific shares, not entire networks
- **Review results**: Always verify findings before acting
- **Secure storage**: Protect exported results

## 🐛 Troubleshooting

### Common Issues

#### "System error 1707 has occurred"
- **Cause**: Invalid network address format
- **Solution**: Use correct UNC path format: `\\host\share`

#### "Access denied" errors
- **Cause**: Insufficient permissions
- **Solution**: Use authenticated access with `-u` and `-p`

#### No shares found
- **Cause**: Network connectivity or authentication issues
- **Solution**: Verify network access and credentials

#### Slow scanning
- **Cause**: Large files or network latency
- **Solution**: Adjust `--deepscan-max-bytes` or use `--max-depth`

### Debug Mode
```bash
# Enable verbose output
python smb_scanner.py --target 10.0.0.5 --verbose
```

## 📋 Command Line Options

### Target Specification
```bash
--target HOST              # Single host or UNC path
--targets-file FILE        # File with list of hosts
--path-unc "\\HOST\Share"  # Direct UNC path
--mounted-root PATH        # Mounted CIFS path (Linux/Mac)
```

### Authentication
```bash
-u, --username USER        # Username (DOMAIN\user or user@domain)
-p, --password PASS        # Password (use "" for blank)
```

### Share Filtering
```bash
--include-shares LIST      # Comma-separated shares to include
--exclude-shares LIST      # Comma-separated shares to exclude
--include-admin-shares     # Include admin shares (C$, ADMIN$)
```

### Content Scanning
```bash
--deepscan-max-bytes N     # Max bytes for deep scan (default: 4MB)
--quickpeek                # Enable OOXML metadata extraction
--max-depth N              # Maximum directory depth (default: 10)
```

### Output Options
```bash
--csv FILE                 # Export results to CSV
--jsonl FILE               # Export results to JSONL
--no-color                 # Disable colored output
--verbose                  # Enable verbose output
```

## 🤝 Contributing

### Development Setup
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

### Code Style
- Follow PEP 8 guidelines
- Add type hints where appropriate
- Include docstrings for functions
- Test with multiple Python versions

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is designed for **authorized security assessments only**. Always ensure you have proper authorization before scanning any systems. The authors are not responsible for any misuse of this tool.

## 🆘 Support

- **Issues**: Report bugs and feature requests on GitHub
- **Discussions**: Ask questions and share experiences
- **Security**: Report security vulnerabilities privately

---

**Happy Scanning! 🔍✨** 
