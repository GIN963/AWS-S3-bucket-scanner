# AWS S3 Bucket Secrets Scanner

This is a custom **Metasploit auxiliary module** designed to scan **public AWS S3 buckets** for **sensitive data** such as AWS credentials, private keys, API keys, JWTs, and passwords.

---

## 🔧 Features

- Scans public S3 buckets for accessible files
- Detects sensitive data inside files using regex patterns:
  - AWS Access Keys (AKIA...)
  - API Keys & Tokens
  - JWTs
  - Private keys
  - Passwords and login info (key-value or SQL format)
  - Database URIs
- Can optionally **bruteforce object names** using a wordlist if the bucket does not allow listing
- Exports findings to both `.txt` and `.json` in Metasploit's `loot` directory

---

## 🚀 Usage

### 1. Drop the module in Metasploit custom module path:

```bash
mkdir -p ~/.msf4/modules/auxiliary/scanner
cp s3_bucket_scanner.rb ~/.msf4/modules/auxiliary/scanner/
```

### 2. Reload Metasploit modules:

```bash
msfconsole
reload_all
```

### 3. Use the module:

```bash
use auxiliary/scanner/s3_bucket_scanner
set BUCKET_NAME vuln-bucket-n4n0n3t
run
```

---

## ⚙️ Options

| Name        | Required | Description                                           |
|-------------|----------|-------------------------------------------------------|
| `BUCKET_NAME` | ✅       | Name of the public S3 bucket (without `.s3.amazonaws.com`) |
| `TIMEOUT`     | ❌       | Delay (in seconds) between requests (default: `2`)     |
| `WORDLIST`    | ❌       | Path to a wordlist of filenames to bruteforce objects |

---

## 🧠 About `WORDLIST`

If the bucket is **public but listing is disabled**, the module can try to guess filenames using a **bruteforce wordlist**. This allows discovery of hidden objects like:

```txt
config.env
credentials.txt
secret_key.json
```

Use it like this:

```bash
set WORDLIST /path/to/wordlist.txt
```

📌 You do **not** need `WORDLIST` if `list_bucket_files` works (i.e. bucket listing is enabled).

A good starter wordlist: `raft-small-files.txt` from [SecLists](https://github.com/danielmiessler/SecLists)

---

## 📝 Example Output

```bash
[*] Starting scan on bucket: vuln-bucket-n4n0n3t
[+] Found 6 files in bucket vuln-bucket-n4n0n3t
[*] Scanning file: config.env
[!] Secrets found in config.env:
[+]     - AWS Access Key(s): AKIAIOSFODNN7EXAMPLE
[+]     - Password(s): hunter2
[*] Scanning file: credentials.txt
[!] Secrets found in credentials.txt:
[+]     - API Key(s) / Token(s): sk_test_abc123...
[*] Auxiliary module execution completed
```

---

## 📂 Output Files

- `~/.msf4/loot/s3_secrets_<bucket>.txt` — plain text results
- `~/.msf4/loot/s3_secrets_<bucket>.json` — structured output

---

## ⚠️ Disclaimer

This module is for **educational and authorized testing** only. Do not use against systems or buckets you do not have permission to scan.
