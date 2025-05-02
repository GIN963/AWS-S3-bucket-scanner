# ☁️ AWS S3 Bucket Secrets Scanner (Metasploit Module)

## Description

`AWS S3 Bucket Secrets Scanner` is a custom **Metasploit auxiliary module** designed to scan publicly accessible AWS S3 buckets and analyze their contents for sensitive information. It helps identify potential security exposures by extracting files and detecting common types of secrets such as:

* AWS Access Keys
* JWT Tokens
* Plaintext Passwords
* Private Keys (RSA, EC, DSA)
* API Keys

This module is particularly useful during **cloud pentesting** and **red team operations** targeting misconfigured storage resources.

---

## Features

- Scans a given public S3 bucket
- Lists files if the bucket allows listing
- Downloads and analyzes each accessible file
- Automatically detects several secret patterns
- Exports results in both plain text and structured JSON
- Supports scan throttling via configurable delay

---

## Demo Bucket Configuration

To safely test this module, a public S3 bucket was created with the following configuration:

### Example Bucket: `vuln-bucket-n4n0n3t`

#### 🔧 Bucket Setup

* **Name**: `vuln-bucket-n4n0n3t`
* **Region**: `us-east-1`
* **Public Access**: Enabled (`s3:GetObject` allowed for all)
* **Object Listing**: Enabled
* **Files Included**:

  * `secrets.txt` – fake AWS key
  * `config.json` – contains mock API key
  * `jwt.token` – dummy JWT
  * `credentials.env` – credentials sample
  * `notes.txt` – harmless file

#### 📜 Bucket Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicReadGetObject",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::vuln-bucket-n4n0n3t/*"
    }
  ]
}
```

---

## Installation

1. Clone the repository:

```bash
git clone https://github.com/GIN963/s3_bucket_scanner.git
```

2. Copy the Ruby module to your Metasploit modules directory:

```bash
cp s3_bucket_scanner.rb ~/.msf4/modules/auxiliary/cloud/
```

3. Restart Metasploit:

```bash
msfconsole
```

---

## Usage

```bash
use auxiliary/cloud/s3_bucket_scanner
set BUCKET_NAME vuln-bucket-n4n0n3t
set TIMEOUT 1
run
```

### Sample Output:

```
[*] Starting scan on bucket: vuln-bucket-n4n0n3t
[+] Found 5 files in bucket vuln-bucket-n4n0n3t
[*] Scanning file: secrets.txt
[!] Secrets found in secrets.txt:
    - AWS Access Key(s): AKIA1234567890TEST
[*] Scanning file: config.json
[!] Secrets found in config.json:
    - API Key(s): api_key = "abcd1234efgh5678ijkl"
...
[+] Exported JSON results to ~/.msf4/loot/s3_secrets_vuln-bucket-n4n0n3t.json
```

---

## Requirements

* Metasploit Framework
* Ruby >= 2.5

---

## Disclaimer

⚠️ This module is for **educational purposes only** or for use in authorized environments (e.g., bug bounty, labs, internal testing). **Never use this tool on production systems or real infrastructure without explicit permission.** All AWS credentials shown in this documentation are **fake** and used for demonstration purposes only.
