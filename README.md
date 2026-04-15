# TrustStore Analyzer
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python: 3.6+](https://img.shields.io/badge/python-3.6+-green.svg)](https://www.python.org/)

A tool for system administrators and security engineers to audit certificate truststores. This utility transforms flat certificate directories into logical hierarchies, making it easy to spot broken chains or expiring certificates.

## 🚀 Features

* **Smart Hierarchy Building:** Automatically links certificates based on Issuer/Subject relationships and visualizes them in a tree.
* **Format Support:** Specifically designed for **X.509 certificates** in **PEM encoding**.
* **Health Monitoring:** Visual status indicators (✅ Valid, ⏳ Expiring Soon, ❌ Invalid) based on a 30-day threshold.
* **Collision Intelligence:** Detects "Name Collisions" (👥) where different certificates share the same Common Name.
* **Hybrid Pydantic Support:** Uses Pydantic for data validation if available, with a built-in fallback.
* **Internationalization:** Full support for localized logging and output via `gettext`.

## 🛠 Configuration (YAML)

The script expects a YAML file that defines your environments and certificate locations. Example structure:

```yaml
env: "prod"
certificate_file_extension: ".crt"
truststores:
  - cert_src_dir: "/etc/ssl/certs/{{ env }}/"
    cert_chain:
      - link: "root_ca"
      - link: "intermediate_ca"
      - link: "server_cert"
```

## Overview
This tool parses certificate files (CRTs) defined in a central YAML configuration, verifies their validity and expiration dates, and reconstructs the issuer/subject hierarchy. It supports output in both human-readable text trees and machine-readable JSON.

## Key Features
* **Chain Visualization:** Automatically builds a tree structure of your certificate hierarchy.
* **Collision Detection:** Identifies certificates with identical Common Names but different contents.
* **Expiration Alerts:** Highlights certificates expiring within a 30-day threshold.
* **Hybrid Pydantic Support:** Uses Pydantic for data validation if available, with a built-in fallback for environments without it.
* **Internationalization:** Ready for translation via `gettext`.

## Requirements
* Python 3.6+
* `PyYAML`
* `cryptography`
* *Optional:* `pydantic` (for enhanced data validation)

## Usage
Run the script by providing a path to your truststore YAML configuration:

```bash
./check_truststore config.yaml --format text --debug
```

## 📊 Output Examples

The tool provides different views of your truststore health depending on your needs.

### JSON based output (Default)
```json
[
  {
    "commonName": "Root CA",
    "isValid": true,
    "isExpiringSoon": false,
    "expiryDate": "2030-01-01T00:00:00+00:00",
    "children": [
      {
        "commonName": "Intermediate CA",
        "isValid": true,
        "isExpiringSoon": false,
        "expiryDate": "2028-06-15T00:00:00+00:00",
        "children": [
          {
            "commonName": "Web Server",
            "isValid": true,
            "isExpiringSoon": true,
            "expiryDate": "2026-05-01T12:00:00+00:00"
          }
        ]
      }
    ]
  }
]
```

### Text-Based Hierarchy (Human Readable)
Ideal for a quick visual audit of the certificate chains. It uses ANSI colors in the terminal for better visibility.

```text
Certificate Hierarchy:
├── GlobalSign Root [✅] (2030-01-01)
├── Root CA [✅] (2030-01-01)
│   ├── Intermediate CA [✅] (2028-06-15)
│   │   └── Web Server [✅] (2026-05-01)
│   └── Old Intermediate [⏳] (2026-04-20)
├── EXTERNAL_OR_MISSING_ISSUER [❓]
│   └── Third-Party Cert [❌] (2024-12-31)
└── MULTIPLE_CA_COLLISION [👥]
    ├── GlobalSign Root (Collision) [✅] (2029-12-31)
    └── GlobalSign Root (Collision) [❌] (2022-01-15)
```

## 🔍 Debugging & Scenario Analysis

When running with the `--debug` flag, the tool outputs detailed logs to `stderr`. This is essential for understanding how the certificate tree is being constructed and where potential issues lie.

### Healthy Execution (Success)
When all certificates are found, validated, and hashes are unique.
```text
🔵 INFO         | Configuration loaded           | Processing 3 certificate paths
✅ OK           | GlobalRoot_CA                  | 2030-01-01 12:00
✅ OK           | Intermediate_CA_V1             | 2028-06-15 12:00
✅ OK           | Production_Webserver           | 2026-05-01 12:00
```

### Missing Files (I/O Errors)
Occurs when a filename defined in the YAML does not exist in the source directory.
```text
❌ READ_ERROR   | missing_cert.crt               | File not found
```

### Missing Root or Intermediate (Untrusted Chain)
Occurs when a certificate's issuer is not present in the current truststore batch. These are grouped under the EXTERNAL_OR_MISSING_ISSUER node in the output.
```text
❓ UNTRUSTED    | External_CA_Provider           | Missing issuer for: My_Intermediate_Cert
```

### Redundant Certificates (Duplicate Content)
If the same certificate is present multiple times (even under different filenames), the tool identifies the identical SHA-256 hash and skips processing to prevent loops and clutter.
```text
⏳ WARNING      | copy_of_root.crt               | Duplicate content
```

### Name Collisions (Same Name, Different Content)
A critical scenario where two different certificates use the same Common Name. The tool detects this and treats them as separate entities to avoid merging incorrect chains.
```text
👥 COLLISION    | Corporate_Root_CA              | Name collision (different content)

```

### Invalid or Corrupted PEM
If a file is present but cannot be parsed as a valid X509 certificate.
```text
❌ READ_ERROR   | invalid_format.crt             | Unable to load PEM certificate
```

### Expired or Expiring Soon
The tool checks the current system time against the certificate's validity window.
```text
⏳ WARNING      | Soon_To_Expire_Cert            | 2026-04-25 10:00
❌ ERROR        | Old_Expired_Cert               | 2023-12-31 23:59
```

## ⚖️ License

**Copyright (C) 2026 Serge van Thillo**

This program is free software: you can redistribute it and/or modify it under the terms of the **GNU General Public License** as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the [GNU General Public License](https://www.gnu.org/licenses/gpl-3.0) for more details.

---
**Status:** Active Development | **Logic validated for current system date:** April 15, 2026