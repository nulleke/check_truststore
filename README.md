# TrustStore Analyzer
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python: 3.6+](https://img.shields.io/badge/python-3.6+-green.svg)](https://www.python.org/)

A tool for system administrators and security engineers to audit certificate truststores. This utility transforms flat certificate directories into logical hierarchies, making it easy to spot broken chains or expiring certificates.

## 🚀 Features

* **Chain Visualization:** Automatically builds a tree structure of your certificate hierarchy.
* **Format Support:** Specifically designed for **X.509 certificates** in **PEM encoding**.
* **Health Monitoring:** Visual status indicators (✅ Valid, ⏳ Expiring Soon, ❌ Invalid) based on a 30-day threshold.
* **Collision Intelligence:** Detects "Name Collisions" (👯) where different certificates share the same Common Name.
* **True Hybrid Architecture:** Seamlessly supports **Pydantic v1** (legacy), **Pydantic v2** (modern), or a **Zero-Dependency Fallback** (standard Python). This ensures the tool remains functional on legacy RHEL/CentOS systems and the latest Python 3.14 environments alike.
* **Expiration Alerts:** Highlights certificates expiring within a 30-day threshold.
* **Internationalization:** Ready for translation via `gettext`.

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

## 🧪 Reliability & CI/CD
This project is rigorously tested via **GitLab CI** across a full matrix of Python versions. 
* **Compatibility Matrix:** Automated tests run on every version from 3.6 to 3.14.
* **Fallback Validation:** We explicitly test a "No-Pydantic" environment to guarantee that the core logic remains 100% functional even when third-party validation libraries are missing.
* **Logic Verification:** All date-based logic is validated against current 2026 standards.

## Requirements
* **Python 3.6+** (Fully tested from 3.6 up to 3.14)
* **cryptography**: For X.509 parsing (compatible with legacy and UTC-aware versions).
* **PyYAML**: For configuration management.
* **pydantic** (Optional): v1.10+ or v2.0+ for enhanced schema validation. The tool automatically detects and adapts to the available version.

## 🔍 Advanced Logic & Visual Indicators
The tool uses **SKI/AKI (Subject/Authority Key Identifier)** to build a cryptographically accurate tree, even if multiple certificates share the same name.

* **`EXTERNAL_OR_MISSING_ISSUER` [❓]**: A virtual node for certificates whose issuer (Root or Intermediate) was not found in the provided source directories.
* **Name Collisions [👯]**: When two different certificates (different hashes) share the same Common Name, the tool adds this icon as aditional icon.
* **Deduplication**: If the exact same certificate (matching SHA-256 hash) is found in multiple paths, it is processed only once to keep the report clean.

## Usage
Run the script by providing a path to your truststore YAML configuration:

```bash
# Basic tree view
./check_truststore vars/prod/stores.yml --format text

# Deep dive with debug logs (shows skipped duplicates and I/O errors)
./check_truststore vars/tst/stores.yml --format text -d

# Export to JSON for integration with other monitoring tools
./check_truststore vars/prod/stores.yml --format json > audit_report.json

# Export to simple JSON for file status monitoring
./check_truststore vars/prod/stores.yml --format status
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
    "expiryDate": "2036-04-13T06:37:12Z",
    "children": [
      {
        "commonName": "Intermediate CA",
        "isValid": true,
        "isExpiringSoon": false,
        "expiryDate": "2027-04-16T06:37:42Z",
        "children": [
          {
            "commonName": "Server Cert A",
            "isValid": true,
            "isExpiringSoon": false,
            "expiryDate": "2027-04-16T06:39:33Z",
          }
        ]
      },
      {
        "commonName": "Intermediate CA",
        "isValid": true,
        "isExpiringSoon": true,
        "expiryDate": "2026-04-26T06:38:21Z",
        "children": [
          {
            "commonName": "Server Cert B",
            "isValid": true,
            "isExpiringSoon": true,
            "expiryDate": "2026-04-21T07:33:10Z",
          }
        ]
      },
      {
        "commonName": "Intermediate CA",
        "isValid": false,
        "isExpiringSoon": false,
        "expiryDate": "2026-04-16T07:29:59Z",
        "children": [
          {
            "commonName": "Expired Server Cert",
            "isValid": false,
            "isExpiringSoon": false,
            "expiryDate": "2026-04-16T07:39:29Z",
          }
        ]
      }
    ]
  },
  {
    "commonName": "EXTERNAL_OR_MISSING_ISSUER",
    "isValid": false,
    "isExpiringSoon": false,
    "expiryDate": "1970-01-01T00:00:00Z",
    "children": [
      {
        "commonName": "Orphan Certificate",
        "isValid": true,
        "isExpiringSoon": false,
        "expiryDate": "2027-04-16T07:42:39Z",
      }
    ]
  }
]
```

### Text-Based Hierarchy (Human Readable)
Ideal for a quick visual audit of the certificate chains. It uses ANSI colors in the terminal for better visibility.

```text
Certificaat Hiërarchie:
├── Root CA [✅]  (2036-04-13)
│   ├── Intermediate CA [✅][👯]  (2027-04-16)
│   │   └── Server Cert A [✅]  (2027-04-16)
│   ├── Intermediate CA [⏳][👯]  (2026-04-26)
│   │   └── Server Cert B [⏳]  (2026-04-21)
│   └── Intermediate CA [❌][👯]  (2026-04-16)
│       └── Expired Server Cert [❌]  (2026-04-16)
└── EXTERNAL ISSUER / MISSING ROOT [❓] 
    └── Orphan Certificate [✅]  (2027-04-16)
```

### File status based JSON
Ideal for a status check for all the mentioned files and status in the input list

#### 🚦 Status Code Definitions

When using the --format status output, each certificate is assigned a numeric statusCode. This allows for easy integration with alerting triggers.

| Code | Label | Description |
| :--- | :--- | :--- |
| **0**	| VALID	| Certificate is within its validity period and has a trusted path to a root in the store. |
| **1**	| EXPIRING_SOON	| Certificate is valid but expires within the 30-day threshold. |
| **2**	| UNTRUSTED	| The certificate is technically valid (dates are OK), but its issuer was not found in the truststore (Orphan). |
| **3**	| EXPIRED	| The certificate's notAfter date has passed or it is not yet valid (notBefore). |
| **4**	| INVALID	| The file could not be parsed or contains structural errors. |

#### Output

```json
[
  {
    "fileName": "root_ca.crt",
    "commonName": "Root CA",
    "statusCode": 0,
    "statusLabel": "VALID",
    "expiryDate": "2036-04-13T06:37:12Z"
  },
  {
    "fileName": "intermediate.crt",
    "commonName": "Intermediate CA",
    "statusCode": 1,
    "statusLabel": "EXPIRING_SOON",
    "expiryDate": "2026-04-26T06:38:21Z"
  },
  {
    "fileName": "orphan.crt",
    "commonName": "Orphan Certificate",
    "statusCode": 2,
    "statusLabel": "UNTRUSTED",
    "expiryDate": "2027-04-16T07:42:39Z"
  }
]
```

## 🔍 Debugging & Scenario Analysis

When running with the `--debug` flag, the tool outputs detailed logs to `stderr`. This is essential for understanding how the certificate tree is being constructed and where potential issues lie.

### Healthy Execution (Success)
When all certificates are found, validated, and hashes are unique.
```text
🔵 INFO         │      │ Configuration loaded           │ Processing 9 certificate paths
❌ READ_ERROR   │      │ non_existing.crt               │ File not found
✅ OK           │      │ Root CA                        │ 2036-04-13 06:37
✅ OK           │  👯  │ Intermediate CA (SKI: e547708) │ 2027-04-16 06:37
⏳ WARNING      │  👯  │ Intermediate CA (SKI: 43aff33) │ 2026-04-26 06:38
❌ ERROR        │  👯  │ Intermediate CA (SKI: f847a79) │ 2026-04-16 07:29
✅ OK           │      │ Server Cert A                  │ 2027-04-16 06:39
⏳ WARNING      │      │ Server Cert B                  │ 2026-04-21 07:33
❌ ERROR        │      │ Expired Server Cert            │ 2026-04-16 07:39
✅ OK           │      │ Orphan Certificate             │ 2027-04-16 07:42
❓ UNTRUSTED    │      │ AKI: 6d8e4e51                  │ Missing issuer for: Orphan Certificate
```

### Missing Files (I/O Errors)
Occurs when a filename defined in the YAML does not exist in the source directory.
```text
❌ READ_ERROR   │      │ non_existing.crt               │ File not found
```

### Missing Root or Intermediate (Untrusted Chain)
Occurs when a certificate's issuer is not present in the current truststore batch. These are grouped under the EXTERNAL_OR_MISSING_ISSUER node in the output.
```text
❓ UNTRUSTED    │      │ AKI: 6d8e4e51                  │ Missing issuer for: Orphan Certificate
```

### Redundant Certificates (Duplicate Content)
If the same certificate is present multiple times (even under different filenames), the tool identifies the identical SHA-256 hash and skips processing to prevent loops and clutter.
```text
⏳ WARNING      │      │ copy_of_root.crt               │ Duplicate content
```

### Invalid or Corrupted PEM
If a file is present but cannot be parsed as a valid X509 certificate.
```text
❌ READ_ERROR   │      │ invalid_format.crt             │ Unable to load PEM certificate
```

### Expired or Expiring Soon
The tool checks the current system time against the certificate's validity window.
```text
⏳ WARNING      │  👯  │ Intermediate CA (SKI: 43aff33) │ 2026-04-26 06:38
❌ ERROR        │      │ Expired Server Cert            │ 2026-04-16 07:39
```

## ⚖️ License

**Copyright (C) 2026 Serge van Thillo**

This program is free software: you can redistribute it and/or modify it under the terms of the **GNU General Public License** as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the [GNU General Public License](https://www.gnu.org/licenses/gpl-3.0) for more details.

---
**Status:** Stable / Production Ready | **Logic validated for current system date:** April 16, 2026