# TrustStore Analyzer
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python: 3.6+](https://img.shields.io/badge/python-3.6+-green.svg)](https://www.python.org/)

A tool for system administrators and security engineers to audit certificate truststores. This utility transforms flat certificate directories into logical hierarchies, making it easy to spot broken chains or expiring certificates.

## ✨ Features

* **Chain Visualization:** Automatically builds a tree structure of your certificate hierarchy.
* **Format Support:** Specifically designed for **X.509 certificates** in **PEM encoding**.
* **Dynamic Health Monitoring:** Visual status indicators (✅ Valid, ⏳ Expiring Soon, ❌ Invalid). The "Expiring Soon" alert is fully configurable via a custom threshold (default is 30 days).
* **Collision Intelligence:** Detects "Name Collisions" (👯) where different certificates share the same Common Name.
* **True Hybrid Architecture:** Seamlessly supports **Pydantic v1** (legacy), **Pydantic v2** (modern), or a **Zero-Dependency Fallback** (standard Python). This ensures the tool remains functional on legacy RHEL/CentOS systems and the latest Python 3.14 environments alike.
* **Expiration Alerts:** Highlights certificates expiring within a 30-day threshold.
* **Internationalization:** Ready for translation via `gettext`.
* **🔐 Signature Verification:** Beyond just mapping IDs, the tool cryptographically verifies signatures (RSA/ECDSA) between certificates in the chain.
    * 🔒 **Locked:** Signature is valid and verified.
    * 💥 **Broken:** Signature verification failed.
    * ❓ **Unknown:** Issuer certificate missing, cannot verify.

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

## 📦 Requirements
* **Python 3.6+** (Fully tested from 3.6 up to 3.14)
* **cryptography**: For X.509 parsing (compatible with legacy and UTC-aware versions).
* **PyYAML**: For configuration management.
* **pydantic** (Optional): v1.10+ or v2.0+ for enhanced schema validation. The tool automatically detects and adapts to the available version.

## 🔍 Advanced Logic & Visual Indicators
The tool uses **SKI/AKI (Subject/Authority Key Identifier)** to build a cryptographically accurate tree, even if multiple certificates share the same name.

### 🔍 Visual Indicators
The tool uses the following icons to provide a quick overview of certificate health and chain integrity:

| Icon | Status | Description |
| :--- | :--- | :--- |
| ✅ | **OK** | Valid and trusted. |
| ⏳ | **WARNING** | Expiring soon (within the defined threshold). |
| ❌ | **ERROR** | Expired, not yet valid, or structurally invalid. |
| 🔒 | **LOCKED** | Signature verified and cryptographically valid. |
| 💥 | **BROKEN** | Signature verification failed (security alert). |
| ❓ | **UNKNOWN** | Missing issuer; signature could not be verified. |
| 👯 | **COLLISION** | Name collision detected (same Common Name, different hash). |
| 💻 | **SYSTEM** | Certificate was loaded from the OS truststore. |

### Core Logic
* **`EXTERNAL_OR_MISSING_ISSUER` [❓]**: A virtual node for certificates whose issuer (Root or Intermediate) was not found in the provided source directories.
* **Name Collisions [👯]**: Even with AKI/SKI tracking, name collisions can occur (e.g., two different CAs using the same Common Name, or a re-issued certificate with a new key). The tool detects these based on differing SHA-256 hashes and flags them, ensuring you can distinguish between them even if they appear identical in the hierarchy.
* **Deduplication**: If the exact same certificate (matching SHA-256 hash) is found in multiple paths, it is processed only once to keep the report clean.

## 🛡️ System Truststore Integration
By default, the tool only analyzes the certificates explicitly defined in your YAML configuration. However, to verify if your local chain is ultimately trusted by the operating system, you can enable system integration.

* **Default:** Disabled.
* **Behavior:** When enabled, the tool scans common system paths (e.g., `/etc/ssl/certs/ca-certificates.crt` on Linux, the Keychain on macOS, or the Windows Certificate Store) to resolve missing root issuers.

## Usage
The analyzer supports two types of input sources. It automatically detects the source type based on the path provided.

### Directory Scan (Ad-hoc)
Point the tool to a directory to scan for all common certificate files (`.crt`, `.pem`, `.cer`, `.der`).

```bash
./check_truststore files/certificates/prod/trust/
```

### YAML Configuration (Structured)
Use a YAML file to define specific truststores and environments.

```bash
# Basic tree view
./check_truststore vars/prod/stores.yml --format text

# Combine local certificates with the system truststore for full chain validation
./check_truststore vars/prod/stores.yml --format text --system

# Run with full debug output and system truststore enabled
./check_truststore vars/prod/stores.yml --format text --debug --system

# Custom expiration check (e.g., alert if certificates expire within 90 days)
./check_truststore vars/prod/stores.yml --format text --threshold 90

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
The tree view combines multiple layers of intelligence: identity validation, date checking, and cryptographic verification.

```text
Certificate Hierarchy:
├── Root CA [✅][🔒]  (2036-04-13)
│   ├── Intermediate CA [✅][🔒][👯]  (2027-04-16)
│   │   └── Server Cert A [✅][🔒]  (2027-04-16)
│   └── Intermediate CA [❌][🔒][👯]  (2026-04-16)
│       └── Expired Server Cert [❌][🔒]  (2026-04-16)
├── Trusted Root CA [⏳][🔒]  (2026-05-18)
│   └── Broken Signature Leaf [❌][💥]  (2026-07-17)
└── EXTERNAL ISSUER / MISSING ROOT [❓] 
    └── Orphan Certificate [✅][❓]  (2027-04-16)
```

### File status based JSON
Ideal for a status check for all the mentioned files and status in the input list

#### 🚦 Status Code Definitions

When using the `--format status` output, each certificate is assigned a numeric `statusCode`. This allows for easy integration with alerting triggers and automated monitoring.

| Code | Label | Description |
| :--- | :--- | :--- |
| **0** | VALID | Certificate is within its validity period and has a trusted path to a root. |
| **1** | EXPIRING_SOON | Certificate is valid but expires within the defined threshold (default: 30 days). |
| **2** | UNTRUSTED | Valid dates, but the issuer was not found in the truststore (Orphan). |
| **3** | EXPIRED | The certificate's `notAfter` date has passed. |
| **4** | NOT_YET_VALID | The certificate's `notBefore` date is in the future. |
| **5** | INVALID | Structural error: The file could not be parsed as a valid X.509 certificate. |
| **6** | SIG_ERR | **Critical:** The cryptographic signature verification failed against the issuer's public key. |

> **Note on Thresholds:** The transition from `VALID` (0) to `EXPIRING_SOON` (1) is triggered when a certificate is within the `N`-day window defined by the `--threshold` argument.

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
The tool displays the signature status (🔒) for verified chains.
```text
🔵 INFO         │      │ Configuration loaded           │ Processing 11 certificate paths
✅ OK           │ 🔒   │ Root CA                        │ 2036-04-13 06:37
✅ OK           │ 🔒👯 │ Intermediate CA (SKI: e547708) │ 2027-04-16 06:37
```

### Signature Verification Failure (Security Alert)
If a signature does not match the issuer's public key, it is flagged with the `SIG_ERR` label and a 💥 icon.
```text
❌ SIG_ERR      │ 💥   │ Broken Signature Leaf          │ 2026-07-17 09:05
```

### Missing Files (I/O Errors)
Occurs when a filename defined in the YAML does not exist in the source directory.
```text
❌ READ_ERROR   │      │ non_existing.crt               │ File not found
```

### Missing Root or Intermediate (Untrusted Chain)
Occurs when a certificate's issuer is not present in the current truststore batch. These are grouped under the `EXTERNAL_OR_MISSING_ISSUER` node in the output.
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

## 🌐 Internationalization (i18n)

The tool supports multiple languages via standard `gettext` locales.
* **Language Selection:** The tool respects the `LANG` environment variable.
* **Scope:** Only human-readable outputs (Debug logs and Text trees) are translated. Machine-to-machine outputs (JSON and Status formats) remain in technical English for stability.

```bash
# Run in Dutch
LANG=nl_NL.UTF-8 ./check_truststore vars/prod/stores.yml -d
```

## 🤝 Contributing
Contributions are welcome! Whether it's reporting a bug, suggesting an enhancement, or submitting a pull request, your help is appreciated.

Please see our [CONTRIBUTING.md](CONTRIBUTING.md) for details on our development standards, legacy environment support (RHEL 8), and how to get started.

## ⚖️ License

**Copyright (C) 2026 Serge van Thillo**

This program is free software: you can redistribute it and/or modify it under the terms of the **GNU General Public License** as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the [GNU General Public License](https://www.gnu.org/licenses/gpl-3.0) for more details.

---
**Status:** Stable / Production Ready | **Logic validated for current system date:** April 16, 2026