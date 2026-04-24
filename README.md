# TrustStore Analyzer
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python: 3.6+](https://img.shields.io/badge/python-3.6+-green.svg)](https://www.python.org/)

A tool for system administrators and security engineers to audit certificate truststores. This utility transforms flat certificate directories into logical hierarchies, making it easy to spot broken chains or expiring certificates.

## ✨ Features

* **Chain Visualization:** Automatically builds a tree structure of your certificate hierarchy.
* **Format Support:** Specifically designed for **X.509 certificates** in **PEM encoding**.
* **Multi-Format Output:** Supports human-readable Text trees, structured JSON, and a specialized **Monitoring Status API**.
* **Dynamic Health Monitoring:** Visual status indicators (✅ Valid, ⏳ Expiring Soon, ❌ Invalid). The "Expiring Soon" alert is fully configurable via a custom threshold (default is 30 days).
* **Collision Intelligence:** Detects "Name Collisions" (👯) where different certificates share the same Common Name but have different cryptographic identities.
* **Dual-Core Architecture:** Specifically optimized for **Pydantic v2** with a built-in **Zero-Dependency Fallback** for standard Python. This ensures full functionality on everything from legacy RHEL/CentOS systems to the latest Python 3.14 environments.
* **Expiration Alerts:** Highlights certificates expiring within a 30-day threshold.
* **Internationalization:** Ready for translation via `gettext`.
* **🔐 Signature Verification:** Beyond just mapping IDs, the tool cryptographically verifies signatures (RSA/ECDSA) between certificates in the chain.
    * 🔒 **Locked:** Signature is valid and verified.
    * 💥 **Broken:** Signature verification failed.
    * ❓ **Unknown:** Issuer certificate missing, cannot verify.
* **Multi-Source Input Engine:** Flexible data ingestion supporting various workflows:
    * **Structured Config:** Parse complex environments using YAML or JSON definition files.
    * **Ad-hoc Scanning:** Recursively scan directories for common certificate extensions (.crt, .pem, .cer, .der).
    * **Single File Audit:** Directly analyze individual files with automatic system truststore resolution.

## 🛠 Installation & Setup
The tool now follows a standard Python project structure and can be installed as an editable package.

```bash
# Clone the repository
git clone https://gitlab.com/nulleke/check_truststore.git
cd check_truststore

# Install in editable mode with all dependencies (including Pydantic)
pip install -e ".[all]"

# The command 'check_truststore' is now available in your PATH (within your venv)
```

## 🛠 Configuration
The analyzer supports both YAML and JSON configuration files to define your environments and certificate locations.

### YAML Structure (`config.yml`)
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

### JSON Structure (`config.json`)

```json
{
  "truststores": [
    {
      "name": "Production Gateway",
      "cert_src_dir": "/etc/ssl/certs/prod/",
      "cert_chain": [
        { "link": "root_ca.crt" },
        { "link": "intermediate_ca.crt" },
        { "link": "server_cert.crt" }
      ]
    }
  ]
}
```

## Overview
This tool parses certificate files (CRTs) defined in a central YAML configuration, verifies their validity and expiration dates, and reconstructs the issuer/subject hierarchy. It supports output in both human-readable text trees and machine-readable JSON.

## 🧪 Reliability & CI/CD
This project is rigorously tested via **GitLab CI** across a full matrix of Python versions. 
* **Compatibility Matrix:** Automated tests run on every version from 3.6 to 3.14.
* **Fallback Validation:** We explicitly test a "No-Pydantic" environment to guarantee that the core logic remains 100% functional even when third-party validation libraries are missing.
* **Logic Verification:** All date-based logic is validated against current 2026 standards.

### Local Validation
You can run the full compatibility suite locally using Podman to ensure your changes work across all supported Python versions:
```bash
./scripts/run_ci.sh
```

## 📦 Requirements
* **Python 3.6+** (Fully tested from 3.6 up to 3.14)
* **cryptography**: For X.509 parsing (compatible with legacy and UTC-aware versions).
* **PyYAML**: For configuration management.
* **pydantic** (Optional): v2.0+ for enhanced schema validation. The tool automatically detects and adapts to the available version.

## 🔍 Advanced Logic & Visual Indicators
The tool uses **SKI/AKI (Subject/Authority Key Identifier)** to build a cryptographically accurate tree. It uniquely identifies certificates using their Subject Key Identifier (SKI). If the SKI extension is missing, it falls back to a deterministic hash of the public key, ensuring consistent identification (labeled as **ID**) across all views.

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
| 👯 | **COLLISION** | Name collision detected (same Common Name, different ID). |
| 💻 | **SYSTEM** | Certificate was loaded from the OS truststore. |

## 🧠 Core Logic & Identity Strategy
* **Smart Deduplication**: To keep reports clean and efficient, the tool uses a dual-layer filtering process. First, it calculates a **SHA-256 fingerprint** for every file. If the exact same certificate (identical binary content) is found in multiple paths, it is processed only once. This prevents redundant entries and circular references in the tree.
* **Persistent Identity (ID)**: The tool uniquely identifies certificates using their **Subject Key Identifier (SKI)**.
    * If the official SKI extension is present, it is used as the primary identifier.
    * If the extension is missing (common in legacy or custom test-certs), the tool generates a **deterministic SHA-256 hash** of the public key.
    * **Result:** You get a consistent `(ID: abcdef12)` label across both the table and the hierarchy, allowing you to trace issuer/subject relationships with cryptographic certainty.
* **Name Collisions [👯]**: Even with ID tracking, name collisions occur (e.g., two different CAs using the same Common Name). The tool detects these based on differing Public Key IDs and flags them. This ensures you can distinguish between them even if they appear identical in the hierarchy.
* **`EXTERNAL_OR_MISSING_ISSUER` [❓]**: A virtual node for certificates whose issuer (Root or Intermediate) was not found in the provided source directories or the system truststore. The debug log will specify the exact **AKI (Authority Key Identifier)** needed to complete the chain.

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

# Export to simple JSON for file status monitoring with json input
./check_truststore config.json --format status
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

### 🚦 Detailed Status API (v1.1.1)
When using `--format status`, the tool generates a deep-inspection JSON object. This is ideal for integration with monitoring dashboards (Zabbix, Grafana) or automated security gateways.

#### JSON Field Definitions
| Field | Type | Description |
| :--- | :--- | :--- |
| `metadata.version` | `string` | The version of the TrustStore Analyzer engine. |
| `metadata.scanDate` | `string` | Timestamp of the scan in ISO-8601 (Zulu) format. |
| `metadata.exitCode` | `int` | Global result code (0-7). The highest severity found in the scan. |
| `groups[].groupName` | `string` | The name of the truststore environment defined in your configuration. |
| `groups[].groupStatus`| `string` | Summary status label for this specific group. |
| `summary.totalCertificates` | `int` | Total count of certificates processed in this group. |
| `summary.isChainComplete` | `bool` | `true` if all certificates have a path to a root or known issuer. |
| `summary.isTrusted` | `bool` | `true` only if the chain is complete AND cryptographically valid. |
| `certificates[].commonName` | `string` | The Subject Common Name (CN) of the certificate. |
| `certificates[].serialNumber`| `string` | The hexadecimal serial number of the certificate. |
| `certificates[].signatureValid`| `bool/null`| Result of the RSA/ECDSA signature check against the parent. |
| `certificates[].expiryDate` | `string` | Expiration date in ISO-8601 format. |
| `certificates[].trustStatus` | `string` | Detailed health label (e.g., `OK`, `SIG_ERR`, `EXPIRED`, `CHAIN_INVALID`). |
| `certificates[].statusCode` | `int` | Numeric status for the individual certificate (0-6). |

#### JSON Example Snippet
```json
{
  "metadata": {
    "version": "1.1.0",
    "scanDate": "2026-04-23T09:24:00Z",
    "exitCode": 0
  },
  "groups": [
    {
      "groupName": "Production Store",
      "groupStatus": "OK",
      "summary": {
        "totalCertificates": 2,
        "isChainComplete": true,
        "isTrusted": true
      },
      "certificates": [
        {
          "commonName": "Root CA",
          "serialNumber": "1A:2B:3C",
          "signatureValid": true,
          "expiryDate": "2027-01-01T12:00:00Z",
          "trustStatus": "OK",
          "statusCode": 0
        },
        {
          "commonName": "Server Cert",
          "serialNumber": "4D:5E:6F",
          "signatureValid": true,
          "expiryDate": "2026-09-01T12:00:00Z",
          "trustStatus": "OK",
          "statusCode": 0
        }
      ]
    }
  ]
}
```

### Text-Based Hierarchy (Human Readable)
The tree view combines multiple layers of intelligence: identity validation, date checking, and cryptographic verification.

```text
Certificate Hierarchy:
├── Root CA [✅][🔒]  (2036-04-13)
│   ├── Intermediate CA (ID: e5477085) [✅][🔒][👯]  (2027-04-16)
│   │   └── Server Cert A [✅][🔒]  (2027-04-16)
│   └── Intermediate CA (ID: f847a79d) [❌][🔒][👯]  (2026-04-16)
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
| **0** | `OK` | All certificates are cryptographically valid and trusted. |
| **1** | `WARNING` | Certificate is valid but expires within the defined threshold. |
| **2** | `EXPIRED` | At least one certificate in the chain has passed its `notAfter` date. |
| **3** | `INCOMPLETE` | The chain is broken; an issuer (Root or Intermediate) was not found. |
| **4** | `INVALID` | **Critical:** Signature verification failure (`SIG_ERR`) or CA-constraint violation. |
| **5** | `REVOKED` | *(Reserved for future CRL/OCSP implementation)*. |
| **6** | `INPUT_ERR` | File access issues, I/O errors, or unparseable certificate structures. |
| **7** | `FATAL` | An unexpected application error or crash occurred. |

> **Note on Thresholds:** The transition from `VALID` (0) to `EXPIRING_SOON` (1) is triggered when a certificate is within the `N`-day window defined by the `--threshold` argument.

## 🔍 Debugging & Scenario Analysis
When running with the `--debug` flag, the tool outputs detailed logs to `stderr`. This is essential for understanding how the certificate tree is being constructed and where potential issues lie.

### Healthy Execution (Success)
The tool displays the signature status (🔒) for verified chains.
```text
🔵 INFO         │      │ Configuration loaded           │ Processing 11 certificate paths
✅ OK           │ 🔒   │ Root CA                        │ 2036-04-13 06:37
✅ OK           │ 🔒👯 │ Intermediate CA (ID: e5477085) │ 2027-04-16 06:37
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
If the same certificate is present multiple times (even under different filenames), the tool identifies the identical fingerprint and skips processing to prevent loops and clutter.
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
⏳ WARNING      │  👯  │ Intermediate CA (ID: 43aff331) │ 2026-04-26 06:38
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

To update or add translations, use the provided utility script:
```bash
./scripts/translate.sh nl  # Updates Dutch translations
```

## 🤝 Contributing
Contributions are welcome! Whether it's reporting a bug, suggesting an enhancement, or submitting a pull request, your help is appreciated.

Please see our [CONTRIBUTING.md](CONTRIBUTING.md) for details on our development standards, legacy environment support (RHEL 8), and how to get started.

## ⚖️ License
**Copyright (C) 2026 Serge van Thillo**

This program is free software: you can redistribute it and/or modify it under the terms of the **GNU General Public License** as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the [GNU General Public License](https://www.gnu.org/licenses/gpl-3.0) for more details.

---
**Status:** Version: 1.0.0 | Stable | **Logic validated for current system date:** April 24, 2026