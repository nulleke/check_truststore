# TrustStore Analyzer
[![pipeline status](https://gitlab.com/nulleke/check_truststore/badges/main/pipeline.svg)](https://gitlab.com/nulleke/check_truststore/-/commits/main)
[![PyPI version](https://img.shields.io/pypi/v/check_truststore.svg)](https://pypi.org/project/check_truststore/)
[![License: LGPL v3](https://img.shields.io/badge/License-LGPLv3-blue.svg)](https://www.gnu.org/licenses/lgpl-3.0)
[![Python: 3.6+](https://img.shields.io/badge/python-3.6+-green.svg)](https://www.python.org/)

A tool for system administrators and security engineers to audit certificate truststores. This utility transforms flat certificate directories into logical hierarchies, making it easy to spot broken chains or expiring certificates.

## 📌 Table of Contents

- [⚡ Quick Start (TL;DR)](#-quick-start-tldr)
- [✨ Features](#-features)
- [🛠 Installation & Setup](#-installation--setup)
  - [PIP Installation](#pip-installation)
  - [Enterprise Linux (RHEL/AlmaLinux/Rocky)](#enterprise-linux-rhelalmalinuxrocky)
  - [🐳 Running via Docker/Podman](#-running-via-dockerpodman)
- [📂 Input Strategies](#-input-strategies)
  - [YAML Structure (config.yml)](#yaml-structure-configyml)
  - [JSON Structure (config.json)](#json-structure-configjson)
  - [File-Based Input](#file-based-input)
  - [Directory-Based Input](#directory-based-input)
  - [🛰️ Network Discovery Integration (Nmap)](#️-network-discovery-integration-nmap)
- [🛠 Usage](#-usage)
  - [Automatic Detection (Files & Directories)](#automatic-detection-files--directories)
  - [Live Network Analysis (Nmap Integration)](#live-network-analysis-nmap-integration)
  - [System Truststores](#system-truststores)
  - [📥 Supported Input Providers](#-supported-input-providers)
  - [🗣️ Verbosity Levels](#️-verbosity-levels)
  - [📄 Format Control](#-format-control)
- [📊 Multiple Outputs](#-multiple-outputs)
  - [JSON based output](#json-based-output)
  - [Verbose JSON Output (-v)](#verbose-json-output--v)
  - [🚦 Detailed Status API (v1.1.2)](#-detailed-status-api-v112)
  - [Text-Based Hierarchy (Human Readable) (Default)](#text-based-hierarchy-human-readable-default)
  - [🛡️ SARIF (Static Analysis Results Interchange Format)](#️-sarif-static-analysis-results-interchange-format)
  - [🎨 Visual PKI Topology (Graphviz)](#-visual-pki-topology-graphviz)
  - [📈 Prometheus Metrics Support](#-prometheus-metrics-support)
- [🧠 Core Logic & Identity Strategy](#-core-logic--identity-strategy)
  - [🏗️ Path Construction & Validation](#️-path-construction--validation)
  - [🆔 Identity Strategy](#-identity-strategy)
  - [🛡️ System Truststore Integration](#️-system-truststore-integration)
  - [🚀 Force Mode](#-force-mode)
  - [🛡️ Maximum Chain Depth Validation](#️-maximum-chain-depth-validation)
- [🔍 Debugging & Scenario Analysis](#-debugging--scenario-analysis)
  - [Healthy Execution & AIA Discovery](#healthy-execution--aia-discovery)
  - [Signature & Security Alerts](#signature--security-alerts)
  - [Missing Files (I/O Errors)](#missing-files-io-errors)
  - [Missing Root or Intermediate (Untrusted Chain)](#missing-root-or-intermediate-untrusted-chain)
  - [Redundant Certificates (Duplicate Content)](#redundant-certificates-duplicate-content)
  - [Invalid or Corrupted PEM](#invalid-or-corrupted-pem)
  - [Expired or Expiring Soon](#expired-or-expiring-soon)
- [🧪 Reliability & CI/CD](#-reliability--cicd)
  - [Local Validation](#local-validation)
- [📦 Requirements](#-requirements)
- [🌐 Internationalization (i18n)](#-internationalization-i18n)
- [💾 Cache Management](#-cache-management)
  - [Automated Cleanup (Linux / RHEL / Fedora)](#automated-cleanup-linux--rhel--fedora)
- [🤝 Contributing](#-contributing)
- [⚖️ License](#️-license)

## ⚡ Quick Start (TL;DR)
**Audit your truststores in seconds**:
1. **Install**: `pip install check-truststore`
2. **Run Ad-hoc**: `check_truststore /path/to/certs/`
3. **Visualize**: `check_truststore /path/to/certs/ --format text --system --online -vvv` or `check_truststore https://example.com --system --online`

*Supports **PEM**, **DER**, and **PKCS#7**. Works on macOS, and Linux. Windows in development*

## ✨ Features

* **Chain Visualization**: Automatically builds a tree structure of your certificate hierarchy.
* **Format Support**: 
    * **X.509 Certificates**: Full support for individual certificates in **PEM encoding**.
    * **PKCS#7 Bundles**: Support for `.p7b` and `.p7c` containers. The tool automatically extracts all certificates from the bundle for analysis.
* **Multi-Format Output**: 
    * **Human-Centric**: Text trees with status icons.
    * **Machine-Readable**: Structured JSON and SARIF for security pipelines.
    * **Monitoring**: Specialized **Status API** for integration with dashboards like Zabbix or Grafana.
    * **Visual Graph**: Generates **GraphViz-compatible DOT files** to visualize complex PKI topologies.
* **Dynamic Health Monitoring**: Visual status indicators (✅ Valid, ⏳ Expiring Soon, ❌ Invalid). The "Expiring Soon" alert is fully configurable via a custom threshold (default is 30 days).
* **AIA Discovery & Chain Repair**: Automatically identifies and fetches missing intermediate or root issuers via the network to complete broken chains.
* **Collision Intelligence**: Detects "Name Collisions" (👯) where different certificates share the same Common Name but have different cryptographic identities.
* **Dual-Core Architecture**: Specifically optimized for **Pydantic v2** with a built-in **Zero-Dependency Fallback** for standard Python. This ensures full functionality on everything from legacy RHEL/CentOS systems to the latest Python 3.14 environments.
* **Expiration Alerts**: Highlights certificates expiring within a 30-day threshold.
* **Internationalization**: Ready for translation via `gettext`.
* **🔐 Signature Verification**: Beyond just mapping IDs, the tool cryptographically verifies signatures (RSA/ECDSA) between certificates in the chain.
    * 🔒 **Locked**: Signature is valid and verified.
    * 💥 **Broken**: Signature verification failed.
    * ❓ **Unknown**: Issuer certificate missing, cannot verify.
* **Multi-Source Input Engine**: Flexible data ingestion supporting various automated workflows:
    * **Structured Environments**: Parse complex truststore definitions using **YAML** or **JSON** configuration files.
    * **Network Scan Integration**: Directly ingest **Nmap XML** output to audit certificates discovered during network discovery.
    * **Ad-hoc Scanning**: Recursively scan directories for certificates. Supports **X.509 (PEM)** and **PKCS#7 (.p7b, .p7c)** containers.
    * **Stream Processing**: Supports piped input (stdin) for JSON, XML, or raw PEM data, allowing seamless integration into shell pipelines.
    * **Single File Audit**: Analyze individual certificate files with automatic system truststore resolution for quick validation.
* **RFC 5280 Compliant Path Building**: Uses AKI/SKI stringing instead of unreliable Subject/Issuer name matching.
* **Name Constraints (RFC 5280)**: The engine now validates whether an intermediate CA is authorized to sign for specific DNS subtrees. It detects "poison pill" certificates where a SAN (Subject Alternative Name) falls outside the permitted scope of the issuer.
* **Cryptographic Chain Integrity**: Full support for signature verification across RSA and ECDSA algorithms.
* **📦 Chain Bundling**: Automatically generates a complete PKCS#7 (`.p7b`) bundle for each analyzed group, including missing intermediates discovered via AIA.

## 🛠 Installation & Setup

### PIP Installation
The tool now follows a standard Python project structure and can be installed as an editable package.

```bash
# Clone the repository
git clone https://gitlab.com/nulleke/check_truststore.git
cd check_truststore

# Install in editable mode with all dependencies (including Pydantic)
pip install -e ".[all]"

# The command 'check_truststore' is now available in your PATH (within your venv)
```

or you can install the pip package directly from pypi

```bash
# Install directly from pypi
pip install check-truststore
```

### Enterprise Linux (RHEL/AlmaLinux/Rocky)
This tool is officially packaged and signed for Enterprise Linux 8, 9, and 10.

#### Platform Support & Compatibility

| OS Version | Support Level | Python Version | GPG Signed | Package Format |
| :--- | :--- | :--- | :--- | :--- |
| **RHEL 8 / Alma 8** | Legacy | 3.6+ | No | RPM (Gzip) |
| **RHEL 9 / Alma 9** | Standard | 3.9+ | **Yes** | RPM (Zstd) |
| **RHEL 10 / Rawhide** | Cutting Edge | 3.12+ | **Yes** | RPM (Zstd) |

> **Security Note on RHEL 8**: 
> The RHEL 8 repository is intentionally not GPG-signed. The modern Elliptic Curve (Ed25519) GPG key used for this project's security supply chain is incompatible with the legacy cryptographic policies and older GnuPG versions (2.2.x) found in RHEL 8. To ensure seamless installation on legacy systems without forcing a downgrade of our security standards, GPG verification is disabled for this specific version. RHEL 9 and 10 provide full cryptographic path validation. So RHEL 8 admins should disable gpg verification in the repo file.

```bash
   sudo curl -sL https://thillo.ddns.net/repository/thillo-rhel.repo -o /etc/yum.repos.d/thillo.repo
   sudo dnf install check_truststore
```

### 🐳 Running via Docker/Podman

If you prefer not to install Python locally, you can use the provided `Dockerfile` to run the analyzer in an isolated environment:
```bash
# Build the image
podman build -t truststore-analyzer .

# Run an audit on a local directory and export bundles
podman run --rm \
  -v ./my-certs:/app/certs:Z \
  -v ./my-output:/app/output_bundles:Z \
  truststore-analyzer /app/certs/ --export-bundles --online
```

## 📂 Input Strategies
The analyzer supports multiple input methods to accommodate different auditing workflows.

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

### File-Based Input
Ideal for a surgical status check of specific certificate files. This mode provides a flat report focused on the validity of individual assets mentioned in your input list.

* **Use case**: Monitoring specific application-level certificates.
* **Behavior**: Each file is validated independently or as part of its own small chain.

### Directory-Based Input
Designed for comprehensive truststore audits. The tool recursively scans directories to build a global map of all available issuers.

* **Use case**: Auditing system-wide stores like `/etc/pki/ca-trust`
* **Behavior**: It automatically links intermediates to roots found within the same or other provided directories to reconstruct the full PKI topology using RFC 5280 logic.

### 🛰️ Network Discovery Integration (Nmap)
The **XML Provider** allows for seamless integration with network scanning workflows. It is specifically optimized to parse Nmap XML output (`-oX`), automatically extracting certificates discovered by the `ssl-cert` script.

#### Features
* **Automatic Extraction**: Scans Nmap XML for PEM-encoded certificates in host script results.
* **Virtual Path Mapping**: Findings are automatically grouped using a virtual directory structure: `nmap/<ip>/<port>`.
* **PEM Sanitization**: Automatically fixes XML-escaped characters and standardizes delimiters (e.g., handling `TRUSTED CERTIFICATE` headers).

## 🔍 Advanced Logic & Visual Indicators
The tool uses **SKI/AKI (Subject/Authority Key Identifier)** to build a cryptographically accurate tree. It uniquely identifies certificates using their Subject Key Identifier (SKI). If the SKI extension is missing, it falls back to a deterministic hash of the public key, ensuring consistent identification (labeled as **ID**) across all views.

### 🔍 Visual Indicators
The tool uses the following icons to provide a quick overview of certificate health and chain integrity:

| Icon | Status | Description |
| :--- | :--- | :--- |
| **✅** | **OK** | Valid and trusted. |
| **⏳** | **WARNING** | Expiring soon (within the defined threshold). |
| **❌** | **ERROR** | Expired, not yet valid, or structurally invalid. |
| **🔒** | **LOCKED** | Signature verified and cryptographically valid. |
| **💥** | **BROKEN** | Signature verification failed (security alert). |
| **❓** | **UNKNOWN** | Missing issuer; signature could not be verified. |
| **👯** | **COLLISION** | Name collision detected (same Common Name, different ID). |
| **💻** | **SYSTEM** | Certificate was loaded from the OS truststore. |

## 🛠 Usage

The analyzer is highly flexible, automatically detecting the appropriate **Input Provider** based on the path or stream content provided.

### Automatic Detection (Files & Directories)
Simply provide a path to a file or directory. The engine will select the correct provider:

* **YAML/JSON**: For structured truststore definitions (supports Jinja2 templating for yaml).
* **Directories**: Recursively scans for `.pem`, `.crt`, `.der`, or `.p7b` files and groups them by folder.
* **Individual Files**: Analyzes a single certificate chain or PKCS#7 bundle.

```bash
# Analyze a local directory of certificates
check_truststore ./my-certs/

# Use a YAML configuration with environment variables
check_truststore vars/prd/stores.yml --env prd
```

### Live Network Analysis (Nmap Integration)
Thanks to the `XmlInputProvider`, you can pipe network scan results directly into the analyzer. The tool extracts certificates from the Nmap XML output and reconstructs the full chain via **AIA**.

```bash
# Scan multiple domains and validate the full chain live
nmap -p 443 --script ssl-cert example.com next.example.com -oX - | check_truststore - --system --online
```

### System Truststores
Using the `--system` flag (powered by `SystemInputProvider`), you can audit the certificates built into your operating system:

* **Linux/macOS**: Scans standard system CA bundles (e.g., `/etc/ssl/certs/ca-certificates.crt`).
* **Windows**: Accesses the Certificate Store (ROOT/CA). (In development)

```bash
# Compare your local certs against the system trusted roots
check_truststore my-certs/ --system
```

```bash
# Check a live website
check_truststore https://www.example.com --system --online
```

### 📥 Supported Input Providers

| Provider | Trigger | Description |
| :--- | :--- | :--- |
| **YAML** | `.yml` | Configuration-driven input with Jinja2 and environment variable support. |
| **JSON** | `.json` | Configuration-driven input from `json`. |
| **XML (Nmap)** | `.xml` or `stdin` | Specifically optimized for Nmap `-oX` output; extracts PEM data from XML elements. |
| **Directory** | Folder path | Scans the filesystem and groups certificates based on directory structure. |
| **File(s)** | `.pem`, `.crt`, `.p7b` | Processes individual files or raw PEM/PKCS#7 data from stdin. |
| **HTTPS** | `https://` | Fetches the full certificate chain from a live website via TLS. |
| **System** | `--system` | Provides access to the native OS root certificate stores. |

### 🗣️ Verbosity Levels
The text-based output can be increased for deeper diagnostics:
* `-v`: **Informative**. Shows the full paths of the read certificate files in addition to the tree structure.
* `-vv`: **Debug**. Displays the full **Subject** and **Issuer** Distinguished Names (DNs) for each certificate.
* `-vvv`: **Trace**. Outputs the full raw certificate attributes, including X509v3 extensions (e.g., AIA and CDP URLs) for every analyzed object.

### 📄 Format Control
Use the `--format` flag to force the desired output type:
* `--format text`: (Default) Human-readable tree structure.
* `--format json`: Compact JSON output.
* `--format status`: Detailed "Deep Inspection" JSON for monitoring systems (v1.1.2+).
* `--format dot`: Generates a Graphviz-compatible DOT file for visualization.

## 📊 Multiple Outputs
The tool provides different views of your truststore health depending on your needs.

### JSON based output
The default JSON output provides a clean hierarchy grouped by source.

```json
[
  {
    "groupName": "Production Store",
    "groupStatus": "OK",
    "tree": [
      {
        "commonName": "Certificate Authority",
        "isValid": true,
        "isExpiringSoon": false,
        "expiryDate": "2043-10-10T09:43:11Z",
        "children": [
          {
            "commonName": "www.example.com",
            "isValid": true,
            "isExpiringSoon": false,
            "expiryDate": "2027-05-06T10:55:09Z"
          }
        ]
      }
    ]
  }
]
```

### Verbose JSON Output (-v)
Using the verbose flag includes the auditStatus object for every certificate, providing detailed machine-readable diagnostic codes and messages.

```json
[
  {
    "groupName": "Production Store",
    "groupStatus": "OK",
    "tree": [
      {
        "commonName": "Certificate Authority",
        "isValid": true,
        "isExpiringSoon": false,
        "expiryDate": "2043-10-10T09:43:11Z",
        "auditStatus": {
          "code": 0,
          "label": "SYSTEM",
          "message": "System trust store certificate.",
          "level": "note"
        },
        "children": [
          {
            "commonName": "www.example.com",
            "isValid": true,
            "isExpiringSoon": false,
            "expiryDate": "2027-05-06T10:55:09Z",
            "auditStatus": {
              "code": 0,
              "label": "VALID",
              "message": "Valid",
              "level": "note"
            }
          }
        ]
      }
    ]
  }
]
```

### 🚦 Detailed Status API (v1.1.2)
When using `--format status`, the tool generates a deep-inspection JSON object. This is ideal for integration with monitoring dashboards (Zabbix, Grafana) or automated security gateways.

#### JSON Field Definitions
| Field | Type | Description |
| :--- | :--- | :--- |
| `metadata.version` | `string` | The version of the TrustStore Analyzer engine. |
| `metadata.engine` | `string` | The engine API version |
| `metadata.scanDate` | `string` | Timestamp of the scan in ISO-8601 (Zulu) format. |
| `metadata.exitCode` | `int` | Global result code (0-7). The highest severity found in the scan. |
| `groups[].groupName` | `string` | The name of the truststore environment defined in your configuration. |
| `groups[].groupStatus`| `string` | Summary status label for this specific group. |
| `groups[].summary` | `object` | Aggregate health metrics for certificates within this specific group. |
| `summary.totalCertificates` | `int` | Total count of certificates processed in this group. |
| `summary.isChainComplete` | `bool` | `true` if all certificates have a path to a root or known issuer. |
| `summary.isTrusted` | `bool` | `true` only if the chain is complete AND cryptographically valid. |
| `certificates[].commonName` | `string` | The Subject Common Name (CN) of the certificate. |
| `certificates[].serialNumber`| `string` | The hexadecimal serial number of the certificate. |
| `certificates[].signatureValid`| `bool/null`| Result of the RSA/ECDSA signature check against the parent. |
| `certificates[].expiryDate` | `string` | Expiration date in ISO-8601 format. |
| `certificates[].trustStatus` | `string` | Detailed health label (e.g., `OK`, `SIG_ERR`, `EXPIRED`, `CHAIN_INVALID`). |
| `certificates[].statusCode` | `int` | Numeric status for the individual certificate (0-6). |
| `certificates[].fileName` | `string` | The source filename (if applicable) for the certificate. |
| `systemCertificates[]` | `list` | Lists certificates loaded from the OS truststore used to complete chains. |

#### JSON Example Snippet
```json
{
  "metadata": {
    "version": "1.2.1",
    "engine": "1.1.2",
    "scanDate": "2026-05-02T11:51:52Z",
    "exitCode": 0
  },
  "groups": [
    {
      "groupName": "Production Store",
      "groupStatus": "OK",
      "summary": {
        "totalCertificates": 1,
        "isChainComplete": true,
        "isTrusted": true
      },
      "certificates": [
        {
          "commonName": "www.example.com",
          "serialNumber": "16",
          "signatureValid": true,
          "expiryDate": "2027-05-06T10:55:09Z",
          "trustStatus": "VALID",
          "statusCode": 0,
          "fileName": "server.crt"
        }
      ]
    }
  ],
  "systemCertificates": [
    {
      "commonName": "Corporate Root CA",
      "serialNumber": "01",
      "signatureValid": true,
      "expiryDate": "2043-10-10T09:43:11Z",
      "trustStatus": "SYSTEM",
      "statusCode": 0
    }
  ]
}
```

#### 🚦 Status Code Definitions
When using the `--format status` output, each certificate is assigned a numeric `statusCode`. This allows for easy integration with alerting triggers and automated monitoring systems.

| Code | Label | Description |
| :--- | :--- | :--- |
| **0** | `OK` | All certificates are cryptographically valid, trusted, and pass all policy checks. |
| **1** | `WARNING` | Certificate is valid but expires within the defined threshold or violates minor policies. |
| **2** | `EXPIRED` | At least one certificate in the chain has passed its `notAfter` date. |
| **3** | `INCOMPLETE` | The chain is broken; an issuer was not found locally, in system store, or via AIA. |
| **4** | `INVALID` | **Critical**: Signature verification failure (`SIG_ERR`) or CA-constraint violation. |
| **5** | `REVOKED` | **Critical**: Certificate has been explicitly revoked via OCSP or CRL check. |
| **6** | `INPUT_ERR` | File access issues, I/O errors, or unparseable certificate structures. |
| **7** | `FATAL` | An unexpected application error, network timeout, or crash occurred. |

> **Note on Thresholds**: The transition from `OK` (0) to `WARNING` (1) is triggered when a certificate is within the `N`-day window defined by the `--threshold` argument.

### Text-Based Hierarchy (Human Readable) (Default)
The tree view combines multiple layers of intelligence: identity validation, date checking, and cryptographic verification.

```text
Certificate Hierarchy:

### Production Environment ###
└── Root CA [✅][🔒][💻] (2043-10-10)
    └── Intermediate CA (ID: e5477085) [✅][🛡️][🔒] (2027-04-16)
        └── www.example.com [✅][🛡️][🔒] (ALT: api.example.com) [Usage: Server Auth] (2027-05-06)
            └── [i] Certificate validity period (731 days) exceeds the 398-day limit. (LONG_VALIDITY)

### Legacy Store ###
├── Trusted Root CA [⏳][🔒] (2026-05-18)
│   └── Broken Signature Leaf [❌][💥] (2026-07-17)
└── EXTERNAL ISSUER / MISSING ROOT [❓] 
    └── Orphan Certificate [✅][❓] (2027-04-16)
```

#### Legend of Indicators
| Icon | Description |
| :--- | :--- |
| **[✅]** | **Valid**: Certificate is within its validity period and structurally sound. |
| **[🔒]** | **Verified**: Cryptographic signature successfully matches the issuer's public key. |
| **[💻]** | **System**: Certificate was automatically sourced from the OS/System truststore to complete the chain. |
| **[🛡️]** | **Revocation Checked**: Status was explicitly verified via OCSP or CRL. |
| **[🌐]** | **AIA**: Certificate was dynamically discovered and downloaded via the network. |
| **[👯]** | **Collision**: Multiple certificates share the same Common Name but have different cryptographic IDs. |
| **[💥]** | **Broken**: Signature verification failed (Critical Security Alert). |
| **[❓]** | **Unknown**: Issuer certificate is missing; signature could not be verified. |
| **[i]** | **Policy Note**: Informational finding regarding industry best practices (e.g., 398-day limit). |
| **[!]** | **Critical Note**: Severe issue affecting the trust or validity of the chain. |

### 🛡️ SARIF (Static Analysis Results Interchange Format)
For integration with security vulnerability dashboards, the tool exports results in **SARIF v2.1.0**. This allows automated tracking of certificate issues as "vulnerabilities".
 
| Rule ID | Name | Severity | Description |
| :--- | :--- | :--- | :--- |
| **TSA-001** | Nearing Expiration | Warning | Certificate is within the warning threshold. |
| **TSA-002** | Expired | Error | Certificate or parent has passed its validity end date. |
| **TSA-003** | Incomplete Chain | Error | Issuer could not be found locally, via System, or AIA. |
| **TSA-004** | Invalid Certificate | Error | Structural failure or signature verification failed. |
| **TSA-005** | Revoked | Error | Certificate explicitly revoked via OCSP/CRL. |

#### SARIF Example Snippet
```json
{
  "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "TrustStore Analyzer",
          "semanticVersion": "1.1.6",
          "rules": [
            { "id": "TSA-002", "shortDescription": { "text": "Certificate expired" } },
            { "id": "TSA-003", "shortDescription": { "text": "Incomplete trust chain" } },
            { "id": "TSA-004", "shortDescription": { "text": "Invalid certificate" } }
          ]
        }
      },
      "results": [
        {
          "ruleId": "TSA-004",
          "level": "error",
          "message": {
            "text": "Certificate 'Intermediate Broken Signature' failed validation: The cryptographic signature is invalid or could not be verified."
          },
          "locations": [{
            "physicalLocation": {
              "artifactLocation": { "uri": "Intermediate Broken Signature.pem" }
            }
          }]
        },
        {
          "ruleId": "TSA-003",
          "level": "error",
          "message": {
            "text": "Certificate 'Loop CA B' failed validation: The certificate issuer could not be found due to a circular reference (Loop), making this chain untrusted."
          },
          "properties": {
            "commonName": "Loop CA B",
            "issueType": "CIRCULAR_REFERENCE"
          }
        },
        {
          "ruleId": "TSA-002",
          "level": "error",
          "message": { "text": "Certificate 'Expired CA' has passed its validity end date." },
          "properties": { "expiryDate": "2026-01-22T12:20:29Z" }
        }
      ]
    }
  ]
}
```

### 🎨 Visual PKI Topology (Graphviz)

The specialized **Graphviz Renderer** transforms the certificate hierarchy into a DOT representation, optimized for visualizing **Directed Acyclic Graphs (DAG)**. It is essential for auditing complex cross-signing scenarios and identifying structural anomalies.

### Key Features
*   **Cross-Signing Support**: Transparently visualizes instances where an intermediate certificate is signed by multiple roots (multiple edges pointing to a single node).
*   **Cluster Grouping**: Uses subgraphs to visually isolate different truststores or environments with dashed boundaries.
*   **Status-Based Color Coding**:
    *   **Green**: Valid and trusted certificates.
    *   **Yellow**: Warnings (e.g., nearing expiration).
    *   **Red**: Critical errors (e.g., expired, broken signatures, or missing issuers).
*   **HTML-Rich Labels**: Displays Common Names, Expiry Dates, and Criticality alerts in a clean, tabular format within each node.

### Topology Map Example
The following map demonstrates how the analyzer handles cross-signed intermediates and flags various failure states like broken signatures or missing roots:

![TrustStore Topology Example](https://raw.githubusercontent.com/nulleke/check_truststore/main/docs/images/topology.png)

#### Usage
To generate a DOT file and convert it to an image (requires Graphviz installation):
```bash
# 1. Generate the DOT output
check_truststore vars/prod/stores.yml --format dot > topology.dot

# 2. Convert to PNG using the 'dot' command
dot -Tpng topology.dot -o topology.png
```

### 📈 Prometheus Metrics Support

The `PrometheusRenderer` transforms hierarchical certificate validation tree results into a flattened, OpenMetrics-compliant text exposition format. This enables native time-series tracking and alerting of your trust store health via Prometheus, VictoriaMetrics, or Datadog.

#### Metric Definitions

The renderer exposes the following core gauges, decorated with contextual labels to pinpoint specific certificates:

| Metric Name | Type | Description |
| :--- | :--- | :--- |
| `truststore_cert_valid_status` | Gauge | Validity status of the certificate (`1` = Valid, `0` = Invalid). |
| `truststore_cert_expiry_timestamp_seconds` | Gauge | The certificate expiration date represented as a Unix timestamp (seconds). |
| `truststore_cert_policy_findings_total` | Gauge | Total number of policy violations discovered, categorized by severity level. |

#### Labels

To ensure high observability without losing structural context, each metric is enriched with the following labels:
* `group`: The configured name of the certificate group context (e.g., system truststore, specific application path).
* `common_name`: The Common Name (CN) of the certificate (with quotes automatically sanitized).
* `serial`: The certificate's serial number.
* `fingerprint`: The unique fingerprint identifying the certificate, preventing intra-group duplicates.
* `level`: *(Only applicable to `truststore_cert_policy_findings_total`)* Specifies the severity of the linting rule (`ERROR`, `WARNING`, or `INFO`).

> 💡 **Note on Edge Cases:** Virtual nodes such as Orphan or Cycle indicators (`ORPHAN_NODE_ID`, `CYCLE_NODE_ID`) are skipped automatically during tree traversal, ensuring only authentic certificate data populates your time-series.

#### Example Exposition Output

When scraped or rendered, the output adheres strictly to the Prometheus text-based format:

```text
# HELP truststore_cert_valid_status Validity status (1 = Valid, 0 = Invalid)
# TYPE truststore_cert_valid_status gauge
truststore_cert_valid_status{group="production-api",common_name="example.com",serial="123456789",fingerprint="a1b2c3d4..."} 1
truststore_cert_valid_status{group="production-api",common_name="Expired Sub-CA",serial="987654321",fingerprint="e5f6g7h8..."} 0

# HELP truststore_cert_expiry_timestamp_seconds Expiration date in unixtime
# TYPE truststore_cert_expiry_timestamp_seconds gauge
truststore_cert_expiry_timestamp_seconds{group="production-api",common_name="example.com",serial="123456789",fingerprint="a1b2c3d4..."} 1785243600
truststore_cert_expiry_timestamp_seconds{group="production-api",common_name="Expired Sub-CA",serial="987654321",fingerprint="e5f6g7h8..."} 1716541200

# HELP truststore_cert_policy_findings_total Policy violations by level
# TYPE truststore_cert_policy_findings_total gauge
truststore_cert_policy_findings_total{group="production-api",common_name="example.com",serial="123456789",fingerprint="a1b2c3d4...",level="ERROR"} 0
truststore_cert_policy_findings_total{group="production-api",common_name="example.com",serial="123456789",fingerprint="a1b2c3d4...",level="WARNING"} 1
truststore_cert_policy_findings_total{group="production-api",common_name="example.com",serial="123456789",fingerprint="a1b2c3d4...",level="INFO"} 0
truststore_cert_policy_findings_total{group="production-api",common_name="Expired Sub-CA",serial="987654321",fingerprint="e5f6g7h8...",level="ERROR"} 1
truststore_cert_policy_findings_total{group="production-api",common_name="Expired Sub-CA",serial="987654321",fingerprint="e5f6g7h8...",level="WARNING"} 0
truststore_cert_policy_findings_total{group="production-api",common_name="Expired Sub-CA",serial="987654321",fingerprint="e5f6g7h8...",level="INFO"} 2
```

## 🧠 Core Logic & Identity Strategy
* **Smart Deduplication**: To keep reports clean and efficient, the tool uses a dual-layer filtering process. First, it calculates a **SHA-256 fingerprint** for every file. If the exact same certificate (identical binary content) is found in multiple paths, it is processed only once. This prevents redundant entries and circular references in the tree.
* **Name Collisions [👯]**: Even with ID tracking, name collisions occur (e.g., two different CAs using the same Common Name). The tool detects these based on differing Public Key IDs and flags them. This ensures you can distinguish between them even if they appear identical in the hierarchy.
* **`EXTERNAL_OR_MISSING_ISSUER` [❓]**: A virtual node for certificates whose issuer (Root or Intermediate) was not found in the provided source directories or the system truststore. The debug log will specify the exact **AKI (Authority Key Identifier)** needed to complete the chain.

### 🏗️ Path Construction & Validation

Unlike simpler tools that rely on filenames or filesystem paths, this analyzer performs deep inspection of the certificate extensions:

* **Authority Key Identifier (AKI) & Subject Key Identifier (SKI)**: The tool uses these extensions (as defined in RFC 5280, Section 4.2.1.1) to bridge certificates. This is the only reliable way to build a chain when multiple certificates share the same Common Name (Name Collisions).
* **Basic Constraints**: It validates the `cA` boolean and `pathLenConstraint` to ensure that an intermediate certificate is actually authorized to sign other certificates.
* **Key Usage**: Checks if the `keyCertSign` bit is set for issuers, preventing security flaws where a non-CA certificate is used to sign a chain.

### 🆔 Identity Strategy

* **Persistent Identity (ID)**: The tool uniquely identifies certificates using their **Subject Key Identifier (SKI)**.
    * If the official SKI extension is present, it is used as the primary identifier.
    * If the extension is missing (common in legacy or custom test-certs), the tool generates a **deterministic SHA-256 hash** of the public key, adhering to the spirit of RFC 5280's identification requirements.
    * Result: You get a consistent `(ID: abcdef12)` label across both the table and the hierarchy, allowing you to trace issuer/subject relationships with cryptographic certainty.

### 🛡️ System Truststore Integration
By default, the tool only analyzes the certificates explicitly defined in your YAML configuration. However, to verify if your local chain is ultimately trusted by the operating system, you can enable system integration.

* **Default**: Disabled.
* **Behavior**: When enabled, the tool scans common system paths (e.g., `/etc/ssl/certs/ca-certificates.crt` on Linux, the Keychain on macOS, or the Windows Certificate Store) to resolve missing root issuers.

### 🚀 Force Mode
Using the `--force` flag bypasses the tool's built-in resource protections:
* **No Limits**: The maximum number of certificates per scan (`1000`) is ignored.
* **Large Files**: Files exceeding the standard `10MB` limit are processed instead of skipped.
* **Use Case**: Use this only when auditing large, complex truststores where you are certain the system has sufficient memory to handle the full dataset.

### 🛡️ Maximum Chain Depth Validation
To prevent resource exhaustion and ensure compliance with security policies, the analyzer supports a configurable chain depth limit.

* **`--max-depth N`**: (Default: `4`). If a chain exceeds the specified `N` levels (Root + Intermediates + Leaf). The analyzer stops processing that specific path. This enforces strict PKI hierarchies and prevents circular reference exploits.

## 🔍 Debugging & Scenario Analysis
When running with the `--debug` flag, the tool outputs detailed logs to `stderr`. This is essential for understanding the certificate tree construction, network activities, and internal decision-making.

### Healthy Execution & AIA Discovery
The tool displays signature status (🔒) and network discovery (🌐) for repaired chains.
```text
🔵 INFO         │      │ Configuration loaded           │ Processing 11 certificate paths
🔵 INFO         │ 🌐   │ AIA Discovery                  │ Fetching: http://ca.example.com/cert.crt
✅ OK           │ 🔒   │ Root CA                        │ 2043-10-10 09:43
✅ OK           │ 🔒🛡️ │ www.example.com                |  2043-10-10 09:43
```

#### 🔄 Cycle Detection (Circular References)
When certificates point to each other in a loop (A signs B, B signs A), the `CYCLE_BREAKER` prevents infinite recursion.

```text
⏳ WARNING      │      │ CYCLE_BREAKER                │ Broken circular chain at 5ede7e4e
❌ INVALID      │ 🔒   │ Loop CA A                    │ 2027-05-02 12:09
❓ UNTRUSTED    │      │ AKI: CIRCULAR                │ Missing issuer for: Loop CA B
```

### Signature & Security Alerts
If a signature does not match the issuer's public key, it is flagged with the `SIG_ERR` label and a 💥 icon.
```text
❌ SIG_ERR      │ 💥   │ Broken Signature Leaf          │ 2026-07-17 09:05
❌ REVOKED      │ 🛡️   │ Compromised Certificate        │ 2026-12-01 11:20
```

### Missing Files (I/O Errors)
Occurs when a filename defined in the YAML does not exist in the source directory.
```text
❌ READ_ERROR   │      │ non_existing.crt               │ File not found
```

### Missing Root or Intermediate (Untrusted Chain)
Occurs when a certificate's issuer is not present in the current truststore batch. These are grouped under the `EXTERNAL_OR_MISSING_ISSUER` node in the output.
```text
❌ INVALID      │ 🔒   │ Orphan Server                  │ 2027-05-02 12:09
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
✅ OK           │ 🔒👯 │ Duplicate Intermediate (ID: e589795a) │ 2027-05-02
❌ ERROR        │      │ Expired Server Cert            │ 2026-04-16 07:39
```

## 🧪 Reliability & CI/CD
This project is rigorously tested via **GitLab CI** across a full matrix of Python versions. 
* **Compatibility Matrix**: Automated tests run on every version from 3.6 to 3.14.
* **Fallback Validation**: We explicitly test a "No-Pydantic" environment to guarantee that the core logic remains 100% functional even when third-party validation libraries are missing.
* **Logic Verification**: All date-based logic is validated against current 2026 standards.

### Local Validation
You can run the full compatibility suite locally using Podman to ensure your changes work across all supported Python versions:
```bash
./scripts/run_ci.sh
```

## 📦 Requirements
* **Python 3.6+**: (Fully tested from 3.6 up to 3.14)
* **cryptography**: For X.509 parsing (compatible with legacy and UTC-aware versions).
* **requests**: For AIA Discovery and fetching missing intermediate certificates.
* **PyYAML**: For configuration management.
* **pydantic**: (Optional): v2.0+ for enhanced schema validation. The tool automatically detects and adapts to the available version.
* **jinja2**: (Optional): Required for using Jinja2-templating within YAML configuration files.

## 🌐 Internationalization (i18n)
The tool supports multiple languages via standard `gettext` locales.
* **Language Selection**: The tool respects the `LANG` environment variable.
* **Scope**: Only human-readable outputs (Debug logs and Text trees) are translated. Machine-to-machine outputs (JSON and Status formats) remain in technical English for stability.

```bash
# Run in Dutch
LANG=nl_NL.UTF-8 check_truststore vars/prod/stores.yml -d
```

To update or add translations, use the provided utility script:
```bash
./scripts/translate.sh nl  # Updates Dutch translations
```

## 💾 Cache Management

The utility caches Authority Information Access (AIA) certificates and Certificate Revocation Lists (CRLs) inside the user's home directory (`~/.cache/truststore_analyzer/`).

### Automated Cleanup (Linux / RHEL / Fedora)

To prevent the cache from growing indefinitely in environments where thousands of certificates are audited, you can leverage `systemd-tmpfiles` to manage cache expiration automatically.

Create a file named `/usr/lib/tmpfiles.d/truststore_analyzer.conf`:

```text
# Type  Path                                               Mode UID  GID  Age
e       /home/*/.cache/truststore_analyzer/ocsp            -    -    -    30d
e       /home/*/.cache/truststore_analyzer/aia             -    -    -    90d

d       /root/.cache/truststore_analyzer/ocsp              0755 root root 30d
d       /root/.cache/truststore_analyzer/aia               0755 root root 90d
```

## 🤝 Contributing
Contributions are welcome! Whether it's reporting a bug, suggesting an enhancement, or submitting a pull request, your help is appreciated.

Please see our [CONTRIBUTING.md](docs/CONTRIBUTING.md) for details on our development standards, legacy environment support (RHEL 8), and how to get started.

## ⚖️ License
**Copyright (C) 2024-2026 Serge van Thillo**

This program is free software: you can redistribute it and/or modify it under the terms of the **GNU Lesser General Public License** as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This project is licensed under the **LGPL-3.0-or-later** - see the [LICENSE](LICENSE) file for details.

---
**Status**: Version: 1.2.5 | Stable | **Logic validated for current system date**: May 23, 2026
