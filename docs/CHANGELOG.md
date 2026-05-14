# 📜 CHANGELOG

All notable changes to this project will be documented in this file.

## [v1.2.2] - 2026-05-14 (Stable)

### 🚀 Highlights
*   **RFC 5280 Name Constraints**: Implemented full validation for `NameConstraints` (permitted and excluded subtrees). The engine now ensures that an issuing CA is authorized to sign for specific (sub)domains, preventing unauthorized certificate issuance.
*   **HTTPS Input Provider**: Added a new provider that allows scanning certificates directly from a URL (e.g., `https://example.com`), including full chain discovery.
*   **Legacy Support (RHEL/CentOS)**: Optimized the engine to run on older system-installed libraries (Python 3.6/3.7) without requiring modern dependencies like Pydantic, while maintaining 100% output consistency.

### Added
*   **Netscape Comment Support**: The tool now detects and displays the legacy Netscape Comment extension (OID `2.16.840.1.113730.1.13`), often used in older PKI infrastructures for administrative notes.
*   **CLI Versioning**: Added the `--version` flag for easier auditing of the installed tool version.
*   **Poison Pill Test Cases**: The `MockProvider` was extended with complex Name Constraint scenarios to verify "forbidden" SAN (Subject Alternative Name) detection.

### Fixed
*   **Dependency Compatibility**: Fixed `GeneralSubtree` imports to ensure the `NameConstraints` logic works across different versions of the `cryptography` library.
*   **Finding Deduplication**: Improved the `add_finding` logic in the models to prevent the same policy violation from being reported multiple times for a single certificate.

### Changed
*   **Refined DNS Matching**: Implemented RFC 5280 compliant DNS subtree matching (e.g., a constraint for `.safe.lan` correctly matches both `safe.lan` and `www.safe.lan`).
*   **Status Signaling**: Introduced a dedicated `EXPIRING` status (⏳) to clearly distinguish certificates nearing expiry from those with general configuration warnings.
*   **Translation Updates**: Synchronized Dutch, German, and French locale files to include the new technical strings for Name Constraints and Netscape Comments.

## [v1.2.0] - 2026-05-07 (Stable)

### 🚀 Highlights
*   **Deduplication in Visualization**: The `TextRenderer` and `GraphvizRenderer` now feature a mechanism to prevent duplicate certificates in complex or cross-signed trust paths. This ensures a much cleaner tree structure without redundant branches.
*   **Optimized Sorting Logic**: Certificates in the output are now consistently sorted by their expiry date. This prioritizes the most relevant and longest-lived certificates at the top of the hierarchy.

### Added
*   **Project Metadata**: Added official support for ReadTheDocs (`.readthedocs.yaml`) and an expanded `MANIFEST.in` to ensure complete distribution of translation files and documentation on PyPI.
*   **SARIF Enhancements**: Updated the `SarifRenderer` to better handle system certificates and unique fingerprints, improving integration with security pipelines such as GitHub Code Scanning.

### Fixed
*   **Rendering Consistency**: Resolved a bug where the `_rendered_fingerprints` cache was not cleared between different truststore groups, which previously caused certificates to be missing from subsequent groups in a single scan.
*   **Pydantic Compatibility**: Refined the `model_rebuild()` logic in `models.py` to better handle recursive self-references within certificate objects for modern Pydantic environments.

### Changed
*   **Code Maintenance**: Unified license headers (LGPL-3.0) and author attributions across all core modules.
*   **CLI Feedback**: Improved error handling and logging in `cli.py` for scenarios where input providers fail to locate certificates, providing better diagnostic information in debug mode.

## [v1.1.6] - 2026-05-04 (Stable)

### 🚀 Highlights
*   **Lazy Loading Architecture**: The `TrustStoreAnalyzer` now loads certificates only when they are actually needed per group.
*   **Efficiency**: This prevents cache pollution between different truststore groups and significantly improves performance for large datasets.
*   **Enhanced System Integration**: The `SystemInputProvider` has been completely overhauled.
*   **System Certificate Handling**: System certificates are now treated as a separate 'pool' that is only accessed to complete chains, rather than being loaded directly into every scan.

### Fixed
*   **Legacy Python Support**: Resolved a `pyo3_runtime.PanicException` affecting Python 3.6 environments.
*   **Dependency Pinning**: The `cryptography` library is now pinned to `< 3.5` via environment markers in `pyproject.toml`.
*   **Deduplication Logic**: Robustness of `cert_id` generation in the `TrustChainBuilder` has been improved.
*   **Fallback Mechanism**: If a *Subject Key Identifier* (SKI) is missing, a consistent SHA256 hash is now generated based on the DER-encoded public key.

### Changed
*   **Provider Refactoring**: All providers (`Json`, `Yaml`, `Directory`, `Xml`) have been optimized for the new orchestrator model.
*   **Memory Optimization**: Providers now pass file paths instead of fully parsed objects, which saves memory.
*   **I18n & Localization**: Dutch translations (`.po` files) have been updated to correctly reflect new technical terms regarding providers and system usage.
*   **Model Cleanup**: Several internal metadata fields (such as `is_system_cert`) have been standardized for better consistency in JSON and SARIF output.

### CI/CD & Dependencies
*   **PyPI Metadata**: Badges in the `README.md` have been updated and now point to the correct PyPI locations.
*   **Test Matrix**: Automated tests now explicitly validate compatibility across different `cryptography` versions for both legacy and modern Python environments.

## [1.1.5] - 2026-05-03 (Stable)
*   **Robustness**: Added a global `KeyboardInterrupt` handler in `cli.py` to prevent stacktraces during user interruptions.
*   **Integrity**: Integrated GitLab source and issue tracker URLs into PyPI metadata.
*   **Automation**: Full GitLab CI/CD pipeline for multi-version Python testing (3.6 to 3.14).
*   **Localization**: Improved `gettext` integration with automated `.mo` compilation in the build process.

## [1.1.3] - 2026-05-02 (Stable)

### Added
*   **Defensive Coding Measures**: Implemented global safety limits to prevent resource exhaustion (CPU/Memory).
    *   **Certificate Limit**: Standardized a maximum of 1,000 certificates per run to avoid infinite loops or memory bloat.
    *   **File Size Limit**: Added a 10MB threshold for individual certificate files to prevent parsing of unintended large binary files.
*   **Safety Override**: Introduced a `force` flag to bypass these limits in exceptional scenarios where extremely large truststores are required.
*   **PKCS#7 Support**: Introduced a new parser for `.p7b` and `.p7c` containers. The tool now automatically detects these based on file extension or the presence of the PKCS7 header in binary data.
*   **Enhanced Deduplication**: Switched to a consistent SHA256 hashing method based on the DER-encoded public bytes of certificates. This prevents duplicate processing when the same certificate is provided in different formats, such as PEM and PKCS#7.
*   **Nmap XML Improvements**: The XML provider is now more robust, handling namespaces and potential "garbage" data (like comments or headers) that may precede the XML output in Nmap files.
*   **Stable System Inventory Tracking**: Introduced `system_store_total_count` to ensure the total number of available system certificates remains consistent, regardless of manual input overlaps.
*   **Dedicated System Usage Reporting**: Added `_log_system_usage` to provide a clear audit trail of which system certificates were actually utilized in a trust chain.
*   **Network Resilience**: Added a modern browser User-Agent to AIA/OCSP/CRL requests to improve compatibility with strict web servers and CDNs.

### Changed
*   **Network Resolver Refactoring**: Migrated all hardcoded log strings to the internationalization engine (`_()`) for multi-language support.
*   **AIA Cache Structure**: Improved cache organization by grouping certificates by Authority Key Identifier (AKI) subdirectories.
*   **Windows Store Safety**: The Windows certificate enumerator now respects the global certificate limit.
*   **Universal File Handling**: The `CertificateRepository` now intelligently delegates file reading to either the PEM or PKCS#7 parser.
*   **Directory Scanning**: The `DirectoryInputProvider` now includes standard PKCS#7 extensions (`.p7b`, `.p7c`) by default when scanning folders.
*   **JSON & YAML Resolution**: Improved logic for resolving relative paths in configuration files, including better support for environment-specific variables like `{{ env }}`.
*   **Logging & I18n**: Various internal messages have been optimized for translation and technical accuracy.
*   **Models**: Updated the `get_audit_status` method in the models to ensure a single source of truth for certificate status determination.
*   **Bypassing Deduplication for Stats**: The global certificate inventory now counts physical certificates *before* deduplication, ensuring accurate "available vs used" metrics.
*   **Recursive Tree Traversal**: Optimized the way used certificates are counted in the tree to prevent double-counting across different branches.

### Fixed
*   **Warnings Suppression**: Specific `cryptography` library warnings regarding PKCS#7 parsing (BER vs DER encoding) are now suppressed for a cleaner output.
*   **Mock Data Consistency**: The `MockProvider` now utilizes the centralized deduplication logic, ensuring consistency between test suites and production code.
*   **Fluctuating System Totals**: Resolved a bug where the total number of available system certificates changed based on whether those certificates were also present in the user-defined `truststores`.
*   **Windows Store Inventory**: Ensured the physical count of certificates in the Windows "ROOT" and "CA" stores is correctly reported in the system usage summary.
*   **Relative Path Resolution**: Fixed edge cases in JSON/YAML providers where relative paths and environment variables were not correctly expanded.