# 📜 CHANGELOG

All notable changes to this project will be documented in this file.

## [1.1.5] - 2026-05-03 (Stable)
* **Robustness:** Added a global `KeyboardInterrupt` handler in `cli.py` to prevent stacktraces during user interruptions.
* **Integrity:** Integrated GitLab source and issue tracker URLs into PyPI metadata.
* **Automation:** Full GitLab CI/CD pipeline for multi-version Python testing (3.6 to 3.14).
* **Localization:** Improved `gettext` integration with automated `.mo` compilation in the build process.

## [1.1.3] - 2026-05-02 (In Progress)

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