# Contributing to TrustStore Analyzer

First off, thank you for considering contributing to TrustStore Analyzer! It is people like you who make this tool better for everyone.

## ⚖️ Our Standards

As this project is licensed under **GPL v3.0**, all contributions you make will also be under this license. We aim for high reliability and broad compatibility (Python 3.6 to 3.14+).

## 🚀 How Can I Contribute?

### Reporting Bugs
* Check the existing **Issues** to see if the bug has already been reported.
* If not, open a new issue. Include your OS, Python version, and a sample YAML configuration (sanitize sensitive data!) that reproduces the error.

### Suggesting Enhancements
* Open an issue to discuss the idea before diving into code. This ensures the feature aligns with the project goals and maintains our compatibility standards.

### Pull Requests (PRs)
1. **Fork the repository** and create your branch from `main`.
2. **Maintain Compatibility**: We support a wide range of Python versions. Avoid using syntax that breaks Python 3.6 (e.g., be careful with very recent Type Hinting features).
3. **Respect the Fallback**: If you add features that use third-party libraries (like Pydantic), ensure the tool still works in **Zero-Dependency Mode** (standard Python + Cryptography/PyYAML).
4. **Update Translations**: If you change UI strings, please update the `.pot` and `.po` files if possible, or mention it in the PR so we can assist.
5. **Run Tests**: Ensure your changes pass the existing GitLab CI pipeline logic.

## 🛠 Local Development Setup

**Clone your fork:**
```bash
git clone https://gitlab.com/nulleke/check_truststore.git
cd check_truststore
```

**Install dependencies (for full feature set):**
```bash
pip install -r requirements.txt
```

**Verify Fallback Mode:**
```bash
# Uninstall pydantic temporarily or use a clean venv
pip uninstall pydantic
python3 check_truststore path/to/config.yml --format text
```

### 🌐 Updating Translations
If you've added or changed UI strings wrapped in `_()`, you should update the translation files. We use a standard `gettext` workflow:

```bash
# 1. Extract strings from the script into the template (POT)
xgettext -L Python -o locale/check_truststore.pot check_truststore

# 2. Merge the new strings into the Dutch translation file (PO)
msgmerge -U locale/nl/LC_MESSAGES/check_truststore.po locale/check_truststore.pot

# 3. Compile the PO file into a machine-readable MO file
msgfmt locale/nl/LC_MESSAGES/check_truststore.po -o locale/nl/LC_MESSAGES/check_truststore.mo
```

## Development Guidelines

### Environment Support
This project officially supports **Python 3.6+**, primarily to remain compatible with **RHEL 8** default environments. 

### Dependency Management
- **Local Development (RHEL/Fedora):** It is recommended to use system RPM packages where possible for stability:
  `sudo dnf install python3-pyyaml python3-cryptography`
  - **CI/CD & Virtual Environments:** We use `requirements.txt` for consistency across different Python versions. 
  - **Legacy Compatibility:** We use environment markers in `requirements.txt` to handle version differences (e.g., Pydantic v1 for Python 3.6).

  ### Code Style & Warnings
  To keep the output clean in legacy environments, certain deprecation warnings (like those from the `cryptography` library on Python 3.6) are suppressed in the main entry point.

## 📝 Commit Messages

We prefer clear and concise commit messages using prefixes. For example:
* `feat: add support for PKCS12 files`
* `fix: handle missing AKI extensions in edge-case certificates`
* `docs: update README with new CLI flags`
* `refactor: optimize certificate tree reconstruction`

## 💬 Questions?
Feel free to open an issue with the `question` label, and we will get back to you as soon as possible!

---
*Thank you for helping us keep system truststores transparent and secure!*
