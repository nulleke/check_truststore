# Contributing to TrustStore Analyzer

First off, thank you for considering contributing to TrustStore Analyzer! It is people like you who make this tool better for everyone.

## ⚖️ Our Standards

As this project is licensed under **LGPL-3.0-or-later**, all contributions you make will also be under this license. We aim for high reliability and broad compatibility (Python 3.6 to 3.14+).

## 🚀 How Can I Contribute?

### Reporting Bugs
* Check the existing **Issues** to see if the bug has already been reported.
* If not, open a new issue. Include your OS, Python version, and a sample YAML configuration (sanitize sensitive data!) that reproduces the error.

### Suggesting Enhancements
* Open an issue to discuss the idea before diving into code. This ensures the feature aligns with the project goals and maintains our compatibility standards.

### Pull Requests (PRs)
1. **Fork the repository** and create your branch from `main`.
2. **Maintain Compatibility**: We support a wide range of Python versions. Avoid using syntax that breaks Python 3.6 (e.g., be careful with very recent Type Hinting features).
3. **Respect the Fallback**: If you add features that use third-party libraries (like Pydantic V2), ensure the tool still works in **Zero-Dependency Mode** (standard Python + Cryptography/PyYAML).
4. **Update Translations**: If you change UI strings, please update the `.pot` and `.po` files if possible, or mention it in the PR so we can assist.
5. **RFC 5280 Compliance**: Logic must follow official X.509 standards. Use AKI/SKI for chain building.
6. **Run Tests**: Ensure your changes pass the existing GitLab CI pipeline logic.

## 🛠 Local Development Setup

**Clone your fork:**
```bash
git clone https://gitlab.com/nulleke/check_truststore.git
cd check_truststore
```

**Install dependencies (for full feature set):**
```bash
pip install -e ".[all]"
```

**Verify Fallback Mode:**
```bash
# Uninstall pydantic temporarily or use a clean venv
pip uninstall pydantic
python3 check_truststore path/to/config.yml --format text
```

### 🌐 Updating Translations
We have automated the `gettext` workflow. You no longer need to run complex manual commands:

```bash
# Update the template and the specific language file (e.g., nl) simultaneously:
./scripts/translate.sh nl
```

## Development Guidelines

### Environment Support
This project officially supports **Python 3.6+**, primarily to remain compatible with **RHEL 8** default environments. 

### Dependency Management
We use `pyproject.toml` for dependency management.
- **Core:** `cryptography`, `PyYAML`.
- **Optional:** `pydantic` (v2 optimized).

### Code Style
We use **Ruff** for linting. Please ensure your code is compliant before submitting:
```bash
ruff check .
```

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
