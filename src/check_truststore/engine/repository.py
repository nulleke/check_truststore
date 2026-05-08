"""
TrustStore Analyzer & Visualizer - CERTIFICATE REPOSITORY
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later

This module manages the indexing, parsing, and deduplication of X.509 certificates.
It acts as a central registry for certificates discovered by various providers.
"""

import re
import hashlib
from typing import Any, Optional, List, Dict, Set
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from .logging import _, WARNING, ERROR


MAX_CERTS_PER_RUN = 1000
MAX_FILE_SIZE_MB = 10


class CertificateRepository:
    """
    Handles the parsing and deduplication of certificates.
    Uses SHA256 hashes to ensure each certificate is only processed once.
    """
    def __init__(self, **kwargs):
        self.options = kwargs
        self.debug = kwargs.get('debug', False)
        self.verbosity = kwargs.get('verbosity', 0)
        self.force = kwargs.get('force', False)
        self.seen_hashes: Set[str] = set()
        self._certs_by_hash: Dict[str, x509.Certificate] = {}
        self.total_scanned_count: int = 0

    def _register_cert(self, cert: x509.Certificate, c_hash: str):
        """Internal helper to index the binary object."""
        self.seen_hashes.add(c_hash)
        self._certs_by_hash[c_hash] = cert

    def get_cert_by_hash(self, sha256_hash: str) -> Optional[x509.Certificate]:
        """
        Retrieves the binary X.509 object from the repository.
        Used by the orchestrator for bundle exports.
        """
        return self._certs_by_hash.get(sha256_hash)

    def _get_cert_hash(self, cert: x509.Certificate) -> str:
        """Helper to get a consistent SHA256 hash from an x509 object."""
        return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()

    def add_der_data(self, content: bytes, source_path: Optional[Path] = None, is_system: bool = False) -> List[Dict[str, Any]]:
        """
        Parses raw DER bytes (used by Windows Store and AIA discovery).
        """
        try:
            cert = x509.load_der_x509_certificate(content, default_backend())
            c_hash = self._get_cert_hash(cert)

            if c_hash in self.seen_hashes:
                return []

            self.seen_hashes.add(c_hash)
            self._register_cert(cert, c_hash)
            self.total_scanned_count += 1

            return [{
                "cert": cert,
                "path": source_path or Path("raw-data"),
                "hash": c_hash,
                "is_system_cert": is_system,
            }]
        except Exception as e:
            if self.debug:
                name = source_path.name if source_path else "raw-der"
                ERROR.log(name, f"{_('Invalid DER structure')}: {str(e)}")
            return []

    def add_pem_data(self, content: bytes, source_path: Optional[Path] = None, is_system: bool = False) -> List[Dict[str, Any]]:
        """
        Parses bytes for PEM blocks and adds unique certificates.
        Supports standard PEM and OpenSSL 'TRUSTED CERTIFICATE' formats.
        """
        new_certs = []
        pattern = b"-----BEGIN (?:TRUSTED )?CERTIFICATE-----.*?-----END (?:TRUSTED )?CERTIFICATE-----"

        for match in re.finditer(pattern, content, re.DOTALL):
            raw_block = match.group(0)
            self.total_scanned_count += 1

            if self.total_scanned_count >= MAX_CERTS_PER_RUN and not self.force:
                if self.debug:
                    name = source_path.name if source_path else "pem-data"
                    WARNING.log(name, _("Maximum certificate limit ({limit}) reached.").format(limit=MAX_CERTS_PER_RUN))
                break

            try:
                pem_block = raw_block.replace(b"TRUSTED ", b"")
                cert = x509.load_pem_x509_certificate(pem_block, default_backend())
                c_hash = self._get_cert_hash(cert)

                if c_hash in self.seen_hashes:
                    if self.debug and not is_system and source_path:
                        WARNING.log(
                            source_path.name,
                            _("Skipping duplicate certificate (already loaded)"),
                            label=_("DUPLICATE"),
                        )
                    continue

                self.seen_hashes.add(c_hash)
                self._register_cert(cert, c_hash)
                new_certs.append({
                    "cert": cert,
                    "path": source_path or Path("stdin"),
                    "hash": c_hash,
                    "is_system_cert": is_system,
                })

            except Exception as e:
                if self.debug:
                    name = source_path.name if source_path else "stdin"
                    ERROR.log(name, f"{_('Invalid certificate structure')}: {str(e)}")

        return new_certs

    def add_pkcs7_data(self, content: bytes, source_path: Optional[Path] = None, is_system: bool = False) -> List[Dict[str, Any]]:
        """Extracts certificates from a PKCS#7 container."""
        new_certs = []
        source_name = source_path.name if source_path else _("PKCS7-container")
        pkcs7_certs = []

        try:
            from cryptography.hazmat.primitives.serialization import pkcs7
            if b"-----BEGIN PKCS7-----" in content:
                pkcs7_certs = pkcs7.load_pem_pkcs7_certificates(content)
            else:
                pkcs7_certs = pkcs7.load_der_pkcs7_certificates(content)
        except (ImportError, AttributeError):
            if self.debug:
                WARNING.log(source_name, _("Legacy cryptography detected, falling back."))
        except Exception as e:
            if self.debug:
                ERROR.log(source_name, _("Failed to parse PKCS7: {error}").format(error=str(e)))
            return []

        for cert in pkcs7_certs:
            self.total_scanned_count += 1
            if self.total_scanned_count >= MAX_CERTS_PER_RUN and not self.force:
                if self.debug:
                    WARNING.log(source_name, _("Maximum certificate limit ({limit}) reached. Stopping scan.").format(limit=MAX_CERTS_PER_RUN))
                break

            c_hash = self._get_cert_hash(cert)
            if c_hash in self.seen_hashes:
                continue

            self.seen_hashes.add(c_hash)
            self._register_cert(cert, c_hash)
            new_certs.append({
                "cert": cert,
                "path": source_path or Path("pkcs7-container"),
                "hash": c_hash,
                "is_system_cert": is_system,
            })
        return new_certs

    def load_from_files(self, paths: List[Path], is_system: bool = False) -> List[Dict[str, Any]]:
        """Unified file loader for providers to use."""
        collected_certs = []
        for path in paths:
            try:
                if not path.exists():
                    continue

                file_size_mb = path.stat().st_size / (1024 * 1024)
                if file_size_mb > MAX_FILE_SIZE_MB and not self.force:
                    if self.debug:
                        ERROR.log(path.name, _("File too large ({size:.1f}MB)").format(size=file_size_mb))
                    continue

                with open(str(path), "rb") as f:
                    content = f.read()
                    if path.suffix.lower() in ['.p7b', '.p7c'] or b"PKCS7" in content:
                        collected_certs.extend(self.add_pkcs7_data(content, source_path=path, is_system=is_system))
                    else:
                        collected_certs.extend(self.add_pem_data(content, source_path=path, is_system=is_system))

            except Exception as e:
                if self.debug and not is_system:
                    ERROR.log(path.name, str(e))
        return collected_certs

    def clear_cache(self):
        self.seen_hashes.clear()
        self._certs_by_hash.clear()
        self.total_scanned_count = 0