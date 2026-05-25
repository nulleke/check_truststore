"""
TrustStore Analyzer & Visualizer - CERTIFICATE REPOSITORY
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later

This module manages the indexing, parsing, and deduplication of X.509 certificates.
It acts as a central registry for certificates discovered by various providers.
"""

import re
from typing import Any, Optional, List, Dict
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from .logging import _, WARNING, ERROR
from .models import Certificate


MAX_CERTS_PER_RUN = 1000
MAX_FILE_SIZE_MB = 10


class CertificateRepository:
    """
    Handles the parsing and deduplication of certificates.
    Uses SHA256 hashes to ensure each certificate is only processed once.
    """
    def __init__(self, **kwargs) -> None:
        """
        Instantiates an empty safe tracking repository context.

        Args:
            **kwargs: Control attributes including debug and force override behaviors.
        """
        self.options = kwargs
        self.debug = kwargs.get('debug', False)
        self.verbosity = kwargs.get('verbosity', 0)
        self.force = kwargs.get('force', False)
        self._certs_by_fingerprint: Dict[str, x509.Certificate] = {}
        self.total_scanned_count: int = 0

    def __contains__(self, fingerprint: str) -> bool:
        """
        Checks if a certificate with the given fingerprint exists in the repository.

        Args:
            fingerprint: The lowercase SHA-256 hex string of the certificate.

        Returns:
            True if the certificate is already registered, False otherwise.
        """
        return fingerprint in self._certs_by_fingerprint

    def _register_cert(self, cert: x509.Certificate, fingerprint: str) -> None:
        """
        Saves a distinct parsed certificate into the internal tracking registers.

        Args:
            cert: Parsed x509.Certificate object reference.
            fingerprint: Computed unique SHA-256 hex signature.
        """
        self._certs_by_fingerprint[fingerprint] = cert

    def get_cert_by_fingerprint(self, fingerprint: str) -> Optional[x509.Certificate]:
        """
        Retrieves a registered cryptography X.509 certificate object by its fingerprint.

        Used by the orchestrator layer for trust bundle exports.

        Args:
            fingerprint: The lowercase SHA-256 hex string identifying the certificate.

        Returns:
            The cryptography.x509.Certificate instance if found, or None.
        """
        return self._certs_by_fingerprint.get(fingerprint)

    def _get_cert_fingerprint(self, cert: x509.Certificate) -> str:
        """
        Generates a consistent lowercase SHA-256 fingerprint from an X.509 object.

        Args:
            cert: The cryptography.x509.Certificate object to evaluate.

        Returns:
            A clean lowercase hex string representing the SHA-256 fingerprint.
        """
        return Certificate.calculate_fingerprint(
            cert.public_bytes(serialization.Encoding.DER)
        )

    def add_der_data(self, content: bytes, source_path: Optional[Path] = None, is_system: bool = False) -> List[Dict[str, Any]]:
        """
        Parses raw binary ASN.1 DER data and registers unique certificates.

        Typically invoked during Windows Certificate Store operations and
        Authority Information Access (AIA) runtime discovery processes.

        Args:
            content: Raw binary DER certificate payload bytes.
            source_path: Optional file path pointer indicating the source origin.
            is_system: If True, flags the parsed entity as an OS-trusted root.

        Returns:
            A list containing a single standardized metadata dictionary if the
            certificate is new and successfully registered, otherwise an empty list.
        """
        try:
            cert = x509.load_der_x509_certificate(content, default_backend())
            c_fp = self._get_cert_fingerprint(cert)

            if c_fp in self._certs_by_fingerprint:
                return []

            self._register_cert(cert, c_fp)
            self.total_scanned_count += 1

            return [{
                "cert": cert,
                "path": source_path or Path("raw-data"),
                "hash": c_fp,
                "is_system_cert": is_system,
            }]
        except Exception as e:
            if self.debug:
                name = source_path.name if source_path else "raw-der"
                ERROR.log(name, f"{_('Invalid DER structure')}: {str(e)}")
            return []

    def add_pem_data(self, content: bytes, source_path: Optional[Path] = None, is_system: bool = False) -> List[Dict[str, Any]]:
        """
        Scans binary content for PEM certificate blocks and extracts unique objects.

        Supports standard RFC 7468 PEM blocks and legacy OpenSSL 'TRUSTED CERTIFICATE'
        formats. Enforces the global MAX_CERTS_PER_RUN boundary checks.

        Args:
            content: Raw byte content containing one or multiple text-encoded PEM blocks.
            source_path: Optional file path pointer mapping back to the filesystem source.
            is_system: Flags whether extracted certificates qualify as system anchors.

        Returns:
            A list of standardized metadata dictionaries representing newly loaded nodes.
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
                c_fp = self._get_cert_fingerprint(cert)

                if c_fp in self._certs_by_fingerprint:
                    if self.debug and not is_system and source_path:
                        WARNING.log(
                            source_path.name,
                            _("Skipping duplicate certificate (already loaded)"),
                            label=_("DUPLICATE"),
                        )
                    continue

                self._register_cert(cert, c_fp)
                new_certs.append({
                    "cert": cert,
                    "path": source_path or Path("stdin"),
                    "hash": c_fp,
                    "is_system_cert": is_system,
                })

            except Exception as e:
                if self.debug:
                    name = source_path.name if source_path else "stdin"
                    ERROR.log(name, f"{_('Invalid certificate structure')}: {str(e)}")

        return new_certs

    def add_pkcs7_data(self, content: bytes, source_path: Optional[Path] = None, is_system: bool = False) -> List[Dict[str, Any]]:
        """
        Extracts individual certificates from a PKCS#7 cryptographic container block.

        Decodes both text-encoded PEM (.p7b, .p7c) and raw binary DER variants.
        Implements fallback validation protocols if modern cryptography parsing is absent.

        Args:
            content: Container payload bytes holding target certificate collections.
            source_path: Optional location context matching the tracking source path.
            is_system: Flags whether assets extracted behave as trusted terminal anchors.

        Returns:
            A list of standardized dictionary elements tracking unique extracted entries.
        """
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

            c_fp = self._get_cert_fingerprint(cert)
            if c_fp in self._certs_by_fingerprint:
                continue

            self._register_cert(cert, c_fp)
            new_certs.append({
                "cert": cert,
                "path": source_path or Path("pkcs7-container"),
                "hash": c_fp,
                "is_system_cert": is_system,
            })
        return new_certs

    def load_from_files(self, paths: List[Path], is_system: bool = False) -> List[Dict[str, Any]]:
        """
        Evaluates local filesystem paths, identifies formats, and extracts certificate objects.

        Args:
            paths: List of explicit target paths pointing to disk configurations.
            is_system: Direct flag identifying if contents qualify as system roots.

        Returns:
            A list of standardized dictionary records identifying metadata states.
        """
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

    def clear_cache(self) -> None:
        """
        Resets the repository by clearing all indexed certificates and counters.

        Flushes the internal fingerprint registry mapping and resets the total
        scanned certificate tracker back to zero. This is typically used between
        isolated analysis cycles to guarantee a clean environment.
        """
        self._certs_by_fingerprint.clear()
        self.total_scanned_count = 0