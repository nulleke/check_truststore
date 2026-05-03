"""
TrustStore Analyzer & Visualizer - CERTIFICATE REPOSITORY
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later

This module manages the indexing and retrieval of X.509 certificates.
It handles both local file-based certificate pools and integration with
the operating system's native trust stores.
"""

import re
import hashlib
import platform
from typing import Any, Optional, List, Dict, Set
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from .logging import _, WARNING, ERROR, Icons as Icons


MAX_CERTS_PER_RUN = 1000
MAX_FILE_SIZE_MB = 10


class CertificateRepository:
    """
    Handles the discovery and raw loading of certificates from the filesystem or OS stores.
    It manages deduplication using SHA256 hashes.
    """
    def __init__(self, **kwargs):
        self.options = kwargs
        self.debug = kwargs.get('debug', False)
        self.verbosity = kwargs.get('verbosity', 0)
        self.force = kwargs.get('force', False)
        self.seen_hashes: Set[str] = set()
        self.total_scanned_count: int = 0
        self.system_store_total_count = 0

    def _get_cert_hash(self, cert: x509.Certificate) -> str:
        """Helper to get a consistent SHA256 hash from an x509 object."""
        return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()

    def add_pem_data(self, content: bytes, source_path: Optional[Path] = None, is_system: bool = False) -> List[Dict[str, Any]]:
        """
        Unified entry point: Parses bytes for PEM blocks and adds unique certificates.
        Supports standard PEM and OpenSSL 'TRUSTED CERTIFICATE' formats.
        """
        new_certs = []

        # Regex to find certificates, including those marked as "TRUSTED CERTIFICATE"
        pattern = b"-----BEGIN (?:TRUSTED )?CERTIFICATE-----.*?-----END (?:TRUSTED )?CERTIFICATE-----"

        for match in re.finditer(pattern, content, re.DOTALL):
            if is_system:
                self.system_store_total_count += 1

            raw_block = match.group(0)
            self.total_scanned_count += 1

            if self.total_scanned_count >= MAX_CERTS_PER_RUN and not self.force:
                if self.debug:
                    WARNING.log(source_path.name, _("Maximum certificate limit ({limit}) reached. Stopping scan.").format(limit=MAX_CERTS_PER_RUN))
                break

            try:
                # Strip 'TRUSTED ' prefix to satisfy standard x509 parser
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
                cert_entry = {
                    "cert": cert,
                    "path": source_path or Path("stdin"),
                    "hash": c_hash,
                    "is_system_cert": is_system,
                }
                new_certs.append(cert_entry)

            except Exception as e:
                if self.debug:
                    name = source_path.name if source_path else "stdin"
                    ERROR.log(name, f"{_('Invalid certificate structure')}: {str(e)}")

        return new_certs

    def add_pkcs7_data(self, content: bytes, source_path: Optional[Path] = None, is_system: bool = False) -> List[Dict[str, Any]]:
        """
        Extracts certificates from a PKCS#7 container using the most compatible API.
        """
        new_certs = []
        source_name = source_path.name if source_path else _("PKCS7-container")

        try:
            from cryptography.hazmat.primitives.serialization import pkcs7

            if b"-----BEGIN PKCS7-----" in content:
                pkcs7_certs = pkcs7.load_pem_pkcs7_certificates(content)
            else:
                pkcs7_certs = pkcs7.load_der_pkcs7_certificates(content)

        except (ImportError, AttributeError):
            if self.debug:
                WARNING.log(source_name, _("Legacy cryptography detected, falling back."))
            return []
        except Exception as e:
            if self.debug:
                msg = _("Failed to parse PKCS7: {error}").format(error=str(e))
                ERROR.log(source_name, msg)
            return []

        for cert in pkcs7_certs:
            if is_system:
                self.system_store_total_count += 1

            self.total_scanned_count += 1

            if self.total_scanned_count >= MAX_CERTS_PER_RUN and not self.force:
                if self.debug:
                    WARNING.log(source_name, _("Maximum certificate limit ({limit}) reached. Stopping scan.").format(limit=MAX_CERTS_PER_RUN))
                break

            c_hash = self._get_cert_hash(cert)

            if c_hash in self.seen_hashes:
                continue

            self.seen_hashes.add(c_hash)
            new_certs.append({
                "cert": cert,
                "path": source_path or Path("pkcs7-container"),
                "hash": c_hash,
                "is_system_cert": is_system,
            })

        return new_certs

    def load_from_files(
        self, paths: List[Path], is_system: bool = False
    ) -> List[Dict[str, Any]]:
        """Iterates through a list of paths to extract PEM-encoded certificates."""
        collected_certs = []
        for path in paths:
            collected_certs.extend(self._load_single_file(path, is_system=is_system))
        return collected_certs

    def _load_single_file(
        self, path: Path, is_system: bool = False
    ) -> List[Dict[str, Any]]:
        """Reads a file and intelligently delegates to PEM or PKCS#7 parser."""
        try:
            file_size_mb = path.stat().st_size / (1024 * 1024)
            if file_size_mb > MAX_FILE_SIZE_MB and not self.force:
                if self.debug:
                    ERROR.log(path.name, _("File too large ({size:.1f}MB). Use --force to override.").format(size=file_size_mb))
                return []

            with open(str(path), "rb") as f:
                content = f.read()
                is_pkcs7 = path.suffix.lower() in ['.p7b', '.p7c'] or b"PKCS7" in content
                if is_pkcs7:
                    return self.add_pkcs7_data(content, source_path=path, is_system=is_system)

                return self.add_pem_data(content, source_path=path, is_system=is_system)

        except (FileNotFoundError, PermissionError) as e:
            if self.debug and not is_system:
                label = _("READ_ERROR")
                msg = _("File not found") if isinstance(e, FileNotFoundError) else _("Permission denied")
                ERROR.log(path.name, f"{msg}: {path.absolute()}", label=label)
        except Exception as e:
            if self.debug and not is_system:
                ERROR.log(path.name, str(e), label=_("READ_ERROR"))
        return []

    def load_from_system(self) -> List[Dict[str, Any]]:
        """Auto-detects the operating system and loads its default truststore."""
        os_type = platform.system()
        results = []
        self.system_store_total_count = 0

        if os_type == "Windows":
            results.extend(self._load_windows_store())
        else:
            paths = self._get_unix_ca_paths(os_type)
            results.extend(self.load_from_files(paths, is_system=True))

        return results

    def _get_unix_ca_paths(self, os_type: str) -> List[Path]:
        """Returns standard CA bundle paths for various Unix/Linux distributions."""
        paths = []
        if os_type == "Linux":
            common = [
                "/etc/pki/tls/certs/ca-bundle.crt",  # Fedora/RHEL/CentOS 6
                "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",  # RHEL/CentOS 7+
                "/etc/ssl/certs/ca-certificates.crt",  # Debian/Ubuntu/Arch
                "/etc/ssl/ca-bundle.pem",  # OpenSUSE
                "/etc/ca-certificates/extracted/tls-ca-bundle.pem",  # Arch/SuSE
            ]

            for p in common:
                path_obj = Path(p)
                if path_obj.exists():
                    paths.append(path_obj)
                    break

        elif os_type == "Darwin":
            p = Path("/etc/ssl/cert.pem")  # macOS
            if p.exists():
                paths.append(p)

        return paths

    def _load_windows_store(self) -> List[Dict[str, Any]]:
        """Accesses the Windows Certificate Store (ROOT and CA) using the ssl module."""
        import ssl

        found = []
        for store_name in ["ROOT", "CA"]:
            for cert_der in ssl.enum_certificates(store_name):
                self.system_store_total_count += 1
                self.total_scanned_count += 1

                if self.total_scanned_count >= MAX_CERTS_PER_RUN and not self.force:
                    break

                try:
                    cert = x509.load_der_x509_certificate(
                        cert_der[0], default_backend()
                    )
                    c_hash = self._get_cert_hash(cert)

                    if c_hash in self.seen_hashes:
                        continue

                    found.append(
                        {
                            "cert": cert,
                            "path": Path(f"Windows-{store_name}-Store"),
                            "hash": c_hash,
                            "is_system_cert": True,
                        }
                    )

                    self.seen_hashes.add(c_hash)

                except Exception:
                    continue
        return found
