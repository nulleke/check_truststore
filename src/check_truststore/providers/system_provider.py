"""
TrustStore Analyzer & Visualizer - SYSTEM PROVIDER
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later

Implementation of the input provider that accesses native OS trust stores.
Supports Windows Certificate Store (CAPI) and standard Unix/Linux CA bundles.
"""

import platform
from pathlib import Path
from typing import Dict, List, Optional, Any
from check_truststore.providers.base import BaseInputProvider, TrustStoreGroup
from check_truststore.engine import CertificateRepository

class SystemInputProvider(BaseInputProvider):
    """Accesses the operating system's built-in trusted certificate stores.

    This provider abstracts platform-specific storage mechanisms (CAPI on Windows,
    PEM-based bundles on Linux/macOS) into a unified interface for the analysis engine.

    Attributes:
        repository (CertificateRepository): Inherited central asset identification mapping store.
        options (Dict[str, Any]): Dictionary containing configuration arguments.
        debug (bool): If True, enables diagnostic traces and deep error reporting.
        verbosity (int): Numeric modifier adjusting logging output volume.
    """

    def __init__(
        self,
        repository: Optional[CertificateRepository] = None,
        **kwargs: Any,
    ) -> None:
        """Initializes the system trust store provider.

        Args:
            repository (Optional[CertificateRepository], optional): Shared index
                repository for certificate discovery. Defaults to None.
            **kwargs: Flexible configuration choices passed down to BaseInputProvider.
        """
        super().__init__(repository=repository, **kwargs)

    def get_groups(self) -> List[TrustStoreGroup]:
        """Detects the underlying OS and aggregates system trust stores as groups.

        Returns:
            List[TrustStoreGroup]: A collection of system-specific trust store
                groups ready for pipeline validation.
        """
        os_type: str = platform.system()
        groups: List[TrustStoreGroup] = []

        if os_type == "Windows":
            groups.extend(self._get_windows_groups())
        else:
            groups.extend(self._get_unix_groups(os_type))

        return groups

    def _get_windows_groups(self) -> List[TrustStoreGroup]:
        """Enumerates certificates from Windows ROOT and CA stores via CAPI.

        Returns:
            List[TrustStoreGroup]: Extracted X.509 certificate groupings from
                the Windows Registry/CAPI storage.
        """
        import ssl

        groups: List[TrustStoreGroup] = []
        target_stores: Dict[str, str] = {
            "ROOT": "Windows-Trusted-Root-CA",
            "CA": "Windows-Intermediate-CA",
            "Disallowed": "Windows-Untrusted-Certificates"
        }
        for store_name, display_name in target_stores.items():
            try:
                certs: Any = ssl.enum_certificates(store_name)

                certs_der: List[bytes] = []
                for cert_data, encoding_type, trust_codes in certs:
                    if encoding_type == 'x509_asn':
                        certs_der.append(cert_data)

                if certs_der:
                    groups.append(
                        TrustStoreGroup(
                            name=display_name,
                            targets=certs_der
                        )
                    )
            except PermissionError:
                continue
            except Exception:
                continue
        return groups

    def _get_unix_groups(self, os_type: str) -> List[TrustStoreGroup]:
        """Identifies standard CA bundle paths on Unix-like operating systems.

        Args:
            os_type (str): The platform identifier (e.g., 'Linux', 'Darwin').

        Returns:
            List[TrustStoreGroup]: Group wrapper containing discovered system bundle paths.
        """
        paths: List[Path] = []

        if os_type == "Linux":
            common_bundles: List[str] = [
                "/etc/pki/tls/certs/ca-bundle.crt",  # Fedora/RHEL/CentOS 6
                "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",  # RHEL/CentOS 7+
                "/etc/ssl/certs/ca-certificates.crt",  # Debian/Ubuntu/Arch
                "/etc/ssl/ca-bundle.pem",  # OpenSUSE
                "/etc/ca-certificates/extracted/tls-ca-bundle.pem",  # Arch/SuSE
            ]
            for p in common_bundles:
                path_obj = Path(p)
                if path_obj.exists():
                    paths.append(path_obj)
                    break

        elif os_type == "Darwin": # macOS
            common_mac_paths: List[str] = [
                "/etc/ssl/cert.pem",
                "/usr/local/etc/openssl@3/cert.pem", # Homebrew OpenSSL 3
            ]
            for p_str in common_mac_paths:
                p = Path(p_str)
                if p.exists():
                    paths.append(p)

        if paths:
            return [TrustStoreGroup(name=f"{os_type}-System-Store", targets=paths)]

        return []