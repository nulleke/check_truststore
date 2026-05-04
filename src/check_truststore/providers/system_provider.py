"""
TrustStore Analyzer & Visualizer - SYSTEM PROVIDER
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later

Implementation of the input provider that accesses native OS trust stores.
Supports Windows Certificate Store (CAPI) and standard Unix/Linux CA bundles.
"""

import platform
from pathlib import Path
from typing import List, Optional, Any
from check_truststore.providers.base import BaseInputProvider, TrustStoreGroup
from check_truststore.engine import CertificateRepository

class SystemInputProvider(BaseInputProvider):
    """
    Accesses the operating system's built-in trusted certificates.
    """

    def __init__(
        self,
        repository: Optional[CertificateRepository] = None,
        **kwargs: Any,
    ):
        super().__init__(repository=repository, **kwargs)

    def get_groups(self) -> List[TrustStoreGroup]:
        """
        Detects the OS and returns the system trust store(s) as groups.
        """
        os_type = platform.system()
        groups: List[TrustStoreGroup] = []

        if os_type == "Windows":
            groups.extend(self._get_windows_groups())
        else:
            groups.extend(self._get_unix_groups(os_type))

        return groups

    def _get_windows_groups(self) -> List[TrustStoreGroup]:
        """Enumerates certificates from Windows ROOT and CA stores."""
        import ssl

        groups = []
        for store_name in ["ROOT", "CA"]:
            try:
                certs_der = [cert[0] for cert in ssl.enum_certificates(store_name)]
                if certs_der:
                    groups.append(
                        TrustStoreGroup(
                            name=f"Windows-{store_name}-Store",
                            targets=certs_der
                        )
                    )
            except Exception:
                continue
        return groups

    def _get_unix_groups(self, os_type: str) -> List[TrustStoreGroup]:
        """Finds standard CA bundle paths on Unix-like systems."""
        paths: List[Path] = []

        if os_type == "Linux":
            common_bundles = [
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
                    break #

        elif os_type == "Darwin": # macOS
            p = Path("/etc/ssl/cert.pem")
            if p.exists():
                paths.append(p)

        if paths:
            return [TrustStoreGroup(name=f"{os_type}-System-Store", targets=paths)]

        return []