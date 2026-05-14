"""
TrustStore Analyzer & Visualizer - HTTPS PROVIDER
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later

Implementation of the input provider for live HTTPS endpoint analysis.
Uses standard library ssl and socket modules to maintain zero-dependency goals.
"""

import socket
import ssl
from pathlib import Path
from typing import List, Optional, Any, Dict
from check_truststore.providers.base import BaseInputProvider, TrustStoreGroup
from check_truststore.engine import CertificateRepository, ERROR, INFO, _


class HttpsInputProvider(BaseInputProvider):
    """
    Handles the discovery of certificates by connecting to a live HTTPS host.
    """

    def __init__(
        self,
        url: str,
        repository: Optional[CertificateRepository] = None,
        **kwargs: Any,
    ):
        """
        Initializes the HTTPS provider.

        Args:
            url: The target URL or hostname (e.g., https://example.com).
            repository: Shared CertificateRepository instance.
        """
        super().__init__(repository=repository, **kwargs)

        self.hostname: str = url.replace("https://", "").replace("http://", "").split('/')[0].split(':')[0]
        self.port: int = 443

        if ":" in url.replace("https://", "").replace("http://", "").split('/')[0]:
            try:
                self.port = int(url.split(':')[-1].split('/')[0])
            except ValueError:
                pass

    def get_groups(self) -> List[TrustStoreGroup]:
        """
        Connects to the host, retrieves the leaf certificate in DER format,
        and registers it in the repository.

        Returns:
            A list containing a TrustStoreGroup with the discovered certificate.
        """
        group_name: str = f"HTTPS: {self.hostname}"
        targets: List[Dict[str, Any]] = []
        connection_success = False

        try:
            context: ssl.SSLContext = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            if self.debug:
                INFO.log(_("Initiating TLS connection to {host}:{port}").format(
                    host=self.hostname, port=self.port
                ))

            with socket.create_connection((self.hostname, self.port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    bin_cert: Optional[bytes] = ssock.getpeercert(binary_form=True)
                    connection_success = True

                    if bin_cert:
                        source_path_obj = Path(f"https://{self.hostname}:{self.port}")
                        new_targets = self.repository.add_der_data(
                            bin_cert,
                            source_path=source_path_obj
                        )
                        if new_targets:
                            targets.extend(new_targets)
                        else:
                            from check_truststore.engine import Certificate
                            fingerprint = Certificate.calculate_fingerprint(bin_cert)
                            existing_cert = self.repository.get_cert_by_fingerprint(fingerprint)

                            if existing_cert:
                                targets.append({
                                    "cert": existing_cert,
                                    "path": source_path_obj,
                                    "hash": fingerprint,
                                    "is_system_cert": False
                                })

        except Exception as e:
            ERROR.log(
                _("Failed to fetch certificate from {host}").format(host=self.hostname),
                str(e)
            )

        if connection_success:
            return [TrustStoreGroup(
                name=group_name,
                targets=targets,
                target_hostname=self.hostname
            )]

        return []