"""
TrustStore Analyzer & Visualizer - HTTPS PROVIDER (Parallel Edition)
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later
"""

import socket
import ssl
from pathlib import Path
from typing import List, Optional, Any, Dict, Union
from concurrent.futures import ThreadPoolExecutor, as_completed
from check_truststore.providers.base import BaseInputProvider, TrustStoreGroup
from check_truststore.engine import CertificateRepository, ERROR, INFO, _


class HttpsInputProvider(BaseInputProvider):
    """
    Handles parallel discovery of certificates by connecting to multiple live HTTPS hosts.
    """

    def __init__(
        self,
        urls: Union[str, List[str]],
        repository: Optional[CertificateRepository] = None,
        max_workers: int = 10,
        **kwargs: Any,
    ):
        """
        Initializes the HTTPS provider with a list of target URLs.
        """
        super().__init__(repository=repository, **kwargs)
        self.max_workers: int = max_workers
        self.targets_to_fetch: List[Dict[str, Any]] = []
        url_list: List[str] = [urls] if isinstance(urls, str) else urls

        for url in url_list:
            hostname: str = url.replace("https://", "").replace("http://", "").split('/')[0].split(':')[0]
            port: int = 443

            if ":" in url.replace("https://", "").replace("http://", "").split('/')[0]:
                try:
                    port = int(url.split(':')[-1].split('/')[0])
                except ValueError:
                    pass

            self.targets_to_fetch.append({"hostname": hostname, "port": port})

    def _fetch_single_certificate(self, hostname: str, port: int) -> Optional[bytes]:
        """
        Establishes a network connection to a single remote host and retrieves its TLS certificate.

        This method executes inside an independent worker thread of the ThreadPoolExecutor
        to achieve concurrent network I/O. It configures a default SSL context with
        disabled hostname validation and certificate verification in order to exclusively
        capture the raw certificate bytes (binary DER form) presented by the endpoint.

        Args:
            hostname (str): The target server hostname or IP address.
            port (int): The target port number (typically 443).

        Returns:
            Optional[bytes]: The raw binary certificate data if successful; None if the
                             connection times out, encounters an SSL error, or fails.
        """
        try:
            context: ssl.SSLContext = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            if self.debug:
                INFO.log(_("Initiating TLS connection to {host}:{port}").format(
                    host=hostname, port=port
                ))

            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return ssock.getpeercert(binary_form=True)
        except Exception as e:
            ERROR.log(
                _("Failed to fetch certificate from {host}").format(host=hostname),
                str(e)
            )
            return None

    def get_groups(self) -> List[TrustStoreGroup]:
        """
        Fetches certificates from all hosts in parallel, then safely processes
        them sequentially on the main thread.
        """
        groups: List[TrustStoreGroup] = []
        raw_results: List[Dict[str, Any]] = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_host = {
                executor.submit(self._fetch_single_certificate, target["hostname"], target["port"]): target
                for target in self.targets_to_fetch
            }

            for future in as_completed(future_to_host):
                target = future_to_host[future]
                try:
                    bin_cert = future.result()
                    if bin_cert:
                        raw_results.append({
                            "hostname": target["hostname"],
                            "port": target["port"],
                            "bin_cert": bin_cert
                        })
                except Exception as e:
                    ERROR.log(
                        _("Thread crash while processing {host}").format(host=target['hostname']),
                        str(e)
                    )

        for result in raw_results:
            hostname = result["hostname"]
            port = result["port"]
            bin_cert = result["bin_cert"]

            group_name: str = f"HTTPS: {hostname}"
            targets: List[Dict[str, Any]] = []
            source_path_obj = Path(f"https://{hostname}:{port}")

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

            groups.append(TrustStoreGroup(
                name=group_name,
                targets=targets,
                target_hostname=hostname
            ))

        return groups