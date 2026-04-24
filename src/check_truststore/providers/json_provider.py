"""
TrustStore Analyzer & Visualizer - JSON PROVIDER
Architect: Serge van Thillo

Implementation of a configuration-driven input provider. This provider reads
a JSON schema to define multiple truststores, their source directories,
and the specific certificate chains that need to be validated.
"""

from pathlib import Path
from typing import List, Optional
from check_truststore.providers.base import BaseInputProvider, TrustStoreGroup
from check_truststore.engine.core import CertificateRepository


class JsonInputProvider(BaseInputProvider):
    """
    Parses a JSON configuration file to discover and group certificates.
    Useful for batch processing and automated audit environments.
    """

    def __init__(
        self,
        json_path: Path,
        repository: Optional[CertificateRepository] = None,
        debug: bool = False,
    ):
        """
        Initializes the JSON provider.

        Args:
            json_path: Path to the JSON configuration file.
            repository: Optional shared repository for certificate loading.
            debug: If True, enables extended error reporting during parsing.
        """
        super().__init__(repository=repository)
        self.json_path = json_path
        self.debug = debug

    def _get_json_content(self) -> Optional[dict]:
        """
        Safely reads and decodes the JSON file content.
        """
        import json

        if not self.json_path.exists():
            return None
        try:
            with open(self.json_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, PermissionError):
            return None

    def get_groups(self) -> List[TrustStoreGroup]:
        """
        Processes the 'truststores' definition in the JSON and returns
        the mapped TrustStoreGroups.

        Expected JSON structure:
        {
            "truststores": [
                {
                    "name": "Production API",
                    "cert_src_dir": "/path/to/certs",
                    "cert_chain": [{"link": "server.crt"}, {"link": "intermediate.crt"}]
                }
            ]
        }
        """
        data = self._get_json_content()
        if not data or not isinstance(data, dict):
            return []

        groups = []
        # Iterate through defined truststores in the config
        for store in data.get("truststores", []):
            store_name = store.get("name", "Unnamed Store")
            # Resolve the source directory relative to the config file or absolute
            source_dir = Path(store.get("cert_src_dir", "")).resolve()

            group_certs = []
            for link in store.get("cert_chain", []):
                filename = link.get("link")
                if not filename:
                    continue

                p = source_dir / filename

                if p.exists():
                    cert = self.load_certificate(p)
                    if cert:
                        group_certs.append(cert)
                elif self.debug:
                    # In a production scenario, we could log the missing file here
                    pass

            # Only add the group if it actually contains valid certificates
            if group_certs:
                groups.append(TrustStoreGroup(name=store_name, targets=group_certs))

        return groups
