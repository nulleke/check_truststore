"""
TrustStore Analyzer & Visualizer - JSON PROVIDER
Architect: Serge van Thillo

JSON provider for internal truststore configuration schemas.
"""

import json
from pathlib import Path
from typing import List, Optional, Union, Dict
from check_truststore.providers.base import BaseInputProvider, TrustStoreGroup
from check_truststore.engine.core import CertificateRepository, _, WARNING

class JsonInputProvider(BaseInputProvider):
    """
    Parses JSON files to discover and group certificates based on
    the tool's internal configuration format.
    """

    def __init__(
        self,
        input_source: Union[Path, str],
        repository: Optional[CertificateRepository] = None,
        is_raw_data: bool = False,
        **kwargs,
    ):
        super().__init__(repository=repository, **kwargs)
        self.input_source = input_source
        self.is_raw_data = is_raw_data

    def _get_json_content(self) -> Optional[Dict]:
        """
        Safely loads JSON data from a file or raw string.
        """
        if self.is_raw_data:
            try:
                content = json.loads(self.input_source)
                return content if isinstance(content, dict) else None
            except json.JSONDecodeError:
                return None

        path = Path(self.input_source)
        if not path.is_file():
            return None

        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, PermissionError):
            return None

    def get_groups(self) -> List[TrustStoreGroup]:
        """
        Detects the JSON schema using deep structural validation.
        """
        data = self._get_json_content()
        if not data or not isinstance(data, dict):
            return []

        if "truststores" in data and isinstance(data["truststores"], list):
            return self._parse_internal_format(data)

        if self.debug:
            WARNING.log(str(self.input_source), _("Unknown JSON format or malformed structure."))

        return []

    def _parse_internal_format(self, data: Dict) -> List[TrustStoreGroup]:
        """
        Parses the tool's native truststore configuration format.
        """
        config_path = Path(self.input_source)
        base_dir = config_path.parent if not self.is_raw_data else Path.cwd()
        groups = []

        for store in data.get("truststores", []):
            store_name = store.get("name", _("Unnamed Store"))
            raw_src_dir = store.get("cert_src_dir", ".")
            raw_src_path = Path(raw_src_dir)

            if raw_src_path.is_absolute():
                source_dir = raw_src_path
            else:
                candidate = (base_dir / raw_src_path).resolve()
                source_dir = candidate if candidate.exists() else raw_src_path.resolve()

            group_certs = []
            for link in store.get("cert_chain", []):
                filename = link.get("link")
                if not filename:
                    continue
                p = source_dir / filename
                if p.is_file():
                    group_certs.extend(self.repository.load_from_files([p]))

            if group_certs:
                groups.append(TrustStoreGroup(name=store_name, targets=group_certs))

        return groups
