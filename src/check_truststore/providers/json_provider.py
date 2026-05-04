"""
TrustStore Analyzer & Visualizer - JSON PROVIDER
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later

JSON provider for internal truststore configuration schemas.
Optimized for lazy loading to ensure group isolation.
"""

import json
from pathlib import Path
from typing import List, Optional, Union, Dict, Any
from check_truststore.providers.base import BaseInputProvider, TrustStoreGroup
from check_truststore.engine import CertificateRepository, _, WARNING

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
        **kwargs: Any,
    ):
        """
        Initializes the JSON provider.

        Args:
            input_source: Path to the JSON file or a raw JSON string.
            repository: Shared CertificateRepository instance.
            is_raw_data: Set to True if input_source is a JSON string.
        """
        super().__init__(repository=repository, **kwargs)
        self.input_source = input_source
        self.is_raw_data = is_raw_data

    def _get_json_content(self) -> Optional[Dict[str, Any]]:
        """
        Safely loads JSON data from a file or raw string.
        """
        if self.is_raw_data:
            try:
                raw_str = self.input_source.decode('utf-8') if isinstance(self.input_source, bytes) else self.input_source
                content = json.loads(raw_str)
                return content if isinstance(content, dict) else None
            except (json.JSONDecodeError, UnicodeDecodeError):
                return None

        path = Path(self.input_source)
        if not path.is_file():
            return None

        try:
            with open(path, "r", encoding="utf-8") as f:
                content = json.load(f)
                return content if isinstance(content, dict) else None
        except (json.JSONDecodeError, PermissionError):
            return None

    def get_groups(self) -> List[TrustStoreGroup]:
        """
        Identifies the JSON schema and dispatches to the appropriate parser.
        """
        data = self._get_json_content()
        if not data:
            return []

        if "truststores" in data and isinstance(data["truststores"], list):
            return self._parse_internal_format(data)

        if self.debug:
            WARNING.log(str(self.input_source), _("Unknown JSON format or malformed structure."))

        return []

    def _parse_internal_format(self, data: Dict[str, Any]) -> List[TrustStoreGroup]:
        """
        Parses the tool's native truststore configuration format.
        Relatively linked files are resolved against the JSON file's directory.
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

            group_targets: List[Path] = []
            for link in store.get("cert_chain", []):
                filename = link.get("link")
                if not filename:
                    continue
                cert_path = source_dir / filename

                if cert_path.is_file():
                    group_targets.append(cert_path)
                elif self.debug:
                    WARNING.log(filename, _("Certificate not found in {}").format(source_dir), label=_("MISSING"))

            if group_targets:
                groups.append(TrustStoreGroup(name=store_name, targets=group_targets))

        return groups