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
    """Parses JSON configurations to discover and group certificates.

    This provider evaluates local configuration structures or raw JSON payloads
    against the tool's internal declarative deployment schemas. Relative asset
    paths are automatically calculated back to their baseline workspace origins.

    Attributes:
        input_source (Union[Path, str, bytes]): The raw JSON content string,
            serialized bytes container, or configuration file destination path.
        is_raw_data (bool): Flag indicating if the input source represents actual
            textual payload strings rather than a location on disk.
        repository (CertificateRepository): Inherited central asset identification mapping store.
        options (Dict[str, Any]): Dictionary containing configuration arguments.
        debug (bool): If True, enables diagnostic traces and deep error reporting.
        verbosity (int): Numeric modifier adjusting logging output volume.
    """

    def __init__(
        self,
        input_source: Union[Path, str],
        repository: Optional[CertificateRepository] = None,
        is_raw_data: bool = False,
        **kwargs: Any,
    ) -> None:
        """Initializes the JSON configuration workspace provider.

        Args:
            input_source (Union[Path, str, bytes]): Path to the configuration file
                or a raw unparsed JSON payload structure string.
            repository (Optional[CertificateRepository], optional): Shared index
                repository for certificate discovery. Defaults to None.
            is_raw_data (bool, optional): Explicit indicator to treat input_source
                as plain textual/binary configuration streams. Defaults to False.
            **kwargs: Flexible configuration choices passed down to BaseInputProvider.
        """
        super().__init__(repository=repository, **kwargs)
        self.input_source: Union[Path, str, bytes] = (
            Path(input_source) if (isinstance(input_source, (str, Path)) and not is_raw_data) else input_source
        )
        self.is_raw_data: bool = is_raw_data

    def _get_json_content(self) -> Optional[Dict[str, Any]]:
        """Safely loads and extracts JSON schema maps from a file or raw string stream.

        Catches internal encoding boundaries, file permission rejections,
        and parser format validation anomalies gracefully.

        Returns:
            Optional[Dict[str, Any]]: Top-level root JSON key-value map if structural
                rules are valid; None if parsing drops or payload is not an object.
        """
        if self.is_raw_data:
            try:
                raw_str: str = self.input_source.decode('utf-8') if isinstance(self.input_source, bytes) else self.input_source
                content: Any = json.loads(raw_str)
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
        """Identifies the underlying configuration format and dispatches to appropriate parsers.

        Returns:
            List[TrustStoreGroup]: A collection of structural groups processed out
                of recognized template layouts, otherwise empty collections.
        """
        data: Optional[Dict[str, Any]] = self._get_json_content()
        if not data:
            return []

        if "truststores" in data and isinstance(data["truststores"], list):
            return self._parse_internal_format(data)

        if self.debug:
            WARNING.log(str(self.input_source), _("Unknown JSON format or malformed structure."))

        return []

    def _parse_internal_format(self, data: Dict[str, Any]) -> List[TrustStoreGroup]:
        """Parses the native architectural trust store blueprint specification schema.

        Resolves localized directories relative to the JSON configuration file's
        parent path or relies fallback-wise on the current working directory block.

        Args:
            data (Dict[str, Any]): Validated root layout mapping from configuration lookups.

        Returns:
            List[TrustStoreGroup]: Packaged and structurally isolated target certificate groups.
        """
        base_dir: Path = (
            self.input_source.parent
            if (isinstance(self.input_source, Path) and not self.is_raw_data)
            else Path.cwd()
        )
        groups: List[TrustStoreGroup] = []

        for store in data.get("truststores", []):
            store_name: str = store.get("name", _("Unnamed Store"))
            raw_src_dir: str = store.get("cert_src_dir", ".")
            raw_src_path: Path = Path(raw_src_dir)

            if raw_src_path.is_absolute():
                source_dir: Path = raw_src_path
            else:
                candidate: Path = (base_dir / raw_src_path).resolve()
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