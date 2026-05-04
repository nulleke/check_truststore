"""
TrustStore Analyzer & Visualizer - FILE PROVIDER
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later

Implementation of the input provider for single file or raw string analysis.
Optimized for lazy loading of files while maintaining support for piped input.
"""

from pathlib import Path
from typing import List, Optional, Union, Any, Dict
from check_truststore.providers.base import BaseInputProvider, TrustStoreGroup
from check_truststore.engine import CertificateRepository

class SingleFileInputProvider(BaseInputProvider):
    """
    Handles the discovery and grouping of a single certificate source.
    Supports both filesystem paths and raw certificate strings (stdin).
    """

    def __init__(
        self,
        input_source: Union[Path, str, bytes],
        repository: Optional[CertificateRepository] = None,
        is_raw_data: bool = False,
        **kwargs: Any,
    ):
        """
        Initializes the file provider.

        Args:
            input_source: Path to the certificate file or raw PEM/PKCS#7 data.
            repository: Shared CertificateRepository instance.
            is_raw_data: Set to True if input_source contains raw certificate data.
        """
        super().__init__(repository=repository, **kwargs)
        self.input_source = input_source
        self.is_raw_data = is_raw_data

    def get_groups(self) -> List[TrustStoreGroup]:
        """
        Packs the input into a TrustStoreGroup for analysis.

        Uses Lazy Loading (Path) for files to ensure group isolation,
        but Direct Registration (Dict) for raw data as no file exists.

        Returns:
            A list containing a TrustStoreGroup or an empty list if loading fails.
        """
        group_name = "Stdin Input"
        targets: List[Union[Path, Dict[str, Any]]] = []

        if self.is_raw_data:
            content = self.input_source
            if isinstance(content, str):
                content = content.encode('utf-8')

            if b"PKCS7" in content or (not content.startswith(b"-----BEGIN") and len(content) > 100):
                targets = self.repository.add_pkcs7_data(content, source_path=None)
            else:
                targets = self.repository.add_pem_data(content, source_path=None)
        else:
            path = Path(self.input_source)
            if path.is_file():
                targets = [path]
                group_name = path.name

        if targets:
            return [TrustStoreGroup(name=group_name, targets=targets)]

        return []