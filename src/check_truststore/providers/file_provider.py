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
    """Handles the discovery and grouping of a single certificate source.

    Supports both lazy-loaded filesystem paths and directly evaluated raw
    certificate blocks, making it highly suitable for handling piped data streams
    via standard input (stdin).

    Attributes:
        input_source (Union[Path, str, bytes]): The raw payload block, string
            stream, or target filesystem path.
        is_raw_data (bool): Flag indicating if the input source represents actual
            certificate bytes/strings rather than a location on disk.
        repository (CertificateRepository): Inherited central asset identification mapping store.
        options (Dict[str, Any]): Dictionary containing configuration arguments.
        debug (bool): If True, enables diagnostic traces and deep error reporting.
        verbosity (int): Numeric modifier adjusting logging output volume.
    """

    def __init__(
        self,
        input_source: Union[Path, str, bytes],
        repository: Optional[CertificateRepository] = None,
        is_raw_data: bool = False,
        **kwargs: Any,
    ) -> None:
        """Initializes the single file or stream provider interface.

        Args:
            input_source (Union[Path, str, bytes]): Path to the certificate file
                or raw PEM/PKCS#7 cryptographic data blocks.
            repository (Optional[CertificateRepository], optional): Shared index
                repository for certificate discovery. Defaults to None.
            is_raw_data (bool, optional): Explicit indicator to treat input_source
                as plain textual/binary data streams. Defaults to False.
            **kwargs: Flexible configuration choices passed down to BaseInputProvider.
        """
        super().__init__(repository=repository, **kwargs)
        self.input_source: Union[Path, str, bytes] = (
            Path(input_source) if (isinstance(input_source, (str, Path)) and not is_raw_data) else input_source
        )
        self.is_raw_data: bool = is_raw_data

    def get_groups(self) -> List[TrustStoreGroup]:
        """Packs the single input source into an executable TrustStoreGroup structure.

        Uses Lazy Loading (via `Path`) for local files to optimize system memory
        boundaries, but applies Direct Registration (yielding metadata mappings via
        `Dict`) for transient data blocks since no concrete file exists on disk.

        Returns:
            List[TrustStoreGroup]: A single-item list containing the generated
                trust group context, or an empty list if data tracking or local
                file lookup fails.
        """
        group_name: str = "Stdin Input"
        targets: List[Union[Path, Dict[str, Any]]] = []

        if self.is_raw_data:
            content: Union[str, bytes] = self.input_source
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