"""
TrustStore Analyzer & Visualizer - FILE PROVIDER
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later

Implementation of the input provider for single file analysis. This provider
is used when a specific certificate file is targeted directly via the CLI
or a dedicated configuration.
"""

from pathlib import Path
from typing import List, Optional, Union
from check_truststore.providers.base import BaseInputProvider, TrustStoreGroup
from check_truststore.engine.core import CertificateRepository

class SingleFileInputProvider(BaseInputProvider):
    """
    Handles the loading and grouping of a single certificate (file or raw string).
    """

    def __init__(
        self,
        input_source: Union[Path, str],
        repository: Optional[CertificateRepository] = None,
        is_raw_data: bool = False,
        **kwargs,
    ):
        """
        Initializes the file provider.

        Args:
            input_source: Path to the target certificate file or raw PEM string.
            repository: Optional shared repository for certificate loading.
            is_raw_data: Boolean flag indicating if input_source is a raw string.
        """
        super().__init__(repository=repository, **kwargs)
        self.input_source = input_source
        self.is_raw_data = is_raw_data

    def get_groups(self) -> List[TrustStoreGroup]:
        """
        Loads the specific input and packs it into a TrustStoreGroup.

        Returns:
            A list containing a single TrustStoreGroup named after the source,
            or an empty list if the loading fails.
        """
        certs = []
        group_name = "Stdin Input"

        if self.is_raw_data:
            # Handle raw string input (e.g., piped data)
            content = self.input_source.encode() if isinstance(self.input_source, str) else self.input_source
            certs = self.repository.add_pem_data(content, source_path=None)
        else:
            # Handle file path input
            path = Path(self.input_source)
            if path.is_file():
                certs = self.repository.load_from_files([path])
                group_name = path.name

        if certs:
            # In the builder/analyzer, 'targets' expects the list of metadata dictionaries
            return [TrustStoreGroup(name=group_name, targets=certs)]

        return []