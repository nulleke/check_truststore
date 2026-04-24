"""
TrustStore Analyzer & Visualizer - FILE PROVIDER
Architect: Serge van Thillo

Implementation of the input provider for single file analysis. This provider
is used when a specific certificate file is targeted directly via the CLI
or a dedicated configuration.
"""

from pathlib import Path
from typing import List, Optional
from check_truststore.providers.base import BaseInputProvider, TrustStoreGroup
from check_truststore.engine.core import CertificateRepository


class SingleFileInputProvider(BaseInputProvider):
    """
    Handles the loading and grouping of a single, specific certificate file.
    """

    def __init__(
        self, file_path: Path, repository: Optional[CertificateRepository] = None
    ):
        """
        Initializes the file provider.

        Args:
            file_path: Path to the target certificate file.
            repository: Optional shared repository for certificate loading.
        """
        super().__init__(repository=repository)
        self.file_path = file_path

    def get_groups(self) -> List[TrustStoreGroup]:
        """
        Loads the specific file and packs it into a TrustStoreGroup.

        Returns:
            A list containing a single TrustStoreGroup named after the file,
            or an empty list if the file is invalid or missing.
        """
        if not self.file_path.is_file():
            return []

        # Load the certificate metadata dictionary
        cert = self.load_certificate(self.file_path)
        # If the file contains no valid certificates, return an empty group list
        certs = [cert] if cert else []

        return [TrustStoreGroup(name=self.file_path.name, targets=certs)]
