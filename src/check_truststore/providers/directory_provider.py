"""
TrustStore Analyzer & Visualizer - DIRECTORY PROVIDER
Architect: Serge van Thillo

Implementation of the input provider that scans filesystem directories
for certificate files. Supports filtering by extensions and recursive scanning.
"""

from pathlib import Path
from typing import List, Optional
from check_truststore.providers.base import BaseInputProvider, TrustStoreGroup
from check_truststore.engine.core import CertificateRepository


class DirectoryInputProvider(BaseInputProvider):
    """
    Scans a specific directory for X.509 certificates based on file extensions.
    """

    def __init__(
        self,
        folder_path: Path,
        repository: Optional[CertificateRepository] = None,
        extensions: Optional[List[str]] = None,
        recursive: bool = False,
    ):
        """
        Initializes the directory scanner.

        Args:
            folder_path: Path to the directory to be scanned.
            repository: Optional shared repository for certificate loading.
            extensions: List of file extensions to include (default: .crt, .pem, .cer, .der).
            recursive: If True, performs a deep scan of all subdirectories.
        """
        super().__init__(repository=repository)
        self.folder_path = folder_path
        self.extensions = extensions or [".crt", ".pem", ".cer", ".der"]
        self.recursive = recursive

    def get_groups(self) -> List[TrustStoreGroup]:
        """
        Discovers files in the configured directory and packs them into a TrustStoreGroup.

        Returns:
            A list containing a single TrustStoreGroup named after the directory.
        """
        if not self.folder_path.is_dir():
            return []

        all_paths = []
        for ext in self.extensions:
            # Construct glob pattern based on recursion preference
            pattern = f"**/*{ext}" if self.recursive else f"*{ext}"
            all_paths.extend(self.folder_path.glob(pattern))

        # Deduplicate paths and ensure they are files, then sort for consistent output
        unique_paths = sorted(list(set(p for p in all_paths if p.is_file())))
        # Load the raw certificate data (metadata dictionaries)
        certs = [self.load_certificate(p) for p in unique_paths]
        # Filter out any None values from failed loads
        certs = [c for c in certs if c]

        return [TrustStoreGroup(name=self.folder_path.name, targets=certs)]
