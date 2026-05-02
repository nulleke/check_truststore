"""
TrustStore Analyzer & Visualizer - DIRECTORY PROVIDER
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later

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
        **kwargs,
    ):
        """
        Initializes the directory scanner.

        Args:
            folder_path: Path to the directory to be scanned.
            repository: Optional shared repository for certificate loading.
            extensions: List of file extensions to include.
                       Defaults to standard PEM, DER, and PKCS#7 formats.
            recursive: If True, performs a deep scan of all subdirectories.
        """
        super().__init__(repository=repository, **kwargs)
        self.folder_path = folder_path
        self.extensions = extensions or [
            ".crt", ".pem", ".cer", ".der", ".p7b", ".p7c",
            ".CRT", ".PEM", ".CER", ".DER", ".P7B", ".P7C",
        ]
        self.recursive = recursive

    def get_groups(self) -> List[TrustStoreGroup]:
        """
        Discovers files in the configured directory and packs them into a TrustStoreGroup.

        Returns:
            A list containing a TrustStoreGroup named after the directory,
            containing all unique discovered certificates.
        """
        if not self.folder_path.is_dir():
            return []

        all_paths = []
        search_pattern = "**/*" if self.recursive else "*"
        for p in self.folder_path.glob(search_pattern):
            if p.is_file() and p.suffix in self.extensions:
                all_paths.append(p)

        # Deduplicate paths and ensure they are files, then sort for consistent output
        unique_paths = sorted(list(set(p for p in all_paths if p.is_file())))

        # Use the repository to load all discovered files at once.
        # This handles PEM bundles within single files and internal deduplication.
        certs = self.repository.load_from_files(unique_paths)

        if certs:
            return [TrustStoreGroup(name=self.folder_path.name, targets=certs)]

        return []