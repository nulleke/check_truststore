"""
TrustStore Analyzer & Visualizer - DIRECTORY PROVIDER
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later

Implementation of the input provider that scans filesystem directories.
It automatically segments certificates into distinct TrustStoreGroups based
on their parent directories, maintaining logical isolation during analysis.
"""

from pathlib import Path
from typing import List, Optional, Any, Dict
from collections import defaultdict
from check_truststore.providers.base import BaseInputProvider, TrustStoreGroup
from check_truststore.engine import CertificateRepository

class DirectoryInputProvider(BaseInputProvider):
    """
    Scans directories for X.509 certificates and groups them by folder.
    """

    def __init__(
        self,
        folder_path: Path,
        repository: Optional[CertificateRepository] = None,
        extensions: Optional[List[str]] = None,
        recursive: bool = False,
        **kwargs: Any,
    ):
        """
        Initializes the directory scanner.

        Args:
            folder_path: Path to the root directory to be scanned.
            repository: Optional shared repository for certificate discovery.
            extensions: List of file extensions to include (e.g., .pem, .crt).
            recursive: If True, scans subdirectories and creates separate groups for them.
        """
        super().__init__(repository=repository, **kwargs)
        self.folder_path = Path(folder_path)
        self.extensions: List[str] = extensions or [
            ".crt", ".pem", ".cer", ".der", ".p7b", ".p7c",
            ".CRT", ".PEM", ".CER", ".DER", ".P7B", ".P7C",
        ]
        self.recursive: bool = recursive

    def get_groups(self) -> List[TrustStoreGroup]:
        """
        Scans the filesystem and organizes discovered certificates into groups.
        Each unique directory containing valid certificates results in a separate group.

        Returns:
            A list of TrustStoreGroup objects, each representing a directory
            and its contained certificate paths.
        """
        if not self.folder_path.is_dir():
            return []

        grouped_files: Dict[Path, List[Path]] = defaultdict(list)
        search_pattern = "**/*" if self.recursive else "*"

        for p in self.folder_path.glob(search_pattern):
            if p.is_file() and p.suffix in self.extensions:
                grouped_files[p.parent].append(p)

        groups: List[TrustStoreGroup] = []

        for parent_dir in sorted(grouped_files.keys()):
            files = sorted(grouped_files[parent_dir])
            if parent_dir == self.folder_path:
                group_name = parent_dir.name
            else:
                try:
                    group_name = str(parent_dir.relative_to(self.folder_path.parent))
                except ValueError:
                    group_name = parent_dir.name

            groups.append(TrustStoreGroup(name=group_name, targets=files))

        return groups