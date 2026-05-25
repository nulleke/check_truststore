"""
TrustStore Analyzer & Visualizer - DIRECTORY PROVIDER
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later

Implementation of the input provider that scans filesystem directories.
It automatically segments certificates into distinct TrustStoreGroups based
on their parent directories, maintaining logical isolation during analysis.
"""

from pathlib import Path
from typing import List, Optional, Any, Dict, Union
from collections import defaultdict
from check_truststore.providers.base import BaseInputProvider, TrustStoreGroup
from check_truststore.engine import CertificateRepository

class DirectoryInputProvider(BaseInputProvider):
    """Scans directories for X.509 certificates and groups them by folder.

    This provider searches specific filesystem paths for public key infrastructure
    artifacts and structures them into separate execution scopes depending on their
    hierarchical positioning on disk.

    Attributes:
        folder_path (Path): The root workspace entry point pointing to the scanned directory.
        extensions (List[str]): Extracted lowercase and uppercase suffix filter masks.
        recursive (bool): Flag toggling global multi-tier folder exploration depth.
        repository (CertificateRepository): Inherited central asset identification mapping store.
        options (Dict[str, Any]): Dictionary containing configuration arguments.
        debug (bool): If True, enables diagnostic traces and deep error reporting.
        verbosity (int): Numeric modifier adjusting logging output volume.
    """

    def __init__(
        self,
        folder_path: Union[str, Path],
        repository: Optional[CertificateRepository] = None,
        extensions: Optional[List[str]] = None,
        recursive: bool = False,
        **kwargs: Any,
    ) -> None:
        """Initializes the directory scanner with path filtering criteria.

        Args:
            folder_path (Union[str, Path]): Path to the root directory to be scanned.
            repository (Optional[CertificateRepository], optional): Shared index
                repository for certificate discovery. Defaults to None.
            extensions (Optional[List[str]], optional): List of file extensions
                to include (e.g., ['.pem', '.crt']). Defaults to standard structural masks.
            recursive (bool, optional): If True, scans nested subdirectories and splits
                them into individual isolated execution groups. Defaults to False.
            **kwargs: Flexible configuration choices passed down to BaseInputProvider.
        """
        super().__init__(repository=repository, **kwargs)
        self.folder_path = Path(folder_path)
        self.extensions: List[str] = extensions or [
            ".crt", ".pem", ".cer", ".der", ".p7b", ".p7c",
            ".CRT", ".PEM", ".CER", ".DER", ".P7B", ".P7C",
        ]
        self.recursive: bool = recursive

    def get_groups(self) -> List[TrustStoreGroup]:
        """Scans the filesystem and organizes discovered certificates into groups.

        Each unique directory encountered that contains files matching the
        configured certificate signature extensions will yield an isolated,
        sorted TrustStoreGroup component.

        Returns:
            List[TrustStoreGroup]: A list of container elements tracking sorted
                target file paths grouped per structural directory.
        """
        if not self.folder_path.is_dir():
            return []

        grouped_files: Dict[Path, List[Path]] = defaultdict(list)
        search_pattern: str = "**/*" if self.recursive else "*"

        for p in self.folder_path.glob(search_pattern):
            if p.is_file() and p.suffix in self.extensions:
                grouped_files[p.parent].append(p)

        groups: List[TrustStoreGroup] = []

        for parent_dir in sorted(grouped_files.keys()):
            files: List[Path] = sorted(grouped_files[parent_dir])
            if parent_dir == self.folder_path:
                group_name: str = parent_dir.name
            else:
                try:
                    group_name = str(parent_dir.relative_to(self.folder_path.parent))
                except ValueError:
                    group_name = parent_dir.name

            groups.append(TrustStoreGroup(name=group_name, targets=files))

        return groups