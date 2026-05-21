"""
TrustStore Analyzer & Visualizer - PROVIDER BASE
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later

Defines the abstract interface for input providers. Providers are responsible
for discovering and grouping certificate locations or raw data before they
are lazily loaded by the orchestrator.
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Any, Union, Dict
from pathlib import Path
from check_truststore.engine import CertificateRepository


class TrustStoreGroup:
    """
    Data container representing a named collection of certificates to be analyzed.
    Each group results in a separate trust tree in the output.
    """

    def __init__(self, name: str, targets: List[Union[Path, Dict[str, Any]]], target_hostname: Optional[str] = None, ignore_ct: bool = False):
        """
        Initializes a group.

        Args:
            name: Display name of the group.
            targets: List of file paths or pre-parsed certificate metadata dictionaries.
        """
        self.name = name
        self.targets = targets
        self.target_hostname = target_hostname
        self.ignore_ct = ignore_ct


class BaseInputProvider(ABC):
    """
    Abstract Base Class for all input sources (e.g., CLI, Directory, Config files).
    Ensures a consistent interface for certificate discovery.
    """

    def __init__(self, repository: Optional[CertificateRepository] = None, **kwargs: Any):
        """
        Initializes the provider.

        Args:
            repository: Shared CertificateRepository instance.
            **kwargs: Flexible configuration options (debug, verbosity, etc.).
        """
        self.repository = repository or CertificateRepository()
        self.options = kwargs
        self.debug: bool = kwargs.get('debug', False)
        self.verbosity: int = kwargs.get('verbosity', 0)

    @abstractmethod
    def get_groups(self) -> List[TrustStoreGroup]:
        """
        Discovers certificates and returns them as TrustStoreGroup objects.

        Subclasses must return groups containing either Path objects (for lazy loading)
        or metadata dictionaries (for raw/mock data).
        """
        pass