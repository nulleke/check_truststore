"""
TrustStore Analyzer & Visualizer - PROVIDER BASE
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later

Defines the abstract interface for input providers. Providers are responsible
for discovering, grouping, and loading certificates before they are passed
to the TrustChainBuilder.
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Any
from pathlib import Path

from check_truststore.engine import Certificate, CertificateRepository


class TrustStoreGroup:
    """
    Data container representing a named collection of certificates to be analyzed.
    Each group will result in a separate trust tree in the output.
    """

    def __init__(self, name: str, targets: List[Certificate]):
        self.name = name
        self.targets = targets


class BaseInputProvider(ABC):
    """
    Abstract Base Class for all input sources (e.g., CLI, Directory, Config files).
    Ensures a consistent interface for feeding the CertificateRepository.
    """

    def __init__(self, repository: Optional[CertificateRepository] = None, **kwargs: Any):
        """
        Initializes the provider with a dedicated repository for deduplication
        and raw X.509 loading.
        """
        self.repository = repository or CertificateRepository()
        self.options = kwargs
        self.debug = kwargs.get('debug', False)
        self.verbosity = kwargs.get('verbosity', 0)

    @abstractmethod
    def get_groups(self) -> List[TrustStoreGroup]:
        """
        Must be implemented by subclasses to return a list of TrustStoreGroup objects
        ready for analysis.
        """
        pass

    def load_certificate(self, path: Path) -> Optional[Certificate]:
        """
        Helper method to load a single certificate file using the repository's
        internal logic. Returns the raw metadata dictionary or None if failed.
        """
        try:
            certs = self.repository.load_from_files([path])

            if certs and len(certs) > 0:
                return certs[0]

            return None
        except Exception:
            return None
