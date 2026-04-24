"""
TrustStore Analyzer & Visualizer - PROVIDER BASE
Architect: Serge van Thillo

Defines the abstract interface for input providers. Providers are responsible
for discovering, grouping, and loading certificates before they are passed
to the TrustChainBuilder.
"""

from abc import ABC, abstractmethod
from typing import List, Optional
from pathlib import Path

from check_truststore.engine.core import Certificate, CertificateRepository


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

    def __init__(self, repository: Optional[CertificateRepository] = None):
        """
        Initializes the provider with a dedicated repository for deduplication
        and raw X.509 loading.
        """
        self.repository = repository or CertificateRepository()

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
            certs = self.repository._load_single_file(path)

            if certs and isinstance(certs, list) and len(certs) > 0:
                return certs[0]

            return None
        except Exception:
            return None
