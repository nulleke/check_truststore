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
    """Data container representing a named collection of certificates to be analyzed.

    Each group resulting from a provider is isolated and will be evaluated into
    a separate, independent trust tree within the orchestrator pipeline.

    Attributes:
        name (str): Display name or identifier of the specific trust store group.
        targets (List[Union[Path, Dict[str, Any]]]): A list containing either file
            system paths pointing to certificate files or raw metadata dictionaries.
        target_hostname (Optional[str]): Target domain or hostname associated
            with this group for TLS or SNI verification contexts.
        disabled_checks (Union[bool, List[str]]): Specific policy validation rule
            codes to skip, or a boolean to bypass all/none.
    """

    def __init__(self, name: str, targets: List[Union[Path, Dict[str, Any]]], target_hostname: Optional[str] = None, disabled_checks: Union[bool, List[str]] = False) -> None:
        """Initializes a certificate store data tracking group.

        Args:
            name (str): Display name or identifier of the group.
            targets (List[Union[Path, Dict[str, Any]]]): List of filesystem paths
                or pre-parsed certificate metadata dictionaries.
            target_hostname (Optional[str], optional): Associated host domain
                for endpoint validation. Defaults to None.
            disabled_checks (Union[bool, List[str]], optional): Policy engine flags
                indicating validations that should be omitted. Defaults to False.
        """
        self.name: str = name
        self.targets: List[Union[Path, Dict[str, Any]]] = targets
        self.target_hostname: Optional[str] = target_hostname
        self.disabled_checks: Union[bool, List[str]] = disabled_checks


class BaseInputProvider(ABC):
    """Abstract Base Class serving as the contract for all data input sources.

    Subclasses (e.g., CLI, Directory, Config files, or System Trust Stores)
    must implement the discovery logic to extract, normalize, and pack paths
    or raw data blocks into generic validation containers.

    Attributes:
        repository (CertificateRepository): Central registration database used
            for tracking and deduplicating certificates.
        options (Dict[str, Any]): Dictionary containing raw configurations.
        debug (bool): If True, enables diagnostic traces and deep error reporting.
        verbosity (int): Numeric modifier adjusting logging output volume.
    """

    def __init__(self, repository: Optional[CertificateRepository] = None, **kwargs: Any):
        """Initializes the provider base interface with shared states and hooks.

        Args:
            repository (Optional[CertificateRepository], optional): Shared indexing
                repository. If omitted, a clean repository instance is instantiated.
            **kwargs: Flexible configuration choices. Accepted parameters:
                debug (bool): Active developer diagnostic output flags.
                verbosity (int): Log granularity modifier thresholds.
        """
        self.repository: CertificateRepository = repository or CertificateRepository()
        self.options: Dict[str, Any] = kwargs
        self.debug: bool = kwargs.get('debug', False)
        self.verbosity: int = kwargs.get('verbosity', 0)

    @abstractmethod
    def get_groups(self) -> List[TrustStoreGroup]:
        """Discovers certificates and organizes them into iterable group structures.

        This method must be overridden by specific input providers to aggregate
        raw data blocks or lazy-loaded filesystem components.

        Returns:
            List[TrustStoreGroup]: A list of filled trust store groups
                ready to be processed by the analysis orchestration layer.
        """
        pass