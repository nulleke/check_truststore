"""
TrustStore Analyzer & Visualizer
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later

The primary package for analyzing and visualizing X.509 certificate trust chains.
This module exposes the public API for orchestrating analysis, extending
input providers, and rendering results.
"""

__author__ = "Serge van Thillo"
__version__ = "1.2.6"

from .engine import (
    Certificate,
    CertificateGroup,
    CertificateRepository,
    TrustStoreAnalyzer,
)
from .providers import TrustStoreProvider
from .providers.base import BaseInputProvider, TrustStoreGroup
from .renderers import TrustStoreRenderer

__all__ = [
    "BaseInputProvider",
    "Certificate",
    "CertificateGroup",
    "CertificateRepository",
    "TrustStoreAnalyzer",
    "TrustStoreGroup",
    "TrustStoreProvider",
    "TrustStoreRenderer",
]
