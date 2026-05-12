"""
TrustStore Analyzer & Visualizer
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later

The primary package for analyzing and visualizing X.509 certificate trust chains.
This module exposes the public API for orchestrating analysis, extending
input providers, and rendering results.
"""

__author__ = "Serge van Thillo"
__version__ = "1.2.1"

from .engine import (
    TrustStoreAnalyzer,
    CertificateRepository,
    Certificate,
    CertificateGroup,
)

from .providers.base import (
    BaseInputProvider,
    TrustStoreGroup
)

from .providers import (
    YamlInputProvider,
    JsonInputProvider,
    XmlInputProvider,
    DirectoryInputProvider,
    SingleFileInputProvider,
)

from .renderers import TrustStoreRenderer

__all__ = [
    "TrustStoreAnalyzer",
    "CertificateRepository",
    "Certificate",
    "CertificateGroup",
    "BaseInputProvider",
    "TrustStoreGroup",
    "YamlInputProvider",
    "JsonInputProvider",
    "XmlInputProvider",
    "DirectoryInputProvider",
    "SingleFileInputProvider",
    "TrustStoreRenderer",
]
