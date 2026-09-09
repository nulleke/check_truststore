"""
TrustStore Analyzer & Visualizer - ENGINE INTERFACE
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later

This module serves as the primary entry point for the TrustStore engine,
exporting core classes and status indicators while managing global
warning filters for certificate parsing.
"""

import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", message=".*serial number.*")
warnings.filterwarnings("ignore", message=".*Python 3.6 is no longer supported.*")
warnings.filterwarnings("ignore", message=".*PKCS#7 certificates could not be parsed as DER.*")

from .builder import TrustChainBuilder
from .logging import (
    AIA,
    COLLISION,
    ERROR,
    INFO,
    MISSING,
    OK,
    REVOKED,
    SYSTEM,
    WARNING,
    _,
)
from .logging import Icons as Icons
from .models import (
    CYCLE_NODE_ID,
    DEPTH_LIMIT_NODE_ID,
    ORPHAN_NODE_ID,
    Certificate,
    CertificateGroup,
)
from .orchestrator import TrustStoreAnalyzer
from .repository import CertificateRepository

__all__ = [
    "AIA",
    "COLLISION",
    "CYCLE_NODE_ID",
    "DEPTH_LIMIT_NODE_ID",
    "ERROR",
    "INFO",
    "MISSING",
    "OK",
    "ORPHAN_NODE_ID",
    "REVOKED",
    "SYSTEM",
    "WARNING",
    "Certificate",
    "CertificateGroup",
    "CertificateRepository",
    "Icons",
    "TrustChainBuilder",
    "TrustStoreAnalyzer",
    "_",
]
