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

from .orchestrator import TrustStoreAnalyzer  # noqa: E402
from .repository import CertificateRepository  # noqa: E402
from .builder import TrustChainBuilder  # noqa: E402
from .logging import OK, INFO, WARNING, MISSING, ERROR, COLLISION, SYSTEM, AIA, REVOKED, _, Icons as Icons  # noqa: E402
from .models import Certificate, CertificateGroup, ORPHAN_NODE_ID, CYCLE_NODE_ID, DEPTH_LIMIT_NODE_ID  # noqa: E402

__all__ = [
    "TrustStoreAnalyzer",
    "CertificateRepository",
    "TrustChainBuilder",
    "Certificate",
    "CertificateGroup",
    "OK",
    "INFO",
    "WARNING",
    "MISSING",
    "ERROR",
    "COLLISION",
    "SYSTEM",
    "AIA",
    "REVOKED",
    "_",
    "ORPHAN_NODE_ID",
    "CYCLE_NODE_ID",
    "DEPTH_LIMIT_NODE_ID",
    "Icons",
]
