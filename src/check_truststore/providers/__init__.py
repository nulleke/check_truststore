"""
TrustStore Analyzer & Visualizer - PROVIDER INTERFACE
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later

This module manages the ingestion layer of the application. It provides
a variety of input providers to load certificates from different sources
(YAML, JSON, XML, Directories, etc.) into a unified format for analysis.
"""


from .base import BaseInputProvider, TrustStoreGroup
from .yaml_provider import YamlInputProvider
from .json_provider import JsonInputProvider
from .xml_provider import XmlInputProvider
from .file_provider import SingleFileInputProvider
from .directory_provider import DirectoryInputProvider

__all__ = [
    "BaseInputProvider",
    "TrustStoreGroup",
    "YamlInputProvider",
    "JsonInputProvider",
    "XmlInputProvider",
    "SingleFileInputProvider",
    "DirectoryInputProvider",
]
