"""
TrustStore Analyzer & Visualizer - PROVIDER LAYER
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later

This module provides a unified orchestration interface for various input sources.
It registers all concrete input providers and dynamically routes input targets
to their matching parser implementation, including standard input (stdin) streams.
"""

from typing import List, Any, Dict, Optional
from pathlib import Path

from .base import BaseInputProvider as BaseInputProvider
from .base import TrustStoreGroup as TrustStoreGroup
from .yaml_provider import YamlInputProvider
from .json_provider import JsonInputProvider
from .xml_provider import XmlInputProvider
from .file_provider import SingleFileInputProvider
from .directory_provider import DirectoryInputProvider
from .https_provider import HttpsInputProvider


class DummyTruthyList(list):
    def __bool__(self) -> bool:
        return True

class AlreadyProcessedProvider(BaseInputProvider):
    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)

    def get_groups(self) -> List[Any]:
        return DummyTruthyList()

class TrustStoreProvider:
    """
    Factory-style registry for certificate input providers.
    Dynamically routes input targets to their matching parser implementation.
    """

    def __init__(self, **kwargs: Any) -> None:
        """
        Initialize the provider registry and inject configuration context.
        """
        self.options: Dict[str, Any] = kwargs
        self.stdin_content: Optional[str] = kwargs.get("stdin_content")

        self._https_processed: bool = False

    def resolve(self, target: str) -> Optional[BaseInputProvider]:
        """
        Dynamically auto-detects and resolves the appropriate provider for a given target.
        Ensures parallel execution for network operations is preserved.
        """
        if not target:
            return None

        if target == "-":
            if not self.stdin_content:
                return None

            content_peek: str = self.stdin_content.lstrip()

            if content_peek.startswith(("{", "[")):
                return JsonInputProvider(self.stdin_content, is_raw_data=True, **self.options)
            if content_peek.startswith("<?xml") or "<nmaprun" in content_peek:
                return XmlInputProvider(self.stdin_content, is_raw_data=True, **self.options)
            if "BEGIN CERTIFICATE" in content_peek:
                return SingleFileInputProvider(self.stdin_content, is_raw_data=True, **self.options)

            yaml_keywords: List[str] = ["truststores:", "cert_src_dir:", "cert_chain:"]
            if any(key in content_peek for key in yaml_keywords):
                return YamlInputProvider(self.stdin_content, is_raw_data=True, **self.options)

            return None

        if target.startswith(("https://", "http://")):
            if self._https_processed:
                return AlreadyProcessedProvider(**self.options)

            self._https_processed = True

            cli_inputs: List[str] = self.options.get("inputs", [])
            https_urls: List[str] = [i for i in cli_inputs if i.startswith(("https://", "http://"))]

            return HttpsInputProvider(urls=https_urls, **self.options)

        path_ref = Path(target)

        if path_ref.is_dir():
            return DirectoryInputProvider(path_ref, recursive=True, **self.options)

        if path_ref.is_file():
            suffix = path_ref.suffix.lower()
            if suffix in [".yaml", ".yml"]:
                return YamlInputProvider(path_ref, **self.options)
            if suffix == ".json":
                return JsonInputProvider(path_ref, **self.options)
            if suffix == ".xml":
                return XmlInputProvider(path_ref, **self.options)

            return SingleFileInputProvider(path_ref, **self.options)

        return None


__all__ = [
    "BaseInputProvider",
    "TrustStoreGroup",
    "TrustStoreProvider",
    "YamlInputProvider",
    "JsonInputProvider",
    "XmlInputProvider",
    "SingleFileInputProvider",
    "DirectoryInputProvider",
    "HttpsInputProvider",
]