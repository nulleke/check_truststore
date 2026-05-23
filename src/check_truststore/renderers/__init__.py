"""
TrustStore Analyzer & Visualizer - RENDERER LAYER
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later

This module provides a unified interface for various output formats.
It maps format identifiers to their respective renderer implementations.
"""


from typing import List, Any
from .base import BaseRenderer as BaseRenderer
from .text_renderer import TextRenderer
from .json_renderer import JsonRenderer
from .status_renderer import StatusRenderer
from .sarif_renderer import SarifRenderer
from .graphviz_renderer import GraphvizRenderer
from .prometheus_renderer import PrometheusRenderer


class TrustStoreRenderer:
    """
    Factory-style orchestrator for certificate tree rendering.
    """
    def __init__(self) -> None:
        """
        Initialize the registry of available renderers.
        """
        self._renderers = {
            "text": TextRenderer(),
            "json": JsonRenderer(),
            "status": StatusRenderer(),
            "sarif": SarifRenderer(),
            "graphviz": GraphvizRenderer(),
            "dot": GraphvizRenderer(),
            "prom": PrometheusRenderer(),
        }

    def render(self, tree_data: List[Any], format_type: str, **kwargs: Any) -> Any:
        """
        Render the provided tree data into the specified format.

        Args:
            tree_data: The list of analyzed certificate objects or tree structure.
            format_type: String identifier of the desired output format.
            **kwargs: Additional configuration for specific renderers.

        Returns:
            The rendered output (string, dict, or file path depending on the renderer).

        Raises:
            ValueError: If the requested format_type is not registered.
        """
        renderer: BaseRenderer = self._renderers.get(format_type)
        if not renderer:
            from check_truststore.engine import _

            raise ValueError(_("Unknown format: {}").format(format_type))

        return renderer.render(tree_data, **kwargs)
