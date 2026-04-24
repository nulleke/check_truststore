"""
TrustStore Analyzer & Visualizer - RENDERER BASE
Architect: Serge van Thillo

Defines the abstract foundation for all output formats (JSON, Text, Graphviz).
Includes a specialized JSON encoder for X.509 date handling.
"""

import json
from abc import ABC, abstractmethod
from typing import List, Any, Union
from datetime import datetime, date
from check_truststore.engine.core import Certificate


class DateTimeEncoder(json.JSONEncoder):
    """
    Custom JSON encoder to handle Python datetime and date objects.
    Ensures all timestamps follow the ISO 8601 format with 'Z' suffix
    for UTC consistency.
    """

    def default(self, obj):
        if isinstance(obj, (datetime, date)):
            # Replace +00:00 with Z for cleaner, standard-compliant UTC strings
            return obj.isoformat().replace("+00:00", "Z")
        return super().default(obj)


class BaseRenderer(ABC):
    """
    Abstract Base Class for all renderers.
    Enforces a consistent interface for generating output from the analysis tree.
    """

    @abstractmethod
    def render(self, tree_data: List[Union[Certificate, Any]], **kwargs) -> str:
        """
        Main rendering method to be implemented by subclasses.

        Args:
            tree_data: The processed trust chain data from the analyzer.
            **kwargs: Format-specific options (e.g., indent level for JSON).

        Returns:
            A string representation of the data in the target format.
        """
        pass


#    def render(self, tree_data: List[Union[Certificate, Any]], format_type: str, **kwargs) -> str:
#        renderer = self._renderers.get(format_type)
#        if not renderer:
#            raise ValueError(_("Unknown format: {}").format(format_type))
#
#        return renderer.render(tree_data, **kwargs)
