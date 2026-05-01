"""
TrustStore Analyzer & Visualizer - RENDERER BASE
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later

Defines the abstract foundation for all output formats (JSON, Text, Graphviz).
Includes a specialized JSON encoder for X.509 date handling.
"""

import json
from abc import ABC, abstractmethod
from typing import List, Any, Union, Optional
from datetime import datetime, date, timezone
from pathlib import Path


class DateTimeEncoder(json.JSONEncoder):
    """
    Custom JSON encoder to handle Python datetime and date objects.
    Ensures all timestamps follow the ISO 8601 format with 'Z' suffix
    for UTC consistency.
    """

    def default(self, obj):
        if isinstance(obj, (datetime, date)):
            return BaseRenderer.format_iso(obj)
        return super().default(obj)


class BaseRenderer(ABC):
    """
    Abstract Base Class for all renderers.
    Enforces a consistent interface for generating output.
    """

    def __init__(self, output_path: Optional[Path] = None):
        """
        Initialize the base renderer.

        Args:
            output_path: Optional path where the rendered output should be saved.
        """
        self.output_path = output_path
        self.verbosity = 0
        self.now = datetime.now(timezone.utc).replace(microsecond=0)

    @staticmethod
    def format_iso(dt: Union[datetime, date, str, None]) -> str:
        """
        Centralized method for consistent date formatting to Zulu (UTC).
        Standardizes output to ISO 8601 without microseconds.
        """
        if dt is None or dt == "1970-01-01":
            return "1970-01-01T00:00:00Z"

        if isinstance(dt, (datetime, date)):
            if isinstance(dt, datetime) and dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)

            return dt.isoformat().replace("+00:00", "Z").split('.')[0].replace("Z", "") + "Z"

        if isinstance(dt, str):
            clean_dt = dt.split('.')[0].rstrip('Z')
            return f"{clean_dt}Z"

        return str(dt)

    @abstractmethod
    def render(self, tree_data: List[Union[Any]], **kwargs) -> str:
        """
        Main rendering method to be implemented by subclasses.

        Args:
            tree_data: The processed trust chain data from the analyzer.
            **kwargs: Format-specific options (e.g., indent level for JSON).

        Returns:
            A string representation of the data in the target format.
        """
        pass
