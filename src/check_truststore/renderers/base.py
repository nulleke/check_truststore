"""
TrustStore Analyzer & Visualizer - RENDERER BASE
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later

Defines the abstract foundation for all output formats (JSON, Text, Graphviz).
Includes a specialized JSON encoder for X.509 date handling.
"""

import json
from abc import ABC, abstractmethod
from typing import List, Any, Union, Optional, Set
from datetime import datetime, date, timezone
from pathlib import Path


class DateTimeEncoder(json.JSONEncoder):
    """Custom JSON encoder to handle Python datetime and date objects.

    Ensures all timestamps follow the ISO 8601 format with a 'Z' suffix
    for UTC consistency across all output formats.
    """

    def default(self, obj) -> Any:
        """Serializes datetime objects to ISO strings."""
        if isinstance(obj, (datetime, date)):
            return BaseRenderer.format_iso(obj)
        return super().default(obj)


class BaseRenderer(ABC):
    """Abstract Base Class for all output renderers.

    Enforces a consistent interface for certificate tree visualization and
    provides shared utilities for data sorting and deduplication.

    Attributes:
        output_path (Optional[Path]): Optional destination for rendered files.
        verbosity (int): Level of detail for the rendering process.
        now (datetime): The current UTC timestamp at the start of rendering.
        _rendered_fingerprints (Set[str]): Cache to prevent redundant rendering.
    """

    def __init__(self, output_path: Optional[Path] = None) -> None:
        """
        Initialize the base renderer.

        Args:
            output_path: Optional path where the rendered output should be saved.
        """
        self.output_path: Optional[Path] = output_path
        self.verbosity: int = 0
        self.now: datetime = datetime.now(timezone.utc).replace(microsecond=0)
        self._rendered_fingerprints: Set[str] = set()

    @staticmethod
    def format_iso(dt: Union[datetime, date, str, None]) -> str:
        """Formats date/datetime objects to ISO 8601 with UTC 'Z' suffix.

        Args:
            dt: The datetime or date object to format.

        Returns:
            A string representing the ISO-formatted date.
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
        """Abstract rendering interface to be implemented by subclasses.

        Args:
            tree_data: The processed trust chain data from the analysis engine.
            **kwargs: Renderer-specific configuration parameters.

        Returns:
            The rendered string representation of the data.
        """
        pass

    def _get_sorted_nodes(self, nodes: List[Any]) -> List[Any]:
        """Sorts nodes by expiry date (descending) and display name.

        Sorts nodes primarily by expiry date to highlight imminent risks,
        using display name as a tie-breaker for deterministic output.

        Args:
            nodes: A list of certificate nodes to sort.

        Returns:
            A sorted list of certificate objects.
        """
        epoch_ts: float = 0.0

        return sorted(
            nodes,
            key=lambda x: (
                -getattr(getattr(x, "expiry_date", None), "timestamp", lambda: epoch_ts)(),
                str(getattr(x, "display_name", "")).lower()
            )
        )

    def _should_skip(self, cert_node: Any) -> bool:
        """Determines if a certificate has already been rendered.

        Used for deduplication in cross-signed trust paths to prevent
        infinite recursion or redundant graph nodes.

        Args:
            cert_node: The certificate object to check.

        Returns:
            True if the fingerprint is already in the cache, False otherwise.
        """
        fp: Optional[str] = getattr(cert_node, "fingerprint", getattr(cert_node, "cert_id", None))
        if not fp:
            return False

        if fp in self._rendered_fingerprints:
            return True

        self._rendered_fingerprints.add(fp)
        return False
