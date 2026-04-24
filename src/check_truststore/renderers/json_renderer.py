"""
TrustStore Analyzer & Visualizer - JSON RENDERER
Architect: Serge van Thillo

Transforms the internal certificate tree structure into a standardized
JSON format. This renderer is optimized for automation, monitoring integrations,
and long-term data storage.
"""

import json
from datetime import datetime, date
from typing import Any
from .base import BaseRenderer, DateTimeEncoder


class JsonRenderer(BaseRenderer):
    """
    Renders certificate tree data into a structured JSON string.
    Supports recursive serialization of nested certificate objects.
    """

    def render(self, tree_data: Any, **kwargs) -> str:
        """
        Serializes the tree data to a JSON string.

        Args:
            tree_data: The result from the TrustStoreAnalyzer.
            **kwargs: Arguments passed to json.dumps (e.g., indent).

        Returns:
            A pretty-printed JSON string.
        """
        try:
            # First, convert complex objects to basic Python primitives
            clean_data = self._to_basic_dict(tree_data)
            return json.dumps(
                clean_data, indent=2, ensure_ascii=False, cls=DateTimeEncoder
            )
        except Exception as e:
            # Robust fallback to ensure the tool always outputs valid JSON
            return json.dumps(
                {"error": "Serialization failed", "details": str(e)}, indent=2
            )

    def _to_basic_dict(self, data: Any) -> Any:
        """
        Recursively converts custom objects (Certificate, Group) into
        JSON-serializable dictionaries.
        """
        # Handle lists (like a list of groups)
        if isinstance(data, list):
            return [self._to_basic_dict(item) for item in data]

        # Handle CertificateGroup objects
        if hasattr(data, "groupName") or hasattr(data, "group_name"):
            return {
                "groupName": getattr(
                    data, "groupName", getattr(data, "group_name", "Unknown")
                ),
                "tree": self._to_basic_dict(getattr(data, "tree", [])),
            }

        # Handle Individual Certificate nodes
        if hasattr(data, "common_name"):
            # Convert dates to ISO format immediately if needed
            expiry = getattr(data, "expiry_date", None)
            if isinstance(expiry, (datetime, date)):
                expiry = expiry.isoformat().replace("+00:00", "Z")

            res = {
                "commonName": getattr(data, "common_name", "Unknown"),
                "isValid": getattr(data, "is_valid", False),
                "isExpiringSoon": getattr(data, "is_expiring_soon", False),
                "expiryDate": expiry or "1970-01-01T00:00:00Z",
            }

            # Recurse into children for the tree structure
            children = getattr(data, "children", [])
            if children:
                res["children"] = self._to_basic_dict(children)

            return res

        # Fallback for standard types or dates
        if isinstance(data, (datetime, date)):
            return data.isoformat().replace("+00:00", "Z")

        return data
