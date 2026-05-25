"""
TrustStore Analyzer & Visualizer - JSON RENDERER
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later

Transforms the internal certificate tree structure into a standardized
JSON format. This renderer is optimized for automation, monitoring integrations,
and long-term data storage.
"""

import json
from typing import Any
from .base import BaseRenderer, DateTimeEncoder


class JsonRenderer(BaseRenderer):
    """Renders certificate tree data into a structured JSON string.

    This renderer supports recursive serialization of complex certificate
    objects into basic Python primitives, ensuring valid and readable
    JSON output for downstream processing.

    Attributes:
        verbosity (int): Inherited from BaseRenderer to control audit detail.
    """

    def render(self, tree_data: Any, **kwargs) -> str:
        """Serializes the tree data to a JSON string.

        Args:
            tree_data: The result set from the TrustStoreAnalyzer.
            **kwargs: Optional configuration arguments, including:
                indent (int): Indentation level for pretty-printing (default: 2).
                verbosity (int): Level of diagnostic detail to include in the output.

        Returns:
            A pretty-printed JSON string.

        Raises:
            TypeError: If the serialization process encounters non-encodable objects.
        """
        indent: int = kwargs.get("indent", 2)
        self.verbosity = kwargs.get("verbosity", 0)
        try:
            # First, convert complex objects to basic Python primitives
            clean_data = self._to_basic_dict(tree_data)
            return json.dumps(
                clean_data, indent=indent, ensure_ascii=False, cls=DateTimeEncoder
            )
        except Exception as e:
            # Robust fallback to ensure the tool always outputs valid JSON
            return json.dumps(
                {"error": "Serialization failed", "details": str(e)}, indent=indent
            )

    def _to_basic_dict(self, data: Any) -> Any:
        """Recursively converts custom objects (Certificate, Group) into serializable dicts.

        Args:
            data: The object, list of objects, or group to transform.

        Returns:
            A dictionary or list structure composed of basic Python types.
        """
        # Handle lists (like a list of groups)
        if isinstance(data, list):
            result = []
            for item in self._get_sorted_nodes(data):
                if not self._should_skip(item):
                    result.append(self._to_basic_dict(item))
            return result

        # Handle CertificateGroup objects
        if hasattr(data, "groupName") or hasattr(data, "group_name"):
            if hasattr(self, "_rendered_fingerprints"):
                self._rendered_fingerprints.clear()

            return {
                "groupName": getattr(
                    data, "groupName", getattr(data, "group_name", "Unknown")
                ),
                "groupStatus": getattr(data, "group_status", "OK"),
                "tree": self._to_basic_dict(getattr(data, "tree", [])),
            }

        # Handle Individual Certificate nodes
        if hasattr(data, "common_name"):
            res = {
                "commonName": getattr(data, "common_name", "Unknown"),
                "isValid": getattr(data, "is_valid", False),
                "isExpiringSoon": getattr(data, "is_expiring_soon", False),
                "expiryDate": self.format_iso(getattr(data, "expiry_date", None)),
            }

            if self.verbosity >= 1:
                res["auditStatus"] = data.get_audit_status()

            if self.verbosity >= 2:
                if hasattr(data, "findings") and data.findings:
                    res["findings"] = [
                        f.model_dump() if hasattr(f, "model_dump") else str(f)
                        for f in data.findings
                    ]

            # Recurse into children for the tree structure
            children = getattr(data, "children", [])
            if children:
                res["children"] = self._to_basic_dict(children)

            return res

        return data
