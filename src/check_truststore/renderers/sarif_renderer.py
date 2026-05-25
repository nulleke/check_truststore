"""
TrustStore Analyzer & Visualizer - SARIF RENDERER
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later
"""

import json
from typing import Any, Dict, List, Optional, Set

from .base import BaseRenderer
from check_truststore import __version__ as tool_version

class SarifRenderer(BaseRenderer):
    """Renders audit results in the industry-standard SARIF format.

    This renderer maps internal certificate validation findings into the
    SARIF 2.1.0 schema, enabling integration with security dashboarding tools.

    Attributes:
        SARIF_SCHEMA (str): URL to the official SARIF JSON schema.
        SARIF_VERSION (str): The version of the SARIF standard used.
    """

    SARIF_SCHEMA = "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json"
    SARIF_VERSION = "2.1.0"

    def render(self, tree_data: Any, **kwargs) -> str:
        """Converts the certificate tree data into a SARIF log.

        Args:
            tree_data: The result set from the TrustStoreAnalyzer.
            **kwargs: Additional configuration parameters (unused by this renderer).

        Returns:
            A formatted JSON string compliant with the SARIF 2.1.0 specification.
        """
        try:
            groups: List[Any] = tree_data if isinstance(tree_data, list) else [tree_data]
            results: List[Dict[str, Any]] = []
            processed_fingerprints: Set[str] = set()

            for group in groups:
                for cert in self._get_sorted_nodes(getattr(group, "chain", [])):
                    if self._should_skip(cert):
                        continue

                    if getattr(cert, "is_system_cert", False):
                        continue

                    fingerprint: Optional[str] = getattr(cert, "fingerprint", getattr(cert, "serial_number", None))
                    if fingerprint in processed_fingerprints:
                        continue

                    audit: Dict[str, Any] = cert.get_audit_status()

                    if audit["code"] == 0:
                        continue

                    if fingerprint:
                        processed_fingerprints.add(fingerprint)

                    results.append(self._create_result(cert, audit))

            sarif_log = {
                "$schema": self.SARIF_SCHEMA,
                "version": self.SARIF_VERSION,
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "TrustStore Analyzer",
                                "semanticVersion": tool_version,
                                "informationUri": "https://gitlab.com/nulleke/check_truststore",
                                "rules": self._get_rule_definitions()
                            }
                        },
                        "results": results
                    }
                ]
            }

            return json.dumps(sarif_log, indent=2)

        except Exception as e:
            return json.dumps({"error": f"SARIF rendering failed: {str(e)}"}, indent=2)

    def _create_result(self, cert: Any, audit: Dict[str, Any]) -> Dict[str, Any]:
        """Maps a certificate finding to a SARIF result object.

        Args:
            cert: The certificate node containing the finding.
            audit: A dictionary containing the audit code, message, and labels.

        Returns:
            A dictionary structured according to the SARIF 'result' object.
        """
        rule_id: str = f"TSA-{audit['code']:03d}"
        file_path: str = getattr(cert, "file_name", "unknown_location")
        fp: str = getattr(cert, "fingerprint", "")
        common_name: str = getattr(cert, "common_name", "Unknown")

        params: Dict[str, Any] = audit.get("params", {}).copy()
        if "{issuer}" in audit['message'] and "issuer" not in params:
            parent = getattr(cert, "parent", None)
            params["issuer"] = getattr(parent, "common_name", "Unknown Issuer") if parent else "Unknown Issuer"
        try:
            message_text: str = audit['message'].format(**params)
        except (KeyError, ValueError):
            message_text = audit['message']

        return {
            "ruleId": rule_id,
            "level": self._map_level(audit["label"]),
            "message": {
                "text": f"Certificate '{cert.common_name}' failed validation: {message_text}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": file_path,
                            "uriBaseId": "PROJECTROOT"
                        },
                        "region": {
                            "startLine": 1
                        }
                    }
                }
            ],
            "fingerprints": {
                "certificate_fingerprint": fp
            },
            "properties": {
                "commonName": common_name,
                "serialNumber": getattr(cert, "serial_number", ""),
                "expiryDate": self.format_iso(getattr(cert, "expiry_date", ""))
            }
        }

    def _map_level(self, label: str) -> str:
        """Maps internal labels to SARIF severity levels (error, warning, note).

        Args:
            label: The internal audit label string.

        Returns:
            The corresponding SARIF level string.
        """
        mapping: Dict[str, str] = {
            "OK": "note",
            "WARNING": "warning",
            "EXPIRING": "warning",
            "EXPIRED": "error",
            "INCOMPLETE": "error",
            "INVALID": "error",
            "REVOKED": "error",
            "SIG_INVALID": "error",
            "PARENT_NOT_A_CA": "error",
            "NO_TRUST": "error",
        }
        return mapping.get(label, "warning")

    def _get_rule_definitions(self) -> List[Dict[str, Any]]:
        """Returns static definitions for the TSA rule set.

        Returns:
            A list of dictionary definitions for the SARIF 'rule' property.
        """
        return [
            {
                "id": "TSA-001",
                "shortDescription": { "text": "Certificate nearing expiration" },
                "fullDescription": { "text": "The certificate is still valid but will expire soon (warning threshold)." },
                "defaultConfiguration": { "level": "warning" }
            },
            {
                "id": "TSA-002",
                "shortDescription": { "text": "Certificate expired" },
                "fullDescription": { "text": "The certificate (or one of its parents) has expired." },
                "defaultConfiguration": { "level": "error" }
            },
            {
                "id": "TSA-003",
                "shortDescription": { "text": "Incomplete trust chain" },
                "fullDescription": { "text": "The certificate issuer could not be found." },
                "defaultConfiguration": { "level": "error" }
            },
            {
                "id": "TSA-004",
                "shortDescription": { "text": "Invalid certificate" },
                "fullDescription": { "text": "Structural validation or signature check failed." },
                "defaultConfiguration": { "level": "error" }
            },
            {
                "id": "TSA-005",
                "shortDescription": { "text": "Revoked certificate" },
                "fullDescription": { "text": "The certificate has been explicitly revoked." },
                "defaultConfiguration": { "level": "error" }
            }
        ]
