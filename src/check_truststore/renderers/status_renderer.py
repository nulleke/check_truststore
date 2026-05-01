"""
TrustStore Analyzer & Visualizer - STATUS RENDERER
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Union

from check_truststore.engine.core import ORPHAN_NODE_ID
from .base import BaseRenderer, DateTimeEncoder
from check_truststore import __version__ as tool_version


class StatusRenderer(BaseRenderer):
    """
    Renders an audit-focused report including exit codes and status summaries.
    Optimized for machine-readability and CI/CD pipeline integration.
    """

    API_VERSION = "1.1.2"

    EXIT_CODES: Dict[str, int] = {
        "OK": 0,
        "WARNING": 1,
        "EXPIRED": 2,
        "INCOMPLETE": 3,
        "INVALID": 4,
        "REVOKED": 5,
        "INPUT_ERR": 6,
        "FATAL": 7,
    }

    def render(self, tree_data: Union[Any, List[Any]], **kwargs) -> str:
        """
        Processes tree data into a flat, audit-ready JSON structure.
        """
        self.verbosity = kwargs.get("verbosity", 0)

        try:
            report_groups: List[Dict[str, Any]] = []
            system_certs_global: Dict[str, Dict[str, Any]] = {}
            global_max_code: int = 0
            scan_now = datetime.now(timezone.utc)

            groups = tree_data if isinstance(tree_data, list) else [tree_data]

            for group in groups:
                g_name = getattr(group, "group_name", "unknown")
                all_nodes = getattr(group, "chain", [])

                certificates_report: List[Dict[str, Any]] = []
                group_max_code: int = 0
                has_incomplete_chain: bool = False

                for cert in all_nodes:
                    c_name = getattr(cert, "common_name", "")
                    audit = cert.get_audit_status()

                    if audit["code"] == 3:
                        has_incomplete_chain = True

                    if c_name == ORPHAN_NODE_ID:
                        continue

                    cert_entry = {
                        "commonName": c_name or "Unknown",
                        "serialNumber": getattr(cert, "serial_number", "UNKNOWN"),
                        "signatureValid": getattr(cert, "signature_valid", None),
                        "expiryDate": self.format_iso(getattr(cert, "expiry_date", None)),
                        "trustStatus": audit["label"],
                        "statusCode": audit["code"],
                    }

                    if audit["code"] > 0 and self.verbosity >= 1:
                        cert_entry["findings"] = [{
                            "code": f"TSA-{audit['code']:03d}",
                            "level": audit["level"].upper(),
                            "message": audit["message"]
                        }]

                        # Add raw findings for deep-dive debugging at higher verbosity
                        raw_findings = getattr(cert, "findings", [])
                        if self.verbosity >= 2 and raw_findings:
                            for f in raw_findings:
                                cert_entry["findings"].append({
                                    "code": getattr(f, "code", "UNKNOWN"),
                                    "level": getattr(f, "level", "INFO"),
                                    "message": getattr(f, "message", "")
                                })

                    f_name = getattr(cert, "file_name", "")
                    if not getattr(cert, "is_system_cert", False) and f_name:
                        cert_entry["fileName"] = f_name

                    if getattr(cert, "is_system_cert", False):
                        c_hash = getattr(cert, "sha256_hash", cert_entry["commonName"])
                        if c_hash not in system_certs_global:
                            system_certs_global[c_hash] = cert_entry
                    else:
                        if audit["code"] > group_max_code:
                            group_max_code = audit["code"]
                        if audit["code"] > global_max_code:
                            global_max_code = audit["code"]
                        certificates_report.append(cert_entry)

                report_groups.append({
                    "groupName": g_name,
                    "groupStatus": self._get_label_by_code(group_max_code),
                    "summary": {
                        "totalCertificates": len(certificates_report),
                        "isChainComplete": not has_incomplete_chain,
                        "isTrusted": group_max_code <= self.EXIT_CODES["WARNING"] and not has_incomplete_chain,
                    },
                    "certificates": certificates_report,
                })

            return json.dumps(
                {
                    "metadata": {
                        "version": self.API_VERSION,
                        "engine": tool_version,
                        "scanDate": self.format_iso(scan_now),
                        "exitCode": global_max_code,
                    },
                    "groups": report_groups,
                    "systemCertificates": list(system_certs_global.values()),
                },
                indent=2,
                cls=DateTimeEncoder,
            )

        except Exception as e:
            return json.dumps({"metadata": {"exitCode": 7}, "error": str(e)}, indent=2)

    def _get_label_by_code(self, code: int) -> str:
        """
        Reverse lookup to find the status label associated with a specific code.
        """
        for label, c in self.EXIT_CODES.items():
            if c == code:
                return label
        return "OK"
