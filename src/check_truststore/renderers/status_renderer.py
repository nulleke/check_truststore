"""
TrustStore Analyzer & Visualizer - STATUS RENDERER
Architect: Serge van Thillo

Generates a flat, high-level audit report in JSON format.
This renderer calculates exit codes, detects chain gaps (orphans),
and separates system certificates from local ones for clarity.
"""

import json
from datetime import datetime, date, timezone
from typing import Any, Dict

from check_truststore.engine.core import ORPHAN_NODE_ID
from .base import BaseRenderer, DateTimeEncoder


class StatusRenderer(BaseRenderer):
    """
    Renders an audit-focused report including exit codes and status summaries.
    Essential for CI/CD pipelines to determine success/failure of a trust check.
    """

    VERSION = "1.1.1"
    EXIT_CODES = {
        "OK": 0,
        "WARNING": 1,
        "EXPIRED": 2,
        "INCOMPLETE": 3,
        "INVALID": 4,
        "REVOKED": 5,
        "INPUT_ERR": 6,
        "FATAL": 7,
    }

    def render(self, tree_data: Any, **kwargs) -> str:
        """
        Processes tree data into a flat status report with metadata.
        """
        try:
            report_groups = []
            system_certs_global = {}
            global_max_code = 0
            scan_now = datetime.now(timezone.utc)

            # Ensure we are working with a list of CertificateGroups
            groups = tree_data if isinstance(tree_data, list) else [tree_data]

            for group in groups:
                g_name = getattr(group, "group_name", "unknown")
                all_nodes = getattr(group, "chain", [])

                certificates_report = []
                group_max_code = 0
                has_orphans = False

                for cert in all_nodes:
                    c_name = getattr(cert, "common_name", "")

                    if c_name == ORPHAN_NODE_ID:
                        has_orphans = True
                        continue

                    v_err = getattr(cert, "validation_error", "") or ""
                    if "MISSING_ISSUER" in v_err or "ORPHAN" in v_err:
                        has_orphans = True

                    # Determine severity and label
                    status_info = self._get_status_info(cert)

                    cert_entry = {
                        "commonName": c_name or "Unknown",
                        "serialNumber": getattr(cert, "serial_number", "UNKNOWN"),
                        "signatureValid": getattr(cert, "signature_valid", None),
                        "expiryDate": self._format_zulu(
                            getattr(cert, "expiry_date", None)
                        ),
                        "trustStatus": status_info["label"],
                        "statusCode": status_info["code"],
                    }

                    # Add file context for non-system certificates
                    f_name = getattr(cert, "file_name", "")
                    if not getattr(cert, "is_system_cert", False) and f_name:
                        cert_entry["fileName"] = f_name

                    # Deduplicate system certificates globally, add others to group report
                    if getattr(cert, "is_system_cert", False):
                        c_hash = getattr(cert, "sha256_hash", cert_entry["commonName"])
                        if c_hash not in system_certs_global:
                            system_certs_global[c_hash] = cert_entry
                    else:
                        # Update status codes based on local cert severity
                        if status_info["code"] > group_max_code:
                            group_max_code = status_info["code"]
                        if status_info["code"] > global_max_code:
                            global_max_code = status_info["code"]
                        certificates_report.append(cert_entry)

                # If chain is incomplete, escalate group status to at least INCOMPLETE (3)
                if has_orphans and group_max_code < 3:
                    group_max_code = 3

                report_groups.append(
                    {
                        "groupName": g_name,
                        "groupStatus": self._get_label_by_code(group_max_code),
                        "summary": {
                            "totalCertificates": len(certificates_report),
                            "isChainComplete": not has_orphans,
                            "isTrusted": group_max_code <= self.EXIT_CODES["WARNING"]
                            and not has_orphans,
                        },
                        "certificates": certificates_report,
                    }
                )

            return json.dumps(
                {
                    "metadata": {
                        "version": self.VERSION,
                        "scanDate": self._format_zulu(scan_now),
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

    def _get_status_info(self, cert: Any) -> Dict:
        """
        Internal logic to determine the status code and label for a certificate.
        """
        is_valid = getattr(cert, "is_valid", False)
        is_expiring = getattr(cert, "is_expiring_soon", False)
        sig_valid = getattr(cert, "signature_valid", True)
        expiry = getattr(cert, "expiry_date", None)
        v_error = getattr(cert, "validation_error", "") or ""
        is_orphan = getattr(cert, "is_orphan", False)

        now = datetime.now(timezone.utc)

        if sig_valid is False:
            return {"code": 4, "label": "SIG_ERR"}

        if v_error:
            # Custom validation error labels (e.g. from the engine)
            return {"code": 4, "label": v_error}

        if expiry and isinstance(expiry, datetime) and expiry < now:
            return {"code": 2, "label": "EXPIRED"}

        if is_orphan or "MISSING_ISSUER" in v_error:
            return {"code": 3, "label": "INCOMPLETE"}

        if not is_valid:
            return {"code": 4, "label": "INVALID"}

        if is_expiring:
            return {"code": 1, "label": "WARNING"}

        return {"code": 0, "label": "OK"}

    def _format_zulu(self, d):
        if isinstance(d, (datetime, date)):
            return d.isoformat().replace("+00:00", "Z")
        return str(d) if d else "1970-01-01T00:00:00Z"

    def _get_label_by_code(self, code):
        for label, c in self.EXIT_CODES.items():
            if c == code:
                return label
        return "OK"
