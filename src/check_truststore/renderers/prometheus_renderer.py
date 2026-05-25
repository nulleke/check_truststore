"""
TrustStore Analyzer & Visualizer - PROMETHEUS RENDERER
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later

Renders the certificate trust analysis results into the Prometheus text exposition
format, enabling native time-series tracking of trust store health.
"""

from typing import List, Any, Set, Dict, Union
from datetime import datetime
from .base import BaseRenderer
from check_truststore.engine import ORPHAN_NODE_ID, CYCLE_NODE_ID


class PrometheusRenderer(BaseRenderer):
    """Transforms hierarchical certificate validation results into Prometheus
    text exposition format (OpenMetrics compliant).

    This renderer converts internal certificate tree structures into time-series
    metrics, allowing integration with monitoring stacks like Prometheus/Grafana.
    """

    def _get_val(self, obj: Any, key: str, default: Any = None) -> Any:
        """Safely retrieves a value from an object attribute or dictionary key.

        Args:
            obj: The object or dictionary to inspect.
            key: The attribute name or dictionary key to retrieve.
            default: The value to return if the key/attribute is missing.

        Returns:
            The retrieved value if it exists, otherwise the provided default.
        """
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)

    def render(self, groups_results: Union[List[Any], Any], **kwargs: Any) -> str:
        """Main entry point to transform analysis results into Prometheus metrics.

        Processes certificate groups, aggregates distinct certificate nodes per
        group, and constructs the metric lines with OpenMetrics-compliant headers.

        Args:
            groups_results: A list of CertificateGroup objects or a single instance.
            **kwargs: Arbitrary keyword arguments (unused).

        Returns:
            A string containing the full Prometheus text exposition payload.
        """
        lines: List[str] = [
            "# HELP truststore_cert_valid_status Validity status (1 = Valid, 0 = Invalid)",
            "# TYPE truststore_cert_valid_status gauge",
            "# HELP truststore_cert_expiry_timestamp_seconds Expiration date in unixtime",
            "# TYPE truststore_cert_expiry_timestamp_seconds gauge",
            "# HELP truststore_cert_policy_findings_total Policy violations by level",
            "# TYPE truststore_cert_policy_findings_total gauge"
        ]

        groups: List[Any] = groups_results if isinstance(groups_results, list) else [groups_results]

        for group in groups:
            processed_fingerprints: Set[str] = set()
            group_name: str = self._get_val(group, "group_name") or self._get_val(group, "name") or "default"
            root_nodes: List[Any] = self._get_val(group, "tree", [])
            self._traverse_and_render_metrics(root_nodes, group_name, processed_fingerprints, lines)

        return "\n".join(lines) + "\n"

    def _traverse_and_render_metrics(
        self,
        nodes: List[Any],
        group_name: str,
        processed_fps: Set[str],
        lines: List[str]
    ) -> None:
        """Recursively traverses certificate nodes to flatten data into time-series metrics.

        Args:
            nodes: List of certificate nodes to traverse.
            group_name: The name of the group context for label decoration.
            processed_fps: Set tracking fingerprints to prevent intra-group duplicates.
            lines: Mutable list of lines collecting the resulting Prometheus metrics.
        """
        if not nodes:
            return

        for node in nodes:
            fp: str = self._get_val(node, "fingerprint") or ""
            cn: str = self._get_val(node, "common_name") or "Unknown"
            serial: str = str(self._get_val(node, "serial_number") or "N/A")

            if cn in [ORPHAN_NODE_ID, CYCLE_NODE_ID] or not fp:
                self._traverse_and_render_metrics(self._get_val(node, "children", []), group_name, processed_fps, lines)
                continue

            if fp in processed_fps:
                continue
            processed_fps.add(fp)

            clean_cn = str(cn).replace("\"", "")
            clean_serial = str(serial).replace("\"", "")

            labels: str = (
                f'group="{group_name}",'
                f'common_name="{clean_cn}",'
                f'serial="{clean_serial}",'
                f'fingerprint="{fp}"'
            )

            is_valid: int = 1 if self._get_val(node, "is_valid") else 0
            lines.append(f'truststore_cert_valid_status{{{labels}}} {is_valid}')

            expiry_dt: Any = self._get_val(node, "expiry_date")
            if isinstance(expiry_dt, datetime):
                lines.append(f'truststore_cert_expiry_timestamp_seconds{{{labels}}} {expiry_dt.timestamp():.0f}')

            findings: List[Any] = self._get_val(node, "findings") or []
            levels: Dict[str, int] = {"ERROR": 0, "WARNING": 0, "INFO": 0}
            for f in findings:
                lvl = str(self._get_val(f, "level", "INFO")).upper()
                if lvl in levels:
                    levels[lvl] += 1

            for lvl, count in levels.items():
                lines.append(f'truststore_cert_policy_findings_total{{{labels},level="{lvl}"}} {count}')

            self._traverse_and_render_metrics(self._get_val(node, "children", []), group_name, processed_fps, lines)