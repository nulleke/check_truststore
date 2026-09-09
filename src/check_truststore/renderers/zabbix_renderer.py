"""
TrustStore Analyzer & Visualizer - ZABBIX RENDERER
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later

Renders certificate analysis results into Zabbix Low Level Discovery (LLD) JSON format,
globally deduplicating shared roots and intermediates with group tracking and SAN support.
"""

import json
from datetime import date, datetime, timezone
from typing import Any, Dict, List, Set, Union

from check_truststore.engine import CYCLE_NODE_ID, ORPHAN_NODE_ID

from .base import BaseRenderer


class ZabbixRenderer(BaseRenderer):
    """Transforms certificate validation results into deduplicated Zabbix LLD JSON."""

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
        """Main entry point to transform analysis results into Zabbix LLD JSON.

        Processes certificate groups, deduplicates shared certificates globally
        across all target groups, and formats the output into an LLD-compliant JSON payload.

        Args:
            groups_results: A list of CertificateGroup objects or a single instance.
            **kwargs: Arbitrary keyword arguments (unused).

        Returns:
            A string containing the formatted Zabbix Low Level Discovery JSON payload.
        """
        groups: List[Any] = groups_results if isinstance(groups_results, list) else [groups_results]

        cert_registry: Dict[str, Dict[str, Any]] = {}

        for group in groups:
            processed_fps: Set[str] = set()
            raw_group_name: str = str(self._get_val(group, "group_name") or self._get_val(group, "name") or "default")
            group_name: str = raw_group_name

            target: str = raw_group_name
            if ": " in raw_group_name:
                _, target_part = raw_group_name.split(": ", 1)
                target = target_part.strip()
            if ":" in target:
                target_parts = target.rsplit(":", 1)
                if target_parts[-1].isdigit():
                    target = target_parts[0]

            root_nodes: List[Any] = self._get_val(group, "tree", [])
            self._collect_and_deduplicate(root_nodes, target, group_name, 0, processed_fps, cert_registry)

        lld_data: List[Dict[str, Any]] = list(cert_registry.values())
        return json.dumps(lld_data, indent=2) + "\n"

    def _collect_and_deduplicate(
        self,
        nodes: List[Any],
        target_host: str,
        group_name: str,
        depth: int,
        processed_fps: Set[str],
        cert_registry: Dict[str, Dict[str, Any]]
    ) -> None:
        """Recursively traverses certificate nodes, normalizes metrics, and updates the global registry.

        Args:
            nodes: List of certificate nodes to traverse.
            target_host: The clean hostname or target identification.
            group_name: The operational group context name.
            depth: The depth level in the trust hierarchy (0 = Root).
            processed_fps: Set tracking fingerprints to prevent intra-group duplicates.
            cert_registry: Central dictionary storing unique certificates globally by fingerprint.
        """
        if not nodes:
            return

        for node in nodes:
            fp: str = str(self._get_val(node, "fingerprint") or "")
            cn: str = str(self._get_val(node, "common_name") or "Unknown")

            children: List[Any] = self._get_val(node, "children") or []

            if cn in [ORPHAN_NODE_ID, CYCLE_NODE_ID] or not fp:
                self._collect_and_deduplicate(children, target_host, group_name, depth + 1, processed_fps, cert_registry)
                continue

            processed_fps.add(fp)

            is_root: bool = bool(self._get_val(node, "is_root", self._get_val(node, "isRoot", False)))

            cert_type: str
            if is_root and depth == 0:
                cert_type = "Root"
            elif children:
                cert_type = "Intermediate"
            else:
                cert_type = "Endpoint"

            raw_san_names: List[str] = self._get_val(node, "san_names") or []
            san_names: List[str] = list(dict.fromkeys(raw_san_names))
            san_str: str = ", ".join(san_names)

            audit_status: Dict[str, Any]
            if hasattr(node, "get_audit_status") and callable(node.get_audit_status):
                audit_status = node.get_audit_status()
            else:
                audit_status = self._get_val(node, "auditStatus", self._get_val(node, "audit_status", {}))

            audit_level: str = str(audit_status.get("level", "note")).lower()

            is_valid: int = 0 if audit_level == "error" else (1 if self._get_val(node, "is_valid") else 0)

            findings: List[Any] = self._get_val(node, "findings") or []
            levels: Dict[str, int] = {"ERROR": 0, "WARNING": 0, "INFO": 0}

            for f in findings:
                lvl: str = str(self._get_val(f, "level", "INFO")).upper()
                if lvl in levels:
                    levels[lvl] += 1

            if audit_level == "error" and levels["ERROR"] == 0:
                levels["ERROR"] = 1

            expiry_dt: Any = self._get_val(node, "expiry_date", self._get_val(node, "expiryDate"))
            expiry_ts: int = 0

            if isinstance(expiry_dt, str) and expiry_dt and expiry_dt != "1970-01-01":
                try:
                    clean_date = expiry_dt.replace("Z", "+00:00")
                    expiry_dt = datetime.fromisoformat(clean_date)
                except ValueError:
                    pass

            if isinstance(expiry_dt, date) and not isinstance(expiry_dt, datetime):
                expiry_dt = datetime(expiry_dt.year, expiry_dt.month, expiry_dt.day, tzinfo=timezone.utc)

            if isinstance(expiry_dt, datetime):
                expiry_ts = int(expiry_dt.timestamp())

            if fp in cert_registry:
                existing_groups: List[str] = cert_registry[fp]["groups"]
                if group_name not in existing_groups:
                    existing_groups.append(group_name)
                cert_registry[fp]["{#CERT_GROUPS}"] = ", ".join(existing_groups)

                if cert_type == "Intermediate" and cert_registry[fp]["{#CERT_TYPE}"] == "Endpoint":
                    cert_registry[fp]["{#CERT_TYPE}"] = "Intermediate"
            else:
                cert_registry[fp] = {
                    "{#CERT_FINGERPRINT}": fp,
                    "{#CERT_UID}": fp[:16],
                    "{#CERT_CN}": cn.replace("\"", ""),
                    "{#CERT_TYPE}": cert_type,
                    "{#CERT_SANS}": san_str,
                    "{#CERT_GROUPS}": group_name,
                    "groups": [group_name],
                    "sans": san_names,
                    "metrics": {
                        "valid": is_valid,
                        "expiry": expiry_ts,
                        "errors": levels["ERROR"],
                        "warnings": levels["WARNING"]
                    }
                }

            self._collect_and_deduplicate(children, target_host, group_name, depth + 1, processed_fps, cert_registry)