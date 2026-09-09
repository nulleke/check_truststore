"""
TrustStore Analyzer & Visualizer - ZABBIX RENDERER
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later

Renders certificate analysis results into Zabbix Low Level Discovery (LLD) JSON format,
globally deduplicating shared roots and intermediates with group tracking.
"""

import json
from datetime import date, datetime, timezone
from typing import Any, Dict, List, Set, Union

from check_truststore.engine import CYCLE_NODE_ID, ORPHAN_NODE_ID

from .base import BaseRenderer


class ZabbixRenderer(BaseRenderer):
    """Transforms certificate validation results into deduplicated Zabbix LLD JSON."""

    def _get_val(self, obj: Any, key: str, default: Any = None) -> Any:
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)

    def render(self, groups_results: Union[List[Any], Any], **kwargs: Any) -> str:
        groups: List[Any] = groups_results if isinstance(groups_results, list) else [groups_results]

        cert_registry: Dict[str, Dict[str, Any]] = {}

        for group in groups:
            processed_fps: Set[str] = set()
            raw_group_name: str = self._get_val(group, "group_name") or self._get_val(group, "name") or "default"
            group_name = raw_group_name

            target = raw_group_name
            if ": " in raw_group_name:
                _, target_part = raw_group_name.split(": ", 1)
                target = target_part.strip()
            if ":" in target:
                target_parts = target.rsplit(":", 1)
                if target_parts[-1].isdigit():
                    target = target_parts[0]

            root_nodes: List[Any] = self._get_val(group, "tree", [])
            self._collect_and_deduplicate(root_nodes, target, group_name, 0, processed_fps, cert_registry)

        lld_data = list(cert_registry.values())
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
        if not nodes:
            return

        for node in nodes:
            fp: str = self._get_val(node, "fingerprint") or ""
            cn: str = self._get_val(node, "common_name") or "Unknown"

            if cn in [ORPHAN_NODE_ID, CYCLE_NODE_ID] or not fp:
                self._collect_and_deduplicate(self._get_val(node, "children", []), target_host, group_name, depth + 1, processed_fps, cert_registry)
                continue

            processed_fps.add(fp)

            cert_type = "Intermediate"
            if depth == 0:
                cert_type = "Root"
            elif not self._get_val(node, "children", []):
                cert_type = "Leaf"

            is_valid: int = 1 if self._get_val(node, "is_valid") else 0

            expiry_dt: Any = self._get_val(node, "expiry_date")
            expiry_ts = 0
            if isinstance(expiry_dt, date) and not isinstance(expiry_dt, datetime):
                expiry_dt = datetime(expiry_dt.year, expiry_dt.month, expiry_dt.day, tzinfo=timezone.utc)
            if isinstance(expiry_dt, datetime):
                expiry_ts = int(expiry_dt.timestamp())

            findings: List[Any] = self._get_val(node, "findings") or []
            levels: Dict[str, int] = {"ERROR": 0, "WARNING": 0, "INFO": 0}
            for f in findings:
                lvl = str(self._get_val(f, "level", "INFO")).upper()
                if lvl in levels:
                    levels[lvl] += 1

            if fp in cert_registry:
                existing_groups = cert_registry[fp]["groups"]
                if group_name not in existing_groups:
                    existing_groups.append(group_name)
                cert_registry[fp]["{#CERT_GROUPS}"] = ", ".join(existing_groups)
            else:
                cert_registry[fp] = {
                    "{#CERT_FINGERPRINT}": fp,
                    "{#CERT_UID}": fp[:16],
                    "{#CERT_CN}": cn.replace("\"", ""),
                    "{#CERT_TYPE}": cert_type,
                    "{#CERT_GROUPS}": group_name,
                    "groups": [group_name],
                    "metrics": {
                        "valid": is_valid,
                        "expiry": expiry_ts,
                        "errors": levels["ERROR"],
                        "warnings": levels["WARNING"]
                    }
                }

            self._collect_and_deduplicate(self._get_val(node, "children", []), target_host, group_name, depth + 1, processed_fps, cert_registry)
