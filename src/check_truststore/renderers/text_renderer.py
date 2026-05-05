"""
TrustStore Analyzer & Visualizer - TEXT RENDERER
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later

Renders the certificate trust tree as an ASCII-style hierarchy in the terminal.
Includes support for internationalization, status icons, and SAN (Subject Alternative Name)
display.
"""

from datetime import datetime, timezone
from typing import List, Any
from check_truststore.engine import (
    _,
    Icons,
    SYSTEM,
    AIA,
    COLLISION,
    ORPHAN_NODE_ID,
    CYCLE_NODE_ID,
)
from .base import BaseRenderer


class TextRenderer(BaseRenderer):
    """
    Generates a human-readable tree representation of the certificate analysis.
    Uses Unicode connectors to visualize the relationship between issuers and subjects.
    """

    def render(self, groups_results: List[Any], **kwargs) -> str:
        """
        Main entry point for rendering the text report.

        Args:
            groups_results: List of CertificateGroup objects or dictionaries.
            **kwargs:
                system (bool): Whether to emphasize system certificates.
                verbosity (int): Level of detail to include in the output.
        """
        _("SIG_INVALID")
        _("NO_TRUST")
        _("UNTRUSTED_CHAIN")
        self.now = datetime.now(timezone.utc)

        output = ["", _("Certificate Hierarchy:")]
        self.include_system = kwargs.get("system", False)
        self.verbosity = kwargs.get("verbosity", 0)

        for group in groups_results:
            if hasattr(self, "_rendered_fingerprints"):
                self._rendered_fingerprints.clear()

            # Handle both raw objects and dictionary inputs
            if isinstance(group, dict):
                group_name = group.get("group_name", _("Unnamed Group"))
                nodes = group.get("tree", [])
            else:
                group_name = getattr(group, "group_name", _("Unnamed Group"))
                nodes = getattr(group, "tree", [])

            output.append(f"\n### {group_name} ###")

            if nodes:
                output.append(self._recursive_render(nodes))
            else:
                output.append(f"  {_('(No certificates found)')}")

        return "\n".join(output)

    def _render_icon_block(self, icon: str) -> str:
        if not icon:
            return ""

        DOUBLE_WIDTH_ICONS=[
            Icons.OCSP_OK
        ]

        if icon in DOUBLE_WIDTH_ICONS:
            return f"[{icon} ]"
        else:
            return f"[{icon}]"

    def _recursive_render(self, nodes: List[Any], indent: str = "") -> str:
        """
        Recursively builds the tree string using ASCII connectors.
        """
        lines = []

        sorted_nodes = sorted(
            nodes,
            key=lambda x: getattr(x, "expiry_date", None) or datetime(1970, 1, 1, tzinfo=timezone.utc),
            reverse=True
        )

        for i, n in enumerate(sorted_nodes):
            if self._should_skip(n):
                continue

            # Extract attributes safely
            audit = n.get_audit_status()
            raw_name = getattr(n, "common_name", _("Unknown"))
            is_system_cert = getattr(n, "is_system_cert", False)
            is_aia_cert = getattr(n, "is_aia_cert", False)
            is_collision = getattr(n, "is_collision", False)
            is_orphan = getattr(n, "is_orphan", False) or raw_name == ORPHAN_NODE_ID
            is_cycle = getattr(n, 'is_in_circular_group', False) or raw_name == CYCLE_NODE_ID

            expiry = getattr(n, "expiry_date", None)
            ocsp_status = getattr(n, "ocsp_status", "UNKNOWN")

            is_special_placeholder = raw_name in [ORPHAN_NODE_ID, CYCLE_NODE_ID]

            # Build status icons
            icons = []
            if is_orphan or is_cycle:
                icons.append(Icons.UNKNOWN)
            else:
                if audit["code"] == 0:
                    icons.append(Icons.VALID)
                elif audit["code"] == 1:
                    icons.append(Icons.WARNING)
                else:
                    icons.append(Icons.EXPIRED)

                if ocsp_status == "REVOKED":
                    icons.append(Icons.REVOKED)
                elif ocsp_status == "GOOD":
                    icons.append(Icons.OCSP_OK)

                icons.append(n.signature_icon)

                if is_system_cert:
                    icons.append(SYSTEM.ICON)
                if is_aia_cert:
                    icons.append(AIA.ICON)
                if is_collision:
                    icons.append(COLLISION.ICON)

            icon_str = "".join([self._render_icon_block(ico) for ico in icons])

            # Process errors and naming
            error_label = ""
            if not is_special_placeholder and audit["code"] > 0:
                error_label = f"<{_(audit['label'])}>"

            if is_special_placeholder and is_orphan:
                name = _("EXTERNAL ISSUER / MISSING ROOT")
            elif is_special_placeholder and is_cycle:
                name = _("CIRCULAR REFERENCE")
            else:
                name = raw_name

            if is_collision:
                cid = getattr(n, "cert_id", "???")
                name = f"{name} (ID: {cid[:8]})"

            eku_display = ""
            if self.verbosity >= 2:
                findings = getattr(n, "findings", [])
                eku_finding = next((f for f in findings if getattr(f, "code", "") == "EKU_PURPOSE"), None)
                if eku_finding:
                    usages = eku_finding.params.get("usages", [])
                    translated_usages = [_(u) for u in usages]
                    eku_text = ", ".join(translated_usages)
                    eku_display = f" [{_('Usage')}: {eku_text}]"

            # Optional SAN display
            san_display = ""
            if self.verbosity >= 1:
                san_names = getattr(n, "san_names", [])
                extra_sans = [s for s in san_names if s != raw_name]
                if extra_sans:
                    max_display = 5
                    if len(extra_sans) > max_display:
                        san_str = ", ".join(extra_sans[:max_display])
                        san_display = f"({_('ALT')}: {san_str} ... +{len(extra_sans) - max_display})"
                    else:
                        san_display = f"({_('ALT')}: {', '.join(extra_sans)})"

            # Date formatting

            date_str = ""
            if expiry and not is_special_placeholder:
                ds = (
                    expiry.strftime("%Y-%m-%d")
                    if isinstance(expiry, datetime)
                    else str(expiry)[:10]
                )
                date_str = f"({ds})"

            # Build the line with tree connectors
            connector = "└── " if i == len(nodes) - 1 else "├── "
            parts = [f"{indent}{connector}{name}", icon_str, error_label, san_display, eku_display, date_str]

            lines.append(" ".join(p for p in parts if p))

            findings = getattr(n, "findings", [])
            if findings and self.verbosity >= 3:
                children = getattr(n, "children", [])
                base_indent = indent + ("    " if i == len(nodes) - 1 else "│   ")
                filtered_findings = [f for f in findings if not (self.verbosity >= 3 and getattr(f, "code", "") == "EKU_PURPOSE")]

                for f_idx, f in enumerate(filtered_findings):
                    is_last_finding = (f_idx == len(filtered_findings) - 1) and not children
                    f_connector = "└── " if is_last_finding else "├── "
                    f_icon = "[!]" if f.level == "ERROR" else "[i]"
                    try:
                        translated_msg = _(f.message).format(**(f.params or {}))
                    except (KeyError, ValueError):
                        translated_msg = _(f.message)
                    lines.append(f"{base_indent}{f_connector}{f_icon} {translated_msg} ({f.code})")

            # Recurse for child certificates (Intermediate/Root)
            children = getattr(n, "children", [])
            if children:
                new_indent = indent + ("    " if i == len(nodes) - 1 else "│   ")
                lines.append(self._recursive_render(children, new_indent))

        return "\n".join(lines)
