"""
TrustStore Analyzer & Visualizer - TEXT RENDERER
Architect: Serge van Thillo

Renders the certificate trust tree as an ASCII-style hierarchy in the terminal.
Includes support for internationalization, status icons, and SAN (Subject Alternative Name)
display.
"""

from datetime import datetime, timezone
from typing import List, Any
from check_truststore.engine.core import (
    _,
    Icons,
    SYSTEM,
    COLLISION,
    ORPHAN_NODE_ID,
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
                show_san (bool): Whether to display Subject Alternative Names.
        """
        output = ["", _("Certificate Hierarchy:")]
        self.include_system = kwargs.get("system", False)
        self.show_san = kwargs.get("show_san", False)

        for group in groups_results:
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

    def _recursive_render(self, nodes: List[Any], indent: str = "") -> str:
        """
        Recursively builds the tree string using ASCII connectors.
        """
        lines = []
        for i, n in enumerate(nodes):
            # Extract attributes safely
            raw_name = getattr(n, "common_name", _("Unknown"))
            is_system_cert = getattr(n, "is_system_cert", False)
            is_collision = getattr(n, "is_collision", False)
            is_orphan = getattr(n, "is_orphan", False) or raw_name == ORPHAN_NODE_ID

            is_valid = getattr(n, "is_valid", False)
            sig_valid = getattr(n, "signature_valid", True)
            v_error = getattr(n, "validation_error", "") or ""
            expiry = getattr(n, "expiry_date", None)
            is_soon = getattr(n, "is_expiring_soon", False)

            # Build status icons
            icons = []
            if is_orphan:
                icons.append(Icons.UNKNOWN)
            else:
                if sig_valid is False:
                    icons.append(Icons.BROKEN)
                elif not is_valid:
                    icons.append(Icons.EXPIRED)
                elif is_soon:
                    icons.append(Icons.WARNING)
                else:
                    icons.append(Icons.VALID)

                if is_system_cert:
                    icons.append(SYSTEM.ICON)
                if is_collision:
                    icons.append(COLLISION.ICON)

            icon_str = "".join([f"[{ico}]" for ico in icons])

            # Process errors and naming
            error_label = ""
            if not is_orphan:
                if sig_valid is False:
                    error_label = f"<{_('SIG_ERR')}>"
                elif v_error:
                    error_label = f"<{_(v_error)}>"
                elif not is_valid and expiry and expiry < datetime.now(timezone.utc):
                    error_label = f"<{_('EXPIRED')}>"

            name = raw_name if not is_orphan else _("EXTERNAL ISSUER / MISSING ROOT")
            if is_collision:
                cid = getattr(n, "cert_id", "???")
                name = f"{name} (ID: {cid[:8]})"

            # Optional SAN display
            san_display = ""
            if self.show_san:
                san_names = getattr(n, "san_names", [])
                extra_sans = [s for s in san_names if s != raw_name]
                if extra_sans:
                    san_display = f"({_('ALT')}: {', '.join(extra_sans)})"

            # Date formatting
            date_str = ""
            if expiry and not is_orphan:
                ds = (
                    expiry.strftime("%Y-%m-%d")
                    if isinstance(expiry, datetime)
                    else str(expiry)[:10]
                )
                date_str = f"({ds})"

            # Build the line with tree connectors
            connector = "└── " if i == len(nodes) - 1 else "├── "
            parts = [f"{indent}{connector}{name}"]
            if icon_str:
                parts.append(icon_str)
            if error_label:
                parts.append(error_label)
            if san_display:
                parts.append(san_display)
            if date_str:
                parts.append(date_str)

            lines.append(" ".join(p for p in parts if p))

            # Recurse for child certificates (Intermediate/Root)
            children = getattr(n, "children", [])
            if children:
                new_indent = indent + ("    " if i == len(nodes) - 1 else "│   ")
                lines.append(self._recursive_render(children, new_indent))

        return "\n".join(lines)
