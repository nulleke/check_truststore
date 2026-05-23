"""
TrustStore Analyzer & Visualizer - GRAPHVIZ RENDERER
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later

Transforms the certificate tree into a DOT graph representation.
Optimized for visualizing Directed Acyclic Graphs (DAG), specifically
useful for cross-signed certificates and complex trust paths.
"""

from typing import Any, Set, List, Dict, Optional, Union
from .base import BaseRenderer


class GraphvizRenderer(BaseRenderer):
    """
    Renders certificate tree data into a Graphviz DOT string.
    Supports cross-signing by allowing multiple edges to point to the same node
    while preventing redundant sub-tree rendering.
    """

    def render(self, tree_data: Union[Any, List[Any]], **kwargs: Any) -> str:
        """
        Main rendering entry point to generate DOT output.

        Args:
            tree_data: A single group or a list of certificate groups/trees.
            **kwargs: Configuration options like 'verbosity'.

        Returns:
            A formatted string in Graphviz DOT format.
        """
        self.nodes: Dict[str, str] = {}
        self.edges: Set[str] = set()
        self.visited_for_children: Set[str] = set()
        self.verbosity: int = kwargs.get("verbosity", 0)

        # Initialize DOT template with global styles
        # Rankdir TB (Top to Bottom) is preferred for PKI hierarchies
        dot_lines: List[str] = [
            'digraph TrustStore {',
            '  rankdir=TB;',
            '  nodesep=0.5;',
            '  ranksep=0.8;',
            '  # Global styles for nodes and edges',
            '  node [fontname="Verdana", shape=rect, style="rounded,filled", fillcolor="#f8f9fa", fontsize=11];',
            '  edge [color="#444444", arrowhead=vee, penwidth=0.8];',
            ''
        ]

        # Normalize input to a list of groups
        groups: List[Any] = tree_data if isinstance(tree_data, list) else [tree_data]

        for i, group in enumerate(groups):
            # Resolve the visual label for the cluster/subgraph
            group_name: str = getattr(group, "group_name", getattr(group, "name", f"Group_{i}"))

            dot_lines.append(f'  subgraph "cluster_{i}" {{')
            dot_lines.append(f'    label="{group_name}";')
            dot_lines.append('    style="dashed"; color="#aaaaaa"; fontcolor="#444444"; fontsize=12; labelloc="t";')

            # Clear visited state per group to allow shared certificates
            # to appear in multiple clusters without merging the clusters in the layout.
            self.visited_for_children.clear()
            nodes_before: Set[str] = set(self.nodes.keys())

            # Start recursive build for this specific group
            self._build_graph_elements(group, group_idx=i)

            # Assign nodes created in this iteration to the current cluster
            new_nodes_in_cluster: Set[str] = set(self.nodes.keys()) - nodes_before
            for node_id in sorted(new_nodes_in_cluster):
                dot_lines.append(f'    {self.nodes[node_id]}')

            dot_lines.append('  }')

        # Add edges at the root level to ensure proper global layout calculation
        dot_lines.extend(sorted(list(self.edges)))
        dot_lines.append('}')

        return "\n".join(dot_lines)

    def _build_graph_elements(self, data: Any, group_idx: int = 0) -> None:
        """
        Recursively traverses the tree and populates node and edge sets.
        Uses group_idx to namespace node IDs, preventing overlap between subgraphs.

        Args:
            data: The current certificate node or list of nodes.
            group_idx: Numerical index of the current subgraph.
        """
        if isinstance(data, list):
            for item in data:
                self._build_graph_elements(item, group_idx)
            return

        # Handle wrapper levels like AnalysisResult or specific Group objects
        if hasattr(data, "group_name") and hasattr(data, "tree"):
            self._build_graph_elements(data.tree, group_idx)
            return

        # Handle generic containers (CertificateGroup)
        if hasattr(data, "children") and not hasattr(data, "fingerprint"):
            for child in getattr(data, "children", []):
                self._build_graph_elements(child, group_idx)
            return

        # Extract the underlying Certificate object
        cert_obj: Optional[Any] = data if (hasattr(data, "cert_id") or hasattr(data, "fingerprint")) else getattr(data, "certificate", None)

        if cert_obj:
            # Use fingerprint as primary identifier
            fp: str = getattr(cert_obj, "fingerprint", "unknown")
            raw_id: str = f"cert_{fp[:16]}"
            scoped_id: str = f"g{group_idx}_{raw_id}"
            findings: List[Any] = getattr(data, "findings", [])

            # Register the node definition (only once per group)
            if scoped_id not in self.nodes:
                # Resolve status and algorithm for visual styling
                is_valid: bool = getattr(cert_obj, "is_valid", getattr(cert_obj, "isValid", True))
                is_cross: bool = getattr(cert_obj, "is_cross_signed", False)
                pk_info: Dict[str, Any] = getattr(cert_obj, "public_key_info", getattr(cert_obj, "publicKeyInfo", {}))
                algo: str = str(pk_info.get("algorithm", "rsa")).lower()

                # Set default colors
                border_color: str = "#333333"
                fill_color: str = "#f8f9fa"

                # ECDSA Styling (Blue tint)
                if "ec" in algo:
                    fill_color = "#e3f2fd"
                    border_color = "#0d47a1"

                # Cross-Signed Styling (Gold tint)
                if is_cross:
                    fill_color = "#fff9c4"
                    border_color = "#fbc02d"

                # Health Overrides (Error > Warning)
                if not is_valid:
                    fill_color = "#f8d7da"
                    border_color = "#dc3545"
                elif any(f.level == "WARNING" for f in findings):
                    fill_color = "#fff3cd"
                    border_color = "#856404"

                label: str = self._create_html_label(cert_obj, findings)
                self.nodes[scoped_id] = f'"{scoped_id}" [label=<{label}>, fillcolor="{fill_color}", color="{border_color}"];'

            # PROCESS DOWNWARD EDGES (Standard Issuance)
            children: List[Any] = getattr(data, "children", [])
            for child in children:
                # Determine child ID for the edge
                c_fp = getattr(child, "fingerprint", "unknown")
                c_scoped_id: str = f"g{group_idx}_cert_{c_fp[:16]}"

                # Logic for Green Dashed Edges (Cross-signing / Alternate paths)
                # If child was already reached, mark this second path as cross-signed
                if c_scoped_id in self.visited_for_children:
                    self.edges.add(f'  "{scoped_id}" -> "{c_scoped_id}" [style="dashed", color="#2e7d32", constraint=false, arrowhead=empty];')
                else:
                    self.edges.add(f'  "{scoped_id}" -> "{c_scoped_id}" [penwidth=1.0];')
                    self.visited_for_children.add(c_scoped_id)
                    self._build_graph_elements(child, group_idx)

            # PROCESS UPWARD/ALTERNATE EDGES (Parent references)
            parents: List[Any] = getattr(cert_obj, "parents", [])
            for parent in parents:
                p_fp = getattr(parent, "fingerprint", "unknown")
                p_scoped_id: str = f"g{group_idx}_cert_{p_fp[:16]}"

                # Ensure we don't draw edges to virtual root containers (Orphans/Cycles)
                if p_scoped_id != scoped_id and "VIRTUAL" not in p_scoped_id:
                    # Check if this link was already established as a standard downward path
                    edge_str: str = f'  "{p_scoped_id}" -> "{scoped_id}"'
                    is_standard: bool = any(e.startswith(edge_str) and "dashed" not in e for e in self.edges)

                    if not is_standard:
                        self.edges.add(f'{edge_str} [style="dashed", color="#2e7d32", constraint=false, arrowhead=empty];')

    def _create_html_label(self, cert: Any, findings: List[Any]) -> str:
        """
        Generates an HTML-based label for Graphviz nodes including metadata.
        """
        cn: str = getattr(cert, "common_name", getattr(cert, "commonName", "Unknown CN"))
        expiry: Any = getattr(cert, "expiry_date", getattr(cert, "expiryDate", None))
        pk_info: Dict[str, Any] = getattr(cert, "public_key_info", getattr(cert, "publicKeyInfo", {}))

        algo: str = str(pk_info.get("algorithm", "RSA")).upper()
        bits: int = pk_info.get("bits", 0)

        # Securely format the expiry date
        expiry_str: str = "Unknown"
        if hasattr(expiry, "strftime"):
            expiry_str = expiry.strftime("%Y-%m-%d")
        elif expiry:
            expiry_str = str(expiry).split(' ')[0]

        # Build HTML table for the node label
        label: str = '<table border="0" cellborder="0" cellspacing="2" cellpadding="2">'
        label += f'<tr><td><b>{cn}</b></td></tr>'
        label += f'<tr><td><font point-size="9" color="#666666">{algo} {bits if bits else ""}</font></td></tr>'
        label += f'<tr><td><font point-size="9" color="#666666">Expires: {expiry_str}</font></td></tr>'

        # Highlight critical errors if they exist
        for f in findings:
            if getattr(f, "level", "") == "ERROR":
                label += f'<tr><td><font color="#dc3545" point-size="8"><b>{getattr(f, "label", "ERROR")}</b></font></td></tr>'
                break

        label += '</table>'
        return label

    def _should_deduplicate(self, cert_node: Any) -> bool:
        """Helper for child classes to determine deduplication logic."""
        return False