"""
TrustStore Analyzer & Visualizer - GRAPHVIZ RENDERER
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later

Transforms the certificate tree into a DOT graph representation.
Optimized for visualizing Directed Acyclic Graphs (DAG), specifically
useful for cross-signed certificates and complex trust paths.
"""

from typing import Any, Set, List, Dict
from .base import BaseRenderer


class GraphvizRenderer(BaseRenderer):
    """
    Renders certificate tree data into a Graphviz DOT string.
    Supports cross-signing by allowing multiple edges to point to the same node
    while preventing redundant sub-tree rendering.
    """

    def render(self, tree_data: Any, **kwargs) -> str:
        """
        Main rendering method for DOT output.
        """
        self.nodes: Dict[str, str] = {}
        self.edges: Set[str] = set()
        self.visited_for_children: Set[str] = set()
        self.verbosity = kwargs.get("verbosity", 0)

        # Initialize DOT template with global styles
        dot_lines = [
            'digraph TrustStore {',
            '  rankdir=LR;',
            '  # Global styles for nodes and edges',
            '  node [fontname="Verdana", shape=rect, style="rounded,filled", fillcolor="#f8f9fa", fontsize=11];',
            '  edge [color="#444444", arrowhead=vee, penwidth=0.8];',
            ''
        ]

        if isinstance(tree_data, list):
            # Process multiple groups (e.g., trust stores or folders) as subgraphs
            for i, group in enumerate(tree_data):
                group_name = getattr(group, "group_name", f"Group_{i}")
                dot_lines.append(f'  subgraph "cluster_{i}" {{')
                dot_lines.append(f'    label="{group_name}";')
                dot_lines.append('    style="dashed"; color="#aaaaaa"; fontcolor="#444444"; fontsize=12; labelloc="t";')

                # Identify which nodes belong specifically to this cluster
                nodes_before = set(self.nodes.keys())
                self._build_graph_elements(group)
                new_nodes_in_cluster = set(self.nodes.keys()) - nodes_before

                for node_id in sorted(new_nodes_in_cluster):
                    dot_lines.append(f'    {self.nodes[node_id]}')

                dot_lines.append('  }')
        else:
            # Flat processing if no groups are present
            self._build_graph_elements(tree_data)
            for node_id in sorted(self.nodes.keys()):
                dot_lines.append(self.nodes[node_id])

        # Add all unique edges at the root level for better layout calculation
        dot_lines.extend(sorted(list(self.edges)))
        dot_lines.append('}')

        return "\n".join(dot_lines)

    def _build_graph_elements(self, data: Any) -> None:
        """
        Recursively traverses the tree/graph and populates node and edge sets.
        """
        if isinstance(data, list):
            for item in data:
                self._build_graph_elements(item)
            return

        # Handle potential wrapper levels (e.g., AnalysisResult or Group objects)
        if hasattr(data, "group_name") and hasattr(data, "tree"):
            self._build_graph_elements(data.tree)
            return

        # Resolve the underlying Certificate object
        cert_obj = data if hasattr(data, "sha256_hash") else getattr(data, "certificate", None)

        if cert_obj:
            # Use SHA256 hash for stable and unique node identification
            cert_id = f"cert_{cert_obj.sha256_hash[:16]}"
            findings = getattr(data, "findings", [])

            # Register the node definition if it hasn't been encountered yet
            if cert_id not in self.nodes:
                fill_color = "#d1e7dd"  # Default Green (Valid)
                border_color = "#333333"

                if any(f.level == "ERROR" for f in findings):
                    fill_color = "#f8d7da"  # Red (Error)
                    border_color = "#dc3545"
                elif any(f.level == "WARNING" for f in findings):
                    fill_color = "#fff3cd"  # Yellow (Warning)
                    border_color = "#856404"

                label = self._create_html_label(cert_obj, findings)
                self.nodes[cert_id] = f'"{cert_id}" [label=<{label}>, fillcolor="{fill_color}", color="{border_color}"];'

            # Process children and register edges
            children = getattr(data, "children", [])
            for child in children:
                child_cert = child if hasattr(child, "sha256_hash") else getattr(child, "certificate", None)
                if child_cert:
                    child_id = f"cert_{child_cert.sha256_hash[:16]}"

                    # ALWAYS add the edge to allow multiple parents (Cross-signing)
                    self.edges.add(f'  "{cert_id}" -> "{child_id}";')

                    # 3. Recursive Traversal: only expand children if not already processed
                    if child_id not in self.visited_for_children:
                        self.visited_for_children.add(child_id)
                        self._build_graph_elements(child)

    def _create_html_label(self, cert: Any, findings: List[Any]) -> str:
        """
        Constructs an HTML-like label for the Graphviz node.
        """
        cn = getattr(cert, "common_name", "Unknown CN")
        expiry_val = getattr(cert, "expiry_date", None)

        # Formatting expiry date safely
        expiry_str = "Unknown"
        if hasattr(expiry_val, "strftime"):
            expiry_str = expiry_val.strftime("%Y-%m-%d")
        elif expiry_val:
            expiry_str = str(expiry_val).split(' ')[0]

        label = '<table border="0" cellborder="0" cellspacing="2" cellpadding="2">'
        label += f'<tr><td><b>{cn}</b></td></tr>'
        label += f'<tr><td><font point-size="9" color="#666666">Expires: {expiry_str}</font></td></tr>'

        if any(f.level == "ERROR" for f in findings):
            label += '<tr><td><font color="#dc3545" point-size="9"><b>[!] CRITICAL</b></font></td></tr>'

        label += '</table>'
        return label

    def _should_deduplicate(self, cert_node: Any) -> bool:
        return False