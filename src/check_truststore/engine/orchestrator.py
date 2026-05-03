"""
TrustStore Analyzer & Visualizer - ORCHESTRATION LAYER
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later

This module orchestrates the end-to-end analysis process. It connects
the certificate repository with the chain builder to process multiple
trust store groups and generate finalized analysis models.
"""

from typing import Any, Optional, List, Dict, Set
from .repository import CertificateRepository
from .models import Certificate, CertificateGroup
from .builder import TrustChainBuilder
from .logging import _, INFO


class TrustStoreAnalyzer:
    """
    High-level orchestrator that manages groups and triggers the analysis pipeline.
    Connects the Repository to the Builder and returns serialized models.
    """
    def __init__(self, groups: List[Any], repository: Optional[CertificateRepository] = None, **kwargs: Any):
        self.repo: CertificateRepository = repository or CertificateRepository(**kwargs)
        self.options: Dict[str, Any] = kwargs
        self.debug: bool = kwargs.get("debug", False)
        self.verbosity: int = kwargs.get("verbosity", 0)
        self.include_system: bool = kwargs.get("system", False)
        self.online: bool = kwargs.get("online", False)
        self.max_depth: int = kwargs.get("max_depth", 4)
        self.groups: List[Any] = groups
        self.threshold: int = kwargs.get("threshold", 30)

    def analyze(self) -> List[CertificateGroup]:
        """
        Main entry point for analyzing all configured groups.

        Returns:
            List[CertificateGroup]: A list of analyzed and finalized certificate groups.
        """
        analysis_results: List[CertificateGroup] = []
        system_certs_data: List[Dict[str, Any]] = []
        system_hashes: Set[str] = set()

        if self.include_system:
            system_certs_data = self.repo.load_from_system()
            system_hashes = {c["hash"] for c in system_certs_data if c.get("is_system_cert")}

        for group_config in self.groups:
            if self.debug:
                INFO.log(_("Processing Group"), group_config.name)

            builder = TrustChainBuilder(repository=self.repo, **self.options)

            current_pool: List[Dict[str, Any]] = []
            for target in group_config.targets:
                if isinstance(target, list):
                    current_pool.extend(target)
                else:
                    current_pool.append(target)

            if self.include_system:
                current_pool.extend(system_certs_data)

            resolver = None
            if self.online:
                from .discovery import NetworkResolver
                resolver = NetworkResolver(**self.options)

            tree_data = builder.build(current_pool, resolver=resolver, max_depth=self.max_depth)

            group_obj = CertificateGroup(
                groupName=group_config.name,
                groupStatus="OK",
                tree=tree_data,
                chain=builder.get_flat_chain(),
            )

            group_obj.summary = builder.get_analysis_summary()
            group_obj.builder = builder
            group_obj.repo = self.repo
            group_obj.finalize()

            analysis_results.append(group_obj)

            if self.include_system and self.debug:
                self._log_system_usage(group_config.name, group_obj.tree, system_hashes)

        return analysis_results

    def _log_system_usage(self, group_name: str, tree: List[Certificate], system_hashes: Set[str]):
        """
        Calculates and logs how many unique system certificates were used in the tree.

        Args:
            group_name: Name of the current group.
            tree: The constructed certificate tree.
            system_hashes: Set of hashes identified as system certificates.
        """
        used_exclusive_system = 0
        seen_hashes: Set[str] = set()

        def traverse(nodes: List[Certificate]) -> None:
            nonlocal used_exclusive_system
            for node in nodes:
                h = getattr(node, 'sha256_hash', None)
                if not h or h in seen_hashes:
                    continue
                seen_hashes.add(h)

                # Count if the certificate is part of the system store and marked as such
                if h in system_hashes:
                    is_sys = getattr(node, 'isSystemCert', False) or getattr(node, 'is_system_cert', False)
                    if is_sys:
                        used_exclusive_system += 1

                if node.children:
                    traverse(node.children)

        traverse(tree)

        message = _("Used {used} out of {total} system certs").format(
            used=used_exclusive_system,
            total=self.repo.system_store_total_count,
        )

        INFO.log(f"[{group_name}] " + _("System usage"), message)

    def _is_in_tree(self, target_hash: str, node: Certificate) -> bool:
        """
        Recursive helper to check if a specific certificate hash exists within a branch.
        """
        if getattr(node, "sha256_hash", None) == target_hash:
            return True
        if node.children:
            return any(self._is_in_tree(target_hash, child) for child in node.children)
        return False
