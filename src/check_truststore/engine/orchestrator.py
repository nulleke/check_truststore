"""
TrustStore Analyzer & Visualizer - ORCHESTRATION LAYER
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later

This module orchestrates the end-to-end analysis process. It connects
the certificate repository with the chain builder to process multiple
trust store groups and generate finalized analysis models.
"""

from typing import Any, Optional, List, Dict, Union, Set
from pathlib import Path
from .repository import CertificateRepository
from .models import Certificate, CertificateGroup
from .builder import TrustChainBuilder
from .logging import _, INFO


class TrustStoreAnalyzer:
    """
    High-level orchestrator that manages certificate groups and triggers
    the analysis pipeline.
    """
    def __init__(self, groups: List[Any], repository: Optional[CertificateRepository] = None, **kwargs: Any):
        """
        Initialize the analyzer with input groups and configuration options.
        """
        self.repo: CertificateRepository = repository or CertificateRepository(**kwargs)
        self.options: Dict[str, Any] = kwargs
        self.debug: bool = kwargs.get("debug", False)
        self.verbosity: int = kwargs.get("verbosity", 0)
        self.include_system: bool = kwargs.get("system", False)
        self.online: bool = kwargs.get("online", False)
        self.max_depth: int = kwargs.get("max_depth", 4)
        self.groups: List[Any] = groups

    def analyze(self) -> List[CertificateGroup]:
        """
        Executes the analysis pipeline for all configured groups.
        """
        analysis_results: List[CertificateGroup] = []
        system_hashes: Set[str] = set()
        system_pool: List[Dict[str, Any]] = []

        if self.include_system:
            try:
                from ..providers.system_provider import SystemInputProvider
                sys_provider = SystemInputProvider(repository=self.repo, **self.options)

                for sys_group in sys_provider.get_groups():
                    resolved_sys = self._resolve_targets(sys_group.targets, is_system=True)
                    system_pool.extend(resolved_sys)
                    for item in resolved_sys:
                        system_hashes.add(item["hash"])
            except Exception as e:
                if self.debug:
                    from .logging import WARNING
                    WARNING.log(_("SystemProvider"), _("Could not load system truststore: {error}").format(error=e))

        for group_config in self.groups:
            if self.debug:
                INFO.log(_("Processing Group"), group_config.name)

            self.repo.clear_cache()
            builder = TrustChainBuilder(repository=self.repo, **self.options)
            current_pool = self._resolve_targets(group_config.targets)

            resolver = None
            if self.online:
                from .discovery import NetworkResolver
                resolver = NetworkResolver(**self.options)

            tree_data = builder.build(
                current_pool,
                authority_pool=system_pool if self.include_system else None,
                resolver=resolver,
                max_depth=self.max_depth
            )

            group_obj = CertificateGroup(
                groupName=group_config.name,
                tree=tree_data,
                chain=builder.get_flat_chain(),
            )
            group_obj.summary = builder.get_analysis_summary()
            group_obj.finalize()
            analysis_results.append(group_obj)

            if self.include_system and self.debug:
                self._log_system_usage(group_config.name, group_obj.tree, system_hashes)

        return analysis_results

    def _log_system_usage(self, group_name: str, tree: List[Certificate], system_hashes: Set[str]) -> None:
        """
        Calculates and logs how many certificates in the final tree
        originated from the system truststore.
        """
        used_system_certs = 0
        seen_hashes: Set[str] = set()

        def traverse(nodes: List[Certificate]) -> None:
            nonlocal used_system_certs
            for node in nodes:
                h = getattr(node, 'sha256_hash', None)
                if not h or h in seen_hashes:
                    continue
                seen_hashes.add(h)

                if getattr(node, 'is_system_cert', False):
                    used_system_certs += 1

                if node.children:
                    traverse(node.children)

        traverse(tree)

        total_system = len(system_hashes)

        message = _("{used} of the {total} system certificates used").format(
            used=used_system_certs,
            total=total_system,
        )
        INFO.log(f"[{group_name}] " + _("System usage"), message)

    def _resolve_targets(self, targets: List[Union[Path, bytes, Dict[str, Any]]], is_system: bool = False) -> List[Dict[str, Any]]:
        """
        Unifies different target types into a standard metadata format.
        """
        resolved: List[Dict[str, Any]] = []
        for t in targets:
            if isinstance(t, Path):
                resolved.extend(self.repo.load_from_files([t], is_system=is_system))
            elif isinstance(t, bytes):
                resolved.extend(self.repo.add_der_data(t, is_system=is_system))
            elif isinstance(t, dict) and "cert" in t:
                self.repo.seen_hashes.add(t["hash"])
                resolved.append(t)
        return resolved