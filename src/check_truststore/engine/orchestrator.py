"""
TrustStore Analyzer & Visualizer - ORCHESTRATION LAYER
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later

This module orchestrates the end-to-end analysis process. It connects
the certificate repository with the chain builder to process multiple
trust store groups and generate finalized analysis models.
"""

from typing import Any, Optional, List, Dict, Union, Set
from cryptography.hazmat.primitives import serialization
from pathlib import Path
from .repository import CertificateRepository
from .models import Certificate, CertificateGroup
from .builder import TrustChainBuilder
from .logging import _, INFO, ERROR


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
        self.export_bundles = kwargs.get("export_bundles", False)
        self.export_dir = kwargs.get("export_dir", "output_bundles")
        self.groups: List[Any] = groups

    def analyze(self) -> List[CertificateGroup]:
        """
        Executes the analysis pipeline for all configured groups.
        """
        analysis_results: List[CertificateGroup] = []
        system_fingerprints: Set[str] = set()
        system_pool: List[Dict[str, Any]] = []
        blacklist_pool: List[Dict[str, Any]] = []

        if self.include_system:
            try:
                from ..providers.system_provider import SystemInputProvider
                sys_provider = SystemInputProvider(repository=self.repo, **self.options)

                for sys_group in sys_provider.get_groups():
                    is_untrusted_store = "Untrusted" in sys_group.name or "Disallowed" in sys_group.name
                    resolved_sys = self._resolve_targets(sys_group.targets, is_system=True)
                    if is_untrusted_store:
                        blacklist_pool.extend(resolved_sys)
                    else:
                        system_pool.extend(resolved_sys)
                        for item in resolved_sys:
                            system_fingerprints.add(item["hash"])
            except Exception as e:
                if self.debug:
                    from .logging import WARNING
                    WARNING.log(_("SystemProvider"), _("Could not load system truststore: {error}").format(error=e))

        for group_config in self.groups:
            if self.debug:
                INFO.log(_("Processing Group"), group_config.name)

            self.repo.clear_cache()

            current_options = self.options.copy()
            target_host = getattr(group_config, 'target_hostname', None)
            if target_host:
                current_options['target_hostname'] = target_host

            builder = TrustChainBuilder(repository=self.repo, **current_options)
            current_pool = self._resolve_targets(group_config.targets)

            from .discovery import NetworkResolver
            resolver = NetworkResolver(**current_options)

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

            if self.export_bundles:
                self.export_bundle(group_obj, self.export_dir)

            if self.include_system and self.debug:
                self._log_system_usage(group_config.name, group_obj.tree, system_fingerprints)

        return analysis_results

    def export_bundle(self, group: CertificateGroup, output_dir: str) -> Optional[Path]:
        """
        Universal PKCS#7 export compatible with RHEL 8 (Python 3.6) and Fedora 43.
        """
        try:
            from cryptography.hazmat.primitives.serialization import pkcs7

            raw_certs = [self.repo.get_cert_by_fingerprint(c.fingerprint) for c in group.chain]
            raw_certs = [c for c in raw_certs if c is not None]

            if not raw_certs:
                return None

            p7_data = None

            if hasattr(pkcs7, "serialize_certificates"):
                try:
                    p7_data = pkcs7.serialize_certificates(raw_certs, serialization.Encoding.PEM)
                except Exception:
                    pass

            if not p7_data and hasattr(pkcs7, "PKCS7SignatureBuilder"):
                try:
                    builder = pkcs7.PKCS7SignatureBuilder()
                    for c in raw_certs:
                        builder = builder.add_certificate(c)

                    if hasattr(builder, "serialize"):
                        p7_data = builder.serialize(serialization.Encoding.PEM)
                    elif hasattr(builder, "finish"):
                        p7_data = builder.finish(serialization.Encoding.PEM)
                except Exception:
                    pass

            if not p7_data:
                if self.debug:
                    INFO.log(_("Export"), _("Using PEM sequence fallback for legacy environment"))
                p7_data = b"".join([c.public_bytes(serialization.Encoding.PEM) for c in raw_certs])

            out_path = Path(output_dir)
            out_path.mkdir(parents=True, exist_ok=True)
            safe_name = group.group_name.replace(".", "_").replace(" ", "_")
            file_path = out_path / f"{safe_name}_bundle.p7b"

            with open(file_path, "wb") as f:
                f.write(p7_data)

            if self.debug:
                INFO.log(f"[{group.group_name}] " + _("Export"), _("Bundle saved to {path}").format(path=file_path))

            return file_path

        except Exception as e:
            if self.debug:
                ERROR.log(_("Export"), _("Failed to create bundle: {error}").format(error=str(e)))
            return None

    def _log_system_usage(self, group_name: str, tree: List[Certificate], system_fingerprints: Set[str]) -> None:
        """
        Calculates and logs how many certificates in the final tree
        originated from the system truststore.
        """
        used_system_certs = 0
        seen_hashes: Set[str] = set()

        def traverse(nodes: List[Certificate]) -> None:
            nonlocal used_system_certs
            for node in nodes:
                h = node.fingerprint
                if not h or h in seen_hashes:
                    continue
                seen_hashes.add(h)

                if getattr(node, 'is_system_cert', False):
                    used_system_certs += 1

                if node.children:
                    traverse(node.children)

        traverse(tree)

        total_system = len(system_fingerprints)

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
                c_hash = Certificate.calculate_fingerprint(t["cert"].public_bytes(serialization.Encoding.DER))
                self.repo._register_cert(t["cert"], c_hash)
                t["hash"] = c_hash
                resolved.append(t)
        return resolved