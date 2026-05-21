"""
TrustStore Analyzer & Visualizer - ORCHESTRATION LAYER
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later

This module orchestrates the end-to-end analysis process. It connects
the certificate repository with the chain builder to process multiple
trust store groups and generate finalized analysis models.
"""

import os
import subprocess
import tempfile
from typing import Any, Optional, List, Dict, Set
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from cryptography.hazmat.primitives import serialization
try:
    from cryptography.hazmat.primitives.serialization import pkcs7
except ImportError:
    pkcs7 = None
from .repository import CertificateRepository
from .models import Certificate, CertificateGroup
from .builder import TrustChainBuilder
from .logging import _, INFO, WARNING, ERROR


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
        self._log_lock = Lock()

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
                    resolved_sys = self._resolve_targets_local(sys_group.targets, self.repo, is_system=True)
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

        def _worker(index: int, group_config: Any):
            """
            Worker function executed within parallel threads to analyze a specific certificate group.

            To ensure strict thread isolation and prevent race conditions, this worker
            instantiates a dedicated local CertificateRepository and TrustChainBuilder.
            It seeds the local repository with global system truststores (if enabled),
            resolves the targets, builds the validation tree, and optionally exports
            the finalized chain to a PKCS#7 bundle.

            Args:
                index (int): The thread or task index, utilized as a unique suffix
                    for bundle exports to prevent file collision.
                group_config (Any): The input group configuration object containing
                    the targets and metadata to analyze.

            Returns:
                tuple: A tuple containing:
                    - group_obj (CertificateGroup): The finalized and summarized analysis model.
                    - name (str): The display name of the certificate group.
                    - tree_data (List[Certificate]): The generated root-level trust tree data.
            """
            local_repo = CertificateRepository(**self.options)

            if self.include_system:
                for item in system_pool:
                    local_repo._register_cert(item["cert"], item["hash"])
                for item in blacklist_pool:
                    local_repo._register_cert(item["cert"], item["hash"])

            current_options = self.options.copy()
            target_host = getattr(group_config, 'target_hostname', None)
            if target_host:
                current_options['target_hostname'] = target_host

            builder = TrustChainBuilder(repository=local_repo, ignore_ct=getattr(group_config, 'ignore_ct', False), **current_options)

            local_targets = [t.copy() if isinstance(t, dict) else t for t in group_config.targets]
            current_pool = self._resolve_targets_local(local_targets, local_repo)

            from .discovery import NetworkResolver
            resolver = NetworkResolver(**current_options)

            tree_data = builder.build(
                current_pool,
                authority_pool=system_pool if self.include_system else None,
                blacklist_pool=blacklist_pool if self.include_system else None,
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

            if self.export_bundles:
                self.export_bundle(group_obj, self.export_dir, repo=local_repo, file_suffix=f"_{index}")

            return group_obj, group_config.name, tree_data

        with ThreadPoolExecutor(max_workers=min(10, len(self.groups))) as executor:
            futures = [executor.submit(_worker, i, g) for i, g in enumerate(self.groups)]

            for future in futures:
                try:
                    group_obj, g_name, tree_data = future.result()
                    analysis_results.append(group_obj)

                    if self.include_system and self.debug:
                        self._log_system_usage(g_name, tree_data, system_fingerprints)
                except Exception as e:
                    if self.debug:
                        with self._log_lock:
                            ERROR.log(_("Parallel Analysis"), _("Group failed: {error}").format(error=str(e)))

        return analysis_results

    def export_bundle(self, group: CertificateGroup, output_dir: str, repo: Optional[CertificateRepository] = None, file_suffix: str = "") -> Optional[Path]:
        """
        Universal PKCS#7 export compatible with RHEL 8 (Python 3.6) and Fedora 43.
        """
        try:
            active_repo = repo or self.repo
            raw_certs = [active_repo.get_cert_by_fingerprint(c.fingerprint) for c in group.chain]
            raw_certs = [c for c in raw_certs if c is not None]
            out_path = Path(output_dir)
            out_path.mkdir(parents=True, exist_ok=True)

            if not raw_certs:
                return None

            p7_data = None
            if pkcs7:
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
                pem_sequence = b"".join([c.public_bytes(serialization.Encoding.PEM) for c in raw_certs])
                try:
                    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as tmp_in:
                        tmp_in.write(pem_sequence)
                        tmp_in_name = tmp_in.name

                    with tempfile.NamedTemporaryFile(delete=False, suffix=".p7b") as tmp_out:
                        tmp_out_name = tmp_out.name

                    cmd = ["openssl", "crl2pkcs7", "-nocrl", "-certfile", tmp_in_name, "-out", tmp_out_name]
                    subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)

                    with open(tmp_out_name, "rb") as f:
                        p7_data = f.read()

                    try:
                        os.unlink(tmp_in_name)
                        os.unlink(tmp_out_name)
                    except Exception:
                        pass

                    if self.debug:
                        INFO.log(f"[{group.group_name}] " + _("Export"), _("Used OpenSSL CLI fallback to generate real PKCS#7 bundle"))

                except Exception as e:
                    if self.debug:
                        WARNING.log(f"[{group.group_name}] " + _("Export"), _("OpenSSL CLI fallback failed, using raw PEM list: {}").format(str(e)))
                    p7_data = pem_sequence

            if not p7_data:
                return None

            safe_name = group.group_name.replace(".", "_").replace(" ", "_")
            file_path = out_path / f"{safe_name}{file_suffix}_bundle.p7b"

            with open(file_path, "wb") as f:
                f.write(p7_data)

            INFO.log(f"[{group.group_name}] " + _("Export"), _("Trust bundle exported successfully to {}").format(file_path))
            return file_path

        except Exception as e:
            ERROR.log(_("Failed to export trust bundle"), str(e))
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

    def _resolve_targets_local(self, targets: List[Any], repo: CertificateRepository, is_system: bool = False) -> List[Dict[str, Any]]:
        """
        Unifies different target types into a standard metadata format.
        """
        resolved: List[Dict[str, Any]] = []
        for t in targets:
            if isinstance(t, Path):
                resolved.extend(repo.load_from_files([t], is_system=is_system))
            elif isinstance(t, bytes):
                resolved.extend(repo.add_der_data(t, is_system=is_system))
            elif isinstance(t, dict) and "cert" in t:
                c_hash = Certificate.calculate_fingerprint(t["cert"].public_bytes(serialization.Encoding.DER))
                repo._register_cert(t["cert"], c_hash)
                t["hash"] = c_hash
                resolved.append(t)
        return resolved