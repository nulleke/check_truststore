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
from typing import Any, Optional, List, Dict, Set, Tuple
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
    """High-level orchestrator managing certificate groups and pipelines.

    Coordinates loading tasks, multi-threaded chain resolution, cryptographic
    verification, telemetry tracking, and platform-agnostic PKCS#7 bundle exports.
    """
    def __init__(self, groups: List[Any], repository: Optional[CertificateRepository] = None, **kwargs: Any) -> None:
        """Initializes the orchestration engine with asset domains and config contexts.

        Args:
            groups: List of target configurations or paths to process into tree layers.
            repository: Optional custom repository instance. Creates a default instance if omitted.
            **kwargs: Configuration flags forwarded directly into repository and builder scopes.
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
        """Executes structural loading, cryptographic verification, and tree building for all groups.

        Utilizes a thread pool to concurrently isolate and process group data-structures,
        evaluating them against optional local operating system trust roots and blacklists.

        Returns:
            A list of fully populated CertificateGroup models enclosing the finalized trees.
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

        def _worker(index: int, group_config: Any) -> Tuple[CertificateGroup, str, List[Certificate]]:
            """Worker function executed within parallel threads to analyze a specific certificate group.

            To ensure strict thread isolation and prevent race conditions, this worker
            instantiates a dedicated local CertificateRepository and TrustChainBuilder.
            It seeds the local repository with global system truststores (if enabled),
            resolves the targets, builds the validation tree, and optionally exports
            the finalized chain to a PKCS#7 bundle.

            Args:
                index: The thread or task index, utilized as a unique suffix
                    for bundle exports to prevent file collisions.
                group_config: The input group configuration object containing
                    the targets and metadata to analyze.

            Returns:
                A tuple containing:
                    - group_obj (CertificateGroup): The finalized analysis model.
                    - name (str): The display name of the certificate group.
                    - tree_data (List[Certificate]): The generated root-level trust tree.
            """
            if self.debug:
                with self._log_lock:
                    INFO.log(_("Processing Group"), group_config.name)

            local_repo: CertificateRepository = CertificateRepository(**self.options)

            if self.include_system:
                for item in system_pool:
                    local_repo._register_cert(item["cert"], item["hash"])
                for item in blacklist_pool:
                    local_repo._register_cert(item["cert"], item["hash"])

            current_options: Dict[str, Any] = self.options.copy()
            target_host: Optional[str] = getattr(group_config, 'target_hostname', None)
            if target_host:
                current_options['target_hostname'] = target_host

            builder: TrustChainBuilder = TrustChainBuilder(repository=local_repo, disabled_checks=getattr(group_config, 'disabled_checks', False), **current_options)

            local_targets: List[Any] = [t.copy() if isinstance(t, dict) else t for t in group_config.targets]
            current_pool: List[Dict[str, Any]] = self._resolve_targets_local(local_targets, local_repo)

            from .discovery import NetworkResolver
            resolver = NetworkResolver(**current_options)

            tree_data: List[Certificate] = builder.build(
                current_pool,
                authority_pool=system_pool if self.include_system else None,
                blacklist_pool=blacklist_pool if self.include_system else None,
                resolver=resolver,
                max_depth=self.max_depth
            )

            group_obj: CertificateGroup = CertificateGroup(
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
        """Universal PKCS#7 export compatible with RHEL 8 (Python 3.6) and Fedora 43.

        Attempts to serialize cryptographic certificates cleanly using available
        PyCa/Cryptography PKCS#7 APIs, falling back seamlessly onto a secure local
        OpenSSL subprocess execution context if needed.

        Args:
            group: Finalized CertificateGroup module containing the target chain.
            output_dir: Local system filesystem directory to house output assets.
            repo: Optional context-specific CertificateRepository instance.
            file_suffix: Deduplication differentiator added to the output filename.

        Returns:
            The resolved Path pointer pointing to the generated archive, or None if failed.
        """
        try:
            active_repo: CertificateRepository = repo or self.repo
            raw_certs: List[Any] = [active_repo.get_cert_by_fingerprint(c.fingerprint) for c in group.chain]
            raw_certs = [c for c in raw_certs if c is not None]
            out_path: Path = Path(output_dir)
            out_path.mkdir(parents=True, exist_ok=True)

            if not raw_certs:
                return None

            p7_data: Optional[bytes] = None
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
                pem_sequence: bytes = b"".join([c.public_bytes(serialization.Encoding.PEM) for c in raw_certs])
                try:
                    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as tmp_in:
                        tmp_in.write(pem_sequence)
                        tmp_in_name: str = tmp_in.name

                    with tempfile.NamedTemporaryFile(delete=False, suffix=".p7b") as tmp_out:
                        tmp_out_name: str = tmp_out.name

                    cmd: List[str] = ["openssl", "crl2pkcs7", "-nocrl", "-certfile", tmp_in_name, "-out", tmp_out_name]
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

            safe_name: str = group.group_name.replace(".", "_").replace(" ", "_")
            file_path: Path = out_path / f"{safe_name}{file_suffix}_bundle.p7b"

            with open(file_path, "wb") as f:
                f.write(p7_data)

            INFO.log(f"[{group.group_name}] " + _("Export"), _("Trust bundle exported successfully to {}").format(file_path))
            return file_path

        except Exception as e:
            ERROR.log(_("Failed to export trust bundle"), str(e))
            return None

    def _log_system_usage(self, group_name: str, tree: List[Certificate], system_fingerprints: Set[str]) -> None:
        """Tracks and outputs telemetry indicating how many system roots were utilized in a tree.

        Args:
            group_name: Context tag identifier for log matching.
            tree: Hierarchical list structure evaluated for anchor presence.
            system_fingerprints: Set containing all known OS root certificate fingerprints.
        """
        used_system_certs: int = 0
        seen_hashes: Set[str] = set()

        def traverse(nodes: List[Certificate]) -> None:
            nonlocal used_system_certs
            for node in nodes:
                h: Optional[str] = node.fingerprint
                if not h or h in seen_hashes:
                    continue
                seen_hashes.add(h)

                if getattr(node, 'is_system_cert', False):
                    used_system_certs += 1

                if node.children:
                    traverse(node.children)

        traverse(tree)

        total_system: int = len(system_fingerprints)

        message: str = _("{used} of the {total} system certificates used").format(
            used=used_system_certs,
            total=total_system,
        )
        INFO.log(f"[{group_name}] " + _("System usage"), message)

    def _resolve_targets_local(self, targets: List[Any], repo: CertificateRepository, is_system: bool = False) -> List[Dict[str, Any]]:
        """Unifies raw multi-type targets (Files, Bytes, PEM, DER) into standardized metadata indexes.

        Args:
            targets: Mixed tracking collection of certificate pointers.
            repo: Target CertificateRepository engine context.
            is_system: Flag determining if these entries behave as trusted anchors.

        Returns:
            A list of structured dictionary objects matching application metadata schemas.
        """
        resolved: List[Dict[str, Any]] = []
        for t in targets:
            if isinstance(t, Path):
                resolved.extend(repo.load_from_files([t], is_system=is_system))
            elif isinstance(t, bytes):
                resolved.extend(repo.add_der_data(t, is_system=is_system))
            elif isinstance(t, dict) and "cert" in t:
                c_hash: str = Certificate.calculate_fingerprint(t["cert"].public_bytes(serialization.Encoding.DER))
                repo._register_cert(t["cert"], c_hash)
                t["hash"] = c_hash
                resolved.append(t)
        return resolved