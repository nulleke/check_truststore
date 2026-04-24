"""
TrustStore Analyzer & Visualizer - CORE MODULE
Architect: Serge van Thillo

This module contains the engine for scanning, building, and validating
X.509 certificate trust chains.
"""

import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", message=".*serial number.*")
warnings.filterwarnings("ignore", message=".*Python 3.6 is no longer supported.*")

import hashlib  # noqa: E402
import platform  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.backends import default_backend  # noqa: E402
from cryptography.x509.oid import ExtensionOID  # noqa: E402
from datetime import datetime, timedelta, timezone  # noqa: E402
from pathlib import Path  # noqa: E402
from collections import defaultdict  # noqa: E402
from typing import Any, Optional, List, Dict, Union, Set  # noqa: E402
from .logging import (  # noqa: E402
    _, ERROR, OK, WARNING, MISSING, COLLISION, INFO, SYSTEM, 
    Icons as Icons
)
from .models import ORPHAN_NODE_ID, Certificate, CertificateGroup  # noqa: E402


class CertificateRepository:
    """
    Handles the discovery and raw loading of certificates from the filesystem or OS stores.
    It manages deduplication using SHA256 hashes.
    """

    def __init__(self, debug: bool = False):
        self.debug = debug
        self.seen_hashes: Set[str] = set()
        self.total_scanned_count: int = 0

    def load_from_files(
        self, paths: List[Path], is_system: bool = False
    ) -> List[Dict[str, Any]]:
        """Iterates through a list of paths to extract PEM-encoded certificates."""
        collected_certs = []
        for path in paths:
            collected_certs.extend(self._load_single_file(path, is_system=is_system))
        return collected_certs

    def _load_single_file(
        self, path: Path, is_system: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Reads a file and extracts certificates using regex.
        Supports standard PEM and 'TRUSTED CERTIFICATE' formats (common in OpenSSL).
        """
        certs_in_file = []
        try:
            with open(str(path), "rb") as f:
                content = f.read()

            import re

            # Regex to find certificates, including those marked as "TRUSTED CERTIFICATE"
            pattern = b"-----BEGIN (?:TRUSTED )?CERTIFICATE-----.*?-----END (?:TRUSTED )?CERTIFICATE-----"
            cert_blocks = re.findall(pattern, content, re.DOTALL)

            for raw_block in cert_blocks:
                self.total_scanned_count += 1
                c_hash = hashlib.sha256(raw_block).hexdigest()

                if c_hash in self.seen_hashes:
                    if self.debug and not is_system:
                        WARNING.log(
                            path.name,
                            _("Skipping duplicate certificate (already loaded)"),
                            label=_("DUPLICATE"),
                        )
                    continue

                try:
                    # Strip 'TRUSTED ' prefix if present to satisfy standard x50
                    pem_block = raw_block.replace(b"TRUSTED ", b"")
                    cert = x509.load_pem_x509_certificate(pem_block, default_backend())

                    self.seen_hashes.add(c_hash)
                    certs_in_file.append(
                        {
                            "cert": cert,
                            "path": path,
                            "hash": c_hash,
                            "is_system_cert": is_system,
                        }
                    )

                except Exception as e:
                    if self.debug:
                        ERROR.log(
                            path.name, f"{_('Invalid certificate structure')}: {str(e)}"
                        )

        except (FileNotFoundError, PermissionError) as e:
            if self.debug and not is_system:
                label = _("READ_ERROR")
                msg = (
                    _("File not found")
                    if isinstance(e, FileNotFoundError)
                    else _("Permission denied")
                )
                ERROR.log(path.name, f"{msg}: {path.absolute()}", label=label)

        except Exception as e:
            if self.debug and not is_system:
                ERROR.log(path.name, str(e), label=_("READ_ERROR"))

        return certs_in_file

    def load_from_system(self) -> List[Dict[str, Any]]:
        """Auto-detects the operating system and loads its default truststore."""
        os_type = platform.system()
        results = []

        if os_type == "Windows":
            results.extend(self._load_windows_store())
        else:
            paths = self._get_unix_ca_paths(os_type)
            results.extend(self.load_from_files(paths, is_system=True))

        return results

    def _get_unix_ca_paths(self, os_type: str) -> List[Path]:
        """Returns standard CA bundle paths for various Unix/Linux distributions."""
        paths = []
        if os_type == "Linux":
            common = [
                "/etc/pki/tls/certs/ca-bundle.crt",  # Fedora/RHEL/CentOS 6
                "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",  # RHEL/CentOS 7+
                "/etc/ssl/certs/ca-certificates.crt",  # Debian/Ubuntu/Arch
                "/etc/ssl/ca-bundle.pem",  # OpenSUSE
                "/etc/ca-certificates/extracted/tls-ca-bundle.pem",  # Arch/SuSE
            ]

            for p in common:
                path_obj = Path(p)
                if path_obj.exists():
                    paths.append(path_obj)
                    break

        elif os_type == "Darwin":
            p = Path("/etc/ssl/cert.pem")  # macOS
            if p.exists():
                paths.append(p)

        return paths

    def _load_windows_store(self) -> List[Dict[str, Any]]:
        """Accesses the Windows Certificate Store (ROOT and CA) using the ssl module."""
        import ssl

        found = []
        for store_name in ["ROOT", "CA"]:
            for cert_der in ssl.enum_certificates(store_name):
                self.total_scanned_count += 1
                try:
                    cert = x509.load_der_x509_certificate(
                        cert_der[0], default_backend()
                    )
                    c_hash = hashlib.sha256(cert_der[0]).hexdigest()

                    if c_hash in self.seen_hashes:
                        continue

                    found.append(
                        {
                            "cert": cert,
                            "path": Path(f"Windows-{store_name}-Store"),
                            "hash": c_hash,
                            "is_system_cert": True,
                        }
                    )

                    self.seen_hashes.add(c_hash)

                except Exception:
                    continue
        return found


class TrustChainBuilder:
    """
    Main logic for assembling flat certificates into a hierarchical tree.
    It matches Authority Key Identifiers (AKI) to Subject Key Identifiers (SKI).
    """

    def __init__(self, threshold_days: int = 30, debug: bool = False):
        self.threshold_days = threshold_days
        self.debug = debug
        self.cert_data: Dict[str, Certificate] = {}
        self.raw_certs: Dict[str, x509.Certificate] = {}
        self.parent_map: Dict[str, str] = {}
        self.name_count: Dict[str, int] = defaultdict(int)

    def build(self, raw_certs_meta: List[Dict[str, Any]]) -> List[Certificate]:
        """Main entry point for tree construction."""
        for item in raw_certs_meta:
            self._process_metadata(item)

        tree_result = self._create_tree()

        if self.debug:
            self._log_debug_summary()

        return tree_result

    def _process_metadata(self, item: Dict[str, Any]):
        """Extracts X509 fields and prepares the internal mapping for chain building."""
        cert = item["cert"]
        path = item["path"]
        c_hash = item["hash"]
        is_system_cert = item.get("is_system_cert", False)

        ski = self._get_extension(cert, x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        cn = self._get_common_name(cert)
        # Use SKI as ID, fallback to public key hash if SKI is missing
        cert_id = (
            ski if ski else hashlib.sha256(cert.subject.public_bytes()).hexdigest()
        )
        formatted_serial = self._get_serial_number(cert)

        # Avoid overwriting user certs with system certs during analysis
        if cert_id in self.cert_data:
            existing = self.cert_data[cert_id]
            if is_system_cert and not existing.is_system_cert:
                return
            if not is_system_cert and existing.is_system_cert:
                self.name_count[cn] -= 1
            else:
                return

        self.raw_certs[cert_id] = cert
        self.name_count[cn] += 1

        aki = self._get_extension(cert, x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
        expiry = (
            cert.not_valid_after_utc
            if hasattr(cert, "not_valid_after_utc")
            else cert.not_valid_after.replace(tzinfo=timezone.utc)
        )
        expiry = expiry.replace(microsecond=0)
        start_date = (
            cert.not_valid_before_utc
            if hasattr(cert, "not_valid_before_utc")
            else cert.not_valid_before.replace(tzinfo=timezone.utc)
        )
        start_date = start_date.replace(microsecond=0)
        now = datetime.now(timezone.utc)
        sans = (
            self._get_extension(cert, x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME) or []
        )
        display_file_name = "" if is_system_cert else path.name

        self.cert_data[cert_id] = Certificate(
            commonName=cn,
            serialNumber=formatted_serial,
            certId=cert_id,
            ski=ski,
            fileName=display_file_name,
            sha256Hash=c_hash,
            isValid=(start_date <= now <= expiry),
            isExpiringSoon=(
                now <= expiry <= (now + timedelta(days=self.threshold_days))
            ),
            expiryDate=expiry,
            isSystemCert=is_system_cert,
            isRoot=(cert.subject == cert.issuer),
            sanNames=sans,
        )

        if aki and aki != cert_id:
            self.parent_map[cert_id] = aki
        elif cert.subject != cert.issuer:
            self.parent_map[cert_id] = ORPHAN_NODE_ID

    def _verify_signature(
        self, cert_to_check: x509.Certificate, issuer_cert: x509.Certificate
    ) -> bool:
        """Performs cryptographic signature verification using the issuer's public key."""
        try:
            from cryptography.hazmat.primitives.asymmetric import (
                rsa,
                ec,
                padding as rsa_padding,
            )
            from cryptography.hazmat.primitives import hashes

            issuer_public_key = issuer_cert.public_key()
            signature = cert_to_check.signature
            data = cert_to_check.tbs_certificate_bytes
            hash_algo = cert_to_check.signature_hash_algorithm

            if isinstance(issuer_public_key, rsa.RSAPublicKey):
                issuer_public_key.verify(
                    signature, data, rsa_padding.PKCS1v15(), hash_algo
                )
                return True

            elif isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
                try:
                    issuer_public_key.verify(signature, data, ec.ECDSA(hash_algo))
                except Exception:
                    algo_name = hash_algo.name.upper()
                    new_algo = getattr(hashes, algo_name)()
                    issuer_public_key.verify(signature, data, ec.ECDSA(new_algo))
                return True

            else:
                issuer_public_key.verify(signature, data, hash_algo)
                return True

        except Exception:
            return False

    def get_analysis_summary(self) -> Dict[str, Any]:
        """Calculates statistics only for the chains relevant to user-loaded certificates."""
        target_skis = {
            ski for ski, cert in self.cert_data.items() if not cert.is_system_cert
        }
        relevant_skis = set()
        for ski in target_skis:
            curr = ski
            while curr and curr in self.cert_data:
                relevant_skis.add(curr)
                curr = self.parent_map.get(curr)

        stats = {
            "ok": 0,
            "warning": 0,
            "error": 0,
            "system": 0,
            "total": len(relevant_skis),
        }
        for ski in relevant_skis:
            c = self.cert_data[ski]
            if c.is_system_cert:
                stats["system"] += 1
            if not c.is_valid or c.signature_valid is False:
                stats["error"] += 1
            elif c.is_expiring_soon:
                stats["warning"] += 1
            else:
                stats["ok"] += 1

        known_skis = set(self.cert_data.keys())
        missing = []
        for c_id in relevant_skis:
            aki = self.parent_map.get(c_id)
            if aki and aki not in known_skis and aki != ORPHAN_NODE_ID:
                missing.append(
                    {
                        "aki": aki,
                        "child_cn": self.cert_data[c_id].common_name,
                        "child_id": c_id[:8],
                    }
                )

        return {"statistics": stats, "unresolved_issuers": missing}

    def _log_debug_summary(self):
        """Prints a flat list of all relevant certificates with their status and ID."""
        target_skis = {
            ski for ski, cert in self.cert_data.items() if not cert.is_system_cert
        }
        relevant_skis = set()

        for ski in target_skis:
            curr = ski
            while curr and curr in self.cert_data:
                relevant_skis.add(curr)
                curr = self.parent_map.get(curr)

        unique_relevant = list(relevant_skis)

        def sort_key(ski):
            obj = self.cert_data[ski]
            sig_order = (
                0
                if obj.signature_valid is True
                else (1 if obj.signature_valid is None else 2)
            )
            return (sig_order, obj.common_name.lower())

        unique_relevant.sort(key=sort_key)

        for ski in unique_relevant:
            cert_obj = self.cert_data[ski]
            cert_obj.is_collision = self.name_count[cert_obj.common_name] > 1

            current_label = None
            is_untrusted = self.parent_map.get(ski) == ORPHAN_NODE_ID

            if cert_obj.signature_valid is False and not is_untrusted:
                st = ERROR
                current_label = _("SIG_ERR")
            elif not cert_obj.is_valid:
                st = ERROR
                current_label = _("INVALID")
            elif cert_obj.is_expiring_soon:
                st = WARNING
            elif cert_obj.is_system_cert:
                st = SYSTEM
            else:
                st = OK

            sig_icon = cert_obj.signature_icon
            coll_icon = COLLISION.ICON if cert_obj.is_collision else ""
            combined_extra = f"{sig_icon}{coll_icon}"

            log_name = (
                f"{cert_obj.common_name} (ID: {cert_obj.cert_id[:8]})"
                if cert_obj.is_collision
                else cert_obj.common_name
            )

            st.log(
                log_name,
                cert_obj.expiry_date.strftime("%Y-%m-%d %H:%M"),
                label=current_label,
                extra_icon=combined_extra,
            )

        known_skis = set(self.cert_data.keys())
        missing_issuers = defaultdict(list)
        for c_id in relevant_skis:
            aki = self.parent_map.get(c_id)
            if aki and aki not in known_skis and aki != ORPHAN_NODE_ID:
                missing_issuers[aki].append(self.cert_data[c_id].common_name)

        for aki, child_names in missing_issuers.items():
            MISSING.log(
                f"AKI: {aki[:8]}",
                _("Missing issuer for: {name}").format(
                    name=", ".join(sorted(child_names))
                ),
                label=_("UNTRUSTED"),
            )

    def _can_act_as_ca(self, cert: x509.Certificate) -> bool:
        """Checks BasicConstraints and KeyUsage to verify if a cert is allowed to sign others."""
        try:
            bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
            if not bc.value.ca:
                return False

            try:
                ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
                if not ku.value.key_cert_sign:
                    return False
            except x509.ExtensionNotFound:
                pass

            return True
        except x509.ExtensionNotFound:
            return False

    def get_flat_chain(self) -> List[Certificate]:
        """Returns a flat list of unique certificates involved in all active chains."""
        target_skis = {
            ski
            for ski, cert in self.cert_data.items()
            if not getattr(cert, "is_system_cert", False)
        }

        relevant_skis = set()
        for ski in target_skis:
            curr = ski
            while curr and curr in self.cert_data:
                relevant_skis.add(curr)
                curr = self.parent_map.get(curr)

        flat_list = []
        for ski in relevant_skis:
            cert_obj = self.cert_data[ski]

            if hasattr(cert_obj, "model_copy"):
                clean_cert = cert_obj.model_copy(update={"children": []})
            else:
                import copy

                clean_cert = copy.copy(cert_obj)
                clean_cert.children = []

            flat_list.append(clean_cert)

        return sorted(flat_list, key=lambda x: x.common_name.lower())

    def _create_tree(self) -> List[Certificate]:
        """
        The core recursive algorithm.
        It filters certificates to only show chains that lead to a user-provided cert.
        """
        # Step 1: Identify all SKIs that are part of a target chain
        target_skis = {
            ski for ski, cert in self.cert_data.items() if not cert.is_system_cert
        }
        relevant_skis = set()

        for ski in target_skis:
            current = ski
            visited = set()
            while current and current not in visited:
                relevant_skis.add(current)
                visited.add(current)
                parent_ski = self.parent_map.get(current)
                if (
                    not parent_ski
                    or parent_ski not in self.cert_data
                    or parent_ski == current
                ):
                    break
                current = parent_ski

        # Step 2: Build a lookup for children to allow recursive traversal
        children_by_parent = defaultdict(list)
        for ski in relevant_skis:
            p_ski = self.parent_map.get(ski)
            if p_ski and p_ski in relevant_skis and p_ski != ski:
                children_by_parent[p_ski].append(ski)

        # Step 3: Recursive function to build Node objects
        def to_node(ski: str, parent_status: str = "VALID") -> Certificate:
            cert_info = self.cert_data[ski]
            raw_cert = self.raw_certs.get(ski)
            p_ski = self.parent_map.get(ski)

            if raw_cert:
                is_root = (
                    getattr(cert_info, "is_root", False)
                    or p_ski == ski
                    or p_ski is None
                )
                issuer_raw = raw_cert if is_root else self.raw_certs.get(p_ski)

                if issuer_raw:
                    # Validate crypto-signature
                    cert_info.signature_valid = self._verify_signature(
                        raw_cert, issuer_raw
                    )
                    # Policy check: Is the parent actually a CA?
                    if (
                        not is_root
                        and cert_info.signature_valid
                        and not self._can_act_as_ca(issuer_raw)
                    ):
                        cert_info.is_valid = False
                        cert_info.validation_error = "PARENT_NOT_A_CA"
                else:
                    cert_info.signature_valid = None

            # Inherit 'invalidity' from parents (Chain of trust)
            if parent_status not in ["VALID", "SYSTEM", "OK"] and cert_info.is_valid:
                cert_info.is_valid = False
                cert_info.validation_error = f"CHAIN_{parent_status}"

            # Recurse for children
            child_skis = children_by_parent.get(ski, [])
            sorted_child_skis = sorted(
                child_skis,
                key=lambda x: (
                    self.cert_data[x].common_name,
                    str(self.cert_data[x].expiry_date),
                    self.cert_data[x].sha256_hash,
                ),
            )

            processed_children = []
            for c_ski in sorted_child_skis:
                child_node = to_node(c_ski, cert_info.status_label)
                processed_children.append(child_node)

            cert_info.children = processed_children
            return cert_info

        # Step 4: Find Roots and Orphans to start the tree
        trusted_tree = []
        orphan_skis = []

        roots = [
            ski
            for ski in relevant_skis
            if self.parent_map.get(ski) not in relevant_skis
        ]

        for r_ski in sorted(roots, key=lambda x: self.cert_data[x].common_name.lower()):
            p_id = self.parent_map.get(r_ski)
            if p_id is None or p_id == r_ski:
                trusted_tree.append(to_node(r_ski))
            else:
                orphan_skis.append(r_ski)

        if orphan_skis:
            ext_node = self._create_virtual_node(ORPHAN_NODE_ID)
            ext_node.children = [
                to_node(o)
                for o in sorted(
                    orphan_skis, key=lambda x: self.cert_data[x].common_name.lower()
                )
            ]
            trusted_tree.append(ext_node)

        return trusted_tree

    def _get_common_name(self, cert) -> str:
        try:
            names = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            return names[0].value if names else _("Unknown")
        except Exception:
            return _("Unknown")

    def _get_serial_number(self, cert: x509.Certificate) -> str:
        s = format(cert.serial_number, "X")
        if len(s) % 2 != 0:
            s = "0" + s
        return ":".join(s[i : i + 2] for i in range(0, len(s), 2))

    def _get_extension(
        self, cert: x509.Certificate, oid: x509.ObjectIdentifier
    ) -> Optional[Union[str, List[str]]]:
        """Extracts and formats specific X509 extensions like SKI, AKI, or SAN."""
        present_oids = [e.oid for e in cert.extensions]

        if oid not in present_oids:
            if oid == x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                return []
            return None

        try:
            ext = cert.extensions.get_extension_for_oid(oid)

            if oid == x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER:
                return ext.value.digest.hex()

            if oid == x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER:
                return (
                    ext.value.key_identifier.hex() if ext.value.key_identifier else None
                )

            if oid == x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                return [
                    str(name.value)
                    for name in ext.value
                    if isinstance(name, x509.DNSName)
                ]

        except Exception:
            if oid == x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                return []
            return None

        return None

    def _create_virtual_node(self, name: str) -> Certificate:
        """Creates a dummy node for grouping orphans (missing/external roots)."""
        epoch_date = datetime(1970, 1, 1, tzinfo=timezone.utc)
        return Certificate(
            commonName=name,
            serialNumber="N/A",
            certId=f"VIRTUAL_{name}",
            isValid=False,
            isExpiringSoon=False,
            expiryDate=epoch_date,
            isCollision=False,
            isSystemCert=False,
            children=[],
        )


class TrustStoreAnalyzer:
    """
    High-level orchestrator that manages groups and triggers the analysis pipeline.
    Connects the Repository to the Builder and returns serialized models.
    """

    def __init__(self, groups: List[Any], **kwargs):
        self.debug = kwargs.get("debug", False)
        self.include_system = kwargs.get("system", False)
        self.groups = groups

        self.repo = CertificateRepository(debug=self.debug)
        self.threshold = kwargs.get("threshold", 30)

    def analyze(self) -> List[CertificateGroup]:
        """Main entry point for analyzing all configured groups."""
        analysis_results = []

        system_certs_data = []
        system_hashes = set()

        if self.include_system:
            self.repo.total_scanned_count = 0
            system_certs_data = self.repo.load_from_system()
            system_hashes = {c["hash"] for c in system_certs_data}

        for group_config in self.groups:
            if self.debug:
                INFO.log(_("Processing Group"), group_config.name)

            builder = TrustChainBuilder(threshold_days=self.threshold, debug=self.debug)

            current_pool = []
            for target in group_config.targets:
                if isinstance(target, list):
                    current_pool.extend(target)
                else:
                    current_pool.append(target)

            if self.include_system:
                current_pool.extend(system_certs_data)

            tree_data = builder.build(current_pool)

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
                used_count = sum(
                    1
                    for c in builder.cert_data.values()
                    if c.sha256_hash in system_hashes
                    and any(
                        self._is_in_tree(c.sha256_hash, node) for node in group_obj.tree
                    )
                )

                INFO.log(
                    f"[{group_config.name}] " + _("System usage"),
                    _("Used {used} out of {total} system certs").format(
                        used=used_count, total=len(system_hashes)
                    ),
                )

        return analysis_results

    def _is_in_tree(self, target_hash: str, node: Certificate) -> bool:
        """Helper to check if a specific cert hash exists within a tree branch."""
        if getattr(node, "sha256_hash", None) == target_hash:
            return True
        if node.children:
            return any(self._is_in_tree(target_hash, child) for child in node.children)
        return False
