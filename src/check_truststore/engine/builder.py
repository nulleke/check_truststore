"""
TrustStore Analyzer & Visualizer - CHAIN BUILDER
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later

This module contains the logic for recursively building and validating
X.509 certificate trust chains. It resolves subjects to issuers and
validates signatures and metadata throughout the chain.
"""

from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from typing import Any, Optional, List, Dict, Union, Set
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from .models import ORPHAN_NODE_ID, CYCLE_NODE_ID, Certificate
from .policy import PolicyEngine, PolicyFinding
from .repository import CertificateRepository
from .logging import _, OK, EXPIRING, WARNING, MISSING, ERROR, COLLISION, SYSTEM, AIA, REVOKED, Icons as Icons

def N_(message):
    return message

class TrustChainBuilder:
    """
    Main logic for assembling flat certificates into a hierarchical tree.
    It matches Authority Key Identifiers (AKI) to Subject Key Identifiers (SKI).
    """
    def __init__(self, repository: CertificateRepository, **kwargs):
        self.repo = repository
        self.options = kwargs
        self.threshold = kwargs.get('threshold', 30)
        self.debug = kwargs.get('debug', False)
        self.verbosity = kwargs.get('verbosity', 0)
        self.cert_data: Dict[str, Certificate] = {}
        self.raw_certs: Dict[str, x509.Certificate] = {}
        self.parent_map: Dict[str, str] = {}
        self.name_count: Dict[str, int] = defaultdict(int)
        self.policy_engine = PolicyEngine(**kwargs)
        self.parents_map: Dict[str, List[str]] = defaultdict(list)

    def build(
        self,
        raw_certs_meta: List[Dict[str, Any]],
        authority_pool: Optional[List[Dict[str, Any]]] = None,
        blacklist_pool: Optional[List[Dict[str, Any]]] = None,
        resolver: Optional[Any] = None,
        max_depth: int = 4
    ) -> List[Certificate]:
        """
        Main entry point for tree construction.

        :param raw_certs_meta: Certificaten die de gebruiker expliciet wil scannen.
        :param authority_pool: Systeem- of extra certificaten (alleen gebruiken als nodig).
        :param resolver: Optionele NetworkResolver voor AIA/OCSP.
        :param max_depth: Maximale diepte voor recursie.
        """
        for item in raw_certs_meta:
            self._process_metadata(item)

        if blacklist_pool:
            for item in blacklist_pool:
                item["is_blacklisted"] = True
                self._process_metadata(item)

        if authority_pool:
            for item in authority_pool:
                self._process_metadata(item)

        if resolver:
            self._perform_aia_discovery(resolver, max_depth=max_depth)

        tree_result = self._create_tree(resolver=resolver)

        if self.debug:
            self._log_debug_summary()

        return tree_result

    def _process_metadata(self, item: Dict[str, Any]):
        """Extracts X509 fields and prepares the internal mapping for chain building."""
        cert = item["cert"]
        c_hash = item["hash"]
        if hasattr(self.repo, "_register_cert"):
            self.repo._register_cert(cert, c_hash)
        path = item["path"]
        is_system_cert = item.get("is_system_cert", False)
        is_blacklisted = item.get("is_blacklisted", False)
        is_aia_cert = item.get("is_aia_cert", False)

        ski = self._get_extension(cert, x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        cn = self._get_common_name(cert)
        subject_sn = self._get_subject_serial(cert)

        if ski:
            cert_id = ski
        else:
            pk_bytes = cert.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            cert_id = Certificate.calculate_fingerprint(pk_bytes)

        if not cn:
            if subject_sn:
                cn = f"{_('Serial')}: {subject_sn}"
            else:
                cn = f"{_('Unknown')} ({cert_id[:8]})"

        aki = self._get_extension(cert, x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
        is_root = self.policy_engine.is_root_ca(cert)

        if aki and aki != cert_id:
            if aki not in self.parents_map[cert_id]:
                self.parents_map[cert_id].append(aki)
            if cert_id not in self.parent_map:
                self.parent_map[cert_id] = aki
        elif not is_root:
            if ORPHAN_NODE_ID not in self.parents_map[cert_id]:
                self.parents_map[cert_id].append(ORPHAN_NODE_ID)
            self.parent_map[cert_id] = ORPHAN_NODE_ID

        # Avoid overwriting user certs with system certs during analysis
        if cert_id in self.cert_data:
            existing = self.cert_data[cert_id]
            if is_system_cert and not existing.is_system_cert:
                return
            if not is_system_cert and existing.is_system_cert:
                self.name_count[cn] -= 1
            else:
                return

        formatted_serial = self._get_serial_number(cert)

        self.raw_certs[cert_id] = cert
        self.name_count[cn] += 1

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

        aia_issuers = self._get_extension(cert, x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS, "issuers") or []
        ocsp_urls = self._get_extension(cert, x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS, "ocsp") or []

        from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519
        pk = cert.public_key()
        pk_info = {"algorithm": "Unknown", "bits": 0}

        if isinstance(pk, rsa.RSAPublicKey):
            pk_info["algorithm"] = "RSA"
            pk_info["bits"] = pk.key_size
        elif isinstance(pk, ec.EllipticCurvePublicKey):
            pk_info["algorithm"] = "ECDSA"
            pk_info["bits"] = pk.curve.key_size
        elif isinstance(pk, ed25519.Ed25519PublicKey):
            pk_info["algorithm"] = "Ed25519"
            pk_info["bits"] = 256
        elif isinstance(pk, dsa.DSAPublicKey):
            pk_info["algorithm"] = "DSA"
            pk_info["bits"] = pk.key_size

        sig_alg_oid = cert.signature_algorithm_oid
        sig_alg = getattr(sig_alg_oid, "_name", str(sig_alg_oid))

        cert_obj = Certificate(
            commonName=cn,
            subjectSerial=subject_sn,
            serialNumber=formatted_serial,
            certId=cert_id,
            ski=ski,
            fileName=display_file_name,
            sha256Hash=c_hash,
            isValid=(start_date <= now <= expiry),
            isExpiringSoon=(
                now <= expiry <= (now + timedelta(days=self.threshold))
            ),
            expiryDate=expiry,
            isSystemCert=is_system_cert,
            isBlacklisted=is_blacklisted,
            isAiaCert=is_aia_cert,
            isRoot=is_root,
            sanNames=sans,
            aiaCaIssuers=aia_issuers,
            aiaOcspUrls=ocsp_urls,
            publicKeyInfo=pk_info,
            signatureAlgorithm=sig_alg,
            ocspStatus=item.get("ocsp_status", "UNKNOWN"),
        )

        if is_blacklisted:
            cert_obj.add_finding(PolicyFinding(
                level="ERROR",
                code="OS_BLACKLISTED",
                label="REVOKED",
                message=N_("This certificate is explicitly untrusted by the Operating System (Blacklisted)."),
                code_int=3
            ))
            cert_obj.isValid = False

        if cert_obj.is_expiring_soon and cert_obj.is_valid:
            cert_obj.add_finding(PolicyFinding(
                level="WARNING",
                code="EXPIRING_SOON",
                label="EXPIRING_SOON",
                message=N_("Certificate expires within {days} days."),
                params={"days": self.threshold},
                code_int=1
            ))

        self.cert_data[cert_id] = cert_obj

    def _sanitize_parent_map(self, relevant_skis: Set[str]):
        visited = set()
        path = []
        self.circular_skis = set()

        def check_cycle(ski):
            if ski in path:
                idx = path.index(ski)
                cycle_participants = path[idx:]
                for member in cycle_participants:
                    self.circular_skis.add(member)

                if self.debug:
                    msg = _("Circular chain detected: {path}").format(
                        path=" -> ".join([s[:8] for s in cycle_participants])
                    )
                    WARNING.log(_("CYCLE_BREAKER"), msg)

                self.parents_map[ski] = [CYCLE_NODE_ID]
                self.parent_map[ski] = CYCLE_NODE_ID
                return True

            if ski in visited:
                return False

            visited.add(ski)
            path.append(ski)

            for parent in list(self.parents_map.get(ski, [])):
                if parent not in [ORPHAN_NODE_ID, CYCLE_NODE_ID] and parent in self.cert_data:
                    if check_cycle(parent):
                        pass

            path.pop()
            return False

        for ski in list(relevant_skis):
            check_cycle(ski)

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
            ocsp_status = getattr(cert_obj, "ocsp_status", None)

            if cert_obj.signature_valid is False and not is_untrusted:
                st = ERROR
                current_label = _("SIG_ERR")
            elif ocsp_status == "REVOKED":
                st = REVOKED
                current_label = _("REVOKED")
            elif not cert_obj.is_valid:
                st = ERROR
                current_label = _("INVALID")
            elif cert_obj.is_expiring_soon:
                st = EXPIRING
            elif cert_obj.is_system_cert:
                st = SYSTEM
            elif cert_obj.is_aia_cert:
                st = AIA
            else:
                st = OK

            sig_icon = cert_obj.signature_icon
            coll_icon = COLLISION.ICON if cert_obj.is_collision else ""
            ocsp_icon = ""
            if ocsp_status == "GOOD":
                ocsp_icon = Icons.OCSP_OK
            elif ocsp_status == "REVOKED":
                ocsp_icon = Icons.REVOKED

            combined_extra = f"{sig_icon}{ocsp_icon}{coll_icon}"

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
            flat_list.append(cert_obj)
        return sorted(flat_list, key=lambda x: x.common_name.lower())

    def _create_tree(self, resolver: Optional[Any] = None) -> List[Certificate]:
        """
        The core recursive algorithm.
        It filters certificates to only show chains that lead to a user-provided cert.
        """
        # Identify all SKIs that are part of a target chain
        target_skis = {
            ski for ski, cert in self.cert_data.items() if not cert.is_system_cert
        }
        relevant_skis = set()

        def collect_all_relevant(ski):
            if ski in relevant_skis or ski not in self.cert_data:
                return
            relevant_skis.add(ski)
            for p_ski in self.parents_map.get(ski, []):
                if p_ski != ski and p_ski != ORPHAN_NODE_ID:
                    collect_all_relevant(p_ski)

        for ski in target_skis:
            collect_all_relevant(ski)

        self._sanitize_parent_map(relevant_skis)

        # Build a lookup for children to allow recursive traversal
        children_by_parent = defaultdict(list)
        for ski in relevant_skis:
            p_skis = self.parents_map.get(ski, [])
            for p_ski in p_skis:
                if p_ski and p_ski in relevant_skis and p_ski != ski:
                    children_by_parent[p_ski].append(ski)

        node_cache = {}

        # Recursive function to build Node objects
        def to_node(ski: str, parent_status: str = "VALID", depth: int = 0) -> Certificate:
            if depth > 15:
                return self._create_virtual_node("LOOP_LIMIT_REACHED")

            cert_info = self.cert_data[ski]
            p_skis = self.parents_map.get(ski, [])

            if len(p_skis) > 1:
                p_skis.sort(
                key=lambda x: (
                    self.cert_data[x].is_system_cert if x in self.cert_data else False,
                    self.cert_data[x].expiry_date if x in self.cert_data else datetime.min.replace(tzinfo=timezone.utc)
                ),
                reverse=True
            )

            is_untrusted = False
            for p_ski in p_skis:
                if p_ski in self.cert_data:
                    parent_obj = self.cert_data[p_ski]
                    if parent_obj not in cert_info.parents:
                        cert_info.add_parent(parent_obj)

                if p_ski == ORPHAN_NODE_ID:
                    is_untrusted = True
                    ext_node = self._create_virtual_node(ORPHAN_NODE_ID)
                    if ext_node not in cert_info.parents:
                        cert_info.add_parent(ext_node)

            if ski in node_cache:
                return node_cache[ski]

            node_cache[ski] = cert_info
            cert_info.is_collision = self.name_count.get(cert_info.common_name, 0) > 1
            raw_cert = self.raw_certs.get(ski)

            if is_untrusted:
                cert_info.add_finding(PolicyFinding(
                    level="ERROR",
                    code="UNTRUSTED_CHAIN",
                    label="UNTRUSTED",
                    message=N_("The certificate chain leads to an untrusted or missing root."),
                    code_int=3
                ))

            if raw_cert:
                primary_parent_ski = p_skis[0] if p_skis else None
                is_root = getattr(cert_info, "is_root", False)
                issuer_raw = raw_cert if is_root else self.raw_certs.get(primary_parent_ski)

                validation_kwargs = {}
                child_skis = children_by_parent.get(ski, [])

                if not child_skis and not cert_info.is_system_cert:
                    target_host = self.options.get("target_hostname")
                    if target_host:
                        validation_kwargs["target_hostname"] = target_host

                findings = self.policy_engine.validate(raw_cert, issuer=issuer_raw, path_depth=depth, **validation_kwargs)

                for finding in findings:
                    if finding.level == "ERROR":
                        cert_info.is_valid = False
                        cert_info.validation_error = finding.code

                    cert_info.add_finding(finding)

                cert_info.signature_valid = not any(f.code == "SIG_INVALID" for f in findings)

                if resolver and not is_root and cert_info.signature_valid:
                    status = resolver.check_ocsp_status(raw_cert, issuer_raw, provided_urls=cert_info.aia_ocsp_urls)
                    cert_info.ocsp_status = status

            # Inherit 'invalidity' from parents (Chain of trust)
            if parent_status not in ["VALID", "SYSTEM", "AIA", "OK"] and cert_info.is_valid:
                cert_info.is_valid = False
                cert_info.validation_error = f"CHAIN_{parent_status}"

            if parent_status == "INCOMPLETE" or is_untrusted:
                cert_info.add_finding(PolicyFinding(
                    level="ERROR",
                    code="CHAIN_INCOMPLETE",
                    label="INCOMPLETE",
                    message=N_("The certificate chain is incomplete due to a missing upstream issuer."),
                    code_int=3
                ))

            if parent_status == "OS_BLACKLISTED":
                cert_info.is_valid = False
                cert_info.add_finding(PolicyFinding(
                    level="ERROR",
                    code="CHAIN_BLACKLISTED",
                    label="REVOKED",
                    message=N_("The chain is untrusted because an upstream issuer is blacklisted by the OS."),
                    code_int=3
                ))

            if parent_status == "REVOKED":
                 cert_info.ocsp_status = "REVOKED"
                 cert_info.is_valid = False

            # Recurse for children
            child_skis = children_by_parent.get(ski, [])
            sorted_child_skis = sorted(
                child_skis,
                key=lambda x: (
                    self.cert_data[x].common_name,
                    self.cert_data[x].subject_serial or "",
                    str(self.cert_data[x].expiry_date),
                    self.cert_data[x].fingerprint,
                ),
            )

            processed_children = []
            for c_ski in sorted_child_skis:
                child_node = to_node(c_ski, cert_info.status_label, depth + 1)
                processed_children.append(child_node)

            cert_info.children = processed_children
            return cert_info

        # Find Roots and Orphans to start the tree
        trusted_tree = []
        orphan_skis = []
        cycle_skis = [ski for ski in relevant_skis if ski in self.circular_skis]

        roots = [
            ski
            for ski in relevant_skis
            if self.parent_map.get(ski) not in relevant_skis
        ]

        for r_ski in sorted(roots, key=lambda x: self.cert_data[x].common_name.lower()):
            p_id = self.parent_map.get(r_ski)
            if p_id is None or p_id == r_ski:
                trusted_tree.append(to_node(r_ski))
            elif p_id == CYCLE_NODE_ID:
                cycle_skis.append(r_ski)
            else:
                orphan_skis.append(r_ski)

        if orphan_skis:
            ext_node = self._create_virtual_node(ORPHAN_NODE_ID)
            processed_orphans = []

            for o in sorted(orphan_skis, key=lambda x: self.cert_data[x].common_name.lower()):
                child_node = to_node(o)
                child_node.add_parent(ext_node)
                processed_orphans.append(child_node)

            ext_node.children = processed_orphans
            trusted_tree.append(ext_node)

        if cycle_skis:
            cycle_root = self._create_virtual_node(CYCLE_NODE_ID)
            processed_cycles = []

            for c_ski in sorted(cycle_skis, key=lambda x: self.cert_data[x].common_name.lower()):
                if c_ski in node_cache:
                    del node_cache[c_ski]
                node = to_node(c_ski, parent_status="INVALID")
                node.children = []
                node.is_in_circular_group = True

                if cycle_root not in node.parents:
                    node.add_parent(cycle_root)
                processed_cycles.append(node)

            cycle_root.children = processed_cycles
            trusted_tree.append(cycle_root)

        return trusted_tree

    def _get_common_name(self, cert) -> str:
        try:
            names = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            if names:
                return names[0].value
            orgs = cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
            if orgs:
                return orgs[0].value
            return ""
        except Exception:
            return ""

    def _get_subject_serial(self, cert: x509.Certificate) -> Optional[str]:
        try:
            from cryptography.x509.oid import NameOID
            serials = cert.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)
            if serials:
                return serials[0].value

            org_ids = cert.subject.get_attributes_for_oid(x509.ObjectIdentifier("2.5.4.97"))
            if org_ids:
                return org_ids[0].value
        except Exception:
            return None

    def _get_serial_number(self, cert: x509.Certificate) -> str:
        s = format(cert.serial_number, "X")
        if len(s) % 2 != 0:
            s = "0" + s
        return ":".join(s[i : i + 2] for i in range(0, len(s), 2))

    def _get_extension(
        self, cert: x509.Certificate, oid: x509.ObjectIdentifier, sub_type: Optional[str] = None
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

            if oid == x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS:
                from cryptography.x509.oid import AuthorityInformationAccessOID
                if sub_type == "issuers":
                    return [ad.access_location.value for ad in ext.value
                            if ad.access_method == AuthorityInformationAccessOID.CA_ISSUERS]
                if sub_type == "ocsp":
                    return [ad.access_location.value for ad in ext.value
                            if ad.access_method == AuthorityInformationAccessOID.OCSP]

        except Exception:
            if oid == x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                return []
            return None

        return None

    def _perform_aia_discovery(self, resolver: Any, max_depth: int = 4) -> None:
        """
        Iteratively identifies missing issuers and attempts to fetch them via AIA.
        Leverages the parallel resolver to discover all possible paths (cross-signing).
        """
        depth = 0
        while depth < max_depth:
            current_skis = set(self.cert_data.keys())
            processed_in_round = set()

            missing_issuers_map: Dict[str, Certificate] = {}
            for cert_id, cert_obj in self.cert_data.items():
                aki = self.parent_map.get(cert_id)

                if aki and aki != ORPHAN_NODE_ID and aki not in current_skis:
                    if cert_obj.aia_ca_issuers:
                        missing_issuers_map[cert_id] = cert_obj

            if not missing_issuers_map:
                break

            found_new_in_this_round = False

            for cert_id, cert_obj in missing_issuers_map.items():
                new_issuers: List[x509.Certificate] = resolver.resolve_via_aia_urls(
                    cert_obj.aia_ca_issuers,
                    child_cert=self.raw_certs.get(cert_id)
                )

                for new_x509 in new_issuers:
                    c_hash = Certificate.calculate_fingerprint(
                        new_x509.public_bytes(serialization.Encoding.DER)
                    )

                    if c_hash in self.repo or c_hash in processed_in_round:
                        continue

                    meta = {
                        "cert": new_x509,
                        "path": Path(f"AIA-Discovery-{cert_obj.cert_id[:8]}"),
                        "hash": c_hash,
                        "is_system_cert": False,
                        "is_aia_cert": True,
                    }

                    self._process_metadata(meta)
                    processed_in_round.add(c_hash)
                    found_new_in_this_round = True

                    if self.debug:
                        common_name: str = self._get_common_name(new_x509)
                        log_msg: str = _("AIA: {name}").format(name=common_name)
                        detail_msg: str = _("Successfully discovered issuer via AIA")
                        AIA.log(log_msg, detail_msg)

            if not found_new_in_this_round:
                break
            depth += 1

    def _create_virtual_node(self, name: str) -> Certificate:
        """Creates a dummy node for grouping orphans (missing/external roots)."""
        epoch_date = datetime(1970, 1, 1, tzinfo=timezone.utc)
        node=Certificate(
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

        if name == ORPHAN_NODE_ID:
            node.add_finding(PolicyFinding(
                level="ERROR",
                code="CHAIN_INCOMPLETE",
                label="UNTRUSTED",
                message=N_("The chain is broken; an issuer (Root or Intermediate) was not found."),
                code_int=3
            ))

        if name == CYCLE_NODE_ID:
            node.add_finding(PolicyFinding(
                level="ERROR",
                code="CIRCULAR_REFERENCE",
                label="CYCLE",
                message=N_("A circular certificate reference was detected."),
                code_int=3
            ))

        return node
