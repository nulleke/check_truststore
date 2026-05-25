"""
TrustStore Analyzer & Visualizer - DOMAIN MODELS
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later

This module defines the core data structures for the engine, including
Certificate and CertificateGroup objects, as well as unique identifiers
for orphans and circular references.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Union, Optional
from .logging import Icons
from .policy import PolicyFinding

PYDANTIC_AVAILABLE = False
try:
    import pydantic
    if pydantic.__version__.startswith("2"):
        from pydantic import BaseModel, Field, ConfigDict, model_validator
        PYDANTIC_AVAILABLE = True
except (ImportError, AttributeError):
    PYDANTIC_AVAILABLE = False

ORPHAN_NODE_ID = "EXTERNAL_OR_MISSING_ISSUER"
CYCLE_NODE_ID = "CIRCULAR_REFERENCE"
DEPTH_LIMIT_NODE_ID = "DEPTH_LIMIT_REACHED"

class _BaseUniversal:
    """
    Shared logic for both Pydantic and non-Pydantic implementations.
    Contains methods for data normalization and UI icon logic.
    """

    @staticmethod
    def _apply_special_logic(data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalizes internal state fields when parsing virtual anchor or structural nodes.

        This method intercepts virtual placeholder nodes (such as missing issuers,
        discovered cryptographic loops, or hard execution depth cut-offs) and enforces
        consistent fallback metrics (e.g., historical epoch expiration dates and
        invalidated status fields) to align them with standard certificate processing pathways.

        Args:
            data (Dict[str, Any]): The raw state configuration intended for node construction.

        Returns:
            Dict[str, Any]: A sanitized copy of the configuration containing default fail states
                            where appropriate.
        """
        cn = data.get("common_name")
        if cn in [ORPHAN_NODE_ID, CYCLE_NODE_ID, DEPTH_LIMIT_NODE_ID]:
            special = {
                "is_valid": False,
                "isValid": False,
                "is_expiring_soon": False,
                "isExpiringSoon": False,
                "expiry_date": datetime(1970, 1, 1, tzinfo=timezone.utc),
                "expiryDate": datetime(1970, 1, 1, tzinfo=timezone.utc),
                "signature_valid": None,
                "signatureValid": None,
            }
            if isinstance(data, dict):
                data.update(special)
        return data

    def get_audit_status(self) -> Dict[str, Any]:
        """
        Evaluates the end-to-end trust state and computes the single source of truth status.

        This method executes a prioritized evaluation pipeline over the node's properties,
        upstream graph hierarchy, and attached compliance warnings. It resolves the final
        health metric into a structured dictionary containing a machine-readable priority code,
        an identity label, and a human-readable explanation.

        The validation sequence operates in the following strict hierarchy:
        1. Structural exceptions (Virtual loop, depth limit, or orphan nodes).
        2. Hard revocation status (OCSP REVOKED signals).
        3. Operating System / Platform trust blacklists.
        4. Cryptographic signature and chain integrity verification.
        5. Upstream inherited errors (broken ancestor paths).
        6. Temporal validity (expired certificates).
        7. Filtered policy findings (evaluating 'error' and 'warning' severities).
        8. Proactive warnings (certificates expiring within the threshold window).

        Note:
            Informational levels ('note' or 'info') are stored within the model for
            deep compliance reporting but are explicitly bypassed during this calculation
            to avoid operational false positives.

        Returns:
            Dict[str, Any]: A status dictionary with the following keys:
                - 'code' (int): A severity rank identifier (higher indicates more critical).
                - 'label' (str): A standard string flag (e.g., 'VALID', 'REVOKED', 'EXPIRING').
                - 'message' (str): A descriptive summary of the resolved audit decision.
                - 'level' (str): The high-level log category ('error', 'warning', or 'note').
        """

        if getattr(self, "common_name", "") == ORPHAN_NODE_ID:
             return {"code": 3, "label": "UNTRUSTED", "message": "The trust chain is broken; an issuer was not found.", "level": "error"}

        if getattr(self, "common_name", "") == CYCLE_NODE_ID:
            return {"code": 3, "label": "CYCLE", "message": "Circular reference detected.", "level": "error"}

        if getattr(self, "is_in_circular_group", False):
            return {"code": 3, "label": "CIRCULAR_PATH", "message": "Part of a circular trust chain.", "level": "error"}

        if getattr(self, "common_name", "") == DEPTH_LIMIT_NODE_ID:
            return {"code": 3, "label": "CHAIN_TOO_DEEP", "message": "The certificate chain exceeds the maximum allowed depth.", "level": "error"}

        # Critical Security & Integrity (Hard Errors)
        # These represent immediate trust failures.
        if getattr(self, "ocsp_status", "UNKNOWN") == "REVOKED":
            return {"code": 5, "label": "REVOKED", "message": "Certificate is revoked.", "level": "error"}

        if getattr(self, "is_blacklisted", False):
            return {"code": 5, "label": "OS_BLACKLISTED", "message": "Explicitly untrusted by the OS.", "level": "error"}

        if getattr(self, "signature_valid", None) is False:
            return {"code": 4, "label": "SIG_INVALID", "message": "Cryptographic signature is invalid.", "level": "error"}

        chain_warning = False

        for parent in getattr(self, "parents", []):
            p_audit = parent.get_audit_status()
            if p_audit["level"] == "error":
                return {
                    "code": 3,
                    "label": "CHAIN_BROKEN",
                    "message": "Trust chain broken by parent.",
                    "level": "error"
                }

            if p_audit["level"] == "warning" and "EXPIRING" in p_audit["label"]:
                 chain_warning = f"Trust chain warning: Parent '{parent.common_name}' is expiring soon."

        # Temporal Validation (Self-Expired)
        now = datetime.now(timezone.utc)
        expiry = getattr(self, "expiry_date", None)

        if isinstance(expiry, datetime) and expiry < now:
            return {"code": 2, "label": "EXPIRED", "message": "Certificate has expired.", "level": "error"}

        # Policy Findings (Filtered by Severity Level)
        # Only findings marked as 'error' or 'warning' will impact the status.
        # 'note' and 'info' findings (e.g., CRL_MISSING) are recorded but skipped here.
        findings = getattr(self, "findings", [])
        serious_findings = [f for f in findings if f.level.lower() in ("error", "warning")]

        if serious_findings:
            # Sort findings to ensure the most critical one (highest code_int) defines the status.
            critical = sorted(serious_findings, key=lambda x: x.code_int, reverse=True)[0]

            if critical.level.lower() == "error":
                return {"code": critical.code_int, "label": "INVALID", "message": critical.message, "level": "error"}

            is_time_issue = any(k in critical.code for k in ["EXPIRING", "VALIDITY", "NOT_BEFORE"])
            res_label = "EXPIRING" if is_time_issue else "WARNING"

            return {"code": critical.code_int, "label": res_label, "message": critical.message, "level": "warning"}

        # Low-Priority Warnings (Expiring Soon)
        # Only checked if no higher-priority errors or policy warnings exist.
        if getattr(self, "is_expiring_soon", False) or chain_warning:
            msg = "Certificate is expiring soon" if not chain_warning else chain_warning
            return {"code": 1, "label": "EXPIRING", "message": msg, "level": "warning"}

        # Default State (Healthy)
        return {"code": 0, "label": "VALID", "message": "Valid", "level": "note"}

    @property
    def signature_icon(self) -> str:
        """
        Retrieves the graphical Unicode icon reflecting the certificate's cryptographic signature.

        Returns:
            str: An icon mapped from the unified logging infrastructure indicating
                 verified lock state, structural breakage, or undetermined status.
        """
        sig = getattr(self, "signature_valid", None)
        if sig is True:
            return Icons.LOCKED
        if sig is False:
            return Icons.BROKEN
        return Icons.UNKNOWN

    @property
    def status_label(self) -> str:
        """
        Retrieves the normalized, upper-case architectural status classification string.

        Returns:
            str: The audit label string (e.g., 'VALID', 'EXPIRED', 'CHAIN_BROKEN').
        """
        return self.get_audit_status()["label"]

    @property
    def display_name(self) -> str:
        """
        Generates a standardized display name for logging and user interface presentation.

        Appends the Subject Serial Number (S/N) to the primary Common Name if present
        to guarantee unambiguous differentiation between certificates sharing identical identities.

        Returns:
            str: The formatted descriptive string.
        """
        cn = getattr(self, "common_name", "Unknown")
        sn = getattr(self, "subject_serial", None)
        if sn:
            return f"{cn} (S/N: {sn})"
        return cn

    @staticmethod
    def calculate_fingerprint(raw_der: bytes) -> str:
        """
        Computes a globally unique, deterministic identifier from raw certificate content.

        Args:
            raw_der (bytes): The raw, binary DER-encoded representation of an X.509 certificate.

        Returns:
            str: A lowercase hexadecimal SHA-256 fingerprint digest string.
        """
        import hashlib
        return hashlib.sha256(raw_der).hexdigest()

    @property
    def fingerprint(self) -> str:
        """
        Abstracted access property to retrieve a unique node identifier.

        Prioritizes the immutable cryptographic SHA-256 fingerprint for genuine
        certificates, falling back gracefully to arbitrary 'cert_id' strings for virtual
        placeholders (orphans, loops). This abstraction allows graph traversal components
        to operate uniformly without executing continuous type isolation blocks.

        Returns:
            str: A unique identifier string representing the node.
        """
        fp = getattr(self, "sha256_hash", None)
        if fp:
            return fp

        return getattr(self, "cert_id", "unknown-fingerprint")

    def to_ansible(self) -> Dict[str, Any]:
        """
        Exports the structural model context into a flat schema compatible with Ansible facts.

        Converts internal complex attributes, Boolean states, UI icons, and temporal fields
        into standard serialized primitive structures optimized for external automation consumption.

        Returns:
            Dict[str, Any]: A dictionary populated with platform fact compatible key-value parameters.
        """
        data = self.model_dump()

        data.update({
            "ansible_audit_label": self.status_label,
            "failed": self.get_audit_status()["level"] == "error",
            "icon": self.signature_icon,
            "display_name": self.display_name
        })

        if isinstance(data.get("expiryDate"), datetime):
            data["expiryDate"] = data["expiryDate"].isoformat()

        return data


if PYDANTIC_AVAILABLE:
    class CertificateGroup(_BaseUniversal, BaseModel):
        """Represents a logical grouping boundary for parsed certificates.

        A group maps a specific tracking context—such as an unparsed file, a
        systemic trust store, or a directory branch—and retains its structural
        validation hierarchy, summary metrics, and output rendering metadata.

        Attributes:
            group_name (str): The unique identifier name of the store or
              container group.
            group_status (str): High-level processing indicator state (defaults
              to 'OK').
            summary (Dict[str, Any]): Aggregated operational and statistics
              counters.
            tree (List[Certificate]): The resolved hierarchical root-level
              nodes.
            chain (List[Certificate]): A flat presentation listing of discovered
              certificates.
        """

        group_name: str = Field(..., alias="groupName")
        group_status: str = Field("OK", alias="groupStatus")
        summary: Dict[str, Any] = Field(default_factory=dict)
        tree: List["Certificate"] = Field(default_factory=list)
        chain: List["Certificate"] = Field(default_factory=list)
        disabled_checks: Union[bool, List[str]] = Field(default=False, exclude=True)

        model_config = ConfigDict(populate_by_name=True, extra="allow")

        def finalize(self) -> None:
            """Triggers the post-analysis compilation pipeline for the group.

            Deduplicates, processes, and isolates top-level root configurations
            before sorting them to prepare the internal tree state for
            consistent UI rendering.
            """
            self._do_finalize_logic()

        def _do_finalize_logic(self) -> None:
            """Isolates top-level architectural nodes and applies precise

            sorting logic.

            Filters out certificates that possess active parent boundaries to
            isolate true cryptographic roots and detached structural nodes.
            Applies a weighted sort ordering to guarantee that verified roots
            appear at the apex of the visualization, while exceptional virtual
            anchors (such as structural errors and orphans) are relegated
            deterministically to the bottom.
            """
            top_level_nodes = [
                c for c in self.tree
                if not getattr(c, "parents", [])
                or getattr(c, "is_root", False)
                or getattr(c, "common_name", "") in [ORPHAN_NODE_ID, CYCLE_NODE_ID, DEPTH_LIMIT_NODE_ID]
            ]

            # Sorting: Real roots first (alphabetical), Orphans last.
            def sort_weight(node):
                name = getattr(node, "common_name", "")
                if name == CYCLE_NODE_ID:
                    return 3
                if name == DEPTH_LIMIT_NODE_ID:
                    return 2
                if name == ORPHAN_NODE_ID:
                    return 1
                return 0

            self.tree = sorted(
                top_level_nodes,
                key=lambda x: (
                    sort_weight(x),
                    getattr(x, "common_name", "").lower(),
                    getattr(x, "serial_number", "").lower()
                ),
            )

        def model_dump(self, **kwargs) -> Dict[str, Any]:
            """Serializes the group entity and its embedded nodes into a

            JSON-compatible primitive.

            Guarantees correct recursive mapping and enforces camelCase property
            alias conventions to match API interface specifications.
            """
            return super().model_dump(by_alias=True)

    class Certificate(_BaseUniversal, BaseModel):
        """Represents a normalized entity tracking validation metrics for a

        specific X.509 certificate.

        This class serves as the uniform domain container across the engine,
        bridging structural cryptography parsing values, local network discovery
        metadata, and policy infraction listings into a single node capable of
        participating in recursive trust-graph relations.

        Attributes:
            common_name (str): Primary Subject Common Name extracted from the
              certificate identifier.
            subject_serial (Optional[str]): Subject Serial Number attribute, if
              present.
            serial_number (str): The unique certificate serial number string.
            expiry_date (datetime): The absolute UTC expiration point of the
              certificate.
            findings (List[PolicyFinding]): List of cryptographic variations or
              policy infractions detected.
            children (List[Certificate]): Downstream certificates issued or
              signed by this node.
            parents (List[Certificate]): Upstream certificates recognized as the
              cryptographic issuer.
        """

        common_name: str = Field(..., alias="commonName")
        subject_serial: Optional[str] = Field(None, alias="subjectSerial")
        serial_number: str = Field("UNKNOWN", alias="serialNumber")
        file_name: str = Field("", alias="fileName", exclude=True)
        sha256_hash: str = Field("", alias="sha256Hash", exclude=True)
        expiry_date: Union[datetime, str] = Field("1970-01-01", alias="expiryDate")

        ski: Optional[str] = Field(None, exclude=True)
        aki: Optional[str] = Field(None, exclude=True)

        is_valid: bool = Field(False, alias="isValid")
        is_expiring_soon: bool = Field(False, alias="isExpiringSoon")
        is_collision: bool = Field(False, alias="isCollision", exclude=True)
        is_system_cert: bool = Field(False, alias="isSystemCert", exclude=True)
        is_blacklisted: bool = Field(False, alias="isBlacklisted", exclude=True)
        is_aia_cert: bool = Field(False, alias="isAiaCert", exclude=True)
        is_in_circular_group: bool = Field(False, exclude=True)
        is_root: bool = Field(False, alias="isRoot", exclude=True)

        cert_id: str = Field("", alias="certId", exclude=True)

        signature_valid: Optional[bool] = Field(None, exclude=True)
        validation_error: Optional[str] = Field(None, exclude=True)
        signature_algorithm: Optional[str] = Field(None, alias="signatureAlgorithm", exclude=True)

        findings: List[PolicyFinding] = Field(default_factory=list, exclude=False)

        aia_ca_issuers: List[str] = Field(default_factory=list, alias="aiaCaIssuers", exclude=True)
        aia_ocsp_urls: List[str] = Field(default_factory=list, alias="aiaOcspUrls", exclude=True)
        ocsp_status: str = Field("UNKNOWN", alias="ocspStatus", exclude=True)

        public_key_info: Dict[str, Any] = Field(default_factory=dict, alias="publicKeyInfo", exclude=True)
        children: Optional[List["Certificate"]] = Field(default_factory=list)
        parents: List["Certificate"] = Field(default_factory=list, exclude=True)

        extensions: Dict[str, Any] = Field(default_factory=dict, exclude=True)
        san_names: List[str] = Field(
            default_factory=list, alias="sanNames", exclude=True
        )

        model_config = ConfigDict(populate_by_name=True, arbitrary_types_allowed=True)

        @model_validator(mode="before")
        @classmethod
        def validate_node_v2(cls, data: Any) -> Any:
            """Pydantic execution hook to intercept data normalization prior to

            structural validation.

            Args:
                data (Any): Input parameter mapping configuration.

            Returns:
                Any: The normalized configuration dictionary.
            """
            return cls._apply_special_logic(data) if isinstance(data, dict) else data

        def add_parent(self, parent: "Certificate") -> None:
            """Establishes a bilateral upstream cryptographic issuer link within

            the trust graph.

            Verifies that the parent's fingerprint is unique within the existing
            ancestor collection before appending the reference and automatically
            updating the parent's child registry.

            Args:
                parent (Certificate): The authoritative upstream certificate
                  node.
            """
            parent_hashes = {p.sha256_hash for p in self.parents}
            if parent.sha256_hash not in parent_hashes:
                self.parents.append(parent)
                parent.add_child(self)

        def add_child(self, child: "Certificate") -> None:
            """Registers a downstream certificate node signed or issued by this

            instance.

            Prevents duplicate registration by verifying uniqueness against
            known child fingerprints.

            Args:
                child (Certificate): The downstream certificate node to attach.
            """
            child_hashes = {c.sha256_hash for c in self.children}
            if child.sha256_hash not in child_hashes:
                self.children.append(child)

        def add_finding(self, finding: PolicyFinding) -> None:
            """Appends a policy infraction or cryptographic warning finding to

            this node.

            De-duplicates incoming findings based on identical structural codes
            and error message definitions to ensure clean dashboard output
            representation.

            Args:
                finding (PolicyFinding): The populated compliance finding
                  container.
            """
            if any(f.code == finding.code and f.message == finding.message for f in self.findings):
                return
            self.findings.append(finding)

        def model_dump(self, **kwargs) -> Dict[str, Any]:
            """Executes an advanced serialization sweep over the certificate

            node and its sub-trees.

            Dynamically injects calculated runtime fields (such as comprehensive
            audit statuses, public key parameters, and structural signature
            algorithms). Manages recursive loop suppression by truncating
            children arrays inside circular relationships and enforces strict
            alphabetical and serial-number ordering across downstream nodes.
            """
            d = super().model_dump(by_alias=True, **kwargs)
            d["fingerprint"] = self.fingerprint
            d["subjectSerial"] = self.subject_serial
            d["isBlacklisted"] = self.is_blacklisted
            d["isSystemCert"] = self.is_system_cert
            d["auditStatus"] = self.get_audit_status()
            d["publicKeyInfo"] = self.public_key_info
            d["signatureAlgorithm"] = self.signature_algorithm
            d["aia"] = {"issuers": self.aia_ca_issuers, "ocsp": self.aia_ocsp_urls}

            if self.findings:
                d["findings"] = [f.model_dump() if hasattr(f, "model_dump") else str(f) for f in self.findings]

            if getattr(self, "is_in_circular_group", False):
                d["children"] = []
                return d

            if self.children:
                limit_node = next((c for c in self.children if getattr(c, "common_name", "") == DEPTH_LIMIT_NODE_ID), None)
                if limit_node:
                    d["children"] = [limit_node.model_dump(**kwargs)]
                else:
                    sorted_children = sorted(
                        self.children,
                        key=lambda x: (
                            getattr(x, "common_name", "").lower(),
                            getattr(x, "serial_number", "").lower(),
                            x.fingerprint.lower(),
                        ),
                    )
                    d["children"] = [c.model_dump(**kwargs) for c in sorted_children]
            else:
                d["children"] = []

            return d

else:

    class CertificateGroup(_BaseUniversal):
        """Represents a logical grouping boundary for parsed certificates.

        A group maps a specific tracking context—such as an unparsed file, a
        systemic trust store, or a directory branch—and retains its structural
        validation hierarchy, summary metrics, and output rendering metadata.

        Attributes:
            group_name (str): The unique identifier name of the store or
              container group.
            group_status (str): High-level processing indicator state (defaults
              to 'OK').
            summary (Dict[str, Any]): Aggregated operational and statistics
              counters.
            tree (List[Certificate]): The resolved hierarchical root-level
              nodes.
            chain (List[Certificate]): A flat presentation listing of discovered
              certificates.
        """

        def __init__(self, **kwargs) -> None:
            """Initializes a certificate tracking group boundary.

            Args:
                **kwargs: Standard parameters mapped directly to internal group
                  attributes.
            """
            self.group_name = kwargs.get(
                "groupName", kwargs.get("group_name", "unknown")
            )
            self.group_status = kwargs.get(
                "groupStatus", kwargs.get("group_status", "OK")
            )
            self.summary = kwargs.get("summary", {})
            self.tree = kwargs.get("tree", [])
            self.chain = kwargs.get("chain", [])
            self.disabled_checks = kwargs.get("disabled_checks", False)

        def finalize(self) -> None:
            """Triggers the post-analysis compilation pipeline for the group.

            Deduplicates, processes, and isolates top-level root configurations
            before sorting them to prepare the internal tree state for
            consistent UI rendering.
            """
            top_level_nodes = [
                c for c in self.tree
                if not getattr(c, "parents", [])
                or getattr(c, "is_root", False)
                or getattr(c, "common_name", "") in [ORPHAN_NODE_ID, CYCLE_NODE_ID, DEPTH_LIMIT_NODE_ID]
            ]
            def sort_weight(node):
                name = getattr(node, "common_name", "")
                if name == CYCLE_NODE_ID:
                    return 3
                if name == DEPTH_LIMIT_NODE_ID:
                    return 2
                if name == ORPHAN_NODE_ID:
                    return 1
                return 0
            self.tree = sorted(
                top_level_nodes,
                key=lambda x: (
                    sort_weight(x),
                    getattr(x, "common_name", "").lower(),
                    getattr(x, "serial_number", "").lower(),
                    x.fingerprint.lower(),
                ),
            )

        def model_dump(self, **kwargs) -> Dict[str, Any]:
            """Serializes the group entity and its embedded nodes into a

            JSON-compatible primitive.

            Guarantees correct recursive mapping and enforces camelCase property
            alias conventions to match API interface specifications.
            """
            return {
                "groupName": self.group_name,
                "groupStatus": self.group_status,
                "summary": self.summary,
                "tree": [c.model_dump(**kwargs) for c in self.tree],
                "chain": [c.model_dump(**kwargs) for c in self.chain],
            }

    class Certificate(_BaseUniversal):
        """Represents a normalized entity tracking validation metrics for a

        specific X.509 certificate.

        This class serves as the uniform domain container across the engine,
        bridging structural cryptography parsing values, local network discovery
        metadata, and policy infraction listings into a single node capable of
        participating in recursive trust-graph relations.

        Attributes:
            common_name (str): Primary Subject Common Name extracted from the
              certificate identifier.
            subject_serial (Optional[str]): Subject Serial Number attribute, if
              present.
            serial_number (str): The unique certificate serial number string.
            expiry_date (datetime): The absolute UTC expiration point of the
              certificate.
            findings (List[PolicyFinding]): List of cryptographic variations or
              policy infractions detected.
            children (List[Certificate]): Downstream certificates issued or
              signed by this node.
            parents (List[Certificate]): Upstream certificates recognized as the
              cryptographic issuer.
        """

        def __init__(self, **kwargs) -> None:
            """Initializes a plain Certificate entity tracking active trust

            metrics.

            Args:
                **kwargs: Standard parameters mapped directly to internal
                  certificate attributes.
            """
            self.findings = []
            self.is_in_circular_group = False
            data = self._apply_special_logic(kwargs)

            mapping = {
                "commonName": "common_name",
                "subjectSerial": "subject_serial",
                "serialNumber": "serial_number",
                "fileName": "file_name",
                "sha256Hash": "sha256_hash",
                "expiryDate": "expiry_date",
                "isValid": "is_valid",
                "isExpiringSoon": "is_expiring_soon",
                "isCollision": "is_collision",
                "isSystemCert": "is_system_cert",
                "isBlacklisted": "is_blacklisted",
                "isAiaCert": "is_aia_cert",
                "isRoot": "is_root",
                "certId": "cert_id",
                "signatureValid": "signature_valid",
                "validationError": "validation_error",
                "signatureAlgorithm": "signature_algorithm",
                "aiaCaIssuers": "aia_ca_issuers",
                "aiaOcspUrls": "aia_ocsp_urls",
                "ocspStatus": "ocsp_status",
                "publicKeyInfo": "public_key_info",
                "extensions": "extensions",
                "sanNames": "san_names",
            }

            self.subject_serial = data.get("subject_serial", data.get("subjectSerial"))
            self.children = []
            self.parents = []
            self.aia_ca_issuers = []
            self.aia_ocsp_urls = []
            self.public_key_info = {}
            self.signature_algorithm = None
            self.extensions = {}

            for k, v in data.items():
                setattr(self, mapping.get(k, k), v)

            self.ocsp_status = data.get("ocsp_status", data.get("ocspStatus", "UNKNOWN"))

            # Manual date parsing for older Python versions
            if (
                isinstance(getattr(self, "expiry_date", None), str)
                and self.expiry_date != "1970-01-01"
            ):
                clean_date = self.expiry_date.replace(" ", "T").replace("Z", "").split(".")[0]
                try:
                    self.expiry_date = datetime.strptime(clean_date, "%Y-%m-%dT%H:%M:%S")
                except ValueError:
                    try:
                        self.expiry_date = datetime.strptime(clean_date, "%Y-%m-%d")
                    except ValueError:
                        pass

        def add_parent(self, parent: "Certificate") -> None:
            """Establishes a bilateral upstream cryptographic issuer link within

            the trust graph.

            Verifies that the parent's fingerprint is unique within the existing
            ancestor collection before appending the reference and automatically
            updating the parent's child registry.

            Args:
                parent (Certificate): The authoritative upstream certificate
                  node.
            """
            parent_hashes = {getattr(p, "sha256_hash", "") for p in self.parents}
            if getattr(parent, "sha256_hash", "") not in parent_hashes:
                self.parents.append(parent)
                parent.add_child(self)

        def add_child(self, child: "Certificate") -> None:
            """Registers a downstream certificate node signed or issued by this

            instance.

            Prevents duplicate registration by verifying uniqueness against
            known child fingerprints.

            Args:
                child (Certificate): The downstream certificate node to attach.
            """
            child_hashes = {getattr(c, "sha256_hash", "") for c in self.children}
            if getattr(child, "sha256_hash", "") not in child_hashes:
                self.children.append(child)

        def add_finding(self, finding: PolicyFinding) -> None:
            """Appends a policy infraction or cryptographic warning finding to

            this node.

            De-duplicates incoming findings based on identical structural codes
            and error message definitions to ensure clean dashboard output
            representation.

            Args:
                finding (PolicyFinding): The populated compliance finding
                  container.
            """
            if any(f.code == finding.code and f.message == finding.message for f in self.findings):
                return
            self.findings.append(finding)

        def model_dump(self, **kwargs):
            """Manual serialization to Dict for JSON output."""
            res = {
                "commonName": getattr(self, "common_name", "UNKNOWN"),
                "fingerprint": self.fingerprint,
                "subjectSerial": getattr(self, "subject_serial", None),
                "serialNumber": getattr(self, "serial_number", "UNKNOWN"),
                "isValid": getattr(self, "is_valid", False),
                "isExpiringSoon": getattr(self, "is_expiring_soon", False),
                "expiryDate": self.expiry_date.isoformat().replace("+00:00", "Z") if isinstance(getattr(self, "expiry_date", None), datetime) else "1970-01-01",
                "signatureValid": getattr(self, "signature_valid", None),
                "isSystemCert": getattr(self, "is_system_cert", False),
                "isBlacklisted": getattr(self, "is_blacklisted", False),
                "isAiaCert": getattr(self, "is_aia_cert", False),
                "auditStatus": self.get_audit_status(),
                "publicKeyInfo": getattr(self, "public_key_info", {}),
                "signatureAlgorithm": getattr(self, "signature_algorithm", None),
                "aia": {
                    "issuers": getattr(self, "aia_ca_issuers", []),
                    "ocsp": getattr(self, "aia_ocsp_urls", [])
                },
                "findings": [f.model_dump() if hasattr(f, "model_dump") else str(f) for f in self.findings],
                "sha256Hash": getattr(self, "sha256_hash", ""),
                "ocspStatus": getattr(self, "ocsp_status", "UNKNOWN"),
                "certId": getattr(self, "cert_id", ""),
            }

            if getattr(self, "is_in_circular_group", False):
                res["children"] = []
                return res

            if self.children:
                limit_node = next((c for c in self.children if getattr(c, "common_name", "") == DEPTH_LIMIT_NODE_ID), None)
                if limit_node:
                    res["children"] = [limit_node.model_dump(**kwargs)]
                else:
                    sorted_children = sorted(
                        self.children,
                        key=lambda x: (
                            getattr(x, "common_name", "").lower(),
                            getattr(x, "serial_number", "").lower(),
                            x.fingerprint.lower(),
                        ),
                    )
                    res["children"] = [c.model_dump(**kwargs) for c in sorted_children]
            else:
                res["children"] = []
            return res

# Rebuild models for Pydantic to handle recursive self-references ("Certificate")
if PYDANTIC_AVAILABLE:
    CertificateGroup.model_rebuild()
    Certificate.model_rebuild()
