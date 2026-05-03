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

try:
    from pydantic import BaseModel, Field, ConfigDict, model_validator

    PYDANTIC_AVAILABLE = True
except ImportError:
    PYDANTIC_AVAILABLE = False

from .logging import Icons

ORPHAN_NODE_ID = "EXTERNAL_OR_MISSING_ISSUER"
CYCLE_NODE_ID = "CIRCULAR_REFERENCE"

class Finding:
    """
    Represents a specific policy violation or observation.
    Standardized for SARIF, JSON, and UI output.
    """
    def __init__(self, code: str, message: str, level: str = "ERROR", code_int: int = 4):
        self.code = code
        self.code_int = code_int
        self.message = message
        self.level = level

    def model_dump(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "code_int": self.code_int,
            "message": self.message,
            "level": self.level
        }
class _BaseUniversal:
    """
    Shared logic for both Pydantic and non-Pydantic implementations.
    Contains methods for data normalization and UI icon logic.
    """

    @staticmethod
    def _apply_special_logic(data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Interprets special nodes like orphans. If a node is identified as
        an orphan, it sets default 'invalid' states and a Unix epoch expiry date.
        """
        cn = data.get("common_name") or data.get("commonName")
        if cn in [ORPHAN_NODE_ID, CYCLE_NODE_ID]:
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
        Single Source of Truth to determine the status of a certificate.
        """
        v_err = getattr(self, "validation_error", "") or ""
        cn = getattr(self, "common_name", "")

        if cn in [ORPHAN_NODE_ID, CYCLE_NODE_ID] or "CHAIN_INCOMPLETE" in v_err or "MISSING_ISSUER" in v_err:
            return {"code": 3, "label": "INCOMPLETE", "message": "Trust chain is incomplete.", "level": "error"}

        if "CHAIN_EXPIRED" in v_err:
            return {"code": 2, "label": "EXPIRED", "message": "Trust chain is broken due to expired parent.", "level": "error"}

        findings = getattr(self, "findings", [])
        if findings:
            critical = sorted([f for f in findings if f.level == "ERROR"], key=lambda x: x.code_int, reverse=True)
            if critical:
                f = critical[0]
                return {"code": f.code_int, "label": f.code, "message": f.message, "level": "error"}

        if getattr(self, "signature_valid", None) is False:
            return {"code": 4, "label": "SIG_ERR", "message": "Signature verification failed.", "level": "error"}

        now = datetime.now(timezone.utc)
        expiry = getattr(self, "expiry_date", None)

        if isinstance(expiry, datetime) and expiry < now:
            return {"code": 2, "label": "EXPIRED", "message": "Certificate has expired.", "level": "error"}

        if getattr(self, "ocsp_status", "UNKNOWN") == "REVOKED":
            return {"code": 5, "label": "REVOKED", "message": "Certificate is revoked.", "level": "error"}

        if getattr(self, "is_expiring_soon", False):
            return {"code": 1, "label": "EXPIRING", "message": "Certificate is expiring soon.", "level": "warning"}

        if getattr(self, "is_system_cert", False):
            return {"code": 0, "label": "SYSTEM", "message": "System trust store certificate.", "level": "note"}

        if getattr(self, "is_aia_cert", False):
            return {"code": 0, "label": "AIA", "message": "Fetched via Authority Information Access.", "level": "note"}

        return {"code": 0, "label": "VALID", "message": "Valid", "level": "note"}

    @property
    def signature_icon(self) -> str:
        """Returns a visual icon based on the cryptographic signature status."""
        sig = getattr(self, "signature_valid", None)
        if sig is True:
            return Icons.LOCKED
        if sig is False:
            return Icons.BROKEN
        return Icons.UNKNOWN

    @property
    def status_label(self) -> str:
        return self.get_audit_status()["label"]


if PYDANTIC_AVAILABLE:

    class CertificateGroup(_BaseUniversal, BaseModel):
        """
        A logical collection of certificates (e.g., a file or a system store).
        Uses Pydantic V2 for strict validation and serialization.
        """

        group_name: str = Field(..., alias="groupName")
        group_status: str = Field("OK", alias="groupStatus")
        summary: Dict[str, Any] = Field(default_factory=dict)
        tree: List["Certificate"] = Field(default_factory=list)
        chain: List["Certificate"] = Field(default_factory=list)

        model_config = ConfigDict(populate_by_name=True, extra="allow")

        def finalize(self):
            """Prepares the group for rendering by deduplicating and sorting nodes."""
            self._do_finalize_logic()

        def _do_finalize_logic(self):
            """
            Identifies 'top-level' nodes by checking which certificates are
            not children of others. Ensures the orphan node is sorted to the bottom.
            """
            top_level_nodes = [
                c for c in self.tree
                if not getattr(c, "parents", [])
                or getattr(c, "is_root", False)
                or getattr(c, "common_name", "") in [ORPHAN_NODE_ID, CYCLE_NODE_ID]
            ]

            # Sorting: Real roots first (alphabetical), Orphans last.
            def sort_weight(node):
                name = getattr(node, "common_name", "")
                if name == CYCLE_NODE_ID:
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

        def model_dump(self, **kwargs):
            """Ensures JSON output uses camelCase aliases."""
            return super().model_dump(by_alias=True)
else:

    class CertificateGroup(_BaseUniversal):
        """Fallback implementation of CertificateGroup for environments without Pydantic."""

        def __init__(self, **kwargs):
            self.group_name = kwargs.get(
                "groupName", kwargs.get("group_name", "unknown")
            )
            self.group_status = kwargs.get(
                "groupStatus", kwargs.get("group_status", "OK")
            )
            self.summary = kwargs.get("summary", {})
            self.tree = kwargs.get("tree", [])
            self.chain = kwargs.get("chain", [])

        def finalize(self):
            top_level_nodes = [
                c for c in self.tree
                if not getattr(c, "parents", [])
                or getattr(c, "is_root", False)
                or getattr(c, "common_name", "") in [ORPHAN_NODE_ID, CYCLE_NODE_ID]
            ]
            def sort_weight(node):
                name = getattr(node, "common_name", "")
                if name == CYCLE_NODE_ID:
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
                    getattr(x, "sha256_hash", "").lower(),
                ),
            )

        def model_dump(self, **kwargs):
            return {
                "groupName": self.group_name,
                "groupStatus": self.group_status,
                "summary": self.summary,
                "tree": [c.model_dump(**kwargs) for c in self.tree],
                "chain": [c.model_dump(**kwargs) for c in self.chain],
            }


if PYDANTIC_AVAILABLE:

    class Certificate(_BaseUniversal, BaseModel):
        """
        Represents a parsed X.509 certificate with validation metadata.
        Standardizes certificate data across different Python versions.
        """

        common_name: str = Field(..., alias="commonName")
        serial_number: str = Field("UNKNOWN", alias="serialNumber")
        file_name: str = Field("", alias="fileName", exclude=True)
        sha256_hash: str = Field("", alias="sha256Hash", exclude=True)
        is_valid: bool = Field(False, alias="isValid")
        is_expiring_soon: bool = Field(False, alias="isExpiringSoon")
        expiry_date: Union[datetime, str] = Field("1970-01-01", alias="expiryDate")
        is_collision: bool = Field(False, alias="isCollision", exclude=True)
        is_system_cert: bool = Field(False, alias="isSystemCert", exclude=True)
        is_aia_cert: bool = Field(False, alias="isAiaCert", exclude=True)
        ocsp_status: str = Field("UNKNOWN", alias="ocspStatus", exclude=True)
        is_root: bool = Field(False, alias="isRoot", exclude=True)
        cert_id: str = Field("", alias="certId", exclude=True)
        san_names: List[str] = Field(
            default_factory=list, alias="sanNames", exclude=True
        )
        signature_valid: Optional[bool] = Field(None, exclude=True)
        validation_error: Optional[str] = Field(None, exclude=True)
        findings: List[Any] = Field(default_factory=list, exclude=False)
        children: Optional[List["Certificate"]] = Field(default_factory=list)
        parents: List["Certificate"] = Field(default_factory=list, exclude=True)
        is_in_circular_group: bool = Field(False, exclude=True)

        ski: Optional[str] = Field(None, exclude=True)
        aki: Optional[str] = Field(None, exclude=True)

        model_config = ConfigDict(populate_by_name=True, arbitrary_types_allowed=True)

        @model_validator(mode="before")
        @classmethod
        def validate_node_v2(cls, data: Any) -> Any:
            """Triggers special data handling (like orphans) before Pydantic validation."""
            return cls._apply_special_logic(data) if isinstance(data, dict) else data

        def add_parent(self, parent: "Certificate"):
            parent_hashes = {p.sha256_hash for p in self.parents}
            if parent.sha256_hash not in parent_hashes:
                self.parents.append(parent)
                parent.add_child(self)

        def add_child(self, child: "Certificate"):
            child_hashes = {c.sha256_hash for c in self.children}
            if child.sha256_hash not in child_hashes:
                self.children.append(child)

        def model_dump(self, **kwargs):
            """Custom dump logic to ensure recursive sorting of children."""
            d = super().model_dump(by_alias=True, **kwargs)
            d["auditStatus"] = self.get_audit_status()
            if self.findings:
                d["findings"] = [f.model_dump() if hasattr(f, "model_dump") else str(f) for f in self.findings]

            if getattr(self, "is_in_circular_group", False):
                d["children"] = []
                return d

            if self.children:
                sorted_children = sorted(
                    self.children,
                    key=lambda x: (
                        getattr(x, "common_name", "").lower(),
                        getattr(x, "serial_number", "").lower(),
                        getattr(x, "sha256_hash", "").lower(),
                    ),
                )
                d["children"] = [c.model_dump(**kwargs) for c in sorted_children]
            else:
                d["children"] = []

            return d

        def add_finding(self, finding):
            self.findings.append(finding)

else:

    class Certificate(_BaseUniversal):
        """Fallback implementation of Certificate for environments without Pydantic."""

        def __init__(self, **kwargs):
            self.findings = []
            self.is_in_circular_group = False
            data = self._apply_special_logic(kwargs)

            mapping = {
                "commonName": "common_name",
                "serialNumber": "serial_number",
                "fileName": "file_name",
                "sha256Hash": "sha256_hash",
                "isValid": "is_valid",
                "isExpiringSoon": "is_expiring_soon",
                "expiryDate": "expiry_date",
                "signatureValid": "signature_valid",
                "validationError": "validation_error",
                "isSystemCert": "is_system_cert",
                "isRoot": "is_root",
                "isAiaCert": "is_aia_cert",
                "ocspStatus": "ocsp_status",
                "isCollision": "is_collision",
                "certId": "cert_id",
                "sanNames": "san_names",
            }

            self.children = []
            self.parents = []

            for k, v in data.items():
                setattr(self, mapping.get(k, k), v)

            self.ocsp_status = data.get("ocsp_status", data.get("ocspStatus", "UNKNOWN"))

            # Manual date parsing for older Python versions
            if (
                isinstance(getattr(self, "expiry_date", None), str)
                and self.expiry_date != "1970-01-01"
            ):
                try:
                    self.expiry_date = datetime.strptime(
                        self.expiry_date.split(".")[0].replace("Z", ""),
                        "%Y-%m-%dT%H:%M:%S",
                    )
                except Exception:
                    pass

        def add_parent(self, parent: "Certificate"):
            parent_hashes = {getattr(p, "sha256_hash", "") for p in self.parents}
            if getattr(parent, "sha256_hash", "") not in parent_hashes:
                self.parents.append(parent)
                parent.add_child(self)

        def add_child(self, child: "Certificate"):
            child_hashes = {getattr(c, "sha256_hash", "") for c in self.children}
            if getattr(child, "sha256_hash", "") not in child_hashes:
                self.children.append(child)

        def model_dump(self, **kwargs):
            """Manual serialization to Dict for JSON output."""
            res = {
                "commonName": getattr(self, "common_name", "UNKNOWN"),
                "serialNumber": getattr(self, "serial_number", "UNKNOWN"),
                "isValid": getattr(self, "is_valid", False),
                "isExpiringSoon": getattr(self, "is_expiring_soon", False),
                "expiryDate": self.expiry_date.isoformat().replace("+00:00", "Z") if isinstance(getattr(self, "expiry_date", None), datetime) else "1970-01-01",
                "signatureValid": getattr(self, "signature_valid", None),
                "sha256Hash": getattr(self, "sha256_hash", ""),
                "isSystemCert": getattr(self, "is_system_cert", False),
                "ocspStatus": getattr(self, "ocsp_status", "UNKNOWN"),
                "certId": getattr(self, "cert_id", ""),
                "auditStatus": self.get_audit_status(),
                "isAiaCert": getattr(self, "is_aia_cert", False),
                "findings": [f.model_dump() if hasattr(f, "model_dump") else str(f) for f in self.findings],
            }

            if getattr(self, "is_in_circular_group", False):
                res["children"] = []
                return res

            if self.children:
                sorted_children = sorted(
                    self.children,
                    key=lambda x: (
                        getattr(x, "common_name", "").lower(),
                        getattr(x, "serial_number", "").lower(),
                        getattr(x, "sha256_hash", "").lower(),
                    ),
                )
                res["children"] = [c.model_dump(**kwargs) for c in sorted_children]
            else:
                res["children"] = []
            return res

        def add_finding(self, finding):
            self.findings.append(finding)

# Rebuild models for Pydantic to handle recursive self-references ("Certificate")
if PYDANTIC_AVAILABLE:
    CertificateGroup.model_rebuild()
    Certificate.model_rebuild()
