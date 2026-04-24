from datetime import datetime, timezone
from typing import Any, Dict, List, Union, Optional

try:
    from pydantic import BaseModel, Field, ConfigDict, model_validator

    PYDANTIC_AVAILABLE = True
except ImportError:
    PYDANTIC_AVAILABLE = False

from .logging import Icons

ORPHAN_NODE_ID = "EXTERNAL_OR_MISSING_ISSUER"


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
        if cn == ORPHAN_NODE_ID:
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
        """
        Determines a short string label representing the certificate's health.
        Order of priority: Validation Errors > Signature Errors > Expiry > System status.
        """
        v_err = getattr(self, "validation_error", None)
        if v_err:
            return v_err
        if getattr(self, "signature_valid", None) is False:
            return "SIG_ERR"
        if not getattr(self, "is_valid", False):
            return "INVALID"
        if getattr(self, "is_expiring_soon", False):
            return "EXPIRING"
        if getattr(self, "is_system_cert", False):
            return "SYSTEM"
        return "VALID"


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
            all_children_hashes = set()

            def collect_children(nodes):
                for node in nodes:
                    objs = getattr(node, "children", []) or []
                    for child in objs:
                        h = getattr(child, "sha256_hash", None)
                        if h:
                            all_children_hashes.add(h.lower())
                        collect_children([child])

            collect_children(self.tree)

            unsorted_tree = [
                c
                for c in list(self.tree)
                if getattr(c, "sha256_hash", "").lower() not in all_children_hashes
                or getattr(c, "common_name", "") == ORPHAN_NODE_ID
            ]

            # Sorting: Real roots first (alphabetical), Orphans last.
            self.tree = sorted(
                unsorted_tree,
                key=lambda x: (
                    1 if getattr(x, "common_name", "") == ORPHAN_NODE_ID else 0,
                    getattr(x, "common_name", "").lower(),
                    getattr(x, "serial_number", "").lower(),
                    getattr(x, "sha256_hash", "").lower(),
                ),
            )
            all_children_hashes = set()

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
            all_children_hashes = set()

            def collect_children(nodes):
                for node in nodes:
                    for child in getattr(node, "children", []):
                        h = getattr(child, "sha256_hash", None)
                        if h:
                            all_children_hashes.add(h.lower())
                        collect_children(getattr(child, "children", []))

            collect_children(self.tree)
            unsorted_tree = [
                c
                for c in self.tree
                if getattr(c, "sha256_hash", "").lower() not in all_children_hashes
            ]
            self.tree = sorted(
                unsorted_tree,
                key=lambda x: (
                    1 if getattr(x, "common_name", "") == ORPHAN_NODE_ID else 0,
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
        is_root: bool = Field(False, alias="isRoot", exclude=True)
        cert_id: str = Field("", alias="certId", exclude=True)
        san_names: List[str] = Field(
            default_factory=list, alias="sanNames", exclude=True
        )
        signature_valid: Optional[bool] = Field(None, exclude=True)
        validation_error: Optional[str] = Field(None, exclude=True)
        children: Optional[List["Certificate"]] = Field(default_factory=list)

        ski: Optional[str] = Field(None, exclude=True)
        aki: Optional[str] = Field(None, exclude=True)

        model_config = ConfigDict(populate_by_name=True, arbitrary_types_allowed=True)

        @model_validator(mode="before")
        @classmethod
        def validate_node_v2(cls, data: Any) -> Any:
            """Triggers special data handling (like orphans) before Pydantic validation."""
            return cls._apply_special_logic(data) if isinstance(data, dict) else data

        def model_dump(self, **kwargs):
            """Custom dump logic to ensure recursive sorting of children."""
            d = super().model_dump(by_alias=True, **kwargs)
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

else:

    class Certificate(_BaseUniversal):
        """Fallback implementation of Certificate for environments without Pydantic."""

        def __init__(self, **kwargs):
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
                "isCollision": "is_collision",
                "certId": "cert_id",
                "sanNames": "san_names",
            }

            self.children = []
            for k, v in data.items():
                setattr(self, mapping.get(k, k), v)

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

        def model_dump(self, **kwargs):
            """Manual serialization to Dict for JSON output."""
            res = {
                "commonName": getattr(self, "common_name", "UNKNOWN"),
                "serialNumber": getattr(self, "serial_number", "UNKNOWN"),
                "isValid": getattr(self, "is_valid", False),
                "isExpiringSoon": getattr(self, "is_expiring_soon", False),
                "expiryDate": self.expiry_date.isoformat().replace("+00:00", "Z")
                if isinstance(getattr(self, "expiry_date", None), datetime)
                else "1970-01-01",
                "signatureValid": getattr(self, "signature_valid", None),
                "sha256Hash": getattr(self, "sha256_hash", ""),
                "isSystemCert": getattr(self, "is_system_cert", False),
                "certId": getattr(self, "cert_id", ""),
            }
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


# Rebuild models for Pydantic to handle recursive self-references ("Certificate")
if PYDANTIC_AVAILABLE:
    CertificateGroup.model_rebuild()
    Certificate.model_rebuild()
