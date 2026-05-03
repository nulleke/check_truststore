# Domain Models & Data Contract

The `check-truststore` engine utilizes standardized data models to represent complex X.509 certificate trust chains. These models are built using **Pydantic V2** (with a transparent fallback for legacy environments) to ensure strict typing, automatic validation, and consistent JSON serialization.

---

## `Certificate` Model
The core entity representing a single X.509 certificate within a trust tree. It handles the transformation from raw cryptography objects to structured, serializable data.

### Schema Overview
| Field | Type | Description |
| :--- | :--- | :--- |
| `common_name` | `str` | The Subject Common Name (CN). Alias: `commonName`. |
| `serial_number` | `str` | Hexadecimal serial number string. Alias: `serialNumber`. |
| `is_valid` | `bool` | High-level indicator if the certificate passed basic validation. |
| `expiry_date` | `datetime` | The UTC expiration date. Alias: `expiryDate`. |
| `findings` | `List[Finding]` | A collection of security observations or policy violations. |
| `children` | `List[Certificate]` | Recursive list of certificates issued by this entity (the "issued" chain). |
| `signature_valid` | `Optional[bool]` | Result of the cryptographic signature verification against the parent. |
| `auditStatus` | `dict` | (Generated during dump) A summary containing `code`, `label`, and `message`. |

### Key Features
*   **Audit Intelligence**: Each certificate automatically calculates its status (e.g., `VALID`, `EXPIRED`, `INCOMPLETE`, `REVOKED`) via the `get_audit_status()` method.
*   **Special Node Handling**: Supports stable internal identifiers for edge cases:
    *   `EXTERNAL_OR_MISSING_ISSUER`: For certificates where the issuer is not present in the provided truststore.
    *   `CIRCULAR_REFERENCE`: For identifying and breaking infinite loops in misconfigured trust chains.
*   **Visual Helpers**: Provides `signature_icon` and `status_label` properties for consistent UI/CLI rendering using standardized icons.

---

## `CertificateGroup` Model
A logical container for analysis results, typically representing a single source of trust (e.g., a `.p12` file, a PEM directory, or the System Trust Store).

### Schema Overview
| Field | Type | Description |
| :--- | :--- | :--- |
| `group_name` | `str` | Human-readable name of the source (e.g., "root-ca-bundle.pem"). Alias: `groupName`. |
| `tree` | `List[Certificate]` | The hierarchical trust tree, starting from the root anchors. |
| `summary` | `dict` | Statistical summary (e.g., counts of errors, warnings, and valid certificates). |
| `group_status` | `str` | Overall status of the group (default: "OK"). Alias: `groupStatus`. |

### Key Features
*   **Tree Finalization**: The `finalize()` method automatically identifies top-level nodes, deduplicates entries, and sorts the tree (Real roots first, orphans/loops last).
*   **CamelCase Serialization**: The `model_dump()` method is pre-configured to output JSON-friendly keys (`commonName` instead of `common_name`).

---

## `Finding` Model
Represents a specific policy violation or security observation discovered by the `PolicyEngine`.

### Schema Overview
| Field | Type | Description |
| :--- | :--- | :--- |
| `code` | `str` | Machine-readable identifier (e.g., `WEAK_RSA`, `DEPRECATED_HASH`). |
| `level` | `str` | Severity level: `ERROR`, `WARNING`, `INFO`, or `NOTE`. |
| `message` | `str` | Human-readable description of the issue. |
| `code_int` | `int` | Integer value (0-4) used for programmatic sorting and severity ranking. |

---

## Integration Guide for Developers

### Using Pydantic (Modern Environments)
If Pydantic is available, these models provide full type safety and validation:
```python
from check_truststore import Certificate

# Models can be instantiated with aliases or field names
cert = Certificate(commonName="My Cert", isValid=True, expiryDate="2026-05-03T12:00:00Z")
print(cert.common_name)  # Accessible via pythonic name
```

## JSON Export
To generate data for a frontend or external API, use `model_dump()`:

```python
# This generates a dictionary with camelCase keys and calculated auditStatus
data = cert.model_dump()
```

## Fallback Mode
In environments where Pydantic is not installed, the library automatically switches to a lightweight `_BaseUniversal` class. This class maintains the same method signatures (`model_dump()`, `get_audit_status()`) to ensure your integration code remains compatible.

---