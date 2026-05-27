"""
TrustStore Analyzer - Policy Engine
Handles X.509 constraint validation, cryptographic verification, and security compliance.
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later
"""

from typing import List, Optional, Any, Dict, Set
from datetime import timezone
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding as rsa_padding
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm

def N_(message):
    return message

class PolicyFinding:
    """
    Represents a specific policy violation or security warning.
    """
    def __init__(self, level: str, code: str, message: str, label: str, params: Optional[Dict[str, Any]] = None, code_int: int = 4):
        """
        Constructs an explicit metadata violation tracking point.

        Args:
            level: Severity tag string ('ERROR', 'WARNING', 'INFO').
            code: Static standardized machine-readable error token identifier.
            message: Raw translatable descriptive text payload template.
            label: Concise short UI label flag.
            params: Dictionary containing interpolation values for message rendering.
            code_int: Internal numerical severity weight mapping.
        """
        self.level = level.upper()
        self.code = code
        self.code_int = code_int
        self.label = label
        self.params = params or {}
        self.raw_message = message

        try:
            self.message = message.format(**self.params) if self.params else message
        except (KeyError, ValueError):
            self.message = message

    def model_dump(self) -> Dict[str, Any]:
        """
        Serializes the policy finding object into a standard dictionary.

        This representation is designed to be compatible with JSON serialization
        mechanisms, command-line outputs, and external API responses.

        Returns:
            A dictionary containing the serialized finding attributes including
            code, integer code, message, severity level, label, and parameters.
        """
        return {
            "code": self.code,
            "code_int": self.code_int,
            "message": self.message,
            "level": self.level,
            "label": self.label,
            "params": self.params
        }

class PolicyEngine:
    """
    Core engine responsible for validating X.509 certificates against
    modern security standards, trust constraints, and cryptographic best practices.
    """

    DEPRECATED_HASHES = frozenset({'sha1', 'md5', 'md2', 'md4'})
    DEFAULT_INTERNAL_TLDS = frozenset({'.lan', '.local', '.internal', '.home.arpa', '.node'})

    def __init__(self, **kwargs) -> None:
        """
        Instantiates the validation policy context.

        Args:
            **kwargs: Configuration options including:
                - internal_domains (List[str]): User-defined internal TLDs.
                - debug (bool): Enable verbose tracking for underlying failures.
                - disabled_checks (Union[bool, List[str]]): Specific checks or
                  global flags to bypass policy evaluation rules.
        """
        self.min_rsa_bits = 2048
        self.min_ecdsa_bits = 256
        user_domains = kwargs.get('internal_domains') or []
        self.internal_tlds = self.DEFAULT_INTERNAL_TLDS.union({
            d if d.startswith('.') else f'.{d}' for d in user_domains
        })
        self.debug = kwargs.get('debug', False)
        self.disabled_checks = kwargs.get('disabled_checks', False)
        self.max_policy_depth = kwargs.get('max_depth', 4)
        if isinstance(self.disabled_checks, list):
            self.disabled_checks = set(self.disabled_checks)

    def _should_ignore(self, check_name: str) -> bool:
        """
        Determines whether a specific rule or check should be bypassed.

        Args:
            check_name: Machine-readable identifier of the validation rule.

        Returns:
            True if the check must be ignored, False otherwise.
        """
        if self.disabled_checks is True:
            return True
        if isinstance(self.disabled_checks, set) and check_name in self.disabled_checks:
            return True
        return False

    def validate(self, cert: x509.Certificate, issuer: Optional[x509.Certificate] = None, path_depth: Optional[int] = None, target_hostname: Optional[str] = None) -> List[PolicyFinding]:
        """
        Performs comprehensive compliance and cryptographic validation on a certificate.

        Args:
            cert: The target X.509 certificate to validate.
            issuer: Optional matching upstream issuer certificate. If self-signed, cert == issuer.
            path_depth: Current distance tracking metric from the leaf node.
            target_hostname: Optional host identifier to cross-reference against SAN designations.

        Returns:
            A list containing all discovered PolicyFinding vulnerabilities.
        """
        findings: List[PolicyFinding] = []
        present_oids = {ext.oid for ext in cert.extensions}
        is_internal = self._is_internal_domain(cert)

        # Independent Cryptographic Checks
        findings.extend(self._check_key_strength(cert))
        findings.extend(self._check_signature_algorithm(cert))

        # Check validity period
        findings.extend(self._check_validity_period(cert, is_internal))

        # RFC 6125 Compliancy Checks
        findings.extend(self._check_rfc6125_compliance(cert, present_oids, is_internal))

        # Link Validation (Requires Issuer)
        if issuer:
            issuer_cn_attribs = issuer.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            issuer_display_name = issuer_cn_attribs[0].value if issuer_cn_attribs else issuer.subject.rfc4514_string()

            # Check cryptographic signature
            if not self.verify_signature(cert, issuer):
                findings.append(PolicyFinding(
                    level="ERROR",
                    code="SIG_INVALID",
                    label="POLICY_VIOLATION",
                    message=N_("The cryptographic signature from issuer '{issuer}' is invalid or could not be verified."),
                    params={"issuer": issuer_display_name},
                    code_int=4
                ))

            # Check if issuer is actually allowed to sign (BasicConstraints)
            if not self.is_ca(issuer):
                findings.append(PolicyFinding(
                    level="ERROR",
                    code="PARENT_NOT_A_CA",
                    label="POLICY_VIOLATION",
                    message=N_("Issuer '{issuer}' is not a CA or lacks keyCertSign usage."),
                    params={"issuer": issuer_display_name},
                    code_int=4
                ))

            # Check if the issuer imposes constraints on the subject's name
            findings.extend(self._check_name_constraints(cert, issuer, present_oids))

            if path_depth is not None:
                findings.extend(self._check_path_limit(cert, issuer, path_depth))
                findings.extend(self._check_excessive_depth(path_depth))

        elif not self.is_root_ca(cert):
            issuer_cn_attribs = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            issuer_display_name = issuer_cn_attribs[0].value if issuer_cn_attribs else cert.issuer.rfc4514_string()

            findings.append(PolicyFinding(
                level="ERROR",
                code="NO_TRUST",
                label="UNTRUSTED",
                message=N_("The issuer '{issuer}' could not be found in the truststore, making this chain untrusted."),
                params={"issuer": issuer_display_name},
                code_int=3
            ))

        if hasattr(cert, 'ocsp_status') and cert.ocsp_status == "REVOKED":
            findings.append(PolicyFinding(
                level="ERROR",
                code="REVOKED_IN_CHAIN",
                label="REVOKED",
                message=N_("This certificate is untrusted because it or an issuer in its chain has been revoked."),
                code_int=5
            ))

        # Usage & Extension checks
        findings.extend(self._check_eku_compliance(cert, present_oids))

        # Checks presence of Signed Certificate Timestamps (SCT)
        if not self._should_ignore("CT_CHECK"):
            findings.extend(self._check_ct_compliance(cert, present_oids, is_internal))

        # Check presence of crl for non root certificates
        if not self._should_ignore("CRL_PRESENCE"):
            findings.extend(self._check_crl_presence(cert, present_oids, is_internal))

        # Check presence of a Netscape Comment field
        findings.extend(self._check_netscape_comment(cert, present_oids))

        # Check if hostname matches the certificate commonName
        if target_hostname:
            findings.extend(self._check_hostname_match(cert, target_hostname))

        return findings

    def verify_signature(self, cert_to_check: x509.Certificate, issuer_cert: x509.Certificate) -> bool:
        """
        Verifies the cryptographic signature of a certificate using the issuer's public key.

        Args:
            cert_to_check: The certificate whose signature needs verification.
            issuer_cert: The certificate containing the public key used for the signature.

        Returns:
            True if the signature is valid, False otherwise.
        """
        hash_algo = cert_to_check.signature_hash_algorithm

        if hash_algo is None:
            return False

        try:
            issuer_public_key = issuer_cert.public_key()
            signature = cert_to_check.signature
            data = cert_to_check.tbs_certificate_bytes

            if isinstance(issuer_public_key, rsa.RSAPublicKey):
                issuer_public_key.verify(
                    signature, data, rsa_padding.PKCS1v15(), hash_algo
                )
                return True

            elif isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
                issuer_public_key.verify(signature, data, ec.ECDSA(hash_algo))
                return True

            else:
                issuer_public_key.verify(signature, data)
                return True

        except (UnsupportedAlgorithm, InvalidSignature):
            return False

        except Exception:
            return False

    def is_ca(self, cert: x509.Certificate) -> bool:
        """
        Determines whether a certificate is authorized to act as a Certificate Authority (CA).

        This method performs a strict structural check on the certificate's extensions,
        verifying that Basic Constraints explicitly assert CA status and that Key Usage
        permits certificate signing.

        To guarantee compatibility across legacy execution environments (such as Python 3.6),
        this method takes a defensive approach by checking OID presence prior to extraction.
        This prevents underlying Rust-layer runtime panics (PyO3) that can occur when
        'ExtensionNotFound' exceptions are propagated through native extensions.

        Args:
            cert (x509.Certificate): The cryptography X.509 certificate object to evaluate.

        Returns:
            bool: True if the certificate has valid CA constraints and signing permissions;
                  False otherwise.
        """
        present_oids = {ext.oid for ext in cert.extensions}

        if ExtensionOID.BASIC_CONSTRAINTS in present_oids:
            bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
            if not bc.value.ca:
                return False
        else:
            return False

        if ExtensionOID.KEY_USAGE in present_oids:
            ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
            if not ku.value.key_cert_sign:
                return False

        return True

    def is_root_ca(self, cert: x509.Certificate) -> bool:
        """
        Validates whether a certificate qualifies as a self-signed Root CA.

        A certificate is classified as a Root CA if it fulfills three criteria:
        1. It possesses valid CA constraints and certificate signing usage capabilities.
        2. Its Subject and Issuer distinguished names (DN) are structurally identical.
        3. Its Subject Key Identifier (SKI) perfectly matches its Authority Key Identifier (AKI),
           confirming identity self-assertion if both extensions are present.

        Like `is_ca`, this method safely queries extensions by verifying OID presence
        before accessing extension properties, mitigating potential cross-version
        compatibility issues within python-cryptography.

        Args:
            cert (x509.Certificate): The cryptography X.509 certificate object to evaluate.

        Returns:
            bool: True if the certificate is a structurally valid, self-signed Root CA;
                  False if it is an intermediate CA, leaf certificate, or lacks proper identifiers.
        """
        if not self.is_ca(cert):
            return False

        is_self_signed_name = cert.subject == cert.issuer
        if not is_self_signed_name:
            return False

        try:
            present_oids = {ext.oid for ext in cert.extensions}

            ski_val = None
            if ExtensionOID.SUBJECT_KEY_IDENTIFIER in present_oids:
                ski_val = cert.extensions.get_extension_for_oid(
                    ExtensionOID.SUBJECT_KEY_IDENTIFIER
                ).value.digest

            aki_val = None
            if ExtensionOID.AUTHORITY_KEY_IDENTIFIER in present_oids:
                aki_val = cert.extensions.get_extension_for_oid(
                    ExtensionOID.AUTHORITY_KEY_IDENTIFIER
                ).value.key_identifier

            if ski_val and aki_val:
                return ski_val == aki_val

        except (x509.ExtensionNotFound, AttributeError):
            return False

        return True

    def _check_ct_compliance(self, cert: x509.Certificate, present_oids: Set[Any], is_internal: bool) -> List[PolicyFinding]:
        """
        Checks if the certificate contains Signed Certificate Timestamps (SCT).

        Args:
            cert: The target X.509 certificate to validate.
            present_oids: Pre-calculated set of OIDs within the certificate.
            is_internal: True if the certificate targets internal namespaces.

        Returns:
            A list containing findings regarding missing Certificate Transparency indicators.
        """
        if is_internal or self.is_ca(cert):
            return []

        CT_SCT_OID = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")
        findings: List[PolicyFinding] = []

        if CT_SCT_OID not in present_oids:
            findings.append(PolicyFinding(
                level="WARNING",
                code="CT_MISSING",
                label="POLICY_VIOLATION",
                message=N_("Certificate lacks Signed Certificate Timestamps (SCT). Not CT-compliant."),
                code_int=2
            ))
        return findings

    def _is_internal_domain(self, cert: x509.Certificate, present_oids: Optional[Set[Any]] = None) -> bool:
        """
        Detects if a certificate is intended for internal/private use.

        Checks for private TLDs, non-FQDNs, and private IP address ranges.

        Args:
            cert: The certificate to assess.
            present_oids: Optional set of predefined OIDs to prevent redundant extraction.

        Returns:
            True if designated for an internal environment, False otherwise.
        """
        try:
            common_names = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            if common_names:
                cn = common_names[0].value.lower()
                if any(cn.endswith(tld) for tld in self.internal_tlds):
                    return True

            if present_oids is None:
                present_oids = {ext.oid for ext in cert.extensions}

            if ExtensionOID.SUBJECT_ALTERNATIVE_NAME in present_oids:
                san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)

                for name in san.value.get_values_for_type(x509.DNSName):
                    if any(name.lower().endswith(tld) for tld in self.internal_tlds):
                        return True

                for ip in san.value.get_values_for_type(x509.IPAddress):
                    if ip.is_private:
                        return True

        except Exception:
            pass
        return False

    def _check_key_strength(self, cert: x509.Certificate) -> List[PolicyFinding]:
        """
        Evaluates the public key size/type against minimum security requirements.

        Args:
            cert: The target certificate containing the public key to evaluate.

        Returns:
            A list containing findings if keys do not meet configuration baselines.
        """
        findings: List[PolicyFinding] = []
        pub_key = cert.public_key()

        if isinstance(pub_key, rsa.RSAPublicKey):
            if pub_key.key_size < self.min_rsa_bits:
                findings.append(PolicyFinding(
                    level="ERROR",
                    code="WEAK_RSA",
                    label="INSECURE",
                    message=N_("RSA key size ({bits} bits) is below the minimum required {min_bits} bits."),
                    params={"bits": pub_key.key_size, "min_bits": self.min_rsa_bits},
                    code_int=4
                ))
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            if pub_key.key_size < self.min_ecdsa_bits:
                findings.append(PolicyFinding(
                    level="ERROR",
                    code="WEAK_ECC",
                    label="INSECURE",
                    message=N_("ECC key size ({bits} bits) is below the minimum required {min_bits} bits."),
                    params={"bits": pub_key.key_size, "min_bits": self.min_ecdsa_bits},
                    code_int=4
                ))
        return findings

    def _check_signature_algorithm(self, cert: x509.Certificate) -> List[PolicyFinding]:
        """
        Checks if the certificate uses secure hashing algorithms for its signature.

        Handles deprecated hashes (SHA1/MD5) and cases where the algorithm is
        unsupported or unknown by the underlying system.

        Args:
            cert: The target certificate to scan.

        Returns:
            A list containing discovered hashing standard violations.
        """
        findings: List[PolicyFinding] = []

        try:
            algo = cert.signature_hash_algorithm
        except (UnsupportedAlgorithm, Exception):
            findings.append(PolicyFinding(
                level="ERROR",
                code="UNKNOWN_HASH",
                label="INSECURE",
                message=N_("The signature algorithm is unknown or unsupported by the system."),
                code_int=4
            ))
            return findings

        if algo is None:
            pub_key = cert.public_key()
            if isinstance(pub_key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
                findings.append(PolicyFinding(
                    level="ERROR",
                    code="MISSING_HASH",
                    label="INSECURE",
                    message=N_("Certificate is missing a hashing algorithm for its signature."),
                    code_int=4
                ))
            return findings

        algo_name = algo.name.lower()
        if algo_name in self.DEPRECATED_HASHES:
            findings.append(PolicyFinding(
                level="ERROR",
                code="DEPRECATED_HASH",
                label="INSECURE",
                message=N_("Certificate uses a deprecated hash algorithm ({name})."),
                params={"name": algo_name.upper()},
                code_int=4
            ))

        return findings

    def _check_eku_compliance(self, cert: x509.Certificate, present_oids: Set[Any]) -> List[PolicyFinding]:
        """
        Analyzes Extended Key Usage (EKU) to ensure the certificate is purposed correctly.

        Args:
            cert: The end-entity or intermediate certificate.
            present_oids: Pre-calculated extension map.

        Returns:
            A list of structural policy warnings based on over-privileging or missing contexts.
        """
        findings: List[PolicyFinding] = []

        if ExtensionOID.EXTENDED_KEY_USAGE not in present_oids:
            # For modern TLS/SSL, EKU is expected.
            # We flag it as INFO/WARNING if missing on end-entity certs.
            if not self.is_ca(cert):
                findings.append(PolicyFinding(
                    level="INFO",
                    code="MISSING_EKU",
                    label="POLICY_VIOLATION",
                    message=N_("End-entity certificate lacks Extended Key Usage extension."),
                    code_int=1
                ))
            return findings

        try:
            eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
            usages = [u.dotted_string for u in eku.value]

            # Check for 'Any Extended Key Usage' (Security Risk)
            if "2.5.29.37.0" in usages:
                findings.append(PolicyFinding(
                    level="WARNING",
                    code="ANY_EKU_PRESENT",
                    label="POLICY_VIOLATION",
                    message=N_("Certificate contains 'Any Extended Key Usage', which is overly permissive."),
                    code_int=2
                ))

            # Check for Over-privileging (Server Auth + Code Signing)
            if ExtendedKeyUsageOID.SERVER_AUTH.dotted_string in usages and \
               ExtendedKeyUsageOID.CODE_SIGNING.dotted_string in usages:
                findings.append(PolicyFinding(
                    level="WARNING",
                    code="EKU_OVERPRIVILEGED",
                    label="POLICY_VIOLATION",
                    message=N_("Certificate allows both Server Auth and Code Signing. Functional separation is recommended."),
                    code_int=2
                ))

            # Add information about the primary purpose for display logic
            readable_usages = self._get_eku(cert, present_oids)
            if readable_usages:
                findings.append(PolicyFinding(
                    level="INFO",
                    code="EKU_PURPOSE",
                    label="EKU_INFORMATION",
                    message=f"Certificate purpose: {', '.join(readable_usages)}",
                    params={"usages": readable_usages},
                    code_int=0
                ))

        except Exception:
            findings.append(PolicyFinding(
                level="ERROR",
                code="EKU_PARSE_ERROR",
                label="POLICY_VIOLATION",
                message=N_("Could not parse Extended Key Usage extension data."),
                code_int=4
            ))

        return findings

    def _get_eku(self, cert: x509.Certificate, present_oids: Set[Any]) -> List[str]:
        """
        Maps EKU OIDs to human-readable strings.

        Args:
            cert: Target certificate context.
            present_oids: Available indexed extensions.

        Returns:
            A list of translated strings representing active usages.
        """
        try:
            if ExtensionOID.EXTENDED_KEY_USAGE not in present_oids:
                return []

            eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)

            mapping = {
                ExtendedKeyUsageOID.SERVER_AUTH.dotted_string: N_("Server Authentication"),
                ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string: N_("Client Authentication"),
                ExtendedKeyUsageOID.CODE_SIGNING.dotted_string: N_("Code Signing"),
                ExtendedKeyUsageOID.EMAIL_PROTECTION.dotted_string: N_("Email Protection"),
                ExtendedKeyUsageOID.TIME_STAMPING.dotted_string: N_("Time Stamping"),
                ExtendedKeyUsageOID.OCSP_SIGNING.dotted_string: N_("OCSP Signing"),
                "1.3.6.1.5.5.7.3.17": N_("IPSec User"),
                "1.3.6.1.5.5.7.3.18": N_("IPSec Intermediate"),
                "1.3.6.1.5.5.7.3.19": N_("IPSec Tunnel"),
            }

            return [
                mapping.get(u.dotted_string, N_("Unknown ({oid})").format(oid=u.dotted_string))
                for u in eku.value
            ]
        except Exception:
            return []

    def _check_validity_period(self, cert: x509.Certificate, is_internal: bool) -> List[PolicyFinding]:
        """
        Checks if the certificate validity exceeds industry standards (e.g., 398 days).

        Args:
            cert: The certificate context to benchmark.
            is_internal: Boolean identifying if high thresholds for local setups apply.

        Returns:
            A list containing life-span duration boundary violations.
        """
        findings: List[PolicyFinding] = []

        not_before = (
            cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc")
            else cert.not_valid_before.replace(tzinfo=timezone.utc)
        )
        not_after = (
            cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc")
            else cert.not_valid_after.replace(tzinfo=timezone.utc)
        )

        duration = not_after - not_before
        limit = 398 if not is_internal else 825

        if not self.is_ca(cert) and duration.days > limit:
            findings.append(PolicyFinding(
                level="INFO" if is_internal else "WARNING",
                code="LONG_VALIDITY",
                label="POLICY_VIOLATION",
                message=N_("Validity period ({days} days) exceeds the {limit}-day limit."),
                params={"days": duration.days, "limit": limit},
                code_int=0 if is_internal else 1
            ))
        return findings

    def _check_rfc6125_compliance(self, cert: x509.Certificate, present_oids: Set[Any], is_internal: bool) -> List[PolicyFinding]:
        """
        Verifies compliance with RFC 6125 naming boundaries.

        Ensures that if the SAN extension is present, the Common Name (CN) is
        replicated within the SAN parameters.

        Args:
            cert: The target certificate to analyze.
            present_oids: Pre-calculated extension map.
            is_internal: True if private rules allow single-label domains.

        Returns:
            A list of discovered SAN alignment abnormalities.
        """
        findings: List[PolicyFinding] = []

        if self.is_ca(cert):
            return findings

        common_names = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if not common_names:
            return findings

        cn_value = common_names[0].value.lower()

        if ExtensionOID.SUBJECT_ALTERNATIVE_NAME in present_oids:
            san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_dns = [name.lower() for name in san.value.get_values_for_type(x509.DNSName)]
            san_ips = [str(ip) for ip in san.value.get_values_for_type(x509.IPAddress)]
            all_san_values = set(san_dns + san_ips)

            if cn_value not in all_san_values:
                findings.append(PolicyFinding(
                    level="WARNING",
                    code="RFC6125_MISMATCH",
                    label="POLICY_VIOLATION",
                    message=N_("Common Name '{cn}' is missing from Subject Alternative Names (SAN)."),
                    params={"cn": cn_value},
                    code_int=2
                ))

                for name in san_dns:
                    if "." not in name:
                        level = "INFO" if is_internal else "WARNING"
                        findings.append(PolicyFinding(
                            level=level,
                            code="NON_FQDN_SAN",
                            label="POLICY_VIOLATION",
                            message=N_("SAN contains a non-FQDN '{name}', which is disallowed for public certificates."),
                            params={"name": name},
                            code_int=0 if is_internal else 2
                        ))
        else:
            findings.append(PolicyFinding(
                level="WARNING",
                code="MISSING_SAN",
                label="POLICY_VIOLATION",
                message=N_("Certificate lacks a SAN extension. Relying solely on CN is deprecated."),
                code_int=2
            ))

        return findings

    def _check_crl_presence(self, cert: x509.Certificate, present_oids: Set[Any], is_internal: bool) -> List[PolicyFinding]:
        """
        Checks for the presence of CRL Distribution Points (CDP).

        Args:
            cert: Certificate node target.
            present_oids: Set containing extracted target extension identifiers.
            is_internal: Exemption tracker for private ecosystems.

        Returns:
            A list containing findings if revocation anchors are missing.
        """
        findings: List[PolicyFinding] = []
        is_root = self.is_root_ca(cert)

        if not is_root:
            if ExtensionOID.CRL_DISTRIBUTION_POINTS not in present_oids:
                level = "INFO" if is_internal else "WARNING"
                findings.append(PolicyFinding(
                    level=level,
                    code="CRL_MISSING",
                    label="POLICY_VIOLATION",
                    message=N_("Certificate lacks CRL Distribution Points (CDP). Revocation checking may be limited."),
                    code_int=0 if is_internal else 2
                ))
        return findings

    def _check_path_limit(self, cert: x509.Certificate, issuer: x509.Certificate, depth: int) -> List[PolicyFinding]:
        """
        Validates the Basic Constraints pathLenConstraint according to RFC 5280.

        Args:
            cert: The actual subject node.
            issuer: The parent node signing the client.
            depth: Current hierarchical track layer position index.

        Returns:
            A list containing findings if validation depth breaks chain policies.
        """
        findings: List[PolicyFinding] = []

        if not self.is_ca(cert):
            return findings

        issuer_oids = {ext.oid for ext in issuer.extensions}

        if ExtensionOID.BASIC_CONSTRAINTS in issuer_oids:
            bc = issuer.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
            path_len = bc.value.path_length
            if path_len is not None and (depth - 1) > path_len:
                findings.append(PolicyFinding(
                    level="ERROR",
                    code="PATH_LEN_EXCEEDED",
                    label="POLICY_VIOLATION",
                    message=N_("Path length constraint exceeded. Issuer allows max {limit} intermediate(s)."),
                    params={"limit": bc.value.path_length, "actual_depth": depth - 1},
                    code_int=4
                ))

        return findings

    def _check_excessive_depth(self, depth: int) -> List[PolicyFinding]:
        """
        Validate the certificate chain depth against defined security policies.

        Args:
            depth (int): The current depth of the certificate chain.

        Returns:
            List[PolicyFinding]: A list containing a 'CHAIN_TOO_DEEP' warning
                                 if the depth exceeds the allowed maximum.
        """
        findings: List[PolicyFinding] = []

        if depth > self.max_policy_depth:
            findings.append(PolicyFinding(
                level="WARNING",
                code="CHAIN_TOO_DEEP",
                label="POLICY_VIOLATION",
                message=N_("The certificate chain exceeds the maximum allowed depth."),
                code_int=2
            ))
        return findings

    def _check_hostname_match(self, cert: x509.Certificate, target_host: str) -> List[PolicyFinding]:
        """
        Validates that the certificate is actually valid for the host being accessed.

        Args:
            cert: End-entity certificate instance.
            target_host: Incoming fully qualified server target or connection IP address string.

        Returns:
            A list of errors if identity mismatch is encountered.
        """
        findings: List[PolicyFinding] = []
        target_host_lower = target_host.lower()
        matched = False

        try:
            san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            dns_names = [name.lower() for name in san.value.get_values_for_type(x509.DNSName)]
        except Exception:
            dns_names = []

        for pattern in dns_names:
            if self._dns_name_match(pattern, target_host_lower):
                matched = True
                break

        if not matched:
            findings.append(PolicyFinding(
                level="ERROR",
                code="HOSTNAME_MISMATCH",
                label="INVALID",
                message=N_("Hostname mismatch: Certificate is valid for '{names}', but you connected to '{target}'."),
                params={"names": ", ".join(dns_names), "target": target_host_lower},
                code_int=4
            ))
        return findings

    def _dns_name_match(self, pattern: str, hostname: str) -> bool:
        """
        Professional RFC 6125 Wildcard Matcher.

        Args:
            pattern: The pattern found inside the SAN extension.
            hostname: Target host requested by the user application.

        Returns:
            True if matching guidelines succeed, False otherwise.
        """
        if pattern == hostname:
            return True

        if '*' not in pattern:
            return False

        parts = pattern.split('.')
        if parts[0] != '*' or len(parts) < 3:
            return False

        remainder = ".".join(parts[1:])
        if not hostname.endswith("." + remainder):
            return False

        hostname_remainder_len = len(hostname) - len(remainder) - 1
        hostname_left_label = hostname[:hostname_remainder_len]

        return "." not in hostname_left_label

    def _check_netscape_comment(self, cert: x509.Certificate, present_oids: Optional[Set[Any]] = None) -> List[PolicyFinding]:
        """
        Extracts and reports the legacy Netscape Comment extension if present.

        Args:
            cert: Target parsing structure.
            present_oids: Optional mapped sequence identifiers.

        Returns:
            A list containing administrative annotations found inside the raw bytes.
        """
        findings = []
        NETSCAPE_COMMENT_OID = x509.ObjectIdentifier("2.16.840.1.113730.1.13")
        try:
            if present_oids is None:
                present_oids = {ext.oid for ext in cert.extensions}

            if NETSCAPE_COMMENT_OID in present_oids:
                ext = cert.extensions.get_extension_for_oid(NETSCAPE_COMMENT_OID)
                comment_value = ext.value.value.decode('utf-8', errors='replace')
                findings.append(PolicyFinding(
                    level="INFO",
                    code="COMMENT",
                    label="COMMENT",
                    message=N_("Netscape Comment found: {comment}"),
                    params={"comment": comment_value},
                    code_int=0
                ))
        except Exception:
            pass
        return findings

    def _check_name_constraints(self, cert: x509.Certificate, issuer: x509.Certificate, present_oids: Optional[Set[Any]] = None) -> List[PolicyFinding]:
        """
        Validates Name Constraints (RFC 5280) imposed by the issuer on the subject.

        Args:
            cert: Evaluated child element node.
            issuer: Upstream parent holding constraints boundaries mapping.
            present_oids: Optional active lookup map.

        Returns:
            A list containing namespace exclusion violations.
        """
        findings = []
        try:
            nc_ext = issuer.extensions.get_extension_for_oid(ExtensionOID.NAME_CONSTRAINTS)
            constraints = nc_ext.value

            cert_names = []
            if ExtensionOID.SUBJECT_ALTERNATIVE_NAME in present_oids:
                san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                cert_names = [
                    n.value.lower() if hasattr(n, 'value') else str(n).lower()
                    for n in san_ext.value.get_values_for_type(x509.DNSName)
                ]
            else:
                cert_names = [
                    attr.value.lower() if hasattr(attr, 'value') else str(attr).lower()
                    for attr in cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                ]

            if constraints.permitted_subtrees:
                for name_str in cert_names:
                    is_permitted = False
                    for subtree in constraints.permitted_subtrees:
                        base = subtree.base if hasattr(subtree, 'base') else subtree

                        if isinstance(base, x509.DNSName):
                            if self._match_dns(name_str, base.value.lower()):
                                is_permitted = True
                                break

                    if not is_permitted:
                        findings.append(PolicyFinding(
                            level="ERROR",
                            code="NAME_CONSTRAINT_VIOLATION",
                            label="RESTRICTED",
                            message=N_("Certificate name '{name}' is not permitted by issuer constraints."),
                            params={"name": name_str},
                            code_int=4
                        ))

            if constraints.excluded_subtrees:
                for name_str in cert_names:
                    for subtree in constraints.excluded_subtrees:
                        base = subtree.base if hasattr(subtree, 'base') else subtree
                        if isinstance(base, x509.DNSName):
                            if self._match_dns(name_str, base.value.lower()):
                                findings.append(PolicyFinding(
                                    level="ERROR",
                                    code="NAME_CONSTRAINT_EXCLUDED",
                                    label="RESTRICTED",
                                    message=N_("Certificate name '{name}' is explicitly excluded by the issuer."),
                                    params={"name": name_str},
                                    code_int=4
                                ))
                                break

        except x509.ExtensionNotFound:
            pass
        return findings

    def _match_dns(self, hostname: str, constraint: str) -> bool:
        """
        Performs DNS subtree matching for Name Constraints.

        Args:
            hostname: Lowercase name under validation.
            constraint: Domain string definition context.

        Returns:
            True if compliant with structural constraints layout, False otherwise.
        """
        clean_constraint = constraint.lstrip('.')

        if hostname.startswith('*.'):
            wildcard_base = hostname[2:]
            return wildcard_base == clean_constraint or wildcard_base.endswith('.' + clean_constraint)

        return hostname == clean_constraint or hostname.endswith('.' + clean_constraint)