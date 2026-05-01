"""
TrustStore Analyzer - Policy Engine
Handles X.509 constraint validation, cryptographic verification, and security compliance.
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later
"""

from typing import List, Optional, Any, Dict
from datetime import timezone
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding as rsa_padding
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm

class PolicyFinding:
    """
    Represents a specific policy violation or security warning.
    """
    def __init__(self, level: str, code: str, message: str, params: Optional[Dict[str, Any]] = None, code_int: int = 4):
        """
        Initializes a policy finding.

        Args:
            level: Severity level (e.g., 'ERROR', 'WARNING', 'INFO').
            code: Unique machine-readable identifier for the finding type.
            message: Human-readable description of the issue.
            params: Optional metadata for dynamic message formatting.
        """
        self.level = level
        self.code = code
        self.message = message
        self.params = params or {}
        self.code_int = code_int

    def model_dump(self):
        """
        Returns a dictionary representation of the finding,
        suitable for JSON serialization or API responses.
        """
        return {
            "level": self.level,
            "code": self.code,
            "message": self.message,
            "code_int": self.code_int,
            "params": self.params
        }

class PolicyEngine:
    """
    Core engine responsible for validating X.509 certificates against
    modern security standards, trust constraints, and cryptographic best practices.
    """

    def __init__(self, **kwargs):
        """
        Initializes the engine with default security thresholds for 2026.
        """
        self.min_rsa_bits = 2048
        self.min_ecdsa_bits = 256
        self.debug = kwargs.get('debug', False)

    def validate(self, cert: x509.Certificate, issuer: Optional[x509.Certificate] = None, path_depth: Optional[int] = None) -> List[PolicyFinding]:
        """
        Performs a comprehensive suite of security checks on a certificate.

        Args:
            cert: The certificate to be validated.
            issuer: The signing certificate (if available) to verify the chain of trust.

        Returns:
            A list of PolicyFinding objects representing discovered issues.
        """
        findings = []

        # Independent Cryptographic Checks
        findings.extend(self._check_key_strength(cert))
        findings.extend(self._check_signature_algorithm(cert))

        # Check validity period
        findings.extend(self._check_validity_period(cert))

        # RFC 6125 Compliancy Checks
        findings.extend(self._check_rfc6125_compliance(cert))

        # Link Validation (Requires Issuer)
        if issuer:
            # Check cryptographic signature
            if not self.verify_signature(cert, issuer):
                findings.append(PolicyFinding(
                    "ERROR", "SIG_INVALID",
                    "The cryptographic signature is invalid or could not be verified.",
                    code_int=4
                ))

            # Check if issuer is actually allowed to sign (BasicConstraints)
            if not self.is_ca(issuer):
                issuer_name = issuer.subject.rfc4514_string()
                findings.append(PolicyFinding(
                    "ERROR", "PARENT_NOT_A_CA",
                    f"Issuer '{issuer_name}' is not a CA or lacks keyCertSign usage.",
                    params={"issuer": issuer_name},
                    code_int=4
                ))

            if path_depth is not None:
                findings.extend(self._check_path_limit(cert, issuer, path_depth))

        elif not cert.subject == cert.issuer:
            findings.append(PolicyFinding(
                level="ERROR",
                code="NO_TRUST",
                message="The certificate issuer could not be found in the truststore, making this chain untrusted.",
                code_int=3
            ))

        # Usage & Extension checks
        findings.extend(self._check_eku_compliance(cert))

        # Check presence of crl for non root certificates
        findings.extend(self._check_crl_presence(cert))

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
        try:
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
                issuer_public_key.verify(signature, data, ec.ECDSA(hash_algo))
                return True

            else:
                issuer_public_key.verify(signature, data)
                return True

        except UnsupportedAlgorithm:
            if self.debug:
                 from .logging import WARNING
                 WARNING.log("SIG_CHECK", f"Unsupported algorithm: {cert_to_check.signature_hash_algorithm.name if hash_algo else 'Unknown'}")
            return False

        except InvalidSignature:
            return False

        except Exception:
            return False

    def is_ca(self, cert: x509.Certificate) -> bool:
        """
        Determines if a certificate is permitted to act as a Certificate Authority (CA).

        Note: This method uses a defensive approach by checking OID presence
        before requesting extension data. This prevents PyO3 runtime panics
        on legacy environments (Python 3.6) that occur when 'ExtensionNotFound'
        exceptions are raised from within the Rust-based cryptography layer.
        """
        present_oids = [ext.oid for ext in cert.extensions]

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

    def _check_key_strength(self, cert: x509.Certificate) -> List[PolicyFinding]:
        """
        Evaluates the public key size/type against minimum security requirements.
        """
        findings = []
        pub_key = cert.public_key()

        if isinstance(pub_key, rsa.RSAPublicKey):
            if pub_key.key_size < self.min_rsa_bits:
                findings.append(PolicyFinding(
                    "ERROR", "WEAK_RSA",
                    f"RSA key size ({pub_key.key_size} bits) is below the minimum required {self.min_rsa_bits} bits.",
                    params={"bits": pub_key.key_size, "min_bits": self.min_rsa_bits},
                    code_int=4
                ))
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            if pub_key.key_size < self.min_ecdsa_bits:
                findings.append(PolicyFinding(
                    "ERROR", "WEAK_ECC",
                    f"ECC key size ({pub_key.key_size} bits) is below the minimum required {self.min_ecdsa_bits} bits.",
                    params={"bits": pub_key.key_size, "min_bits": self.min_ecdsa_bits},
                    code_int=4
                ))
        return findings

    def _check_signature_algorithm(self, cert: x509.Certificate) -> List[PolicyFinding]:
        """
        Checks if the certificate uses secure hashing algorithms for its signature.
        """
        findings = []
        # SHA-1 check
        if isinstance(cert.signature_hash_algorithm, hashes.SHA1):
            findings.append(PolicyFinding(
                "ERROR", "DEPRECATED_HASH",
                "Certificate uses SHA-1 signature algorithm which is no longer trusted.",
                params={"algo": "SHA-1"},
                code_int=4
            ))
        return findings

    def _check_eku_compliance(self, cert: x509.Certificate) -> List[PolicyFinding]:
        """
        Analyzes Extended Key Usage (EKU) to ensure the certificate is
        purposed correctly and not over-privileged.
        """
        findings = []
        present_oids = [ext.oid for ext in cert.extensions]

        if ExtensionOID.EXTENDED_KEY_USAGE not in present_oids:
            # For modern TLS/SSL, EKU is expected.
            # We flag it as INFO/WARNING if missing on end-entity certs.
            if not self.is_ca(cert):
                findings.append(PolicyFinding(
                    "INFO", "MISSING_EKU",
                    "End-entity certificate lacks Extended Key Usage extension.",
                    code_int=1
                ))
            return findings

        try:
            eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
            usages = [u.dotted_string for u in eku.value]

            # Check for 'Any Extended Key Usage' (Security Risk)
            if "2.5.29.37.0" in usages:
                findings.append(PolicyFinding(
                    "WARNING", "ANY_EKU_PRESENT",
                    "Certificate contains 'Any Extended Key Usage', which is overly permissive.",
                    code_int=2
                ))

            # Check for Over-privileging (Server Auth + Code Signing)
            if ExtendedKeyUsageOID.SERVER_AUTH.dotted_string in usages and \
               ExtendedKeyUsageOID.CODE_SIGNING.dotted_string in usages:
                findings.append(PolicyFinding(
                    "WARNING", "EKU_OVERPRIVILEGED",
                    "Certificate allows both Server Auth and Code Signing. Functional separation is recommended.",
                    code_int=2
                ))

            # Add information about the primary purpose for display logic
            readable_usages = self._get_eku(cert)
            if readable_usages:
                findings.append(PolicyFinding(
                    "INFO", "EKU_PURPOSE",
                    f"Certificate purpose: {', '.join(readable_usages)}",
                    params={"usages": readable_usages},
                    code_int=1
                ))

        except Exception:
            findings.append(PolicyFinding(
                "ERROR", "EKU_PARSE_ERROR",
                "Could not parse Extended Key Usage extension data.",
                code_int=4
            ))

        return findings

    def _get_eku(self, cert: x509.Certificate) -> List[str]:
        """
        Maps EKU OIDs to human-readable strings.
        """
        try:
            present_oids = [ext.oid for ext in cert.extensions]
            if ExtensionOID.EXTENDED_KEY_USAGE not in present_oids:
                return []

            eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)

            mapping = {
                ExtendedKeyUsageOID.SERVER_AUTH.dotted_string: "Server Authentication",
                ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string: "Client Authentication",
                ExtendedKeyUsageOID.CODE_SIGNING.dotted_string: "Code Signing",
                ExtendedKeyUsageOID.EMAIL_PROTECTION.dotted_string: "Email Protection",
                ExtendedKeyUsageOID.TIME_STAMPING.dotted_string: "Time Stamping",
                ExtendedKeyUsageOID.OCSP_SIGNING.dotted_string: "OCSP Signing",
                "1.3.6.1.5.5.7.3.17": "IPSec User",
                "1.3.6.1.5.5.7.3.18": "IPSec Intermediate",
                "1.3.6.1.5.5.7.3.19": "IPSec Tunnel",
            }

            return [mapping.get(u.dotted_string, f"Unknown ({u.dotted_string})") for u in eku.value]
        except Exception:
            return []

    def _check_validity_period(self, cert: x509.Certificate) -> List[PolicyFinding]:
        """
        Check if the certificate validity period exceeds the industry standard of 398 days.
        Ref: CAB Forum BR 6.3.2
        """
        findings = []

        # Calculate the duration
        not_before = (
            cert.not_valid_before_utc
            if hasattr(cert, "not_valid_after_utc")
            else cert.not_valid_before.replace(tzinfo=timezone.utc)
        )
        not_after = (
            cert.not_valid_after_utc
            if hasattr(cert, "not_valid_after_utc")
            else cert.not_valid_after.replace(tzinfo=timezone.utc)
        )
        duration = not_after - not_before

        if not self.is_ca(cert):
            if duration.days > 398:
                findings.append(PolicyFinding(
                    level="WARNING",
                    code="LONG_VALIDITY",
                    message=f"Certificate validity period ({duration.days} days) exceeds the 398-day limit.",
                    params={"duration_days": duration.days, "status_code": 1},
                    code_int=1
                ))

        return findings

    def _check_rfc6125_compliance(self, cert: x509.Certificate) -> List[PolicyFinding]:
        """
        Verifies compliance with RFC 6125: If the SAN extension is present,
        the Common Name (CN) must also be included within the SAN list.
        """
        findings = []

        if self.is_ca(cert):
            return findings

        common_names = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if not common_names:
            return findings

        cn_value = common_names[0].value.lower()
        present_oids = [ext.oid for ext in cert.extensions]

        if ExtensionOID.SUBJECT_ALTERNATIVE_NAME in present_oids:
            san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_names = san.value.get_values_for_type(x509.DNSName)
            san_ips = [str(ip) for ip in san.value.get_values_for_type(x509.IPAddress)]
            all_san_values = [name.lower() for name in san_names] + san_ips

            if cn_value not in all_san_values:
                findings.append(PolicyFinding(
                    "WARNING", "RFC6125_MISMATCH",
                    f"Common Name '{cn_value}' is missing from Subject Alternative Names (SAN).",
                    params={"cn": cn_value, "san": all_san_values},
                    code_int=2
                ))
        else:
            findings.append(PolicyFinding(
                "WARNING", "MISSING_SAN",
                "Certificate lacks a SAN extension. Relying solely on CN is deprecated.",
                code_int=2
            ))

        return findings

    def _check_crl_presence(self, cert: x509.Certificate) -> List[PolicyFinding]:
        """
        Checks for CRL Distribution Points (CDP).
        Warnings are suppressed for Root certificates (self-signed).
        """
        findings = []
        is_root = cert.subject == cert.issuer

        if not self.is_ca(cert):
            present_oids = [ext.oid for ext in cert.extensions]
            if ExtensionOID.CRL_DISTRIBUTION_POINTS not in present_oids:
                if not is_root:
                    findings.append(PolicyFinding(
                    "WARNING", "CRL_MISSING",
                    "Certificate lacks CRL Distribution Points (CDP). Revocation checking may be limited.",
                    code_int=2
                ))
        return findings

    def _check_path_limit(self, cert: x509.Certificate, issuer: x509.Certificate, depth: int) -> List[PolicyFinding]:
        """
        Validates the Basic Constraints pathLenConstraint according to RFC 5280.
        The pathLenConstraint specifies the maximum number of non-self-issued
        intermediate certificates that may follow this certificate in a valid chain.
        """
        findings = []

        if not self.is_ca(cert):
            return findings

        present_oids = [ext.oid for ext in issuer.extensions]

        if ExtensionOID.BASIC_CONSTRAINTS in present_oids:
            bc = issuer.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
            path_len = bc.value.path_length
            if path_len is not None and (depth - 1) > path_len:
                findings.append(PolicyFinding(
                    "ERROR", "PATH_LEN_EXCEEDED",
                    f"Path length constraint exceeded. Issuer allows max {path_len} intermediate(s), but found at depth {depth-1}.",
                    params={"limit": path_len, "actual_depth": depth - 1},
                    code_int=4
                ))

        return findings