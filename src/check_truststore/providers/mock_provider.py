"""
TrustStore Analyzer - Mock Provider
Generates in-memory certificates for testing all edge cases without physical files.
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later

This provider generates mock X.509 data for testing purposes. It returns
metadata dictionaries to the orchestrator to ensure registration happens
after the repository cache reset.
"""

from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional, Any, Tuple

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import UnsupportedAlgorithm

from check_truststore.providers.base import BaseInputProvider, TrustStoreGroup
from check_truststore.engine import CertificateRepository
from check_truststore.engine.models import Certificate


class MockProvider(BaseInputProvider):
    """
    Provides mock certificates and groups to simulate various trust chain scenarios.

    Attributes:
        repository: Reference to the central certificate storage.
        keys (Dict[str, rsa.RSAPrivateKey]): Cache of generated keys to maintain
            consistency between issuers and subjects.
    """
    def __init__(self, repository: Optional[CertificateRepository] = None, **kwargs: Any) -> None:
        """
        Initializes the mock provider.

        Args:
            repository: Optional repository instance for integration testing.
        """
        super().__init__(repository=repository, **kwargs)
        self.keys: Dict[Tuple[str, int, str], Any] = {}

    def _get_key(self, cn: str, key_size: int = 2048, algo: str = "rsa") -> Any:
        """
        Retrieves or generates a persistent RSA private key for a specific
        Common Name and key size.
        """
        actual_size = 256 if algo == "ec" else key_size
        cache_key = (cn, actual_size, algo)

        if cache_key not in self.keys:
            if algo == "ec":
                self.keys[cache_key] = ec.generate_private_key(ec.SECP256R1(), default_backend())
            else:
                self.keys[cache_key] = rsa.generate_private_key(
                    public_exponent=65537, key_size=actual_size, backend=default_backend()
                )
        return self.keys[cache_key]

    def create_cert(
        self,
        common_name: str,
        issuer_cn: Optional[str] = None,
        is_ca: bool = False,
        key_type: str = "rsa",
        issuer_key_type: str = "rsa",
        days_valid: int = 365,
        corrupt_signature: bool = False,
        subject_key_override: Optional[rsa.RSAPrivateKey] = None,
        issuer_key_override: Optional[rsa.RSAPrivateKey] = None,
        san_names: Optional[List[str]] = None,
        add_crl: bool = False,
        key_size: int = 2048,
        hash_algo: hashes.HashAlgorithm = hashes.SHA256(),
        permitted_dns: Optional[List[str]] = None,
        excluded_dns: Optional[List[str]] = None,
    ) -> x509.Certificate:
        """
        Fabricates an x509 certificate with specific properties for test scenarios.
        """
        subject_key = subject_key_override or self._get_key(common_name, key_size, algo=key_type)

        if issuer_cn and issuer_cn != common_name:
            issuer_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])
            issuer_key = issuer_key_override or self._get_key(issuer_cn, algo=issuer_key_type)
        else:
            issuer_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
            issuer_key = subject_key

        now = datetime.now(timezone.utc)
        if days_valid < 0:
            not_before = now + timedelta(days=days_valid - 1)
            not_after = now + timedelta(days=days_valid)
        else:
            not_before = now - timedelta(days=1)
            not_after = now + timedelta(days=days_valid)

        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
            .issuer_name(issuer_name)
            .public_key(subject_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
        )

        # Subject Key Identifier
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()),
            critical=False
        )

        # Authority Key Identifier
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False
        )

        # Basic Constraints
        builder = builder.add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=None),
            critical=True
        )

        # Key Usage
        usage = x509.KeyUsage(
            digital_signature=True, content_commitment=False,
            key_encipherment=not is_ca, data_encipherment=False,
            key_agreement=False, key_cert_sign=is_ca,
            crl_sign=is_ca, encipher_only=False, decipher_only=False
        )
        builder = builder.add_extension(usage, critical=True)

        # Name Constraints (RFC 5280)
        if permitted_dns or excluded_dns:
            GS = getattr(x509, "GeneralSubtree", None)
            if GS is None:
                for loc in ["cryptography.x509.name_constraints", "cryptography.x509.general_name"]:
                    try:
                        mod = __import__(loc, fromlist=["GeneralSubtree"])
                        GS = getattr(mod, "GeneralSubtree")
                        break
                    except (ImportError, AttributeError):
                        continue

            if GS:
                permitted = [GS(x509.DNSName(name)) for name in permitted_dns] if permitted_dns else None
                excluded = [GS(x509.DNSName(name)) for name in excluded_dns] if excluded_dns else None

                try:
                    builder = builder.add_extension(
                        x509.NameConstraints(permitted_subtrees=permitted, excluded_subtrees=excluded),
                        critical=True
                    )
                except Exception:
                    pass

            else:
                try:
                    builder = builder.add_extension(
                        x509.NameConstraints(
                            permitted_subtrees=[x509.DNSName(n) for n in permitted_dns] if permitted_dns else None,
                            excluded_subtrees=[x509.DNSName(n) for n in excluded_dns] if excluded_dns else None
                        ),
                        critical=True
                    )
                except Exception:
                    pass

        # SAN & EKU for Leaf certificates
        if not is_ca:
            names = [x509.DNSName(common_name)]
            if san_names:
                names.extend([x509.DNSName(n) for n in san_names])
            builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
            builder = builder.add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False
            )

        signing_key = issuer_key
        if corrupt_signature:
            signing_key = rsa.generate_private_key(65537, 2048, default_backend())

        if add_crl:
            crl_url = f"http://crl.mock-pki.com/{issuer_cn or common_name}.crl"
            builder = builder.add_extension(
                x509.CRLDistributionPoints([
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier(crl_url)],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]),
                critical=False
            )

        try:
            return builder.sign(signing_key, hash_algo, default_backend())
        except (UnsupportedAlgorithm, Exception):
            return builder.sign(signing_key, hashes.SHA256(), default_backend())

    def get_groups(self) -> List[TrustStoreGroup]:
        certs = self._generate_test_suite()
        pool: List[Dict[str, Any]] = []

        for cert in certs:
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

            der_bytes = cert.public_bytes(serialization.Encoding.DER)
            cert_hash = Certificate.calculate_fingerprint(der_bytes)

            pool.append({
                "cert": cert,
                "path": Path("MockData") / f"{cn}.pem",
                "hash": cert_hash,
                "is_system_cert": False
            })

        return [TrustStoreGroup(name="Mock Test Suite", targets=pool, ignore_ct=True)]

    def _generate_test_suite(self) -> List[x509.Certificate]:
        """
        Generates the mock test suite.

        Returns certificate data as dictionaries so the Orchestrator can handle
        the registration after the cache reset.
        """
        certs = []

        # Valid Chain
        certs.append(self.create_cert("Root CA", is_ca=True))
        certs.append(self.create_cert("Intermediate Valid", issuer_cn="Root CA", is_ca=True, add_crl=True))
        certs.append(self.create_cert("www.example.com", issuer_cn="Intermediate Valid",
                                      san_names=["example.com", "api.example.com"], add_crl=True))

        # Expired
        certs.append(self.create_cert("Expired CA", is_ca=True, days_valid=-100))
        certs.append(self.create_cert("Server Under Expired CA", issuer_cn="Expired CA", add_crl=True))

        # Expiring soon
        certs.append(self.create_cert("Intermediate Expiring Soon", issuer_cn="Root CA", is_ca=True, days_valid=5, add_crl=True))
        certs.append(self.create_cert("Server at Risk", issuer_cn="Intermediate Expiring Soon", add_crl=True))

        # Weak Crypto Cases
        certs.append(self.create_cert("Weak SHA1 Server", issuer_cn="Root CA", hash_algo=hashes.SHA1(), key_size=1024, add_crl=True))
        certs.append(self.create_cert("Weak RSA 1024 Server", issuer_cn="Root CA", key_size=1024, add_crl=True))

        # Constraint & Integrity Fails
        certs.append(self.create_cert("Invalid Issuer (Not CA)", issuer_cn="Root CA", is_ca=False, add_crl=True))
        certs.append(self.create_cert("Server with Invalid Issuer", issuer_cn="Invalid Issuer (Not CA)", add_crl=True))

        certs.append(self.create_cert("Intermediate Broken Signature", issuer_cn="Root CA",
                                      is_ca=True, corrupt_signature=True, add_crl=True))
        certs.append(self.create_cert("Server under Broken Inter", issuer_cn="Intermediate Broken Signature", add_crl=True))

        # Elliptic Curve
        certs.append(self.create_cert("Root A1", is_ca=True, key_type="rsa"))
        certs.append(self.create_cert("Root A2 (Cross)", issuer_cn="Root A1", is_ca=True, key_type="ec", issuer_key_type="rsa", add_crl=True))
        certs.append(self.create_cert("ec-server.lan", issuer_cn="Root A2 (Cross)", key_type="ec", issuer_key_type="ec", san_names=["ec-server.lan"], add_crl=True))

        # Loops
        loop_a_key = self._get_key("Loop CA A")
        loop_b_key = self._get_key("Loop CA B")

        certs.append(self.create_cert("Loop CA A", issuer_cn="Loop CA B", is_ca=True,
                                      subject_key_override=loop_a_key, issuer_key_override=loop_b_key))
        certs.append(self.create_cert("Loop CA B", issuer_cn="Loop CA A", is_ca=True,
                                      subject_key_override=loop_b_key, issuer_key_override=loop_a_key))

        # Name constraints
        certs.append(self.create_cert(
            "Name Constrained CA",
            issuer_cn="Root CA",
            is_ca=True,
            permitted_dns=["safe.lan"],
            excluded_dns=["invalid.safe.lan"],
            add_crl=True,
        ))

        certs.append(self.create_cert(
            "safe.lan",
            issuer_cn="Name Constrained CA",
            san_names=["safe.lan", "www.safe.lan"],
            add_crl=True,
        ))

        certs.append(self.create_cert(
            "www.notsafe.lan",
            issuer_cn="Name Constrained CA",
            add_crl=True,
        ))

        certs.append(self.create_cert(
            "invalid.safe.lan",
            issuer_cn="Name Constrained CA",
            san_names=["invalid.safe.lan", "www.safe.lan"],
            add_crl=True,
        ))

        # Orphans
        certs.append(self.create_cert("Orphan Server", issuer_cn="Non-Existent Root", is_ca=False))

        return certs