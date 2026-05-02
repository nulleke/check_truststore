"""
TrustStore Analyzer - Mock Provider
Generates in-memory certificates for testing all edge cases without physical files.
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later
"""

from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from check_truststore.providers.base import BaseInputProvider, TrustStoreGroup
from check_truststore.engine.core import CertificateRepository

class MockProvider(BaseInputProvider):
    """
    Provides mock certificates and groups to simulate various trust chain scenarios.

    Attributes:
        repository: Reference to the central certificate storage.
        keys (Dict[str, rsa.RSAPrivateKey]): Cache of generated keys to maintain
            consistency between issuers and subjects.
    """
    def __init__(self, repository: Optional[CertificateRepository] = None, **kwargs) -> None:
        """
        Initializes the mock provider.

        Args:
            repository: Optional repository instance for integration testing.
        """
        super().__init__(repository=repository, **kwargs)
        self.keys: Dict[str, rsa.RSAPrivateKey] = {}

    def _get_key(self, cn: str) -> rsa.RSAPrivateKey:
        """
        Retrieves or generates a persistent RSA private key for a specific Common Name.
        """
        if cn not in self.keys:
            self.keys[cn] = rsa.generate_private_key(
                public_exponent=65537, key_size=2048, backend=default_backend()
            )
        return self.keys[cn]

    def create_cert(
        self,
        common_name: str,
        issuer_cn: Optional[str] = None,
        is_ca: bool = False,
        days_valid: int = 365,
        corrupt_signature: bool = False,
        custom_serial: Optional[int] = None,
        force_new_key: bool = False,
        sans: Optional[List[str]] = None,
        issuer_key_override: Optional[rsa.RSAPrivateKey] = None,
        subject_key_override: Optional[rsa.RSAPrivateKey] = None
    ) -> x509.Certificate:
        """
        Fabricates an x509 certificate with specific properties for test scenarios.
        """
        if subject_key_override:
            subject_key = subject_key_override
        elif force_new_key:
            subject_key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048, backend=default_backend()
            )
        else:
            subject_key = self._get_key(common_name)

        issuer_name = issuer_cn if issuer_cn else common_name
        signing_key = issuer_key_override if issuer_key_override else self._get_key(issuer_name)

        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)])

        now = datetime.now(timezone.utc)

        if days_valid < 0:
            start_date = now + timedelta(days=days_valid - 365)
            end_date = now + timedelta(days=days_valid)
        else:
            start_date = now - timedelta(days=1)
            end_date = now + timedelta(days=days_valid)

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(subject_key.public_key())
            .serial_number(custom_serial or x509.random_serial_number())
            .not_valid_before(start_date)
            .not_valid_after(end_date)
        )

        ski = x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key())
        builder = builder.add_extension(ski, critical=False)

        if issuer_cn and issuer_cn != common_name:
            aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(signing_key.public_key())
            builder = builder.add_extension(aki, critical=False)

        if is_ca:
            builder = builder.add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            )

        if sans:
            dns_names = [x509.DNSName(name) for name in sans]
            builder = builder.add_extension(
                x509.SubjectAlternativeName(dns_names), critical=False
            )

        cert = builder.sign(signing_key, hashes.SHA256(), default_backend())

        if corrupt_signature:
            der_bytes = bytearray(cert.public_bytes(serialization.Encoding.DER))
            # Manually flip bits in the signature part of the DER
            der_bytes[-5:] = b"\x00\x66\x66\x66\x00"
            cert = x509.load_der_x509_certificate(bytes(der_bytes), default_backend())

        return cert

    def get_groups(self) -> List[TrustStoreGroup]:
        """
        Generates the mock test suite and registers it with the repository.

        Returns:
            A list containing a 'Mock Test Suite' group with all generated certificates.
        """
        certs = self._generate_test_suite()
        pool = []

        for cert in certs:
            # Extract common name for the virtual mock path
            cn_attributes = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            cn = cn_attributes[0].value if cn_attributes else "Unknown"

            # By using add_pem_data, we trigger the new v1.1.3 deduplication logic
            # which uses the DER-based SHA256 hash.
            metadata = self.repository.add_pem_data(
                cert.public_bytes(serialization.Encoding.PEM),
                source_path=Path("MockData") / f"{cn}.pem",
            )
            if metadata:
                pool.extend(metadata)

        return [TrustStoreGroup(name="Mock Test Suite", targets=pool)]

    def _generate_test_suite(self) -> List[x509.Certificate]:
        """Comprehensive set of certificates covering edge cases."""
        certs = []

        # Valid Chain
        root_key = self._get_key("Root CA")
        certs.append(self.create_cert("Root CA", is_ca=True))
        certs.append(self.create_cert("Intermediate Valid", issuer_cn="Root CA", is_ca=True))
        certs.append(self.create_cert("www.example.com", issuer_cn="Intermediate Valid", sans=["example.com", "www.example.com", "api.example.com"]))

        # Expired
        certs.append(self.create_cert("Expired CA", is_ca=True, days_valid=-100))

        # Constraint Violation
        certs.append(self.create_cert("Invalid Issuer (Not CA)", issuer_cn="Root CA", is_ca=False))
        certs.append(self.create_cert("Server with Invalid Issuer", issuer_cn="Invalid Issuer (Not CA)"))

        # Broken Signature
        certs.append(self.create_cert("Intermediate Expiring Soon", issuer_cn="Root CA", is_ca=True, days_valid=5))
        certs.append(self.create_cert("Server at Risk", issuer_cn="Intermediate Expiring Soon"))

        # Integrity Failures (Signature Verification)
        certs.append(self.create_cert("Intermediate Broken Signature", issuer_cn="Root CA", is_ca=True, corrupt_signature=True))
        certs.append(self.create_cert("Server under Broken Inter", issuer_cn="Intermediate Broken Signature"))

        # Key Collisions & Duplicates
        certs.append(self.create_cert("Duplicate Intermediate", issuer_cn="Root CA", is_ca=True))
        certs.append(self.create_cert("Leaf Path A", issuer_cn="Duplicate Intermediate"))
        inter_b_key = rsa.generate_private_key(65537, 2048, default_backend())
        certs.append(self.create_cert("Duplicate Intermediate", issuer_cn="Root CA", is_ca=True, subject_key_override=inter_b_key, issuer_key_override=root_key))
        certs.append(self.create_cert("Leaf Path B", issuer_cn="Duplicate Intermediate", issuer_key_override=inter_b_key))

        # Loop Detection (Ruff Fix: Removed unused assignments)
        loop_a = self.create_cert(
            "Loop CA A",
            issuer_cn="Loop CA B",
            is_ca=True,
        )
        loop_b = self.create_cert(
            "Loop CA B",
            issuer_cn="Loop CA A",
            is_ca=True,
        )
        certs.extend([loop_a, loop_b])

        # Orphans (AIA / Untrusted)
        certs.append(self.create_cert("Orphan Server", issuer_cn="Non-Existent Root", is_ca=False))

        return certs
