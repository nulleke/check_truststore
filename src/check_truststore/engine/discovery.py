"""
TrustStore Analyzer - Discovery Module
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later

Handles fetching missing certificates via Authority Information Access (AIA)
and validating revocation status via OCSP (Online Certificate Status Protocol)
and CRL (Certificate Revocation List).
"""

import os
import tempfile
import time
import socket
import hashlib
import requests
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
try:
    from cryptography.x509.ocsp import OCSPNonce
except ImportError:
    OCSPNonce = getattr(x509, "OCSPNonce", None)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from typing import Optional, List, Set
from .logging import INFO, WARNING, ERROR, _, AIA as AIA_LOG


class NetworkResolver:
    """
    Handles network-based certificate operations including issuer discovery
    and revocation checks (OCSP/CRL).

    Attributes:
        online (bool): Whether outgoing network requests are permitted.
        timeout (float): Maximum time in seconds for network operations.
        processed_urls (Set[str]): Cache of visited URLs to prevent circular fetches.
        cache_dir (Path): Local filesystem base for certificate/CRL persistence.
        aia_cache_ttl_days (int): Days to keep intermediate certificates in cache.
        ocsp_cache_ttl_days (int): Hours to keep revocation status in cache.
    """

    def __init__(self, **kwargs) -> None:
        """
        Initializes the resolver with connectivity settings and cache structures.

        Args:
            online: Enable or disable outgoing network requests.
            timeout: Seconds to wait for a response.
            debug: If True, logs detailed diagnostic information.
        """
        self.options = kwargs
        self.online: bool = kwargs.get('online', False)
        self.timeout: float = kwargs.get('timeout', 2.0)
        self.verbosity: int = kwargs.get('verbosity', 0)
        self.debug: bool = kwargs.get('debug', False)
        self.processed_urls: Set[str] = set()
        self.no_cache: bool = kwargs.get('no_cache', False)

        self.headers = {
            'User-Agent': (
                'Mozilla/5.0 (X11; Linux x86_64) '
                'AppleWebKit/537.36 (KHTML, like Gecko) '
                'Chrome/146.0.0.0 Safari/537.36'
            )
        }

        # Cache setup
        self.cache_dir: Path = Path.home() / ".cache" / "truststore_analyzer"
        self.aia_cache: Path = self.cache_dir / "aia"
        self.aia_cache_ttl_days: int = kwargs.get('aia_cache_ttl', 30)
        self.ocsp_cache: Path = self.cache_dir / "ocsp"
        self.ocsp_cache_ttl_hours: int = kwargs.get('ocsp_cache_ttl_hours', 24)

        for p in [self.aia_cache, self.ocsp_cache]:
            try:
                p.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                if self.debug:
                    WARNING.log(_("Cache"), f"{_('Could not create cache directory')}: {e}")

    def resolve_all_issuers(self, child_cert: x509.Certificate) -> List[x509.Certificate]:
        """
        Finds ALL potential issuers via local cache and AIA.
        Crucial for cross-signed certificate graphs.
        """
        issuers = []
        seen_fingerprints = set()

        aki = self._get_aki_hex(child_cert)
        if not aki:
            return []

        if not self.no_cache:
            aki_dir = self.aia_cache / aki
            if aki_dir.exists():
                for cert_file in aki_dir.glob("*.der"):
                    if self._is_cache_fresh(cert_file, self.aia_cache_ttl_days * 24):
                        cert = self._load_cert_file(cert_file)
                        if cert and self._get_fp(cert) not in seen_fingerprints:
                            issuers.append(cert)
                            seen_fingerprints.add(self._get_fp(cert))

        if self.online:
            if issuers and not self.no_cache:
                if self.debug:
                    INFO.log(_("AIA_CACHE"), _("Skipping network discovery: valid issuers found in cache"), label=_("CACHE"))
                return issuers

            if self.no_cache and self.debug:
                INFO.log(_("AIA_FETCH"), _("Bypassing cache due to --no-cache flag"), label=_("AUDIT"))

            urls = self.find_aia_urls(child_cert)
            for url in urls:
                new_cert = self.fetch_issuer(url)
                if new_cert:
                    fp = self._get_fp(new_cert)
                    if fp not in seen_fingerprints:
                        issuers.append(new_cert)
                        seen_fingerprints.add(fp)
                        self._save_to_aia_cache(aki, new_cert)

        return issuers

    def _load_cert_file(self, path: Path) -> Optional[x509.Certificate]:
        """Helper to load a DER certificate from disk."""
        try:
            with open(path, "rb") as f:
                return x509.load_der_x509_certificate(f.read(), default_backend())
        except Exception as e:
            if self.debug:
                ERROR.log(_("CACHE_LOAD"), f"{_('Failed to load cached cert')} {path.name}: {e}")
            return None

    def _get_fp(self, cert: x509.Certificate) -> str:
        """Helper to get SHA256 fingerprint."""
        return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()

    def _get_aki_hex(self, cert: x509.Certificate) -> Optional[str]:
        """Extracts Authority Key Identifier as hex string."""
        try:
            aki_ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
            if aki_ext.value.key_identifier:
                return aki_ext.value.key_identifier.hex()
        except x509.ExtensionNotFound:
            pass
        return None

    def find_aia_urls(self, cert: x509.Certificate) -> List[str]:
        """Parses Authority Information Access (AIA) for CA Issuer URIs."""
        urls = []
        try:
            aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            for access_description in aia.value:
                if access_description.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
                    uri = access_description.access_location.value
                    if isinstance(uri, str) and uri.startswith("http"):
                        urls.append(uri)
        except x509.ExtensionNotFound:
            pass
        except Exception as e:
            if self.debug:
                ERROR.log(_("AIA_PARSE"), f"{_('Error parsing AIA extension')} :{e}")
        return urls

    def fetch_issuer(self, url: str) -> Optional[x509.Certificate]:
        """
        Download certificate with strict connection and read timeouts.
        Returns None if download fails or internet is disabled.
        """
        if not self.online or url in self.processed_urls:
            return None

        if not self._can_resolve(url):
            return None

        try:
            if self.debug:
                INFO.log(_("AIA_FETCH"), f"{_('Downloading')}: {url}")

            response = requests.get(
                url,
                headers=self.headers,
                timeout=(1.0, self.timeout)
            )
            response.raise_for_status()

            content = response.content
            if len(content) > 1024 * 50:
                if self.debug:
                    ERROR.log(_("AIA_SIZE"), _("Certificate too large"))
                return None

            self.processed_urls.add(url)

            # Try DER (binary) first, then PEM (base64)
            try:
                return x509.load_der_x509_certificate(content)
            except Exception:
                try:
                    return x509.load_pem_x509_certificate(content)
                except Exception as pem_err:
                    if self.debug:
                        msg = _("Could not load cert from {url} (Tried DER & PEM)").format(url=url)
                        ERROR.log(_("AIA_PARSE"), f"{msg}: {pem_err}")
                    return None

        except requests.exceptions.RequestException as e:
            if self.debug:
                # We use WARNING here because it's an expected failure in restricted networks
                WARNING.log(_("AIA_FAILED"), f"{_('Connection failed')}: {url} ({e})")
        except Exception as e:
            if self.debug:
                ERROR.log(_("AIA_ERROR"), f"{_('Unexpected error')}: {str(e)}")

        return None

    def find_ocsp_urls(self, cert: x509.Certificate) -> List[str]:
        """Parses AIA extension for OCSP responder URIs."""
        urls = []
        try:
            aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            for desc in aia.value:
                if desc.access_method == AuthorityInformationAccessOID.OCSP:
                    uri = desc.access_location.value
                    if isinstance(uri, str) and uri.startswith("http"):
                        urls.append(uri)
        except x509.ExtensionNotFound:
            pass
        return urls

    def check_ocsp_status(self, cert: x509.Certificate, issuer: x509.Certificate) -> str:
        """
        Queries OCSP responders for certificate status.

        Returns:
            One of ['GOOD', 'REVOKED', 'UNKNOWN', 'ERROR'].
        """
        if cert.subject == cert.issuer:
            return "GOOD"

        if not self.online:
            return "UNKNOWN"

        urls = self.find_ocsp_urls(cert)
        if urls:
            try:
                # Build OCSP Request
                builder = ocsp.OCSPRequestBuilder()
                builder = builder.add_certificate(cert, issuer, hashes.SHA1())
                if OCSPNonce:
                    nonce = os.urandom(16)
                    try:
                        builder = builder.add_extension(OCSPNonce(nonce), critical=False)
                    except Exception:
                        pass

                request_der = builder.build().public_bytes(serialization.Encoding.DER)
            except Exception as e:
                if self.debug:
                    ERROR.log(_("OCSP_BUILD"), str(e))
                return "ERROR"

            ocsp_headers = self.headers.copy()
            ocsp_headers['Content-Type'] = 'application/ocsp-request'

            for url in urls:
                if not self._can_resolve(url):
                    continue

                try:
                    if self.debug:
                        msg = _("Checking: {url}").format(url=url)
                        INFO.log(_("OCSP_CHECK"), msg)

                    response = requests.post(
                        url,
                        data=request_der,
                        headers=ocsp_headers,
                        timeout=(1.0, self.timeout)
                    )
                    response.raise_for_status()

                    ocsp_resp = ocsp.load_der_ocsp_response(response.content)

                    if ocsp_resp.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
                        continue

                    cert_status = ocsp_resp.certificate_status
                    if cert_status == ocsp.OCSPCertStatus.GOOD:
                        return "GOOD"
                    elif cert_status == ocsp.OCSPCertStatus.REVOKED:
                        return "REVOKED"

                except Exception as e:
                    if self.debug:
                        WARNING.log(_("OCSP_FAILED"), f"{_('OCSP request failed')} {url}: {e}")

        return self.check_crl_status(cert)

    def find_crl_urls(self, cert: x509.Certificate) -> List[str]:
        """Parses CRL Distribution Points (CDP) from certificate extensions."""
        urls = []
        try:
            crl_dp = cert.extensions.get_extension_for_oid(x509.ExtensionOID.CRL_DISTRIBUTION_POINTS)
            for dp in crl_dp.value:
                for fullName in dp.full_name:
                    uri = fullName.value
                    if isinstance(uri, str) and uri.startswith("http"):
                        urls.append(uri)
        except x509.ExtensionNotFound:
            pass
        return urls

    def check_crl_status(self, cert: x509.Certificate) -> str:
        """
        Validates certificate status against CRLs. Uses local caching to speed up
        validation for certificates sharing the same distribution point.

        Note: Warnings for missing CRL endpoints are suppressed for Root certificates.
        """
        # A Root certificate is self-signed; revocation is handled by trust store management, not CRLs.
        is_root = (cert.subject == cert.issuer)

        if is_root:
            return "GOOD"

        urls = self.find_crl_urls(cert)
        if not urls:
            if self.debug:
                WARNING.log(_("CRL_CHECK"), _("No CRL endpoints found in certificate"))
            return "UNKNOWN"

        for url in urls:
            try:
                url_hash = hashlib.md5(url.encode()).hexdigest()
                cache_path = self.ocsp_cache / f"crl_{url_hash}.der"
                crl_data: Optional[x509.CertificateRevocationList] = None

                # Check if cached CRL exists and is within TTL
                if not self.no_cache:
                    if self._is_cache_fresh(cache_path, self.ocsp_cache_ttl_hours):
                        with open(cache_path, "rb") as f:
                            temp_crl = x509.load_der_x509_crl(f.read(), default_backend())
                            next_upd = self._get_next_update(temp_crl)

                            if next_upd > datetime.now(timezone.utc):
                                if self.debug:
                                    msg = _("Using cached CRL for")
                                    INFO.log(_("CRL_CACHE"), f"{msg}: {urlparse(url).hostname}", label=_("CACHE"))
                                crl_data = temp_crl
                            elif self.debug:
                                INFO.log(_("CRL_CACHE"), _("Cached CRL is stale (nextUpdate passed)"), label=_("EXPIRE"))
                elif self.debug:
                    # Log dat we de cache bewust negeren voor de audit
                    INFO.log(_("CRL_CACHE"), _("Bypassing cached CRL due to --no-cache flag"), label=_("AUDIT"))

                # Fetch CRL if not in cache or expired
                if crl_data is None:
                    if url in self.processed_urls:
                        if self.debug:
                            INFO.log(_("DEBUG_CRL"), f"{_('Skip download (already done in this run)')}: {url}")
                        return "UNKNOWN"
                    if not self.online:
                        continue
                    if self.debug:
                        INFO.log(_("CRL_FETCH"), f"{_('Downloading CRL')}: {url}")

                    response = requests.get(
                        url,
                        headers=self.headers,
                        timeout=(1.5, max(self.timeout, 5.0))
                    )
                    response.raise_for_status()

                    crl_data = x509.load_der_x509_crl(response.content, default_backend())

                    try:
                        self.ocsp_cache.mkdir(parents=True, exist_ok=True)
                        with tempfile.NamedTemporaryFile(dir=self.ocsp_cache, delete=False, suffix=".tmp") as tmp_file:
                            tmp_file.write(response.content)
                            temp_path = tmp_file.name

                        os.replace(temp_path, cache_path)
                    except Exception as e:
                        if 'temp_path' in locals() and os.path.exists(temp_path):
                            os.unlink(temp_path)
                        if self.debug:
                            WARNING.log(_("CRL_CACHE"), f"Could not save CRL to cache: {e}")

                # Check for serial number in CRL
                revoked = crl_data.get_revoked_certificate_by_serial_number(cert.serial_number)
                if revoked:
                    if self.debug:
                        msg = _("Serial {serial_number} is REVOKED").format(serial_number=cert.serial_number)
                        WARNING.log(_("CRL_RESULT"), msg)
                    return "REVOKED"

                self.processed_urls.add(url)
                return "GOOD"

            except Exception as e:
                if self.debug:
                    WARNING.log(_("CRL_FAILED"), f"{_('Failed to check CRL')} {url}: {e}")

        return "UNKNOWN"

    def _is_cache_fresh(self, cache_path: Path, ttl_hours: float) -> bool:
        """Checks if a cache file is newer than the allowed TTL in hours."""
        if not cache_path.exists():
            return False

        file_age_hours = (time.time() - os.path.getmtime(cache_path)) / 3600
        return file_age_hours <= ttl_hours

    def _get_from_aia_cache(self, aki: str) -> Optional[x509.Certificate]:
        """Loads a certificate from the AIA cache if fresh (< 10 days)."""
        cache_path = self.aia_cache / f"{aki}.der"

        if not self._is_cache_fresh(cache_path, self.aia_cache_ttl_days * 24):
            if cache_path.exists() and self.debug:
                AIA_LOG.log(f"{_('AKI')}: {aki[:8]}", _("Cache expired based on TTL, refreshing..."))
            return None

        try:
            with open(cache_path, "rb") as f:
                cert = x509.load_der_x509_certificate(f.read(), default_backend())
                expiry = self._get_expiry(cert)
                if expiry < datetime.now(timezone.utc):
                    if self.debug:
                        WARNING.log(_("Cache"), f"{_('Cached certificate expired on')}: {expiry}")
                    return None

                return cert

        except Exception as e:
            if self.debug:
                ERROR.log(_("Cache"), f"{_('Error reading cache')}: {e}")
            return None

    def _get_next_update(self, crl: x509.CertificateRevocationList) -> datetime:
        """Helper for cross-version cryptography compatibility for CRL next_update."""
        if hasattr(crl, 'next_update_utc'):
            return crl.next_update_utc
        return crl.next_update.replace(tzinfo=timezone.utc)

    def _get_expiry(self, cert: x509.Certificate) -> datetime:
        """Helper for cross-version cryptography compatibility for cert expiry."""
        if hasattr(cert, 'not_valid_after_utc'):
            return cert.not_valid_after_utc
        return cert.not_valid_after.replace(tzinfo=timezone.utc)

    def _can_resolve(self, url: str) -> bool:
        """
        Validates DNS resolution for a URL to avoid OS-level timeout hangs.

        Returns:
            True if hostname resolves, False otherwise.
        """
        try:
            hostname = urlparse(url).hostname
            if not hostname:
                return False
            socket.gethostbyname(hostname)
            return True
        except (socket.gaierror, Exception):
            if self.debug and self.verbosity >= 3:
                WARNING.log(_("DNS"), f"{_('Could not resolve host')}: {hostname}")
            return False

    def _save_to_aia_cache(self, aki: str, cert: x509.Certificate) -> None:
        """
        Saves a certificate to the AIA cache using atomic writes to prevent corruption.
        """
        try:
            aki_dir = self.aia_cache / aki
            aki_dir.mkdir(parents=True, exist_ok=True)
            fp = self._get_fp(cert)
            final_path = aki_dir / f"{fp}.der"

            with tempfile.NamedTemporaryFile(dir=aki_dir, delete=False, suffix=".tmp") as tmp_file:
                tmp_file.write(cert.public_bytes(serialization.Encoding.DER))
                temp_path = tmp_file.name

            try:
                os.replace(temp_path, final_path)
            except Exception:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
                raise

        except Exception as e:
            if self.debug:
                ERROR.log(_("CACHE"), f"{_('Could not save certificate to cache')}: {e}")
