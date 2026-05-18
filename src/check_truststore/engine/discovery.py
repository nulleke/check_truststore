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
import concurrent.futures
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
from .logging import INFO, WARNING, ERROR, _
from .models import Certificate


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
        self.max_workers: int = kwargs.get('max_workers', 5)

        self.headers = {
            'User-Agent': (
                'Mozilla/5.0 (X11; Linux x86_64) '
                'AppleWebKit/537.36 (KHTML, like Gecko) '
                'Chrome/146.0.0.0 Safari/537.36'
            )
        }

        # Cache Paths
        self.cache_dir: Path = Path.home() / ".cache" / "truststore_analyzer"
        self.aia_cache: Path = self.cache_dir / "aia"
        self.aia_cache_ttl_days: int = kwargs.get('aia_cache_ttl', 10)
        self.ocsp_cache: Path = self.cache_dir / "ocsp"
        self.ocsp_cache_ttl_hours: int = kwargs.get('ocsp_cache_ttl_hours', 24)

        self._ensure_cache_dirs()

    def _ensure_cache_dirs(self) -> None:
        """Creates necessary cache directories on initialization."""
        for p in [self.aia_cache, self.ocsp_cache]:
            try:
                p.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                if self.debug:
                    WARNING.log(_("CACHE"), f"{_('Could not create cache directory')}: {e}")

    def resolve_via_aia_urls(self, urls: List[str], child_cert: Optional[x509.Certificate] = None) -> List[x509.Certificate]:
        """
        Primary entry point for AIA discovery.
        Resolves issuers from URLs, checking cache first if a child_cert is provided.
        """
        issuers: List[x509.Certificate] = []
        seen_fingerprints: Set[str] = set()

        if not urls:
            return []

        if child_cert and not self.no_cache:
            aki = self._get_aki_hex(child_cert)
            if aki:
                cached = self._get_from_aia_cache(aki)
                if cached:
                    if self.debug:
                        INFO.log(_("AIA_CACHE"), _("Cache hit for AKI {aki}, skipping network.").format(aki=aki[:8]), label=_("CACHE"))
                    return cached
            pass

        if self.online and self.no_cache and self.debug:
            INFO.log(_("AIA_FETCH"), _("Bypassing cache due to --no-cache flag"), label=_("AUDIT"))

        if not self.online:
            return []

        valid_urls = [u for u in urls if u not in self.processed_urls]
        if not valid_urls:
            return issuers

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_url = {executor.submit(self.fetch_issuer, url): url for url in valid_urls}

            for future in concurrent.futures.as_completed(future_to_url):
                try:
                    new_cert = future.result()
                    if new_cert:
                        fp = self._get_fingerprint(new_cert)
                        if fp not in seen_fingerprints:
                            issuers.append(new_cert)
                            seen_fingerprints.add(fp)
                            ski = self._get_ski_hex(new_cert)
                            if ski:
                                self._save_to_aia_cache(ski, new_cert)
                except Exception as e:
                    if self.debug:
                        ERROR.log(_("AIA_THREAD"), f"{_('Thread error during discovery')}: {e}")

        return issuers

    def fetch_issuer(self, url: str) -> Optional[x509.Certificate]:
        """Downloads and parses a single certificate from a URL."""
        if not self.online or url in self.processed_urls:
            return None

        if not self._can_resolve(url):
            return None

        try:
            if self.debug:
                INFO.log(_("AIA_FETCH"), f"{_('Downloading')}: {url}")

            response = requests.get(url, headers=self.headers, timeout=(1.0, self.timeout))
            response.raise_for_status()

            if len(response.content) > 51200:
                if self.debug:
                    ERROR.log(_("AIA_SIZE"), _("Certificate at {url} exceeds size limit.").format(url=url))
                return None

            self.processed_urls.add(url)
            return self._parse_certificate(response.content, url)

        except requests.exceptions.RequestException as e:
            if self.debug:
                WARNING.log(_("AIA_FAILED"), f"{_('Connection failed')}: {url} ({e})")
        return None

    def _parse_certificate(self, data: bytes, url: str) -> Optional[x509.Certificate]:
        """Tries to load certificate data as DER, then PEM."""
        try:
            return x509.load_der_x509_certificate(data)
        except Exception:
            try:
                return x509.load_pem_x509_certificate(data)
            except Exception:
                if self.debug:
                    ERROR.log(_("AIA_PARSE"), _("Failed to parse certificate from {url}").format(url=url))
                return None

    def check_ocsp_status(self, cert: x509.Certificate, issuer: x509.Certificate, provided_urls: Optional[List[str]] = None) -> str:
        """
        Queries OCSP responders in parallel for certificate status.
        Returns: One of ['GOOD', 'REVOKED', 'UNKNOWN', 'ERROR'].
        """
        if self._is_effectively_root(cert):
            return "GOOD"

        if not self.online:
            return "UNKNOWN"

        urls = provided_urls if provided_urls else self.find_ocsp_urls(cert)
        if not urls:
            return self.check_crl_status(cert)

        try:
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

        final_status = "UNKNOWN"

        if len(urls) == 1:
            final_status = self._fetch_single_ocsp(urls[0], request_der)
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_url = {executor.submit(self._fetch_single_ocsp, url, request_der): url for url in urls}

                for future in concurrent.futures.as_completed(future_to_url):
                    try:
                        status = future.result()
                        if status == "REVOKED":
                            return "REVOKED"
                        if status == "GOOD":
                            final_status = "GOOD"
                    except Exception as e:
                        if self.debug:
                            msg = f"{_('OCSP thread error')}: {e}"
                            WARNING.log(_("OCSP_THREAD"), msg)

        if final_status in ["GOOD", "REVOKED"]:
            return final_status

        return self.check_crl_status(cert)

    def check_crl_status(self, cert: x509.Certificate) -> str:
        """
        Validates certificate status against CRLs in parallel.
        Returns: One of ['GOOD', 'REVOKED', 'UNKNOWN', 'ERROR'].
        """
        # A Root certificate is self-signed; revocation is handled by trust store management, not CRLs.
        is_root = self._is_effectively_root(cert)

        if is_root:
            return "GOOD"

        urls = self.find_crl_urls(cert)
        if not urls:
            if self.debug:
                WARNING.log(_("CRL_CHECK"), _("No CRL endpoints found in certificate"))
            return "UNKNOWN"

        final_status = "UNKNOWN"

        if len(urls) == 1:
            final_status = self._process_single_crl(urls[0], cert)
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_url = {executor.submit(self._process_single_crl, url, cert): url for url in urls}

                for future in concurrent.futures.as_completed(future_to_url):
                    try:
                        status = future.result()
                        if status == "REVOKED":
                            return "REVOKED"
                        if status == "GOOD":
                            final_status = "GOOD"
                    except Exception as e:
                        if self.debug:
                            msg = f"{_('CRL thread error')}: {e}"
                            WARNING.log(_("CRL_THREAD"), msg)

        return final_status

    def _get_aki_hex(self, cert: x509.Certificate) -> Optional[str]:
        """Extracts Authority Key Identifier as hex string."""
        try:
            aki_ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
            if aki_ext.value.key_identifier:
                return aki_ext.value.key_identifier.hex()
        except x509.ExtensionNotFound:
            pass
        return None

    def _get_ski_hex(self, cert: x509.Certificate) -> Optional[str]:
        """Extracts Subject Key Identifier as hex string."""
        try:
            ski_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
            return ski_ext.value.digest.hex()
        except x509.ExtensionNotFound:
            return None

    def _get_fingerprint(self, cert: x509.Certificate) -> str:
        """Helper to get SHA256 fingerprint."""
        return Certificate.calculate_fingerprint(cert.public_bytes(serialization.Encoding.DER))

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

    def _get_from_aia_cache(self, aki: str) -> List[x509.Certificate]:
        found_certs = []
        aki_dir = self.aia_cache / aki

        if not aki_dir.exists() or not aki_dir.is_dir():
            return []

        try:
            for cert_file in aki_dir.glob("*.der"):
                if not self._is_cache_fresh(cert_file, self.aia_cache_ttl_days * 24):
                    continue

                cert = self._load_cert_file(cert_file)
                if cert:
                    expiry = self._get_expiry(cert)
                    if expiry >= datetime.now(timezone.utc):
                        found_certs.append(cert)

            return found_certs

        except Exception as e:
            if self.debug:
                ERROR.log(_("Cache"), f"{_('Error reading cache')}: {e}")
            return []

    def _load_cert_file(self, path: Path) -> Optional[x509.Certificate]:
        """Helper to load a DER certificate from disk."""
        try:
            with open(path, "rb") as f:
                return x509.load_der_x509_certificate(f.read(), default_backend())
        except Exception as e:
            if self.debug:
                ERROR.log(_("CACHE_LOAD"), f"{_('Failed to load cached cert')} {path.name}: {e}")
            return None

    def _is_cache_fresh(self, cache_path: Path, ttl_hours: float) -> bool:
        """Checks if a cache file is newer than the allowed TTL in hours."""
        if not cache_path.exists():
            return False

        file_age_hours = (time.time() - os.path.getmtime(cache_path)) / 3600
        return file_age_hours <= ttl_hours

    def _get_expiry(self, cert: x509.Certificate) -> datetime:
        """Helper for cross-version cryptography compatibility for cert expiry."""
        if hasattr(cert, 'not_valid_after_utc'):
            return cert.not_valid_after_utc
        return cert.not_valid_after.replace(tzinfo=timezone.utc)

    def _save_to_aia_cache(self, key: str, cert: x509.Certificate) -> None:
        """
        Saves a certificate to the AIA cache using atomic writes to prevent corruption.
        """
        try:
            key_dir = self.aia_cache / key
            key_dir.mkdir(parents=True, exist_ok=True)
            fp = self._get_fingerprint(cert)
            final_path = key_dir / f"{fp}.der"

            with tempfile.NamedTemporaryFile(dir=key_dir, delete=False, suffix=".tmp") as tmp_file:
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

    def _fetch_single_ocsp(self, url: str, request_der: bytes) -> str:
        """Helper method for a single OCSP call within a thread."""
        if not self._can_resolve(url):
            return "DNS_ERROR"

        try:
            if self.debug:
                msg = _("Checking: {url}").format(url=url)
                INFO.log(_("OCSP_CHECK"), msg)

            ocsp_headers = self.headers.copy()
            ocsp_headers['Content-Type'] = 'application/ocsp-request'

            response = requests.post(
                url,
                data=request_der,
                headers=ocsp_headers,
                timeout=(1.0, self.timeout)
            )
            response.raise_for_status()

            ocsp_resp = ocsp.load_der_ocsp_response(response.content)

            if ocsp_resp.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
                return "UNSUCCESSFUL"

            cert_status = ocsp_resp.certificate_status
            if cert_status == ocsp.OCSPCertStatus.GOOD:
                return "GOOD"
            elif cert_status == ocsp.OCSPCertStatus.REVOKED:
                return "REVOKED"
            elif cert_status == ocsp.OCSPCertStatus.UNKNOWN:
                return "UNKNOWN"

        except requests.exceptions.Timeout:
            return "TIMEOUT"
        except Exception as e:
            if self.debug:
                WARNING.log(_("OCSP_FAILED"), f"{_('OCSP request failed')} {url}: {e}")
            return "CONNECTION_ERROR"

        return "ERROR"

    def _process_single_crl(self, url: str, cert: x509.Certificate) -> str:
        """Helper method to download, cache, and inspect a single CRL."""
        try:
            url_hash = hashlib.md5(url.encode()).hexdigest()
            cache_path = self.ocsp_cache / f"crl_{url_hash}.der"
            crl_data: Optional[x509.CertificateRevocationList] = None

            if not self.no_cache:
                if self._is_cache_fresh(cache_path, self.ocsp_cache_ttl_hours):
                    with open(cache_path, "rb") as f:
                        temp_crl = x509.load_der_x509_crl(f.read(), default_backend())
                        next_update = self._get_next_update(temp_crl)

                        if next_update > datetime.now(timezone.utc):
                            if self.debug:
                                msg = _("Using cached CRL for")
                                INFO.log(_("CRL_CACHE"), f"{msg}: {urlparse(url).hostname}", label=_("CACHE"))
                            crl_data = temp_crl

            if crl_data is None:
                if not self.online or url in self.processed_urls:
                    return "UNKNOWN"

                if not self._can_resolve(url):
                    return "ERROR"

                if self.debug:
                    INFO.log(_("CRL_FETCH"), f"{_('Downloading CRL')}: {url}")

                response = requests.get(
                    url,
                    headers=self.headers,
                    timeout=(1.5, max(self.timeout, 5.0))
                )
                response.raise_for_status()
                crl_data = x509.load_der_x509_crl(response.content, default_backend())

                self._save_crl_to_cache(cache_path, response.content)

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

        return "ERROR"

    def _save_crl_to_cache(self, cache_path: Path, content: bytes) -> None:
        """
        Saves CRL data to the local cache using an atomic write operation.

        This prevents race conditions where one thread might attempt to read
         a partially written file created by another thread.
        """
        try:
            self.ocsp_cache.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(dir=self.ocsp_cache, delete=False, suffix=".tmp") as tmp_file:
                tmp_file.write(content)
                temp_path = tmp_file.name
            os.replace(temp_path, cache_path)
        except Exception as e:
            if self.debug:
                WARNING.log(_("CRL_CACHE"), f"{_('Could not save CRL to cache')}: {e}")

    def _get_next_update(self, crl: x509.CertificateRevocationList) -> datetime:
        """Helper for cross-version cryptography compatibility for CRL next_update."""
        if hasattr(crl, 'next_update_utc'):
            return crl.next_update_utc
        return crl.next_update.replace(tzinfo=timezone.utc)

    def _is_effectively_root(self, cert: x509.Certificate) -> bool:
        """Internal helper to determine if a cert is a self-signed Root CA."""
        try:
            bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
            if not bc.value.ca:
                return False
        except x509.ExtensionNotFound:
            return False

        if cert.subject != cert.issuer:
            return False

        aki = self._get_aki_hex(cert)
        ski = None
        try:
            ski_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
            ski = ski_ext.value.digest.hex()
        except x509.ExtensionNotFound:
            pass

        if aki and ski:
            return aki == ski

        return True
