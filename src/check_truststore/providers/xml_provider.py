"""
TrustStore Analyzer & Visualizer - XML PROVIDER
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later

Implementation of an XML input provider. Primarily supports Nmap XML output
to extract certificates directly from scan results without external conversion.
Optimized for lazy registration to ensure group isolation.
"""

import xml.etree.ElementTree as ET
import re
from pathlib import Path
from typing import List, Optional, Union, Any
from check_truststore.providers.base import BaseInputProvider, TrustStoreGroup
from check_truststore.engine import CertificateRepository

class XmlInputProvider(BaseInputProvider):
    """
    XML Input Provider for certificate extraction.
    Currently optimized for Nmap XML output (-oX).
    """

    def __init__(
        self,
        input_source: Union[Path, str, bytes],
        repository: Optional[CertificateRepository] = None,
        is_raw_data: bool = False,
        **kwargs: Any,
    ):
        """
        Initializes the XML provider.

        Args:
            input_source: Path to the XML file or raw XML string/bytes.
            repository: Shared CertificateRepository instance.
            is_raw_data: Set to True if input_source is raw XML data.
        """
        super().__init__(repository=repository, **kwargs)
        self.input_source = input_source
        self.is_raw_data = is_raw_data

    def _get_xml_root(self) -> Optional[ET.Element]:
        """
        Parses the input source and returns the XML root element.
        Handles namespaces and potential leading garbage in Nmap output.
        """
        try:
            if self.is_raw_data:
                xml_data = self.input_source
                if isinstance(xml_data, bytes):
                    xml_data = xml_data.decode('utf-8', errors='ignore')

                if not isinstance(xml_data, str):
                    return None

                start_match = re.search(r'<(?:[a-zA-Z0-9_]+:)?nmaprun', xml_data)
                if start_match:
                    xml_data = xml_data[start_match.start():]

                return ET.fromstring(xml_data)

            path = Path(self.input_source)
            if not path.is_file():
                return None
            return ET.parse(str(path)).getroot()
        except Exception:
            return None

    def get_groups(self) -> List[TrustStoreGroup]:
        """
        Detects the XML schema and extracts certificates as lazy-loadable groups.
        """
        root = self._get_xml_root()
        if root is None:
            return []

        if "nmaprun" in root.tag.lower():
            return self._parse_nmap_xml(root)

        return []

    def _parse_nmap_xml(self, root: ET.Element) -> List[TrustStoreGroup]:
        """
        Extracts certificates from Nmap 'ssl-cert' script output.

        Returns metadata dictionaries to the orchestrator to allow for
        clean registration after repository cache resets.
        """
        groups = []

        for host in root.findall(".//host"):
            address = "Unknown Host"
            addr_elem = host.find("./address[@addrtype='ipv4']") or host.find("./address")
            if addr_elem is not None:
                address = addr_elem.get("addr", address)

            for port_elem in host.findall(".//port"):
                port_id = port_elem.get("portid", "unknown")
                script = port_elem.find("./script[@id='ssl-cert']")

                if script is not None:
                    pem_elem = script.find("./elem[@key='pem']")
                    pem_raw = pem_elem.text if pem_elem is not None else script.get("output", "")

                    if pem_raw:
                        pem_clean = self._fix_pem(pem_raw)
                        if "-----BEGIN CERTIFICATE-----" in pem_clean:
                            source_info = Path(f"nmap/{address}/{port_id}")

                            temp_certs = self.repository.add_pem_data(
                                pem_clean.encode(),
                                source_path=source_info
                            )

                            if temp_certs:
                                groups.append(TrustStoreGroup(
                                    name=f"Nmap: {address}:{port_id}",
                                    targets=temp_certs
                                ))
        return groups

    def _fix_pem(self, raw: str) -> str:
        """
        Cleans XML-escaped characters and ensures standard PEM delimiters.
        """
        clean = raw.replace("-&#45;", "--").replace("&#45;", "-")
        clean = clean.replace("&#xa;", "\n").replace("\xa0", " ")
        clean = re.sub(r'-{3,}\s*BEGIN (?:TRUSTED )?CERTIFICATE\s*-{3,}', "-----BEGIN CERTIFICATE-----", clean)
        clean = re.sub(r'-{3,}\s*END (?:TRUSTED )?CERTIFICATE\s*-{3,}', "-----END CERTIFICATE-----", clean)
        return clean