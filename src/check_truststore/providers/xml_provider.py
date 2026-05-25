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
from typing import List, Dict, Optional, Union, Any
from check_truststore.providers.base import BaseInputProvider, TrustStoreGroup
from check_truststore.engine import CertificateRepository

class XmlInputProvider(BaseInputProvider):
    """XML Input Provider for certificate extraction.

    This provider scans structured XML payloads and is highly optimized to extract
    embedded PEM certificates out of Nmap XML scan outputs (`-oX`) mapped via the
    `ssl-cert` NSE script engine.

    Attributes:
        input_source (Union[Path, str, bytes]): The raw XML content string,
            serialized bytes container, or report input file destination path.
        is_raw_data (bool): Flag indicating if the input source represents actual
            textual payload strings rather than a location on disk.
        repository (CertificateRepository): Inherited central asset identification mapping store.
        options (Dict[str, Any]): Dictionary containing configuration arguments.
        debug (bool): If True, enables diagnostic traces and deep error reporting.
        verbosity (int): Numeric modifier adjusting logging output volume.
    """

    def __init__(
        self,
        input_source: Union[Path, str, bytes],
        repository: Optional[CertificateRepository] = None,
        is_raw_data: bool = False,
        **kwargs: Any,
    ) -> None:
        """Initializes the XML report parser provider interface.

        Args:
            input_source (Union[Path, str, bytes]): Path to the XML file
                or a raw unparsed XML payload structure string/bytes.
            repository (Optional[CertificateRepository], optional): Shared index
                repository for certificate discovery. Defaults to None.
            is_raw_data (bool, optional): Explicit indicator to treat input_source
                as plain textual/binary data report streams. Defaults to False.
            **kwargs: Flexible configuration choices passed down to BaseInputProvider.
        """
        super().__init__(repository=repository, **kwargs)
        self.input_source: Union[Path, str, bytes] = (
            Path(input_source) if (isinstance(input_source, (str, Path)) and not is_raw_data) else input_source
        )
        self.is_raw_data: bool = is_raw_data

    def _get_xml_root(self) -> Optional[ET.Element]:
        """Parses the localized input stream and returns the XML root element node.

        Handles extraction edge-cases like XML namespace boundaries and potential
        leading terminal junk or shell header wrappers preceding Nmap definitions.

        Returns:
            Optional[ET.Element]: Root element of the parsed XML syntax tree
                if structural layout is valid, otherwise None.
        """
        try:
            if self.is_raw_data:
                xml_data: Union[str, bytes] = self.input_source
                if isinstance(xml_data, bytes):
                    xml_data = xml_data.decode('utf-8', errors='ignore')

                if not isinstance(xml_data, str):
                    return None

                start_match: Optional[re.Match[str]] = re.search(r'<(?:[a-zA-Z0-9_]+:)?nmaprun', xml_data)
                if start_match:
                    xml_data = xml_data[start_match.start():]

                return ET.fromstring(xml_data)

            if isinstance(self.input_source, Path) and not self.input_source.is_file():
                return None
            return ET.parse(str(self.input_source)).getroot()
        except Exception:
            return None

    def get_groups(self) -> List[TrustStoreGroup]:
        """Detects the underlying XML schema type and dispatches processing paths.

        Returns:
            List[TrustStoreGroup]: A collection of isolated target host groups
                extracted out of the recognized XML schema.
        """
        root: Optional[ET.Element] = self._get_xml_root()
        if root is None:
            return []

        if "nmaprun" in root.tag.lower():
            return self._parse_nmap_xml(root)

        return []

    def _parse_nmap_xml(self, root: ET.Element) -> List[TrustStoreGroup]:
        """Extracts X.509 certificates from Nmap 'ssl-cert' script result blocks.

        Iterates recursively through host definitions, attempts to find active
        IPv4 or fallback addresses, extracts explicit domains, cleans underlying
        escaped formatting blocks, and logs data metrics inside the local repository.

        Args:
            root (ET.Element): The validated ElementTree root node for Nmap processing.

        Returns:
            List[TrustStoreGroup]: List of segmented target host groups mapped
                sequentially per identified network target.
        """
        groups: List[TrustStoreGroup] = []

        for host in root.findall(".//host"):
            address: str = "Unknown Host"
            addr_elem: Optional[ET.Element] = host.find("./address[@addrtype='ipv4']") or host.find("./address")
            if addr_elem is not None:
                address = addr_elem.get("addr", address)

            hostname_elem: Optional[ET.Element] = host.find(".//hostnames/hostname[@type='user']") or host.find(".//hostnames/hostname")
            display_name: str = hostname_elem.get("name") if hostname_elem is not None else address

            for port_elem in host.findall(".//port"):
                port_id: str = port_elem.get("portid", "unknown")
                script: Optional[ET.Element] = port_elem.find("./script[@id='ssl-cert']")

                if script is not None:
                    pem_elem: Optional[ET.Element] = script.find("./elem[@key='pem']")
                    pem_raw: Optional[str] = pem_elem.text if pem_elem is not None else script.get("output", "")

                    if pem_raw:
                        pem_clean: str = self._fix_pem(pem_raw)
                        if "-----BEGIN CERTIFICATE-----" in pem_clean:
                            source_info: Path = Path(f"nmap/{address}/{port_id}")

                            temp_certs: List[Dict[str, Any]] = self.repository.add_pem_data(
                                pem_clean.encode(),
                                source_path=source_info
                            )

                            if temp_certs:
                                groups.append(TrustStoreGroup(
                                    name=f"Nmap: {display_name}:{port_id}",
                                    targets=temp_certs,
                                    target_hostname=display_name,
                                ))
        return groups

    def _fix_pem(self, raw: str) -> str:
        """Cleans XML-escaped entities and sanitizes standard PEM bounding boxes.

        Restores baseline dash signatures and fixes newline serialization blocks
        emitted during script report translations.

        Args:
            raw (str): Raw string block extracted from the XML text contents.

        Returns:
            str: Normalized formatting block with compliant PEM certificate boundaries.
        """
        clean: str = raw.replace("-&#45;", "--").replace("&#45;", "-")
        clean = clean.replace("&#xa;", "\n").replace("\xa0", " ")
        clean = re.sub(r'-{3,}\s*BEGIN (?:TRUSTED )?CERTIFICATE\s*-{3,}', "-----BEGIN CERTIFICATE-----", clean)
        clean = re.sub(r'-{3,}\s*END (?:TRUSTED )?CERTIFICATE\s*-{3,}', "-----END CERTIFICATE-----", clean)
        return clean