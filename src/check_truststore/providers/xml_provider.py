"""
TrustStore Analyzer & Visualizer - XML PROVIDER
Architect: Serge van Thillo

Implementation of an XML input provider. Primarily supports Nmap XML output
to extract certificates directly from scan results without external conversion.
"""

import xml.etree.ElementTree as ET
import re
from pathlib import Path, PurePosixPath
from typing import List, Optional, Union
from check_truststore.providers.base import BaseInputProvider, TrustStoreGroup
from check_truststore.engine.core import CertificateRepository

class XmlInputProvider(BaseInputProvider):
    """
    XML Input Provider for certificate extraction.
    Currently optimized for Nmap XML output (-oX).
    """

    def __init__(
        self,
        input_source: Union[Path, str],
        repository: Optional[CertificateRepository] = None,
        is_raw_data: bool = False,
        **kwargs,
    ):
        super().__init__(repository=repository, **kwargs)
        self.input_source = input_source
        self.is_raw_data = is_raw_data

    def _get_xml_root(self) -> Optional[ET.Element]:
        """
        Parses the input source and returns the XML root element.
        Handles both file paths and raw string data (stdin).
        """
        try:
            if self.is_raw_data:
                xml_data = self.input_source

                if not isinstance(xml_data, str):
                    return None

                # Strip potential leading garbage before the XML declaration
                if "<nmaprun" in xml_data:
                    start_idx = xml_data.find("<nmaprun")
                    if start_idx != -1:
                        xml_data = xml_data[start_idx:]

                return ET.fromstring(xml_data)

            path = Path(self.input_source)
            if not path.is_file():
                return None
            return ET.parse(str(path)).getroot()
        except Exception:
            return None

    def get_groups(self) -> List[TrustStoreGroup]:
        """
        Identifies the XML structure and dispatches to the appropriate parser.
        """
        root = self._get_xml_root()
        if root is None:
            return []

        # Use partial tag match for namespace tolerance
        if "nmaprun" in root.tag.lower():
            return self._parse_nmap_xml(root)

        return []

    def _parse_nmap_xml(self, root: ET.Element) -> List[TrustStoreGroup]:
        """
        Iterates through Nmap XML to find hosts, ports, and 'ssl-cert' script output.
        """
        groups = []

        # Helper to strip namespaces from tags
        def get_local_tag(tag):
            return tag.split('}')[-1] if '}' in tag else tag

        for host in root.iter():
            if get_local_tag(host.tag) != "host":
                continue

            address = "Unknown Host"
            # Extract IP or hostname
            addr_elem = next((e for e in host if get_local_tag(e.tag) == "address"), None)
            if addr_elem is not None:
                address = addr_elem.get("addr", address)

            for port in host.iter():
                if get_local_tag(port.tag) != "port":
                    continue

                port_id = port.get("portid", "unknown")

                # Search for the ssl-cert script element
                for script in port.iter():
                    if get_local_tag(script.tag) == "script" and script.get("id") == "ssl-cert":
                        pem_raw = ""
                        # Attempt to find structured PEM data
                        for elem in script.iter():
                            if get_local_tag(elem.tag) == "elem" and elem.get("key") == "pem":
                                pem_raw = elem.text
                                break

                        # Fallback to raw script output
                        if not pem_raw:
                            pem_raw = script.get("output", "")

                        if pem_raw:
                            pem_clean = self._fix_pem(pem_raw)
                            if "-----BEGIN CERTIFICATE-----" in pem_clean:
                                # We pass a descriptive string. The analyzer must handle
                                # non-Path objects for virtual sources.
                                source_info = PurePosixPath(f"nmap/{address}/{port_id}")
                                certs = self.repository.add_pem_data(
                                    pem_clean.encode(),
                                    source_path=source_info
                                )
                                if certs:
                                    groups.append(TrustStoreGroup(
                                        name=f"Nmap: {address}:{port_id}",
                                        targets=certs
                                    ))
        return groups

    def _fix_pem(self, raw: str) -> str:
        """
        Sanitizes raw PEM data from XML entities and formatting artifacts.
        """
        # Clean XML escaped hyphens and newlines
        clean = raw.replace("-&#45;", "--").replace("&#45;", "-")
        clean = clean.replace("&#xa;", "\n").replace("\xa0", " ")
        # Ensure standard BEGIN/END markers
        clean = re.sub(r'-+\s*BEGIN CERTIFICATE\s*-+', "-----BEGIN CERTIFICATE-----", clean)
        clean = re.sub(r'-+\s*END CERTIFICATE\s*-+', "-----END CERTIFICATE-----", clean)
        return clean