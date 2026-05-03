"""
TrustStore Analyzer & Visualizer - YAML PROVIDER
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later

Advanced configuration-driven provider that supports YAML syntax,
environment-based variables, and automated file extension resolution.
"""

import yaml
from pathlib import Path
from typing import List, Optional, Union, Dict
from check_truststore.providers.base import BaseInputProvider, TrustStoreGroup
from check_truststore.engine import _, ERROR, WARNING, INFO, CertificateRepository

class YamlInputProvider(BaseInputProvider):
    """
    Parses a YAML configuration file to define truststores.
    Supports dynamic path replacement and logging of missing components.
    """

    def __init__(
        self,
        input_source: Union[Path, str],
        repository: Optional[CertificateRepository] = None,
        env: str = "tst",
        is_raw_data: bool = False,
        **kwargs,
    ):
        """
        Initializes the YAML provider.

        Args:
            input_source: Path to the YAML file or raw YAML string.
            repository: Shared CertificateRepository instance.
            env: Default environment name for variable substitution.
            is_raw_data: True if input_source contains raw YAML content.
        """
        super().__init__(repository=repository, **kwargs)
        self.input_source = input_source
        self.env = env
        self.is_raw_data = is_raw_data

    def _get_yaml_content(self) -> Optional[Dict]:
        """
        Safely loads and parses YAML content.
        """
        try:
            if self.is_raw_data:
                return yaml.safe_load(self.input_source)

            path = Path(self.input_source)
            if not path.is_file():
                return None

            with open(path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f)
        except (yaml.YAMLError, AttributeError, PermissionError) as e:
            if self.debug:
                ERROR.log(_("YAML Parse Error"), str(e))
            return None

    def get_groups(self) -> List[TrustStoreGroup]:
        """
        Processes the YAML structure and returns initialized TrustStoreGroups.
        """
        data = self._get_yaml_content()
        if not data or not isinstance(data, dict):
            return []

        # Determine base directory for relative path resolution
        base_dir = Path(self.input_source).parent if not self.is_raw_data else Path.cwd()

        # Global config overrides
        env_name = data.get("env", self.env)
        default_ext = data.get("certificate_file_extension", ".crt")
        groups = []

        for store in data.get("truststores", []):
            store_name = store.get("name", _("Unnamed Store"))

            # Dynamic path resolution with environment support
            raw_src_dir = store.get("cert_src_dir", ".").replace("{{ env }}", env_name)
            raw_src_path = Path(raw_src_dir)

            if raw_src_path.is_absolute():
                source_dir = raw_src_path
            else:
                candidate_path = (base_dir / raw_src_path).resolve()
                if candidate_path.exists():
                    source_dir = candidate_path
                else:
                    source_dir = raw_src_path.resolve()

            group_certs = []
            for link in store.get("cert_chain", []):
                cert_name = link.get("link")
                if not cert_name:
                    continue

                # Auto-append extension if missing
                filename = cert_name if "." in cert_name else f"{cert_name}{default_ext}"
                p = source_dir / filename

                if p.is_file():
                    # Centralized loading ensures PEM/PKCS7/DER support and deduplication
                    certs = self.repository.load_from_files([p])
                    if certs:
                        group_certs.extend(certs)
                    elif self.debug:
                        ERROR.log(filename, _("Failed to extract valid certificates from file."), label=_("LOAD_ERR"))
                elif self.debug:
                    WARNING.log(filename, _("Certificate not found in {}").format(source_dir), label=_("MISSING"))

            if group_certs:
                if self.debug:
                    INFO.log(store_name, _("Loaded group with {count} certificates.").format(count=len(group_certs)))
                groups.append(TrustStoreGroup(name=store_name, targets=group_certs))
            else:
                WARNING.log(store_name, _("Group contains no valid certificates."), label=_("EMPTY_GROUP"))

        return groups
