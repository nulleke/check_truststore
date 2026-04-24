"""
TrustStore Analyzer & Visualizer - YAML PROVIDER
Architect: Serge van Thillo

Advanced configuration-driven provider that supports YAML syntax,
environment-based variables, and automated file extension resolution.
"""

from pathlib import Path
from typing import List, Optional

from check_truststore.providers.base import BaseInputProvider, TrustStoreGroup
from check_truststore.engine.core import _, ERROR, WARNING, INFO, CertificateRepository


class YamlInputProvider(BaseInputProvider):
    """
    Parses a YAML configuration file to define truststores.
    Supports dynamic path replacement and logging of missing components
    when running in debug mode.
    """

    def __init__(
        self,
        yaml_path: Path,
        repository: Optional[CertificateRepository] = None,
        env: str = "tst",
        debug: bool = False,
    ):
        """
        Initializes the YAML provider.

        Args:
            yaml_path: Path to the .yaml or .yml configuration file.
            repository: Optional shared repository for certificate loading.
            env: Environment string to replace '{{ env }}' placeholders.
            debug: If True, uses the logging engine to report loading issues.
        """
        super().__init__(repository=repository)
        self.yaml_path = yaml_path
        self.env = env
        self.debug = debug

    def _get_yaml_content(self) -> Optional[dict]:
        """
        Safely loads YAML content using PyYAML.

        Raises:
            ImportError: If the 'pyyaml' package is not installed.
        """
        try:
            import yaml
        except ImportError:
            raise ImportError(_("Package 'pyyaml' is required for YAML support."))

        if not self.yaml_path.exists():
            return None

        try:
            with open(self.yaml_path, "r") as f:
                return yaml.safe_load(f)

        except (yaml.YAMLError, AttributeError, PermissionError):
            return None

    def get_groups(self) -> List[TrustStoreGroup]:
        """
        Processes the YAML structure and returns the mapped TrustStoreGroups.
        Handles placeholder replacement and automated extension appending.

        Returns:
            A list of TrustStoreGroup objects found in the configuration.
        """
        data = self._get_yaml_content()
        if not data or not isinstance(data, dict):
            return []

        # Global settings from YAML or defaults
        env_name = data.get("env", self.env)
        extension = data.get("certificate_file_extension", ".crt")
        groups = []

        for store in data.get("truststores", []):
            store_name = store.get("name", _("Unnamed Store"))

            # Dynamic path resolution: replace {{ env }} with the active environment
            source_dir_str = store.get("cert_src_dir", "").replace(
                "{{ env }}", env_name
            )
            source_dir = Path(source_dir_str).resolve()

            group_certs = []
            for link in store.get("cert_chain", []):
                cert_name = link.get("link")
                if not cert_name:
                    continue

                # Auto-append extension if not provided in the link name
                filename = (
                    cert_name
                    if cert_name.endswith(extension)
                    else cert_name + extension
                )
                p = source_dir / filename

                if p.exists():
                    cert = self.load_certificate(p)
                    if cert:
                        group_certs.append(cert)
                    elif self.debug:
                        ERROR.log(
                            filename,
                            _("File exists but failed to load certificate."),
                            label=_("LOAD_ERR"),
                        )
                elif self.debug:
                    WARNING.log(
                        filename,
                        _("Certificate file not found in {}").format(source_dir),
                        label=_("MISSING"),
                    )

            # Logic to pack groups or warn if a group definition is empty
            if group_certs:
                if self.debug:
                    INFO.log(
                        _("Group Loaded"),
                        _("Group '{name}' loaded with {count} certificates.").format(
                            name=store_name, count=len(group_certs)
                        ),
                    )
                groups.append(TrustStoreGroup(name=store_name, targets=group_certs))
            else:
                WARNING.log(
                    store_name,
                    _("Group has NO valid certificates."),
                    label=_("EMPTY_GROUP"),
                )

        return groups
