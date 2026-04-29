"""
TrustStore Analyzer & Visualizer - YAML PROVIDER
Architect: Serge van Thillo

Advanced configuration-driven provider that supports YAML syntax,
environment-based variables, and automated file extension resolution.
"""

from pathlib import Path
from typing import List, Optional, Union
from check_truststore.providers.base import BaseInputProvider, TrustStoreGroup
from check_truststore.engine.core import _, ERROR, WARNING, INFO, CertificateRepository
try:
    import yaml
except ImportError:
    raise ImportError(_("Package 'pyyaml' is required for YAML support."))

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
        super().__init__(repository=repository, **kwargs)
        self.input_source = input_source
        self.env = env
        self.is_raw_data = is_raw_data

    def _get_yaml_content(self) -> Optional[dict]:
        try:
            if self.is_raw_data:
                return yaml.safe_load(self.input_source)

            path = Path(self.input_source)
            if not path.is_file():
                return None

            with open(path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f)
        except (yaml.YAMLError, AttributeError, PermissionError):
            return None
        except Exception as e:
            if self.debug:
                ERROR.log(_("YAML Load Error"), str(e))
            return None

    def get_groups(self) -> List[TrustStoreGroup]:
        data = self._get_yaml_content()
        if not data or not isinstance(data, dict):
            return []

        # Determine base directory for relative paths (relative to the config file)
        base_dir = Path(self.input_source).parent if not self.is_raw_data else Path.cwd()

        env_name = data.get("env", self.env)
        extension = data.get("certificate_file_extension", ".crt")
        groups = []

        for store in data.get("truststores", []):
            store_name = store.get("name", _("Unnamed Store"))

            # Resolve cert_src_dir with environment placeholder support
            raw_src_dir_str = store.get("cert_src_dir", ".").replace("{{ env }}", env_name)
            raw_src_path = Path(raw_src_dir_str)

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

                # Ensure filename has the correct extension
                filename = cert_name if cert_name.endswith(extension) else f"{cert_name}{extension}"
                p = source_dir / filename

                if p.is_file():
                    # Consistent repository loading
                    certs = self.repository.load_from_files([p])
                    if certs:
                        group_certs.extend(certs)
                    elif self.debug:
                        ERROR.log(filename, _("File exists but failed to load certificate."), label=_("LOAD_ERR"))
                elif self.debug:
                    WARNING.log(filename, _("Certificate file not found in {}").format(source_dir), label=_("MISSING"))

            if group_certs:
                if self.debug:
                    INFO.log(_("Group Loaded"), _("Group '{name}' loaded with {count} certificates.").format(
                        name=store_name, count=len(group_certs)))
                groups.append(TrustStoreGroup(name=store_name, targets=group_certs))
            else:
                WARNING.log(store_name, _("Group has NO valid certificates."), label=_("EMPTY_GROUP"))

        return groups