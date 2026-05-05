"""
TrustStore Analyzer & Visualizer - YAML PROVIDER
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later

Advanced configuration-driven provider that supports YAML syntax,
Jinja2 templating (optional), and automated file extension resolution.
"""

import yaml
import os
import re
from pathlib import Path
from typing import List, Optional, Union, Dict, Any
from check_truststore.providers.base import BaseInputProvider, TrustStoreGroup
from check_truststore.engine import _, ERROR, WARNING, INFO, CertificateRepository


class YamlInputProvider(BaseInputProvider):
    """
    Parses a YAML configuration file to define truststores.
    Supports Jinja2 templating if installed, otherwise falls back to basic regex replacement.
    """

    def __init__(
        self,
        input_source: Union[Path, str],
        repository: Optional[CertificateRepository] = None,
        env: str = "tst",
        is_raw_data: bool = False,
        **kwargs: Any,
    ):
        """
        Initializes the YAML provider.

        Args:
            input_source: Path to the YAML file or raw YAML string.
            repository: Shared CertificateRepository instance.
            env: Default environment name for variable substitution.
            is_raw_data: True if input_source contains raw YAML content.
            **kwargs: Additional variables for template rendering.
        """
        super().__init__(repository=repository, **kwargs)
        self.input_source = input_source
        self.env = env
        self.is_raw_data = is_raw_data
        self.kwargs = kwargs
        self._j2_env = None

    @property
    def j2_env(self) -> Optional[Any]:
        """
        Lazy loads the Jinja2 environment to minimize overhead.

        Returns:
            Jinja2 Environment object if available, otherwise None.
        """
        if self._j2_env is None:
            try:
                from jinja2 import Environment, FileSystemLoader
                search_path = [str(Path(self.input_source).parent)] if not self.is_raw_data else ["."]
                self._j2_env = Environment(loader=FileSystemLoader(search_path))
            except ImportError:
                return None
        return self._j2_env

    def _render_content(self, raw_content: str, extra_vars: Optional[Dict[str, Any]] = None) -> str:
        """
        Renders content using Jinja2 or a robust regex-based fallback.

        Args:
            raw_content: The unparsed string from the YAML source.
            extra_vars: Variables extracted from the YAML root for the second pass.

        Returns:
            The rendered string with variables replaced.
        """
        render_vars = {
            "env": self.env,
            "os_env": os.environ,
            "cwd": str(Path.cwd()),
            **(extra_vars or {}),
            **self.kwargs
        }

        if self.j2_env:
            try:
                return self.j2_env.from_string(raw_content).render(**render_vars)
            except Exception as e:
                if self.debug:
                    WARNING.log(_("Jinja2 Render Error"), str(e))
                return raw_content

        if self.debug:
            INFO.log("Jinja2", _("Jinja2 not found. Using regex fallback."))

        def replace_match(match):
            key = match.group(1).strip()
            return str(render_vars.get(key, match.group(0)))

        return re.sub(r"\{\{\s*(.*?)\s*\}\}", replace_match, raw_content)

    def _resolve_source_dir(self, raw_src_dir: str, yaml_dir: Path) -> Path:
        """
        Resolves the certificate source directory relative to CWD or YAML location.

        Args:
            raw_src_dir: The directory path string from YAML.
            yaml_dir: The directory where the YAML file is located.

        Returns:
            A resolved Path object.
        """
        raw_path = Path(raw_src_dir)
        if raw_path.is_absolute():
            return raw_path

        for base in [Path.cwd(), yaml_dir]:
            candidate = (base / raw_path).resolve()
            if candidate.is_dir():
                return candidate

        return Path.cwd() / raw_path

    def _get_yaml_content(self) -> Optional[Dict[str, Any]]:
        """
        Reads, renders, and parses YAML content using a two-pass approach.

        Returns:
            A dictionary representing the YAML structure, or None if parsing fails.
        """
        try:
            if self.is_raw_data:
                raw_content = str(self.input_source)
            else:
                path = Path(self.input_source)
                if not path.is_file():
                    return None
                raw_content = path.read_text(encoding="utf-8")

            try:
                pre_parsed = yaml.safe_load(raw_content) or {}
            except yaml.YAMLError as e:
                if "{{" in raw_content and any(x in str(e) for x in ["mapping", "unhashable"]):
                    ERROR.log(_("YAML Syntax Error"),
                             _("Found unquoted Jinja2 delimiters. Wrap expressions like '{{ var }}' in quotes."))
                raise e

            root_vars = {k: v for k, v in pre_parsed.items() if k != "truststores"} if isinstance(pre_parsed, dict) else {}

            return yaml.safe_load(self._render_content(raw_content, extra_vars=root_vars))

        except (yaml.YAMLError, OSError) as e:
            if self.debug:
                ERROR.log(_("YAML Parse Error"), f"\n{str(e)}")
            return None

    def get_groups(self) -> List[TrustStoreGroup]:
        """
        Processes the YAML structure and returns initialized TrustStoreGroups.

        Returns:
            A list of TrustStoreGroup objects containing discovered certificate paths.
        """
        data = self._get_yaml_content()
        if not data or "truststores" not in data:
            return []

        yaml_dir = Path(self.input_source).parent if not self.is_raw_data else Path.cwd()
        default_ext = data.get("certificate_file_extension", ".crt")
        groups = []

        for i, store in enumerate(data.get("truststores", []), 1):
            name = store.get("name", f"{_('Unnamed Store')} {i}")
            source_dir = self._resolve_source_dir(store.get("cert_src_dir", "."), yaml_dir)

            group_targets = []
            for link in store.get("cert_chain", []):
                cert_name = link.get("link") if isinstance(link, dict) else link
                if not cert_name:
                    continue

                filename = cert_name if "." in cert_name else f"{cert_name}{default_ext}"
                p = source_dir / filename

                if p.is_file():
                    group_targets.append(p)
                elif self.debug:
                    WARNING.log(filename, _("Certificate not found in {}").format(source_dir), label=_("MISSING"))

            if group_targets:
                groups.append(TrustStoreGroup(name=name, targets=group_targets))
            else:
                WARNING.log(name, _("Group contains no valid certificates."), label=_("EMPTY_GROUP"))

        return groups