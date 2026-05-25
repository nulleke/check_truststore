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
    """Parses complex YAML configuration files to define certificate truststores.

    This provider supports advanced dynamic configuration by integrating Jinja2
    templating (if available) or a robust fallback regex engine, enabling
    environment-aware certificate path resolution.

    Attributes:
        input_source (Union[Path, str, bytes]): The raw YAML content string or
            configuration file destination path.
        env (str): Identifier for the target deployment environment context.
        is_raw_data (bool): Flag indicating if input is a literal YAML data stream.
        kwargs (Dict[str, Any]): Injection variables for the template renderer.
        repository (CertificateRepository): Inherited central asset identification mapping store.
        debug (bool): If True, enables diagnostic traces and deep error reporting.
        verbosity (int): Numeric modifier adjusting logging output volume.
    """

    def __init__(
        self,
        input_source: Union[Path, str],
        repository: Optional[CertificateRepository] = None,
        env: str = "tst",
        is_raw_data: bool = False,
        **kwargs: Any,
    ) -> None:
        """Initializes the YAML configuration engine.

        Args:
            input_source (Union[Path, str]): Path to the YAML file or a literal YAML string.
            repository (Optional[CertificateRepository], optional): Shared index
                repository for certificate discovery. Defaults to None.
            env (str, optional): Default environment name for variable substitution. Defaults to "tst".
            is_raw_data (bool, optional): Treat input as raw string content. Defaults to False.
            **kwargs: Additional variables available for template rendering.
        """
        super().__init__(repository=repository, **kwargs)
        self.input_source: Union[Path, str] = (
            Path(input_source) if (isinstance(input_source, (str, Path)) and not is_raw_data) else input_source
        )
        self.env: str = env
        self.is_raw_data: bool = is_raw_data
        self.kwargs: Dict[str, Any] = kwargs
        self._j2_env: Optional[Any] = None

    @property
    def j2_env(self) -> Optional[Any]:
        """Lazy-loads the Jinja2 rendering environment to minimize initialization overhead.

        Returns:
            Optional[Any]: Jinja2 Environment object if the package is installed,
                otherwise None (triggering fallback).
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
        """Renders configuration content via Jinja2 or a robust regex-based fallback.

        Args:
            raw_content (str): The raw template string from the YAML source.
            extra_vars (Optional[Dict[str, Any]], optional): Contextual variables
                extracted from the YAML root to facilitate templating.

        Returns:
            str: The fully rendered string with resolved placeholders.
        """
        render_vars: Dict[str, Any] = {
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
            key: str = match.group(1).strip()
            return str(render_vars.get(key, match.group(0)))

        return re.sub(r"\{\{\s*(.*?)\s*\}\}", replace_match, raw_content)

    def _resolve_source_dir(self, raw_src_dir: str, yaml_dir: Path) -> Path:
        """Resolves the certificate repository directory relative to execution context.

        Args:
            raw_src_dir (str): The directory path string discovered in YAML.
            yaml_dir (Path): The base path where the configuration file originated.

        Returns:
            Path: An absolute, resolved filesystem path for source assets.
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
        """Reads, renders, and parses YAML structures using a multi-pass approach.

        Returns:
            Optional[Dict[str, Any]]: The parsed configuration map if the syntax is
                valid and renderable; None if parsing fails.
        """
        try:
            raw_content: str
            if self.is_raw_data:
                raw_content = str(self.input_source)
            elif isinstance(self.input_source, Path):
                raw_content = self.input_source.read_text(encoding="utf-8")
            else:
                return None

            try:
                pre_parsed: Any = yaml.safe_load(raw_content) or {}
            except yaml.YAMLError as e:
                if "{{" in raw_content and any(x in str(e) for x in ["mapping", "unhashable"]):
                    ERROR.log(_("YAML Syntax Error"),
                             _("Found unquoted Jinja2 delimiters. Wrap expressions like '{{ var }}' in quotes."))
                raise e

            root_vars: Dict[str, Any] = {k: v for k, v in pre_parsed.items() if k != "truststores"} if isinstance(pre_parsed, dict) else {}

            return yaml.safe_load(self._render_content(raw_content, extra_vars=root_vars))

        except (yaml.YAMLError, OSError) as e:
            if self.debug:
                ERROR.log(_("YAML Parse Error"), f"\n{str(e)}")
            return None

    def get_groups(self) -> List[TrustStoreGroup]:
        """Processes the YAML schema and returns initialized container groups.

        Returns:
            List[TrustStoreGroup]: Discovered and validated certificate path groups
                ready for orchestrator pipeline analysis.
        """
        data: Optional[Dict[str, Any]] = self._get_yaml_content()
        if not data or "truststores" not in data:
            return []

        yaml_dir: Path = Path(self.input_source).parent if not self.is_raw_data else Path.cwd()
        default_ext: str = data.get("certificate_file_extension", ".crt")
        groups: List[TrustStoreGroup] = []

        for i, store in enumerate(data.get("truststores", []), 1):
            name: str = store.get("name", f"{_('Unnamed Store')} {i}")
            source_dir: Path = self._resolve_source_dir(store.get("cert_src_dir", "."), yaml_dir)

            group_targets: List[Path] = []
            for link in store.get("cert_chain", []):
                cert_name: Optional[str] = link.get("link") if isinstance(link, dict) else link
                if not cert_name:
                    continue

                filename: str = cert_name if "." in cert_name else f"{cert_name}{default_ext}"
                p: Path = source_dir / filename

                if p.is_file():
                    group_targets.append(p)
                elif self.debug:
                    WARNING.log(filename, _("Certificate not found in {}").format(source_dir), label=_("MISSING"))

            if group_targets:
                groups.append(TrustStoreGroup(name=name, targets=group_targets))
            else:
                WARNING.log(name, _("Group contains no valid certificates."), label=_("EMPTY_GROUP"))

        return groups