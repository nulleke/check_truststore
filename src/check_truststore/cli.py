# -----------------------------------------------------------------------------
# TrustStore Analyzer & Visualizer
# -----------------------------------------------------------------------------
# Main Architect & Lead Developer: Serge van Thillo <nulleke76@gmail.com>
# Development Assistant: AI (Refactoring & Pydantic compatibility)
# Date: 2026
#
# Logic & Design:
# This tool was architected to analyze certificate truststores via YAML.
# The core logic for chain reconstruction and collision detection was
# designed by the Lead Developer. AI was used to assist with syntax
# optimization and cross-version Python support.
#
# Copyright (C) 2024-2026 Serge van Thillo <nulleke76@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# -----------------------------------------------------------------------------

import sys
import argparse
import json
import io
from pathlib import Path
from typing import Optional

from check_truststore.engine import (
    _,
    ERROR,
    WARNING,
    INFO,
    CertificateRepository,
    TrustStoreAnalyzer,
)
from check_truststore.providers import (
    YamlInputProvider,
    JsonInputProvider,
    XmlInputProvider,
    SingleFileInputProvider,
    DirectoryInputProvider,
)
from check_truststore.renderers import TrustStoreRenderer
from check_truststore.providers.base import BaseInputProvider

def setup_utf8_output() -> None:
    """
    Forces UTF-8 encoding on stdout and stderr.
    Crucial for older Python 3.6 environments and containers (e.g., Podman/Docker)
    to prevent 'UnicodeEncodeError' when printing emojis or special symbols.
    """
    if sys.stdout.encoding is None or sys.stdout.encoding.lower() != 'utf-8':
        if hasattr(sys.stdout, 'buffer'):
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
            sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

def get_provider(input_str: str, stdin_content: Optional[str], repo: CertificateRepository, **kwargs) -> Optional[BaseInputProvider]:
    """
    Factory logic to determine the correct provider based on input type or content.
    """
    if input_str == "-":
        if not stdin_content:
            return None

        content = stdin_content.lstrip()
        if content.startswith(("{", "[")):
            return JsonInputProvider(stdin_content, repository=repo, is_raw_data=True, **kwargs)
        if content.startswith("<?xml") or "<nmaprun" in content:
            return XmlInputProvider(stdin_content, repository=repo, is_raw_data=True, **kwargs)
        if "BEGIN CERTIFICATE" in content:
            return SingleFileInputProvider(stdin_content, repository=repo, is_raw_data=True, **kwargs)
        if ":" in content:
            return YamlInputProvider(stdin_content, repository=repo, is_raw_data=True, **kwargs)
        return None

    path = Path(input_str)
    if not path.exists():
        return None

    if path.is_dir():
        return DirectoryInputProvider(path, repository=repo, recursive=True, **kwargs)

    suffix = path.suffix.lower()
    if suffix in [".yml", ".yaml"]:
        return YamlInputProvider(path, repository=repo, **kwargs)
    if suffix == ".json":
        return JsonInputProvider(path, repository=repo, **kwargs)
    if suffix == ".xml":
        return XmlInputProvider(path, repository=repo, **kwargs)

    return SingleFileInputProvider(path, repository=repo, **kwargs)

def main() -> None:
    setup_utf8_output()
    try:
        _("ERROR")
        _("WARNING")
        _("OK")
        _("INFO")
        _("CHAIN")
        _("INVALID")
        _("EXPIRED")
        _("EXPIRING")
        _("SYSTEM")
        _("PARENT_NOT_A_CA")

        parser = argparse.ArgumentParser(
            description=_(
                "Analyze certificate truststores and visualize the chain hierarchy."
            ),
            epilog=_("Compatible with Python 3.6+"),
            add_help=False,
        )
        parser.add_argument(
            "-h",
            "--help",
            action="help",
            default=argparse.SUPPRESS,
            help=_("Show this help message and exit"),
        )
        parser.add_argument(
            "inputs", type=str, nargs="*", help=_("Path to the input source(s)")
        )

        input_group = parser.add_argument_group(_("Input & Network Configuration"))
        input_group.add_argument(
            "-s",
            "--system",
            action="store_true",
            default=False,
            help=_("Incorporate system truststore"),
        )
        input_group.add_argument(
            "-O",
            "--online",
            action="store_true",
            default=False,
            help=_("Allow internet access for AIA discovery and revocation checks"),
        )
        input_group.add_argument(
            "--no-cache",
            action="store_true",
            help=_("Bypass local cache and force download of AIA/CRL/OCSP data")
        )
        input_group.add_argument(
            "-F", "--force",
            action="store_true",
            help=_("Override safety limits (max file size and certificate count)")
        )

        analysis_group = parser.add_argument_group(_("Analysis Settings"))
        analysis_group.add_argument(
            "-t",
            "--threshold",
            type=int,
            default=30,
            help=_("Expiration threshold in days (default: 30)"),
        )
        analysis_group.add_argument(
            "--max-depth",
            type=int,
            default=4,
            help=_("Maximum recursion depth for chain discovery (default: 4)"),
        )

        output_group = parser.add_argument_group(_("Output & Debugging"))
        output_group.add_argument(
            "-f",
            "--format",
            choices=["json", "text", "status", "sarif", "dot"],
            default="text",
            help=_("Output format"),
        )
        output_group.add_argument(
            "-v", "--verbose",
            action="count",
            default=0,
            dest="verbosity",
            help=_("Increase output verbosity (e.g., -v for SANs, -vv for policy findings)")
        )
        output_group.add_argument(
            "-d", "--debug",
            action="store_true",
            default=False,
            help=_("Show debug info")
        )
        export_group = parser.add_argument_group(_("Export Options"))
        export_group.add_argument(
            "--export-bundles",
            action="store_true",
            default=False,
            dest="export_bundles",
            help=_("Export a complete PKCS#7 (.p7b) bundle for each analyzed group"),
        )
        export_group.add_argument(
            "--export-dir",
            type=str,
            default="output_bundles",
            dest="export_dir",
            help=_("Directory where bundles will be saved (default: output_bundles)"),
        )

        parser.add_argument(
            "--mock",
            action="store_true",
            default=False,
            help=argparse.SUPPRESS,
        )
        parser.add_argument(
            "-o",
            action="store_true",
            help=argparse.SUPPRESS,
        )

        args = parser.parse_args()

        if "-o" in sys.argv:
            ERROR.log(
                _("Parameter '-o' is unknown"),
                _("Did you mean '-O' (uppercase) for online discovery?"),
            )
            sys.exit(1)

        stdin_content = None
        if "-" in args.inputs or (not args.mock and not args.inputs):
            if not sys.stdin.isatty():
                stdin_content = sys.stdin.read().strip()
            elif "-" in args.inputs:
                parser.error(_("Stdin requested via '-' but no data piped."))

        repo = CertificateRepository(**vars(args))
        analysis_groups = []

        if args.mock:
            from check_truststore.providers.mock_provider import MockProvider
            analysis_groups.extend(MockProvider(repository=repo).get_groups())

        # Main provider loop
        effective_inputs = args.inputs if args.inputs else ["-"]
        for input_str in effective_inputs:
            provider = get_provider(input_str, stdin_content, repo, **vars(args))

            if provider:
                groups = provider.get_groups()
                if groups:
                    analysis_groups.extend(groups)
                elif args.debug:
                    WARNING.log(input_str, _("No certificates found via this provider."))
            elif input_str != "-" or stdin_content:
                WARNING.log(input_str, _("Could not determine provider for this input."))

        if not analysis_groups:
            WARNING.log(_("No certificates found to display."))
            sys.exit(0)

        analyzer = TrustStoreAnalyzer(groups=analysis_groups, repository=repo, **vars(args))
        results = analyzer.analyze()

        renderer = TrustStoreRenderer()
        output = renderer.render(results, args.format, **vars(args))

        sys.stdout.write(output)
        sys.stdout.flush()
        print()

        if args.format == "status":
            try:
                report = json.loads(output)
                sys.exit(report.get("metadata", {}).get("exitCode", 0))
            except Exception:
                sys.exit(7)

        if args.format == "sarif" and '"level": "error"' in output:
            sys.exit(1)

    except KeyboardInterrupt:
        sys.stderr.write("\n")
        INFO.log(_("Analysis interrupted by user"))
        sys.exit(130)
    except Exception as e:
        ERROR.log(_("An unexpected error occurred"), str(e))
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
