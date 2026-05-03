from .base import BaseRenderer as BaseRenderer
from .text_renderer import TextRenderer
from .json_renderer import JsonRenderer
from .status_renderer import StatusRenderer
from .sarif_renderer import SarifRenderer
from .graphviz_renderer import GraphvizRenderer


class TrustStoreRenderer:
    def __init__(self):
        self._renderers = {
            "text": TextRenderer(),
            "json": JsonRenderer(),
            "status": StatusRenderer(),
            "sarif": SarifRenderer(),
            "graphviz": GraphvizRenderer(),
            "dot": GraphvizRenderer(),
        }

    def render(self, tree_data, format_type, **kwargs):
        renderer = self._renderers.get(format_type)
        if not renderer:
            from check_truststore.engine import _

            raise ValueError(_("Unknown format: {}").format(format_type))

        return renderer.render(tree_data, **kwargs)
