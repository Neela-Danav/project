import json
import os

from django.contrib import messages

from sastf.SASTF.settings import DETAILS_DIR, ARTICLES
from sastf.SASTF.mixins import ContextMixinBase, TemplateAPIView


class DetailsView(ContextMixinBase, TemplateAPIView):
    """A view for displaying details of a specific item."""

    template_name = "details.html"

    def get_context_data(self, **kwargs):
        """
        Retrieve and prepare the context data for rendering the details view.

        :param kwargs: Additional keyword arguments.
        :return: A dictionary containing the context data.
        """
        context = super().get_context_data(**kwargs)
        context["pages"] = ARTICLES

        platform = self.kwargs["platform"].lower()
        name = self.kwargs["name"].lower()

        path = DETAILS_DIR / platform / f"{name}.jsontx"
        if not path.exists():
            messages.warning(
                self.request, f"Invalid details name: {path}", "FileNotFoundError"
            )
            return context

        if not os.path.commonprefix((path, DETAILS_DIR)).startswith(str(DETAILS_DIR)):
            messages.warning(
                self.request, f"Invalid path name: {path}", "FileNotFoundError"
            )
            return context

        with open(str(path), "r", encoding="utf-8") as fp:
            # Error handling will be done in dispatch() view
            context["data"] = json.load(fp)

        return context
