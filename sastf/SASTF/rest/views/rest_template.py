from re import sub
from uuid import uuid4

from rest_framework import permissions
from rest_framework.request import Request

from sastf.SASTF.serializers import TemplateSerializer
from sastf.SASTF.models import FindingTemplate
from sastf.SASTF.forms import FindingTemplateForm
from sastf.SASTF.rest.permissions import IsExternal

from .base import APIViewBase, CreationAPIViewBase, ListAPIViewBase

__all__ = [
    "FindingTemplateView",
    "FindingTemplateListView",
    "FindingTemplateCreationView",
]


class FindingTemplateView(APIViewBase):
    """API-Endpoint for creating, managing and removing finding templates."""

    permission_classes = [permissions.IsAuthenticated]

    model = FindingTemplate
    lookup_field = "template_id"
    serializer_class = TemplateSerializer


class FindingTemplateCreationView(CreationAPIViewBase):
    """Separate APIView for creating new ``FindingTemplate`` objects"""

    permission_classes = [permissions.IsAuthenticated]
    form_class = FindingTemplateForm
    model = FindingTemplate

    def set_defaults(self, request: Request, data: dict) -> None:
        data["internal_id"] = sub(r"[\s_:]", "-", data.get("title")).lower()

    def make_uuid(self):
        return f"FT-{uuid4()}-{uuid4()}"


class FindingTemplateListView(ListAPIViewBase):
    """A view listing all finding templates"""

    queryset = FindingTemplate.objects.all()
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = TemplateSerializer
