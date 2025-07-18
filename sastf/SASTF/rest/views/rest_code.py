import logging

from os.path import commonprefix, realpath, normpath
from pathlib import Path

from django.shortcuts import get_object_or_404

from rest_framework import permissions, authentication, views
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework import status

from sastf.SASTF import settings
from sastf.SASTF.rest.permissions import CanEditProject, CanEditScan
from sastf.SASTF.models import Finding, Vulnerability, Project, File, Scan
from sastf.SASTF.serializers import SnippetSerializer
from sastf.SASTF.utils import filetree


from .base import GetObjectMixin

__all__ = ["FindingCodeView", "VulnerabilityCodeView", "FiletreeView", "FileCodeView"]

logger = logging.getLogger(__name__)


class CodeView(views.APIView):
    authentication_classes = [
        authentication.BasicAuthentication,
        authentication.SessionAuthentication,
        authentication.TokenAuthentication,
    ]

    permission_classes = [permissions.IsAuthenticated & CanEditProject]

    model = None

    def get(self, request: Request, finding_id: str) -> Response:
        finding = get_object_or_404(self.model.objects.all(), finding_id=finding_id)

        snippet = finding.snippet
        if not snippet:
            return Response(
                {"detail": "No Code assigned to this template"},
                status.HTTP_204_NO_CONTENT,
            )

        src_file = Path(snippet.sys_path)
        # validate whether the requesting user has the necessary
        # permissions to view the file
        project = finding.scan.project
        self.check_object_permissions(request, project)

        if not src_file.exists() or src_file.is_dir():
            return Response(
                {"detail": "Project source file does not exist or is a directory"},
                status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        with src_file.open(encoding="utf-8") as fp:
            code = fp.read()

        serializer = SnippetSerializer(snippet)
        data = {"code": code, "snippet": serializer.data}
        return Response(data)


class FindingCodeView(CodeView):
    model = Finding


class VulnerabilityCodeView(CodeView):
    model = Vulnerability


class FiletreeView(GetObjectMixin, views.APIView):
    authentication_classes = [
        authentication.BasicAuthentication,
        authentication.SessionAuthentication,
        authentication.TokenAuthentication,
    ]

    permission_classes = [permissions.IsAuthenticated & CanEditScan]

    model = Scan
    lookup_field = "scan_uuid"

    def get(self, request, *args, **kwargs):
        scan: Scan = self.get_object()
        target = scan.project.dir(scan.file.internal_name)

        # The root node's name must be changed as it would display
        # the md5 hash value
        tree = filetree.apply_rules(target, scan.file.internal_name)
        tree["type"] = "projectstructure"
        tree["text"] = scan.file.file_name
        return Response(tree)


class FileCodeView(GetObjectMixin, views.APIView):
    authentication_classes = [
        authentication.BasicAuthentication,
        authentication.SessionAuthentication,
        authentication.TokenAuthentication,
    ]

    permission_classes = [permissions.IsAuthenticated]

    model = File
    lookup_field = "internal_name"

    def get(self, request: Request, *args, **kwargs) -> Response:
        scan_file = self.get_object()
        project = self.get_object(Project, "project_uuid", False)
        scan = Scan.objects.get(file=scan_file, project=project)

        permission = CanEditScan()
        if not permission.has_object_permission(request, self, scan) or (
            not CanEditProject.has_object_permission(request, self, project)
        ):
            self.permission_denied(
                request,
                message=getattr(permission, "message", None),
                code=getattr(permission, "code", None),
            )

        path = request.query_params.get("file", None)
        safe_dir = realpath(normpath(f"{scan_file.internal_name}/"))
        if not path or commonprefix((realpath(normpath(path)), safe_dir)) != safe_dir:
            return Response(status=status.HTTP_400_BAD_REQUEST)

        target = scan.project.directory / path
        if not target.exists():
            logger.warning("Could not find file at '%s'", str(target))
            return Response(status=status.HTTP_404_NOT_FOUND)

        return Response(open(str(target), "r"))
