from shutil import rmtree

from django.db.models import Q, QuerySet
from django.contrib.auth.models import User

from rest_framework import permissions, views, authentication, status, exceptions
from rest_framework.request import Request
from rest_framework.response import Response

from sastf.SASTF import settings
from sastf.SASTF.utils.enum import Visibility
from sastf.SASTF.scanners.plugin import ScannerPlugin
from sastf.SASTF.permissions import CanEditProject, CanDeleteProject
from sastf.SASTF.serializers import ProjectSerializer, TeamSerializer, UserSerializer
from sastf.SASTF.models import Project, Scan, Finding, Vulnerability, Scanner, Team
from sastf.SASTF.forms import ProjectCreationForm

from .base import ListAPIViewBase, APIViewBase, CreationAPIViewBase, GetObjectMixin

__all__ = ["ProjectView", "ProjectCreationView", "ProjectListView", "ProjectChartView"]


class ProjectView(APIViewBase):
    """API-Endpoint designed to create, manage and delete projects.

    The different HTTP methods are mapped as follows:

        - ``GET``: Lists information about a single project
        - ``DELETE``: obviously deletes the current project
        - ``PATCH``: updates single attributes of a project
    """

    permission_classes = [
        # The user has to be authenticated
        permissions.IsAuthenticated
        & (CanEditProject | CanDeleteProject)
    ]
    bound_permissions = [CanDeleteProject, CanEditProject]

    model = Project
    serializer_class = ProjectSerializer
    lookup_field = "project_uuid"

    def prepare_patch(self, data: dict, instance):
        if "owner" in data:
            # remove current permissions and add them to the next user
            new_owner = data["owner"]
            try:
                if isinstance(new_owner, (str, int)):
                    new_owner = User.objects.get(pk=int(new_owner))
            except Exception as err:
                raise exceptions.ValidationError(
                    "Could not find user with provided ID"
                ) from err

            if isinstance(new_owner, User):
                CanDeleteProject.assign_to(new_owner, instance.pk)
                CanEditProject.assign_to(new_owner, instance.pk)
                CanDeleteProject.remove_from(instance.owner, instance)
                CanEditProject.remove_from(instance.owner, instance)

    def on_delete(self, request: Request, obj) -> None:
        rmtree(settings.PROJECTS_ROOT / str(obj.project_uuid))


class ProjectCreationView(CreationAPIViewBase):
    """Basic API-Endpoint to create a new project."""

    permission_classes = [permissions.IsAuthenticated]
    form_class = ProjectCreationForm
    model = Project
    bound_permissions = [CanDeleteProject, CanEditProject]

    def on_create(self, request: Request, instance: Project) -> None:
        path = settings.PROJECTS_ROOT / str(instance.project_uuid)
        path.mkdir()

    def set_defaults(self, request: Request, data: dict) -> None:
        team_name = data.pop("team_name", None)
        if team_name:
            data["team"] = Team.get(request.user, team_name)

        if not data.get("team", None):
            data["owner"] = request.user


class ProjectListView(ListAPIViewBase):
    """Lists all projects that can be viewed by a user"""

    queryset = Project.objects.all()
    """Dummy queryset"""

    serializer_class = ProjectSerializer
    # The user must be the owner or the project must be public
    permission_classes = [permissions.IsAuthenticated & CanEditProject]

    def filter_queryset(self, queryset: QuerySet) -> QuerySet:
        return queryset.filter(
            Q(owner=self.request.user)
            | Q(team__users__pk=self.request.user)
            | Q(visibility=Visibility.PUBLIC, team=None)
        )


class ProjectChartView(GetObjectMixin, views.APIView):
    authentication_classes = [
        authentication.BasicAuthentication,
        authentication.SessionAuthentication,
        authentication.TokenAuthentication,
    ]

    permission_classes = [permissions.IsAuthenticated & CanEditProject]

    model = Project
    lookup_field = "project_uuid"

    def get(self, request: Request, *args, **kwargs) -> Response:
        """Generates a timeline for all vulnerabilities and findings of a project.

        :param request: the HttpRequest
        :type request: Request
        :return: a timeline in JSON format
        :rtype: Response
        """
        project = self.get_object()
        name = self.kwargs["name"]
        if not hasattr(self, f"chart_{name}"):
            return Response(status=status.HTTP_404_NOT_FOUND)

        func = getattr(self, f"chart_{name}")
        data = func(project)
        return Response(data)

    def chart_timeline(self, project: Project) -> dict:
        data = {}
        for scan in Scan.objects.filter(project=project):
            data[str(scan.start_date)] = {
                "vuln_count": len(Vulnerability.objects.filter(scan=scan)),
                "finding_count": len(Finding.objects.filter(scan=scan)),
            }
        return data

    def chart_pie(self, project: Project) -> dict:
        data = {}
        plugins = ScannerPlugin.all()
        for scanner in Scanner.objects.filter(scan__project=project):
            name = plugins[scanner.name].title
            data[name] = len(
                Finding.objects.filter(scan__project=project, scanner=scanner)
            )

        return data
