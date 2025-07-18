# This file defines default mixins that can be used within each
# extension of a scanner.
from django.db.models import Count

from sastf.SASTF.models import (
    Scan,
    Details,
    namespace,
    File,
    PermissionFinding,
    Vulnerability,
    Finding,
    Scanner,
    FindingTemplate,
    Host,
    Component,
)
from sastf.SASTF.serializers import (
    HostSerializer,
    PermissionFindingSerializer,
    VulnerabilitySerializer,
    FindingSerializer,
    ComponentSerializer,
)
from sastf.SASTF.utils.enum import HostType

__all__ = [
    "DetailsMixin",
    "PermissionsMixin",
    "VulnerabilitiesMixin",
    "FindingsMixins",
    "HostsMixin",
    "ComponentsMixin",
]


class DetailsMixin:
    """Add-on to generate app details

    If you use this mixin and you enable chart-rendering, they will
    be displayed on the front page of scan results.
    """

    charts: bool = True
    """Defines whether summary charts should be displayed on the
    details page."""

    def ctx_details(self, scan: Scan, file: File, scanner: Scanner) -> dict:
        """Returns the details context for the desired extension.

        :param scan: the scan to view
        :type scan: Scan
        :return: all relevant context information
        :rtype: dict
        """
        context = namespace()
        context.details = Details.objects.get(scan=scan, file=file)
        context.charts = self.charts
        return context


class PermissionsMixin:
    """Add-on to generate permission lists according to the selected file

    The returned data will be a list of ``PermissionFinding`` instances that store
    information where the permission has been found and the actual ``AppPermission``
    reference.
    """

    def ctx_permissions(self, scan: Scan, file: File, scanner: Scanner) -> list:
        """Returns all permissions mapped to a specific file."""
        return PermissionFinding.objects.filter(
            scan=scan, scan__file=file, scanner=scanner
        )

    def res_permissions(self, scan: Scan, scanner: Scanner) -> list:
        data = self.ctx_permissions(scan, scan.file, scanner)
        return PermissionFindingSerializer(data, many=True).data


class VulnerabilitiesMixin:
    """Add-on to generate vulnerabilites according to the selected file."""

    def ctx_vulnerabilities(self, scan: Scan, file: File, scanner: Scanner) -> list:
        """Returns all vulnerabilities that have been identified in the scan target.

        :param project: the project instance
        :type project: Project
        :param file: the scan target
        :type file: File
        :return: a list of vulnerabilities
        :rtype: list
        """
        vuln = Vulnerability.objects.filter(scan=scan, scanner=scanner)
        data = []

        languages = (
            vuln.values("snippet__language")
            .annotate(lcount=Count("snippet__language"))
            .order_by()
        )
        if len(languages) == 0:
            return data

        for language in languages:
            lang = {"name": language["snippet__language"], "count": language["lcount"]}
            categories = []

            templates = (
                vuln.filter(snippet__language=lang["name"])
                .values("template")
                .annotate(tcount=Count("template"))
                .order_by()
            )

            for category in templates:
                template_pk = category["template"]
                template = FindingTemplate.objects.get(pk=template_pk)
                cat = {
                    "name": template.title if template else "Untitled",
                    "count": category["tcount"],
                }

                vuln_data = vuln.filter(
                    snippet__language=lang["name"], template=template
                )
                cat["vuln_data"] = VulnerabilitySerializer(vuln_data, many=True).data
                categories.append(cat)

            categories.sort(key=lambda x: x["name"])
            lang["categories"] = categories
            data.append(lang)
        return data

    def res_vulnerabilities(self, scan: Scan, scanner: Scanner) -> list:
        return self.ctx_vulnerabilities(scan, scan.file, scanner)


class FindingsMixins:
    """Add-on to generate a finding list according to the selected file."""

    def ctx_findings(self, scan: Scan, file: File, scanner: Scanner) -> list:
        """Returns all findings that have been identified in the scan target.

        :param project: the project instance
        :type project: Project
        :param file: the scan target
        :type file: File
        :return: a list of vulnerabilities
        :rtype: list
        """
        data = []
        findings = Finding.objects.filter(scan=scan, scanner=scanner)

        templates = (
            findings.values("template").annotate(tcount=Count("template")).order_by()
        )
        if len(templates) == 0:
            return data

        for category in templates:
            pk = category["template"]
            template = FindingTemplate.objects.get(pk=pk)
            filtered = findings.filter(template=template)
            data.append(
                {
                    "name": template.title if template else "Untitled",
                    "internal_id": template.template_id,
                    "count": category["tcount"],
                    "finding_data": FindingSerializer(filtered, many=True).data,
                }
            )

        return data

    def res_findings(self, scan: Scan, scanner: Scanner) -> list:
        return self.ctx_findings(scan, scan.file, scanner)


class HostsMixin:
    """Mixin class for working with hosts in a scan.

    This mixin provides methods for retrieving and manipulating hosts within a scan.

    Usage:
    ~~~~~~

    - Use ``ctx_hosts()`` to get all hosts identified within the scan target.
    - Use ``res_hosts()`` to get a serialized representation of hosts within the scan.

    Example:
    ~~~~~~~~

    .. code-block:: python

        mixin = HostsMixin()
        ctx_hosts_data = mixin.ctx_hosts(scan, file, scanner)
        res_hosts_data = mixin.res_hosts(scan, scanner)
    """

    def ctx_hosts(self, scan: Scan, file: File, scanner: Scanner) -> list:
        """
        Get all hosts identified within the scan target.

        :param scan: The scan instance.
        :type scan: Scan
        :param file: The scan target.
        :type file: File
        :param scanner: The scanner instance.
        :type scanner: Scanner
        :return: A list of hosts.
        :rtype: list
        """
        data = namespace()
        data.hosts = Host.objects.filter(scan=scan, scanner=scanner)
        data.host_types = [str(x) for x in HostType]
        return data

    def res_hosts(self, scan: Scan, scanner: Scanner) -> list:
        """
        Get a serialized representation of hosts within the scan.

        :param scan: The scan instance.
        :type scan: Scan
        :param scanner: The scanner instance.
        :type scanner: Scanner
        :return: A list of serialized hosts.
        :rtype: list
        """
        data = Host.objects.filter(scan=scan, scanner=scanner)
        return HostSerializer(data, many=True).data


class ComponentsMixin:
    """Mixin class for working with components in a scan.

    This mixin provides methods for retrieving and manipulating components within
    a scan.

    Usage:
    ~~~~~~

    - Use ``ctx_components()`` to get components statistics and elements for a scan.
    - Use ``res_components()`` to get a serialized representation of components within the scan.

    Example:
    ~~~~~~~~

    .. code-block:: python

        mixin = ComponentsMixin()
        ctx_components_data = mixin.ctx_components(scan, file, scanner)
        res_components_data = mixin.res_components(scan, scanner)
    """

    def ctx_components(self, scan: Scan, file: File, scanner: Scanner):
        """
        Get components statistics and elements for a scan.

        :param scan: The scan instance.
        :type scan: Scan
        :param file: The scan target.
        :type file: File
        :param scanner: The scanner instance.
        :type scanner: Scanner
        :return: A namespace object containing component statistics and elements.
        """
        data = namespace(stats=Component.stats(scan))
        data.elements = Component.objects.filter(scanner=scanner)
        return data

    def res_hosts(self, scan: Scan, scanner: Scanner) -> list:
        """
        Get a serialized representation of components within the scan.

        :param scan: The scan instance.
        :type scan: Scan
        :param scanner: The scanner instance.
        :type scanner: Scanner
        :return: A list of serialized components.
        :rtype: list
        """
        data = Component.objects.filter(scanner=scanner)
        return ComponentSerializer(data, many=True).data
