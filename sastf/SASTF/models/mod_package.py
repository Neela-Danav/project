from django.db import models

from sastf.SASTF.utils.enum import Platform, PackageType, Relation, Severity

from .base import Project, TimedModel
from .mod_scan import Scanner

__all__ = ["Package", "PackageVulnerability", "Dependency"]


class Package(TimedModel):
    """A Django model that represents a software package."""

    package_uuid = models.UUIDField(max_length=36, primary_key=True)
    """The unique id for this package"""

    name = models.CharField(max_length=512, blank=True)
    """The name of the package."""

    artifact_id = models.CharField(max_length=512, blank=True)
    """The artifact ID of the package. (may be null)"""

    group_id = models.CharField(max_length=512, blank=True)
    """The group ID of the package. (may be null)"""

    package_type = models.CharField(
        default=PackageType.NONE, choices=PackageType.choices, max_length=256
    )
    """
    The type of the package. It is a string that should be one of the values from
    :class:`PackageType`.
    """

    platform = models.CharField(
        default=Platform.UNKNOWN, choices=Platform.choices, max_length=256
    )
    """
    The platform on which the package can be run. It is a string that should be one
    of the values from :class:`Platform`.
    """

    is_tracker = models.BooleanField(default=False)
    """Identifies this software package to be linked to tracking services."""

    description = models.TextField(blank=True)
    """A brief description for report generation."""

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["group_id", "artifact_id"],
                name="unique_package_groupid_artifactid",
            )
        ]


class PackageVulnerability(TimedModel):
    """A Django model that represents a vulnerability associated with a software package."""

    identifier = models.UUIDField(max_length=36, primary_key=True)
    """The universally unique identifier for the vulnerability."""

    cve_id = models.CharField(max_length=256, blank=True)
    """The Common Vulnerabilities and Exposures (CVE) identifier for the vulnerability."""

    package = models.ForeignKey(Package, on_delete=models.CASCADE)
    """The software package that is vulnerable."""

    version = models.CharField(max_length=512, blank=True)
    """The version of the software package that is vulnerable."""

    severity = models.CharField(
        max_length=32, choices=Severity.choices, default=Severity.NONE
    )
    """The severity of the vulnerability. It is a string that should be one of the values from."""


class Dependency(TimedModel):
    """Represents a dependency of a project on a software package."""

    dependency_uuid = models.CharField(max_length=72, primary_key=True)  # UUID*2
    """The dependency's uuid."""

    package = models.ForeignKey(Package, on_delete=models.SET_NULL, null=True)
    """The linked software package."""

    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    """The project this dependency belongs to."""

    relation = models.CharField(
        default=Relation.DIRECT, choices=Relation.choices, max_length=256
    )
    """The relation of this dependency (defaults to DIRECT). Not used yet."""

    scanner = models.ForeignKey(Scanner, models.CASCADE)
    """The scanner which found this dependency."""

    outdated = models.CharField(max_length=512, blank=True)
    """Indicates whether the package is outdated."""

    version = models.CharField(max_length=512, blank=True)
    """The extracted version number. (may be blank)"""

    license = models.CharField(max_length=256, blank=True)
    """Stores all extracted license information (comma spearated)"""

    def vulnerabilities(self):
        """Returns a generator that yields all vulnerabilities associated with the
        package of this dependency and its version.

        :return: a generator of vulnerabilities
        :rtype: Generator[PackageVulnerability, Any, None]
        """
        # Get all vulnerabilities associated with the package of this dependency
        vulnerabilities = PackageVulnerability.objects.filter(package=self.package)

        # Yield vulnerabilities that match this dependency's version exactly
        for vulnerability in vulnerabilities.filter(version=self.version):
            yield vulnerability

        for vulnerability in vulnerabilities.exclude(version=self.version):
            lower_bound, upper_bound = None, None

            # Extract lower and upper bounds from the version range
            if "-" in vulnerability.version:
                lower_bound, upper_bound = vulnerability.version.split("-")
            elif vulnerability.version.startswith("<"):
                lower_bound = self.version[1:].replace("=", "")
            elif vulnerability.version.startswith(">"):
                upper_bound = vulnerability.version[1:].replace("=", "")

            if (  # Check if this dependency's version matches the lower bound of the version range
                lower_bound is not None
                and ("=" in vulnerability.version and self.version >= lower_bound)
                or self.version > lower_bound
            ):
                yield vulnerability

            if (  # Check if this dependency's version matches the upper bound of the version range
                upper_bound is not None
                and ("=" in vulnerability.version and self.version <= upper_bound)
                or self.version < upper_bound
            ):
                yield vulnerability
