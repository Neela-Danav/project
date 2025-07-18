import datetime
import logging
import json

from django.db import models
from django.contrib.auth.models import User

from sastf.SASTF.utils.enum import Severity

from .base import Project, File, Team, TimedModel

__all__ = [
    "Scan",
    "Scanner",
    "ScanTask",
    "Details",
    "Certificate",
    "DeveloperInfo",
    "StoreInfo",
]

logger = logging.getLogger(__name__)


class Scan(TimedModel):
    """Describes a static app scan."""

    scan_uuid = models.CharField(primary_key=True, max_length=256)
    """Stores the identifier for this scan."""

    origin = models.CharField(blank=True, max_length=32)
    """Stores the scan origin of the scan. The origin can point to the following values:

        - Play-Store
        - iOS-App-Store
        - APKPure
        - File
        - ...
    """

    source = models.CharField(blank=True, max_length=256)
    """Stores the file source.

    The source of an uploaded file can be one of the following:
    - URL: An URL was given from where the file was downloaded
    - File: Simple file upload
    """

    file = models.ForeignKey(File, on_delete=models.CASCADE, null=True)
    """Stores a relation to the file to scan."""

    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    """The project of this scan"""

    scan_type = models.CharField(blank=True, max_length=50)
    """Stores the name of the scan type"""

    start_date = models.DateField(default=datetime.datetime.now)
    """Stores the start time of this scan"""

    end_date = models.DateField(null=True)
    """Stores the ent datetime of the scan"""

    status = models.CharField(blank=True, max_length=256)
    """Stores information about the current scan's status"""

    risk_level = models.CharField(
        default=Severity.NONE, choices=Severity.choices, max_length=256
    )
    """Stores the classification (LOW, MEDIUM, HIGH)"""

    initiator = models.ForeignKey(User, on_delete=models.CASCADE)
    """Stores the user that has started the scan"""

    is_active = models.BooleanField(default=False)
    """Simple property used to indicate whether the scan is stil busy."""

    finished = models.BooleanField(default=False)
    """Property to determine whether this scan has finished."""

    @staticmethod
    def last_scan(project: Project = None, initiator: User = None):
        """Returns the last scan that was started by the provided user or within the given project.

        :param project: the project the last scan has been started in, defaults to None
        :type project: Project, optional
        :param initiator: the initiator of the last scan, defaults to None
        :type initiator: User, optional
        :return: the last scan instance or None
        :rtype: Scan
        """
        scans = Scan.objects.order_by("start_date")
        if project:
            scans = scans.filter(project=project)

        if initiator:
            scans = scans.filter(initiator=initiator)

        if not project and not initiator:
            scans = []  # !important: we don't want users to access unknown scans

        return scans[0] if len(scans) > 0 else None

    @staticmethod
    def files(
        project: Project = None, initiator: User = None, team: Team = None
    ) -> list:
        """Returns a list of files that have been saved by a given user or within the provided project.

        :param project: the project, defaults to None
        :type project: Project, optional
        :param initiator: the initiator of target scans, defaults to None
        :type initiator: User, optional
        :return: a list of uploaded files
        :rtype: list
        """
        scans = Scan.objects.all()
        if project:
            scans = scans.filter(project=project)

        if initiator:
            scans = scans.filter(initiator=initiator)

        if team:
            scans = scans.filter(project__team=team)

        if not project and not team and not initiator:
            return []  # !important: we don't want users to access unknown files

        return [x.file for x in scans]


class Scanner(TimedModel):
    """Simple model to map selected scanners to a scan."""

    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, null=True)
    """Stores a relation to the scan this scanner is used in."""

    name = models.CharField(max_length=256, null=False)
    """Stores a name of the plugin to use."""

    @staticmethod
    def names(project: Project) -> list:
        """Returns a list of names of scanners that are assigned to a project.

        :param project: the target project
        :type project: Project
        :return: a list of selected scanners (only names)
        :rtype: list
        """
        return list(
            set([x.name for x in Scanner.objects.filter(scan__project=project)])
        )


class ScanTask(TimedModel):
    """Represents a task for internal scans.

    .. note::
        This model is introduced to enable multiple web instances being able to
        handle task-specific requests.
    """

    task_uuid = models.UUIDField(max_length=32, primary_key=True, null=False)
    """
    The UUID field with a maximum length of 32 characters is set as the primary key of
    the model.
    """

    scan = models.ForeignKey(Scan, models.CASCADE)
    """
    A foreign key to the :class:`Scan` model, with the ``CASCADE`` option to ensure
    that when a :class:`Scan` object is deleted, all related ``ScanTask`` objects are
    also deleted.
    """

    scanner = models.ForeignKey(Scanner, models.CASCADE, null=True)
    """
    A foreign key to the :class:`Scanner` model, with the ``CASCADE`` option and
    able to allow null values.
    """

    name = models.CharField(max_length=256, blank=True)
    """The task's name (primarily used in HTML representation)"""

    celery_id = models.CharField(max_length=256, blank=True, null=True)
    """The assigned celery id (may be null on creation)."""

    active = models.BooleanField(default=True)
    """Indicates whether the :class:`ScanTask` object is currently active."""

    @staticmethod
    def active_tasks(scan: Scan = None, project: Project = None) -> list:
        """A static method that returns a list of active :class:`ScanTask` objects.

         It takes two optional parameters: scan and project. If scan is provided, it
         returns a list of active ScanTask objects associated with that :class:`Scan`
         object. If project is provided, it returns a list of active ScanTask objects
         associated with :class:`Scan` objects that belong to that :class:`Project`
         object. If neither parameter is provided, an empty list is returned.

        :param scan: the target scan, defaults to None
        :type scan: :class:`Scan`, optional
        :param project: the target project, defaults to None
        :type project: :class:`Project`, optional
        :return: a list of active scans
        :rtype: list
        """
        if scan:
            return list(ScanTask.objects.filter(active=True, scan=scan))

        if project:
            return list(ScanTask.objects.filter(active=True, scan__project=project))
        return []

    @staticmethod
    def finish_scan(scan: Scan, task: "ScanTask") -> None:
        """
        This method is used to finish a scan by setting the ``is_active`` attribute of
        the corresponding Scan object to False when all related ScanTask objects have
        completed.
        """
        tasks = ScanTask.active_tasks(scan)
        if len(tasks) == 0 or (len(tasks) == 1 and tasks[0] == task):
            scan.is_active = False
            scan.status = "Done"  # TODO: change to enum value
            scan.save()


# -- Scan Details ------------------------------------------------------------
class Certificate(TimedModel):
    """Represents an identified certificate.

    The :class:`Details` is designed to store multiple certificate instances as
    each app may contain more than one certificates. We don't specify the scan
    reference directly as it will be created in a many-to-many relationship.

    :ivar details: A list of :class:`Details` objects this certificate was found in
    :type details: ``ManyToManyField``
    """

    version = models.CharField(max_length=12, blank=True)
    """Indicates whether the APK is signed using APK signature scheme version X.

    Note that version values are stored in the format ``vX`` where ``X`` represents the
    version number. In addition, a higher version number declares lower signature schemes
    impicitly.
    """

    sha1 = models.CharField(max_length=255, blank=True)
    """The sha1 fingerprint"""

    sha256 = models.CharField(max_length=255, blank=True)
    """The sha256 fingerprint"""

    issuer = models.TextField(blank=True)
    """Human readable certificate issuer."""

    subject = models.TextField(blank=True)
    """Human readable subject."""

    hash_algorithm = models.TextField(blank=True)
    """Describes the used hashing algorithm"""

    signature_algorithm = models.TextField(blank=True)
    """The used signature algorithm."""

    serial_number = models.TextField(blank=True)
    """If present, the serial number will be stored in a ``TextField``."""


class DeveloperInfo(TimedModel):
    """Model representing developer information."""

    developer_id = models.CharField(primary_key=True, max_length=512)
    """Unique ID for each developer."""

    name = models.CharField(max_length=512, blank=True)
    """Name of the devloper (mostly the company's name)"""

    email = models.EmailField(blank=True)
    """Email address of the developer"""

    website = models.URLField(blank=True)
    """Website URL of the developer"""

    address = models.CharField(max_length=512, blank=True)
    """Email address of the developer"""


class StoreInfo(TimedModel):
    """Model storing information about the app available at the platform's app-store."""

    store_name = models.CharField(max_length=32, blank=True)
    app_id = models.CharField(max_length=512, blank=True)

    title = models.CharField(max_length=256, blank=True)
    score = models.FloatField(default=0.0)
    installs = models.CharField(max_length=128, blank=True, default="0")
    price = models.CharField(max_length=256, blank=True)
    url = models.URLField(blank=True)
    release_date = models.CharField(max_length=256, blank=True)
    developer = models.ForeignKey(DeveloperInfo, on_delete=models.SET_NULL, null=True)
    description = models.TextField(blank=True)


class Details(TimedModel):  # TODO
    scan = models.ForeignKey(Scan, models.CASCADE, null=True)
    file = models.ForeignKey(File, models.CASCADE, null=True)
    cvss = models.FloatField(default=0)
    icon = models.CharField(max_length=1024, blank=True)
    tracker_count = models.IntegerField(default=0)

    app_name = models.CharField(max_length=512, blank=True)
    app_id = models.CharField(max_length=512, blank=True)
    app_version = models.CharField(max_length=512, blank=True)

    target_sdk = models.CharField(max_length=32, blank=True)
    store_info = models.ForeignKey(StoreInfo, on_delete=models.SET_NULL, null=True)

    # Many-To-Many relationships here
    certificates = models.ManyToManyField(Certificate, related_name="details")
