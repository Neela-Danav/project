from uuid import uuid4
from django.db import models

from sastf.SASTF.utils.enum import ProtectionLevel

from .mod_finding import AbstractBaseFinding, DataFlowItem
from .base import TimedModel

__all__ = ["AppPermission", "PermissionFinding"]


class AppPermission(TimedModel):
    """Represents an application permission with its related attributes."""

    PROTECTION_LEVEL_SEPARATOR = ","

    permission_uuid = models.UUIDField(primary_key=True)
    """The unique ID of the permission."""

    identifier = models.CharField(max_length=256, null=False, unique=True)
    """The string identifier of the permission.

    .. hint::
        While Android permission identifiers start with something like ``android.permission``,
        Apple's permission strings does not contain a package name. To emulate that, a custom
        package name will be added: ``!apple.permission``.
    """

    name = models.CharField(max_length=256, blank=True)
    """The name of the permission. Can be null."""

    protection_level = models.TextField(blank=True)
    """The protection level of the permission. Can be empty."""

    dangerous = models.BooleanField(default=False)
    """A flag indicating whether the permission is dangerous or not."""

    group = models.CharField(max_length=256, blank=True)
    """The group to which the permission belongs. Can be null."""

    short_description = models.CharField(max_length=256, blank=True)
    """A short description of the permission. Can be empty."""

    description = models.TextField(blank=True)
    """A full description of the permission."""

    risk = models.TextField(blank=True)
    """The risk associated with the permission. Can be empty."""

    @property
    def plevel_status(self) -> dict:
        """
        Get a dictionary that maps the protection levels of the permission to
        their respective color codes.

        :return: A dictionary that maps the protection levels of the permission
                 to their respective color codes.
        :rtype: dict
        """
        plevel = {}
        colors = ProtectionLevel.colors()
        for level in self.protection_level.split(
            AppPermission.PROTECTION_LEVEL_SEPARATOR
        ):
            found = False
            level = str(level).capitalize()
            for color, values in colors.items():
                if level in values:
                    plevel[level] = color
                    found = True
                    break

            if not found:
                plevel[level] = "secondary"
        return plevel

    @staticmethod
    def create_unknown(identifier, protection_level) -> "AppPermission":
        """Create an :class:`AppPermission` instance for an unknown permission.

        :param identifier: The string identifier of the permission.
        :type identifier: str
        :param protection_level: The protection level of the permission.
        :type protection_level: str
        :return: An :class:`AppPermission` instance for the unknown permission.
        :rtype: AppPermission
        """
        return AppPermission.objects.create(
            pk=uuid4(),
            identifier=identifier,
            name=identifier.split(".")[-1].lower().capitalize(),
            protection_level=protection_level,
            dangerous="dangerous" in str(protection_level).lower(),
            short_description="Dynamic generated description. Please edit the short and long description"
            "in the plugins-context of your MAST-F Instance.",
        )


class PermissionFinding(AbstractBaseFinding):
    """The PermissionFinding class is a model class that represents a finding for a permission."""

    permission = models.ForeignKey(AppPermission, null=True, on_delete=models.SET_NULL)
    """A foreign key that associates a permission with a finding."""
