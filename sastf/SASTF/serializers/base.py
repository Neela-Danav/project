import logging

from django.contrib.auth.models import User, Permission
from django.db.models import Manager, Model

from rest_framework import serializers
from rest_framework.fields import empty

from sastf.SASTF.permissions import BoundPermission, CanEditTeam
from sastf.SASTF.models import Project, Team, Bundle, Account, Environment

__all__ = [
    "UserSerializer",
    "TeamSerializer",
    "ProjectSerializer",
    "ManyToManyField",
    "ManyToManySerializer",
    "BundleSerializer",
    "AccountSerializer",
    "EnvironmentSerializer",
]

logger = logging.getLogger(__name__)


class ManyToManyField(serializers.Field):
    """ """

    def __init__(
        self, model, field_name="pk", delimiter: str = ",", mapper=None, **kwargs
    ) -> None:
        super().__init__(**kwargs)
        self.model = model
        self.delimiter = delimiter or ","
        self.pk_name = field_name or "pk"
        self.converter = mapper or str

    def to_internal_value(self, data: str) -> tuple:
        """Transform the *incoming* primitive data into a native value."""
        values = (
            str(data).split(self.delimiter)
            if not isinstance(data, (list, tuple))
            else data
        )

        elements = []
        append = True
        for objid in values:
            if isinstance(objid, self.model):
                elements.append(objid)
                continue

            if objid == "$set":
                append = False

            element_id = objid if not self.converter else self.converter(objid)
            try:
                elements.append(self.model.objects.get(**{self.pk_name: element_id}))
            except (Model.DoesNotExist, Model.MultipleObjectsReturned):
                logger.debug(
                    f'Could not resolve objID: "{objid}" and name: "{self.field_name}"'
                )

        return elements, append

    def to_representation(self, value: list):
        """Transform the *outgoing* native value into primitive data."""
        if isinstance(value, str) or not value:
            return str(value)

        if isinstance(value, Manager):
            value = value.all()

        key = self.pk_name or "pk"
        return [str(getattr(x, key)) for x in value]


class ManyToManySerializer(serializers.ModelSerializer):
    """ """

    rel_fields = None
    """The fields related to a many-to-many relationship."""

    bound_permissions = None

    def update(self, instance, validated_data):
        if self.rel_fields and isinstance(self.rel_fields, (list, tuple)):
            for field_name in self.rel_fields:
                if field_name not in validated_data:
                    continue
                try:
                    # Many-To-Many relationships are represented by a Manager
                    # instance internally.
                    manager = getattr(instance, field_name)
                    elements, append = validated_data.pop(field_name)
                    if append:
                        manager.add(*elements)
                    else:
                        self._remove_permissions(instance, manager, elements)
                        manager.set(*elements)
                except KeyError:
                    logger.debug(
                        '(%s) Could not find field ("%s") in class: "%s"',
                        self.__class__,
                        field_name,
                        instance.__class__,
                    )

        return super().update(instance, validated_data)

    def _remove_permissions(self, instance, manager, elements):
        current = manager.all()
        diff = set(current) - set(elements)

        for permission in self.bound_permissions or []:
            assert isinstance(
                permission, BoundPermission
            ), f"The given permission object must be a BoundPermission! (Got: {permission})"
            for element in diff:
                # Currently only user elements will be affected from this change
                if isinstance(element, User):
                    permission.remove_from(element, instance)


class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = "__all__"


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["username", "email", "groups", "date_joined", "user_permissions"]


class TeamSerializer(ManyToManySerializer):
    rel_fields = ["users"]
    users = ManyToManyField(User)

    class Meta:
        model = Team
        fields = "__all__"


class ProjectSerializer(serializers.ModelSerializer):
    class Meta:
        model = Project
        fields = "__all__"


class BundleSerializer(ManyToManySerializer):
    rel_fields = ["projects"]
    projects = ManyToManyField(Project)
    bound_permissions = [CanEditTeam]

    class Meta:
        model = Bundle
        fields = "__all__"


class AccountSerializer(serializers.ModelSerializer):
    user = UserSerializer(many=False)

    class Meta:
        model = Account
        fields = "__all__"


class EnvironmentSerializer(serializers.ModelSerializer):
    class Meta:
        fields = "__all__"
        model = Environment
