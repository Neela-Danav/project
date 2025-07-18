import logging

from django import forms
from django.db.models import Model
from django.contrib.auth.models import User

from sastf.SASTF.models import Project
from sastf.SASTF.settings import SASTF_PASSWD_MIN_LEN, SASTF_USERNAME_MIN_LEN

__all__ = [
    "ModelField",
    "RegistrationForm",
    "ProjectCreationForm",
    "AppPermissionForm",
    "TeamForm",
    "ManyToManyField",
    "BundleForm",
    "ChangePasswordForm",
    "EditTeamMembersForm",
    "SetupForm",
]

logger = logging.getLogger(__name__)


class ModelField(forms.CharField):
    """To apply foreign-key references, just use the ``ModelField``.

    >>> class ExampleForm(forms.Form):
    ...    user = ModelField(User, mapper=int)
    >>> # The cleaned data will store the referenced User instance
    >>> POST = {'user': "1"}
    >>> form = ExampleForm(POST)
    >>> if form.is_valid():
    ...     cleaned = form.cleaned_data
    ...     user = cleaned['user']
    ...     print(user.username)

    :param model: The Django model class
    :type model: class<? extends ``Model``>
    :param field_name: The field name to query
    :type field_name: str
    :param mapper: A conversion function to optionally convert input key
    :type mapper: Callable[T, [str]]
    """

    def __init__(self, model, field_name="pk", mapper=None, **kwargs) -> None:
        super().__init__(**kwargs)
        self.model = model
        self.field_name = field_name
        self.converter = mapper

    def clean(self, value) -> object:
        if not value:
            return None

        raw_value = super().clean(value)
        try:
            value = self.converter(raw_value) if self.converter else raw_value
        except Exception as err:
            logger.error(
                "ModelField::Converter - Error converting value, using raw value instead: %s",
                str(err),
            )
            value = raw_value

        try:
            queryset = self.model.objects.get(**{self.field_name: value})
        except (Model.DoesNotExist, Model.MultipleObjectsReturned):
            logger.error(
                "RefError: Model=%s, Target-Key=%s, Target=%s",
                self.model,
                self.field_name,
                value,
            )
            raise forms.ValidationError(
                "This field must be a reference to an existing model", code="required"
            )

        return queryset


class ManyToManyField(forms.CharField):
    """Implementation of a Many-To-Many relation for Django forms.

    This class aims to enhance the capabilities of Django forms by
    providing a way to include Many-To-Many relationships. This
    field is represented by a string that cancatenates the primary
    keys of the referenced objects.

    This field may be used within a form class to specify a Many-To-Many
    relationship:

    .. code-block:: python
        :linenos:

        class AuthorForm(forms.Form):
            books = ManyToManyField(Book, mapper=int, required=False)
            name = forms.CharField(max_length=50, required=True)

    The cleaned data of the previously defined form would contain all
    ``Book`` objects that have been referenced in the request. Note that
    we have to provide a mapping function to convert the string values
    to integer primary keys.

    For instance, the following code uses the form to retrieve all
    ``Book`` objects that are needed:

    .. code-block:: python
        :linenos:

        POST = {"name": "Foo", "books": "1,2,3,4"}
        form = AuthorForm(data=POST)
        if form.is_valid():
            data = form.cleaned_data
            # The returned value is a list storing all referenced
            # Book objects.
            books = data.pop('books')


    :param model: The Django model class
    :type model: class<? extends ``Model``>
    :param delimiter: The string delimiter to use when splitting the
                      input string
    :type delimiter: str
    :param field_name: The field name to query
    :type field_name: str
    :param mapper: A conversion function to optionally convert input keys
    :type mapper: Callable[T, [str]]
    """

    def __init__(
        self, model, field_name="pk", delimiter: str = ",", mapper=None, **kwargs
    ) -> None:
        super().__init__(**kwargs)
        self.model = model
        self.delimiter = delimiter or ","
        self.field_name = field_name
        self.converter = mapper

    def clean(self, value: str) -> list:
        if not value:
            return []

        values = value.split(self.delimiter)
        elements = []
        for raw_id in values:
            objid = self.convert_id(raw_id)
            try:
                elements.append(self.model.objects.get(**{self.field_name: objid}))
            except (Model.DoesNotExist, Model.MultipleObjectsReturned):
                logger.debug(
                    "ManyToManyField::Query - Model=%s, Target-Key=%s, Target=%s - Could not resolve object",
                    self.model,
                    self.field_name,
                    objid,
                )

        return elements

    def convert_id(self, raw_id):
        """Converts the given raw id - by default, it returns the raw id"""
        if not self.converter:
            return raw_id
        return self.converter(raw_id)


class RegistrationForm(forms.Form):
    """Simple form used to register new users"""

    username = forms.CharField(
        max_length=256, min_length=SASTF_USERNAME_MIN_LEN, required=True
    )
    """The username which has to be unique"""

    password = forms.CharField(
        max_length=256, min_length=SASTF_PASSWD_MIN_LEN, required=True
    )
    """The minimum password length will be defined by ``SASTF_PASSWD_MIN_LEN``."""

    role = forms.CharField(max_length=32, required=False)


class ChangePasswordForm(forms.Form):
    password = forms.CharField(required=True)


class ProjectCreationForm(forms.Form):
    """Simple form to create new projects"""

    name = forms.CharField(max_length=256, required=True)
    tags = forms.CharField(max_length=4096, required=False)
    visibility = forms.CharField(max_length=32, required=True)
    risk_level = forms.CharField(max_length=16, required=True)
    inspection_type = forms.CharField(max_length=32, required=True)
    team_name = forms.CharField(max_length=256, required=False)


class AppPermissionForm(forms.Form):
    """Form used to create and update app permissions"""

    identifier = forms.CharField(max_length=256, required=True)
    name = forms.CharField(max_length=256, required=True)
    protection_level = forms.CharField(max_length=256, required=True)
    dangerous = forms.BooleanField(required=False, initial=False)
    group = forms.CharField(max_length=256, required=False)

    short_description = forms.CharField(max_length=256, required=True)
    description = forms.CharField(required=False)
    risk = forms.CharField(required=False)


class TeamForm(forms.Form):
    name = forms.CharField(max_length=256, required=True)
    owner = ModelField(User, max_length=256, mapper=int)
    users = ManyToManyField(User, mapper=int, required=False)


class EditTeamMembersForm(forms.Form):
    users = ManyToManyField(User, mapper=int)


class BundleForm(forms.Form):
    name = forms.CharField(max_length=256, required=True)
    tags = forms.CharField(required=False)
    risk_level = forms.CharField(max_length=32, required=False)
    projects = ManyToManyField(Project, required=False)


class SetupForm(forms.Form):
    username = forms.CharField(
        max_length=256, min_length=SASTF_USERNAME_MIN_LEN, required=True
    )
    """The username which has to be unique"""

    password = forms.CharField(
        max_length=256, min_length=SASTF_PASSWD_MIN_LEN, required=True
    )
    """The minimum password length will be defined by ``SASTF_PASSWD_MIN_LEN``."""

    # Here is space for more configuration elements
