# This file is part of MAST-F's Frontend API
# Copyright (c) 2024 Mobile Application Security Testing Framework
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
__doc__ = """
Enum class definitions that can be used as choices within Django models
or as enum values. Note that all classes of this module inherit the
:class:`StringEnum` class, which acts as a string if you use special
methods like ``==``, ``!=``, ``str(x)`` and ``hash(x)``.
"""
import sys
import inspect

from enum import Enum


class StringEnum(Enum):
    """A custom enumeration that allows for the use of string values as enum members.

    It extends the built-in 'Enum' class in Python and overrides several methods
    to provide additional functionality. To use this class, simply inherit from the
    :class:`StringEnum` class and define class members with string values.

    For example:

    .. code-block:: python
        :linenos:
        :caption: enum.py

        class MyEnum(StringEnum):
            FOO = "foo"
            BAR = "bar"
            BAZ = "baz"

    You can then use the enum members like any other enum member, including comparing
    them with strings:

    >>> MyEnum.FOO == "foo"
    True
    >>> MyEnum.BAR != "qux"
    True
    >>> str(MyEnum.BAZ)
    'baz'

    Note that you can still use the usual comparison operators (``<``, ``<=``, ``>``,
    ``>=``) with StringEnum members, but they will be compared based on their order of
    definition in the class, not their string values.

    .. hint::
        You can use the class attribute ``choices`` within definitions of Django database
        models to restrict the amount of accepted values. Note also, that the static field
        won't be added if you place your enum in other files than ``/sastf/SASTF/utils/enum.py``.

        >>> MyEnum.choices
        [('foo', 'foo'), ('bar', 'bar'), ('baz', 'baz')]

    """

    def __eq__(self, __value: object) -> bool:
        if isinstance(__value, str):
            return __value == self.value
        return super().__eq__(__value)

    def __ne__(self, __value: object) -> bool:
        if isinstance(__value, str):
            return self.value != __value
        return super().__ne__(__value)

    def __str__(self) -> str:
        return self.value

    def __hash__(self) -> int:
        return hash(self.value)


class Role(StringEnum):
    """
    This class is an enumeration of different roles available to users within the
    context of the :class:`Account` model. The purpose of this class is to provide
    a way to link a user to a specific role.
    """

    ADMIN = "Admin"
    """
    All users with this role have access to all resources of the framework instance,
    they can add and delete existing users as well as teams.

    .. warning::
        If you are the only user (administrative) and try to delete your account
        with no other admin account present, the system will prevent removal. The
        same approach is applied if you want to remove your administrator priviledges
        from your account but being the only registered admin user.
    """

    REGULAR = "Regular"
    """Normal users can create, modify and delete teams, projects and bundles."""

    EXTERNAL = "External"
    """
    This role is still in development but is thought to be a restriction to users that
    should prevent them to access specific resources of this framework.
    """


class Severity(StringEnum):
    """
    This class is an enumeration of different severity levels that can be used to
    categorize vulnerabilities, findings, projects, bundles or scans. The purpose
    of this class is to provide a standardized and consistent way of categorizing
    issues based on their severity level.

    The Severity class can be used to categorize vulnerabilities and other models
    based on their severity level. For example, different classes use the this
    class to categorize reported vulnerabilities based on their severity level.
    """

    CRITICAL = "Critical"
    """
    Represents a critical severity level. It is typically used to indicate
    vulnerabilities that require immediate attention and could have severe
    consequences if left unresolved.
    """

    HIGH = "High"
    """
    Represents a high severity level. It is typically used to indicate vulnerabilities
    or API findings that are important and require attention, but are not as urgent or
    critical as critical findings.
    """

    MEDIUM = "Medium"
    """
    Represents a medium severity level. It is typically used to indicate issues that
    are less urgent than high or critical findings, but still require attention.
    """

    LOW = "Low"
    """
    Represents a low severity level. It is typically used to indicate findings that
    are minor and have a low impact on the system or user experience.
    """

    INFO = "Info"
    """
    Represents an information severity level. It is typically used on findigns that
    are not necessarily problems or bugs, but provide helpful information to users or
    developers.
    """

    SECURE = "Secure"
    """
    Represents a secure severity level. It is applied to findigns related to security
    or compliance.
    """

    NONE = "None"
    """
    Represents no severity level. This will be the default level applied to all
    categories that use a severity as their risk indicator. It can also be used
    to indicate that there is no severity level associated with a particular
    finding or vulnerability.
    """


class State(StringEnum):
    """
    Different states that can be used to track the status of a vulnerability or.
    The purpose of this class is to provide a regulated and consistent way of
    categorizing the state of a vulnerability.
    """

    TO_VERIFY = "To Verify"
    """
    Represents the state of a vulnerability that needs to be verified. It expresses
    that the vulnerability has been reported or detected, but it has not yet been
    confirmed to be valid.
    """

    CONFIRMED = "Confirmed"
    """
    Represents the state of a vulnerability that has been confirmed as a valid
    vulnerability. It indicates that the vulnerability has been validated and its
    existence has been confirmed.
    """

    URGENT = "Urgent"
    """
    Represents the state of a vulnerability that requires immediate attention. It
    implies that the vulnerability is critical and needs to be addressed urgently.

    .. hint:: Risk level
        Vulnerabilities annotated with an urgent state should be marked with
        ``CRITICAL`` as their severity level.
    """

    NOT_EXPLOITABLE = "Not Exploitable"
    """
    Mirrors the state of a vulnerability that is not exploitable. It marks the
    vulnerability to be reviewed and determined to be not exploitable.
    """

    PROPOSED_NOT_EXPLOITABLE = "Proposed not exploitable"
    """
    Represents the state of a vulnerability that is proposed to be not exploitable.
    It indicates that the vulnerability has been reviewed and a decision to classify
    it as not exploitable has been proposed.
    """


class Visibility(StringEnum):
    """
    This enum represents the different visibility options available for the
    :class:`Project` and :class:`Team` model. It is intended to provide a consistent
    approach to categorizing the visibility of a project or team.
    """

    PUBLIC = "Public"
    """
    Indicates that the project is publicly visible to everyone. This attribute should
    be used when a project is intended to be open and visible to all users.

    .. attention::
        Use this visibility level only if you want to make your project's or team's
        resources available to all other users.
    """

    PRIVATE = "Private"
    """
    Indicates that the project is not visible to everyone and is restricted to authorized
    users only. This attribute should be used when a project is intended to be kept
    confidential and not accessible to everyone.
    """

    INTERNAL = "Internal"
    """
    Implies that the project is visible only to users within the selected or team. This
    attribute should be used when a project is intended to be visible only to the internal
    team and not to the public.

    .. note::
        This visibility level may not be used for :class:`Team` objects.
    """


# TODO:(docs)
class InspectionType(StringEnum):
    SIMPLE = "Simple"
    ADVANCED = "Advanced"


class Platform(StringEnum):
    """
    The ``Platform`` enum provides options to indicate the platform on which a
    software package was published. Its use-case is to filter possible dependencies
    according to the used scan-target.
    """

    ANDROID = "Android"
    """
    Represents the Android platform. This attribute can be used to indicate that an
    identified package is designed to work on Android devices.
    """

    IOS = "iOS"
    """
    Represents the iOS platform. This attribute can be used to indicate that an
    identified package is designed to work on iOS devices.
    """

    UNKNOWN = "Undefined"
    """
    Represents an undefined or unknown platform. This attribute will be used as the
    default value for new packages and can also be used when the platform of a
    pcakge is unknown or cannot be determined.
    """


class PackageType(StringEnum):
    """
    Provides options to indicate the type of a software package published on a specific
    platform. It can be used to standardize and classify software packages based on their
    type.

    This enum is in the following context:

    .. code-block:: python
        :linenos:

        from sastf.SASTF.utils.enum import PackageType

        class Package(models.Model):
            name = models.CharField(max_length=...)
            type = models.CharField(choices=PackageType.choices, default=PackageType.NONE, max_length=20)
            ...

    In the above code snippet, the ``type`` field is set as a ``CharField`` with
    a maximum length of 20 and the available choices are taken from the ``PackageType``
    enum. This allows for easy and consistent specification of the package type. The
    attribute can also be used as a parameter in methods to filter results based on
    their package type.

    """

    GITHUB = "Github"
    """
    Represents a package published on Github. This attribute can be used to indicate that
    a software package is available on Github (may not be).
    """

    DART = "Dart"
    """
    Represents a Dart package. This attribute marks a software package to be developed using
    Dart programming language.
    """

    CORDOVA = "Cordova"
    """
    Represents a Cordova package. This attribute can be used to indicate that a software
    package is developed using Cordova framework.
    """

    FLUTTER = "Flutter"
    """
    Represents a Flutter package. This attribute is used on software packages that are
    developed using Flutter framework.
    """

    NATIVE = "Native"
    """
    Represents a native package. This attribute is used on software packages that are
    pre-compiled within the app (.so-files, MACH-O executables)
    """

    MAVEN = "Maven"
    """Represents a software package published on the Maven platform."""

    NONE = "None"
    """
    Represents a package with no specific type. This is used when the type of a package
    is unknown or does not belong to any of the other categories.
    """


class Relation(StringEnum):
    """
    Intended to be used to define the type of relation that a dependency has to
    its application.

    .. note::
        This feature is proposed and not implemented as of version ``0.0.1-alpha``.
    """

    TRANSITIVE = "Transitive"
    """
    Represents a transitive relationship between the dependency and the application. This
    attribute can be used to indicate that the dependency is not directly required by the
    application, but is instead required by another dependency.
    """

    DIRECT = "Direct"
    """
    Represents a direct relationship between the dependency and the application. This
    attribute illustrates that the dependency is directly required by the application.
    """


class HostType(StringEnum):
    """Intended to be used to categorize the type of connection an app has made."""

    INVALID = "Invalid"
    """Represents an invalid or erroneous connection."""

    TRACKER = "Tracker"
    """Represents a connection made to a tracking service."""

    MALWARE = "Malware"
    """Represents a connection made to a known malware domain."""

    OK = "Ok"
    """Represents a connection made to a safe and trusted domain."""

    NOT_SET = "Not Set"
    """
    Represents a connection for which the type has not been set or cannot
    be determined.
    """


class DataProtectionLevel(StringEnum):
    """
    Represents the different levels of data protection that can be applied to
    transmitted data.
    """

    PRIVATE = "Private"
    """Represents data that is intended to be kept private and confidential."""

    PUBLIC = "Public"
    """Represents data that can be freely shared with others."""


class ProtectionLevel(StringEnum):
    """
    The ProtectionLevel class represents different permission protection levels
    that are used in the Android permission system to protect user privacy and
    security. (`Android Protection Levels`_)

    .. _android protection levels: https://developer.android.com/reference/android/R.attr#protectionLevel
    """

    APP_PREDICTOR = "AppPredictor"
    """Used for permissions that are granted to app prediction services."""

    APPOP = "Appop"
    """Used for permissions that are granted to AppOps services."""

    COMPANION = "Companion"
    """Used for permissions that are granted to companion devices."""

    CONFIGURATOR = "Configurator"
    """Used for permissions that are granted to app configurator services."""

    DANGEROUS = "Dangerous"
    """Used for dangerous permissions that have to be approved by a user."""

    DEVELOPMENT = "Development"
    """Used for permissions that are granted to development tools and features."""

    INCIDENTREPORTAPPROVER = "IncidentReportApprover"
    """Used for permissions that are granted to incident report approver services."""

    INSTALLER = "Installer"
    """Used for permissions that are granted to app installer services."""

    INSTANT = "Instant"
    """Used for permissions that are granted to instant apps."""

    INTERNAL = "Internal"
    """Used for permissions that are granted to internal system components and apps."""

    KNOWNSIGNER = "KnownSigner"
    """Used for permissions that are granted to apps signed with a known signature."""

    MODULE = "Module"
    """Used for permissions that are granted to dynamic feature modules."""

    NORMAL = "Normal"
    """Used for normal permissions that don't pose a significant risk to user privacy and security."""

    OEM = "OEM"
    """Used for permissions that are granted to OEM-specific apps and features."""

    PRE23 = "Pre23"
    """Used for permissions that were introduced in Android 6.0 (API level 23) or earlier."""

    PREINSTALLED = "Preinstalled"
    """Used for permissions that are granted to preinstalled system apps."""

    PRIVILEGED = "Privileged"
    """Used for permissions that are granted to privileged system apps."""

    RECENTS = "Recents"
    """Used for permissions that are granted to the recents screen."""

    RETAILDEMO = "RetailDemo"
    """Used for permissions that are granted to retail demo apps."""

    ROLE = "Role"
    """Used for permissions that are granted to app roles."""

    RUNTIME = "Runtime"
    """Used for permissions that are granted at runtime."""

    SETUP = "Setup"
    """Used for permissions that are granted to setup services."""

    SIGNATURE = "Signature"
    """
    A permission that the system is to grant only if the requesting application
    is signed with the same certificate as the application that declared the
    permission.
    """

    SIGNATUREORSYSTEM = "SignatureOrSystem"
    """Old synonym for ``signature|privileged``. Deprecated in API level 23."""

    SYSTEM = "System"
    """Used for permissions that are granted to system components."""

    TEXTCLASSIFIER = "TextClassifier"
    """Used for permissions that are granted to text classification services."""

    VENDORPRIVILEGED = "VendorPrivileged"
    """Used for permissions that are granted to vendor-specific apps and features."""

    VERIFIER = "Verifier"
    """Used for permissions that are granted to package verifier services."""

    @staticmethod
    def colors() -> dict:
        """Returns protection levels categorized into three groups.

        :return: categorized protection level groups.
        :rtype: dict
        """
        return {
            "green": (
                ProtectionLevel.SIGNATURE,
                ProtectionLevel.SIGNATUREORSYSTEM,
                ProtectionLevel.KNOWNSIGNER,
                ProtectionLevel.RUNTIME,
                ProtectionLevel.DEVELOPMENT,
                ProtectionLevel.PREINSTALLED,
            ),
            "red": (
                ProtectionLevel.DANGEROUS,
                ProtectionLevel.SYSTEM,
                ProtectionLevel.OEM,
                ProtectionLevel.PRIVILEGED,
                ProtectionLevel.VENDORPRIVILEGED,
            ),
            "azure": (
                ProtectionLevel.NORMAL,
                ProtectionLevel.COMPANION,
                ProtectionLevel.CONFIGURATOR,
                ProtectionLevel.PRE23,
            ),
        }


class ComponentCategory(StringEnum):
    ACTIVITY = "Activity"
    SERVICE = "Service"
    RECEIVER = "Receiver"
    PROVIDER = "Provider"
    APPLICATION = "Application"


# Small workaround to set an additional static attribute for Django models
def isstringenum(member) -> bool:
    return (
        inspect.isclass(member)
        and issubclass(member, StringEnum)
        and member.__name__ != "StringEnum"
    )


mod = sys.modules[__name__]
for _, clazz in inspect.getmembers(mod, isstringenum):
    setattr(clazz, "choices", [(str(x), str(x)) for x in clazz])
