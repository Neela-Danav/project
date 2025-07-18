__doc__ = """


.. code-block:: python
    :caption: converters.py

    # [...]
    class MyIDConverter(StringConverter):
        regex = r"some-value-\\d{4}"
    # [...]

In URL definitions we can access this newly defined converter by using
its class name:

.. code-block:: python
    :caption: urls.py

    urlpatterns = [
        # The name must be lower-case and without 'converter' at the end
        path("/some/path/<myid:pk>", MyModelView.as_view(), name=...),
    ]
"""
import inspect
import sys


class StringConverter:
    """Base class for string-based converters."""

    def to_python(self, value: str) -> str:
        return value

    def to_url(self, value: str) -> str:
        return value


class FindingTemplateIDConverter(StringConverter):
    regex = r"FT-[\w-]{36}-[\w-]{36}"


class VulnerabilityIDConverter(StringConverter):
    regex = r"SV-[\w-]{36}-[\w-]{36}"


class FindingIDConverter(StringConverter):
    regex = r"SF-[\w-]{36}-[\w-]{36}"


class MD5Converter(StringConverter):
    regex = r"[0-9a-fA-F]{32}"


class HostIDConverter(StringConverter):
    regex = r"hst_[\dA-Za-z-]{36}"


class ComponentIdConverter(StringConverter):
    regex = r"cpt_[\dA-Za-z-]{36}"


class DependencyIdConverter(StringConverter):
    regex = r"([0-9a-fA-F]{32}){2}"


def listconverters() -> dict:
    """Returns all converters of this module.

    The mapped name will be the class name transformed to lower
    case and with the ``"converter"`` extra removed.

    :return: a dictionary storing all registered converter classes
    :rtype: dict
    """
    mod = sys.modules[__name__]
    members = inspect.getmembers(mod, inspect.isclass)

    conv = {}
    for name, clazz in members:
        if issubclass(clazz, StringConverter) and clazz != StringConverter:
            name = name.lower().replace("converter", "")
            conv[name] = clazz

    return conv
