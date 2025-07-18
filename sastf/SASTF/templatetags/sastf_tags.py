from django import template
from datetime import date
from time import mktime

from sastf.SASTF.models import AbstractBaseFinding, PackageVulnerability
from sastf.SASTF.mixins import VulnContextMixin
from sastf.SASTF.utils.enum import ComponentCategory

register = template.Library()


@register.filter(name="split")
def split(value: str, key: str) -> list:
    """
    Returns the value turned into a list.
    """
    return value.split(key) if value else []


@register.filter(name="vuln_stats")
def vuln_stats(value):
    mixin = VulnContextMixin()
    data = {}

    mixin.apply_vuln_context(
        data, AbstractBaseFinding.stats(PackageVulnerability, base=list(value))
    )
    return data


@register.filter(name="component_color")
def component_color(category) -> str:
    if category == ComponentCategory.ACTIVITY:
        return "green"
    elif category == ComponentCategory.PROVIDER:
        return "red"
    elif category == ComponentCategory.SERVICE:
        return "yellow"
    elif category == ComponentCategory.RECEIVER:
        return "orange"

    return "secondary"


@register.filter(name="timestamp")
def timestamp(obj: date):
    obj = obj or date.today()

    return mktime(obj.timetuple()) * 1000


@register.filter(name="render_code")
def render_code(text: str) -> str:
    output = ""
    count = 0

    for char in text:
        if char == "`":
            output = "%s<%skbd>" % (output, "/" if count % 2 != 0 else "")
            count += 1
        else:
            output = "".join([output, char])

    return output
