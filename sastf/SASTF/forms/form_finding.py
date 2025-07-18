from django import forms

from sastf.SASTF.models import Scan, FindingTemplate, Scanner, Component
from sastf.SASTF.utils.enum import ComponentCategory
from sastf.SASTF.rest.permissions import CanEditScanAsField

from .base import ModelField

__all__ = [
    "FindingTemplateForm",
    "AbstractFindingForm",
    "FindingForm",
    "VulnerabilityForm",
    "ComponentForm",
]


class FindingTemplateForm(forms.Form):
    title = forms.CharField(max_length=256, required=True)
    severity = forms.CharField(max_length=256, required=False)
    # The next two fields won't get a length maximum
    description = forms.CharField(required=False)
    risk = forms.CharField(required=False)
    mitigation = forms.CharField(required=False)


class AbstractFindingForm(forms.Form):
    scan = ModelField(Scan, max_length=256, required=True)
    language = forms.CharField(max_length=256, required=False)
    severity = forms.CharField(max_length=32, required=True)
    source_file = forms.CharField(max_length=512, required=True)
    source_line = forms.CharField(max_length=512, required=False)
    scanner = ModelField(Scanner, max_length=256, required=True)
    template = ModelField(FindingTemplate, max_length=256, required=True)

    class Meta:
        abstract = True


class FindingForm(AbstractFindingForm):
    is_custom = forms.BooleanField(required=False)


class VulnerabilityForm(AbstractFindingForm):
    state = forms.CharField(max_length=256, required=True)


class ComponentForm(forms.Form):
    scanner = ModelField(Scanner, required=True)
    name = forms.CharField(max_length=2048, required=True)
    is_protected = forms.BooleanField(required=False)
    is_exported = forms.BooleanField(required=False)
    category = forms.ChoiceField(choices=ComponentCategory.choices, required=True)
