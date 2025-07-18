from django import forms

from sastf.SASTF.models import Package, Project, Scanner

from .base import ModelField

__all__ = ["PackageForm", "PackageVulnerabilityForm", "DependencyForm"]


class PackageForm(forms.Form):
    name = forms.CharField(max_length=512, required=True)
    artifact_id = forms.CharField(max_length=512, required=False)
    group_id = forms.CharField(max_length=512, required=False)
    package_type = forms.CharField(max_length=256, required=True)
    platform = forms.CharField(max_length=256, required=True)


class PackageVulnerabilityForm(forms.Form):
    cve_id = forms.CharField(max_length=256, required=True)
    package = ModelField(Package, max_length=72, required=True)
    version = forms.CharField(max_length=512, required=True)
    severity = forms.CharField(max_length=32, required=False)


class DependencyForm(forms.Form):
    package = ModelField(Package, max_length=36, required=True)
    project = ModelField(Project, max_length=256, required=True)
    relation = forms.CharField(
        max_length=256, required=False
    )  # maybe add enum validator
    scanner = ModelField(Scanner, max_length=256, required=True)
    outdated = forms.CharField(max_length=512, required=False)
    version = forms.CharField(max_length=512, required=False)
    license = forms.CharField(max_length=256, required=False)
