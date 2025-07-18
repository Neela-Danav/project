from django import forms

from sastf.SASTF.models import Host, HostTemplate, Snippet, Scanner

from .base import ModelField, ManyToManyField

__all__ = [
    "CipherSuiteForm",
    "TLSForm",
    "DataCollectionGroupForm",
    "HostForm",
    "HostTemplateForm",
]


class CipherSuiteForm(forms.Form):
    hosts = ManyToManyField(Host, max_length=256, required=False)
    name = forms.CharField(max_length=256, required=True)
    recommended = forms.BooleanField(required=False)


class TLSForm(forms.Form):
    hosts = ManyToManyField(Host, max_length=256, required=False)
    name = forms.CharField(max_length=256, required=True)
    recommended = forms.BooleanField(required=False)


class DataCollectionGroupForm(forms.Form):
    hosts = ManyToManyField(Host, max_length=256, required=False)
    group = forms.CharField(max_length=256, required=True)
    protection_level = forms.CharField(max_length=256, required=False)


class HostForm(forms.Form):
    scanner = ModelField(Scanner, required=True)
    classification = forms.CharField(max_length=256, required=False)
    snippet = ModelField(Snippet, required=False)
    template = ModelField(HostTemplate, required=False)

    url = forms.URLField(max_length=2048, required=True)
    ip = forms.CharField(max_length=32, required=True)
    port = forms.IntegerField(max_value=65535, min_value=0, required=True)
    protocol = forms.CharField(max_length=256, required=False)

    country = forms.CharField(max_length=256, required=False)
    longitude = forms.FloatField(required=False)
    langitude = forms.FloatField(required=False)


class HostTemplateForm(forms.Form):
    domain_name = forms.CharField(max_length=256, required=True)
    ip_address = forms.CharField(max_length=32, required=False)
    owner = forms.CharField(max_length=256, required=False)
    description = forms.CharField(required=False)
