from django.db import models
from uuid import uuid4

from sastf.SASTF.utils.enum import ComponentCategory

from .mod_scan import Scanner, Scan
from .mod_permission import AppPermission
from .base import namespace, TimedModel

__all__ = ["Component", "IntentFilter"]


class IntentFilter(TimedModel):
    name = models.CharField(max_length=1024, blank=True)
    action = models.CharField(max_length=1024, blank=True)


class Component(TimedModel):
    cid = models.CharField(max_length=256, primary_key=True)
    scanner = models.ForeignKey(Scanner, on_delete=models.CASCADE)

    name = models.CharField(max_length=2048)
    is_exported = models.BooleanField(default=False)
    is_protected = models.BooleanField(default=True)
    is_launcher = models.BooleanField(default=False)
    is_main = models.BooleanField(default=False)
    permission = models.ForeignKey(AppPermission, null=True, on_delete=models.SET_NULL)

    category = models.CharField(
        blank=True, choices=ComponentCategory.choices, max_length=256
    )
    intent_filters = models.ManyToManyField(IntentFilter, related_name="components")

    @staticmethod
    def make_uuid(*args) -> str:
        return f"cpt_{uuid4()}"

    @staticmethod
    def stats(scan: Scan) -> list:  # type := list[namespace]
        values = []
        components = Component.objects.filter(scanner__scan=scan)

        categories = (
            components.values("category")
            .annotate(ccount=models.Count("category"))
            .order_by()
        )
        rel_count = 1 if len(components) == 0 else len(components)
        for element in categories:
            category = element["category"]
            data = namespace(count=element["ccount"], category=category)

            data.protected = len(
                components.filter(category=category, is_protected=True)
            )
            data.protected_rel = (data.protected / rel_count) * 100
            data.exported = len(components.filter(category=category, is_exported=True))
            data.exported_rel = (data.exported / rel_count) * 100
            values.append(data)
        return values
