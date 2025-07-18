from rest_framework import serializers

from sastf.SASTF.models import (
    FindingTemplate,
    AppPermission,
    Package,
    PackageVulnerability,
    Dependency,
    Finding,
    Vulnerability,
    Snippet,
    Component,
    PermissionFinding,
)

__all__ = [
    "TemplateSerializer",
    "AppPermissionSerializer",
    "SnippetSerializer",
    "FindingSerializer",
    "VulnerabilitySerializer",
    "PackageSerializer",
    "PackageVulnerabilitySerializer",
    "DependencySerializer",
    "ComponentSerializer",
    "PermissionFindingSerializer",
]


class TemplateSerializer(serializers.ModelSerializer):
    class Meta:
        model = FindingTemplate
        fields = "__all__"


class AppPermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = AppPermission
        fields = "__all__"


class PermissionFindingSerializer(serializers.Serializer):
    permission = AppPermissionSerializer(many=False)

    class Meta:
        model = PermissionFinding
        fields = "__all__"


class SnippetSerializer(serializers.ModelSerializer):
    class Meta:
        model = Snippet
        exclude = ["sys_path"]


class FindingSerializer(serializers.ModelSerializer):
    template = TemplateSerializer(many=False)
    snippet = SnippetSerializer(many=False)

    class Meta:
        model = Finding
        fields = "__all__"


class VulnerabilitySerializer(serializers.ModelSerializer):
    template = TemplateSerializer(many=False)
    snippet = SnippetSerializer(many=False)

    class Meta:
        model = Vulnerability
        fields = "__all__"


class PackageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Package
        fields = "__all__"


class PackageVulnerabilitySerializer(serializers.ModelSerializer):
    package = PackageSerializer(many=False)

    class Meta:
        model = PackageVulnerability
        fields = "__all__"


class DependencySerializer(serializers.ModelSerializer):
    package = PackageSerializer(many=False)

    class Meta:
        model = Dependency
        fields = "__all__"


class ComponentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Component
        fields = "__all__"
