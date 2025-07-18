from rest_framework.request import HttpRequest
from rest_framework.permissions import (
    BasePermission,
    SAFE_METHODS,
)

from sastf.SASTF.permissions import CanEditProject
from sastf.SASTF.utils.enum import Visibility, Role
from sastf.SASTF.models import Account


class IsAdmin(BasePermission):
    def has_permission(self, request, view):
        user = request.user
        if user.is_anonymous or not user.is_authenticated:
            return False

        return Account.objects.get(user=user).role == Role.ADMIN


class IsExternal(BasePermission):
    def has_permission(self, request, view):
        user = request.user
        if user.is_anonymous or not user.is_authenticated:
            return False

        return Account.objects.get(user=user).role == Role.EXTERNAL


class ReadOnly(BasePermission):
    """Checks whether the request is read-only"""

    def has_permission(self, request: HttpRequest, view):
        return request.method in SAFE_METHODS


class IsProjectPublic(BasePermission):
    def has_object_permission(self, request, view, obj):
        return not obj.team and obj.visibility == Visibility.PUBLIC


class IsScanInitiator(BasePermission):
    def has_object_permission(self, request, view, obj):
        return request.user == obj.initiator


class IsScanProjectMember(BasePermission):
    def has_object_permission(self, request, view, obj):
        return CanEditProject.has_object_permission(request, view, obj.project)


class IsScanTaskInitiator(BasePermission):
    def has_object_permission(self, request, view, obj):
        return request.user == obj.scan.initiator


class IsScanTaskMember(BasePermission):
    def has_object_permission(self, request, view, obj):
        return CanEditProject.has_object_permission(request, view, obj.project)


CanEditScanTask = IsScanTaskInitiator | IsScanTaskMember
CanEditScan = IsScanInitiator | IsScanProjectMember | IsAdmin


class CanEditScanAsField(BasePermission):
    ref = CanEditScan()

    def has_object_permission(self, request, view, obj):
        return self.ref.has_object_permission(request, view, obj.scan)


class CanEditScanFromScanner(BasePermission):
    ref = CanEditScanAsField()

    def has_object_permission(self, request, view, obj):
        return self.ref.has_object_permission(request, view, obj.scanner)
