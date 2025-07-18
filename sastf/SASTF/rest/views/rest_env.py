from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout

from rest_framework.views import APIView
from rest_framework import permissions, authentication, status
from rest_framework.response import Response
from rest_framework.request import Request

from sastf.SASTF.serializers import EnvironmentSerializer
from sastf.SASTF.rest.permissions import IsAdmin
from sastf.SASTF.models import Account, Environment

from .base import APIViewBase, GetObjectMixin

__all__ = ["EnvironmentView"]


class EnvironmentView(APIViewBase):
    model = Environment
    permission_classes = [permissions.IsAuthenticated & IsAdmin]
    serializer_class = EnvironmentSerializer
    delete = None
