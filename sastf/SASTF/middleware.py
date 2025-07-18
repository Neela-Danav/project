__doc__ = """
Additional middleware classes that intercept requests before any view
can handle them.
"""
from django.shortcuts import render

from sastf.SASTF.models import Environment


class FirstTimeMiddleware:
    """Used to redirect to the setup page when starting this framework
    for the first time.

    Note that this middleware will return a rendered setup page for all
    incoming request if the framework has not been initialized.
    """

    def __init__(self, get_response) -> None:
        self.get_response = get_response

    def __call__(self, request, *args, **kwargs):
        response = self.get_response(request)

        # If it's the first time the app is started and the request is
        # not for the setup wizard, return the setup wizard page (which
        # will guide the user through the initial configuration steps)
        env = Environment.env()
        if env.first_start and request.path != "/api/v1/setup/":
            return render(request, "setup/wizard.html")

        return response
