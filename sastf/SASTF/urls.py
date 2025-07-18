from django.urls import include, path, register_converter

from sastf.SASTF import settings, converters


for name, clazz in converters.listconverters().items():
    register_converter(clazz, name)

urlpatterns = [
    path("api/v1/", include("sastf.SASTF.rest.urls")),
]

if settings.DEBUG:
    urlpatterns.extend(
        [path("api-auth/", include("rest_framework.urls", namespace="rest_framework"))]
    )

if not settings.API_ONLY:
    from sastf.SASTF.web import views

    urlpatterns.extend(
        [
            path("web/", include("sastf.SASTF.web.urls")),
            path("", views.DashboardView.as_view()),
        ]
    )
