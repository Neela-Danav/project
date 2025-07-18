import os

from whitenoise import WhiteNoise
from django.core.wsgi import get_wsgi_application

from sastf.SASTF import settings

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "sastf.SASTF.settings")

static = os.path.join(settings.BASE_DIR, "static")
application = WhiteNoise(get_wsgi_application(), root=static, prefix="static/")
