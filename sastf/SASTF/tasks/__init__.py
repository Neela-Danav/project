# This file is used to bundle all async tasks that should
# be executed on a Celery worker node.
from .tsk_scan import *
from .tsk_sast import *
from .tsk_semgrep import *
