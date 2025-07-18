import uuid
import pathlib

from datetime import datetime
from typing import Callable

from celery import shared_task, group
from celery.result import AsyncResult, GroupResult
from celery.utils.log import get_task_logger

from sastf.core.files import TaskFileHandler
from sastf.core.progress import Observer

from sastf.SASTF import settings
from sastf.SASTF.models import Scan, ScanTask, Scanner, File, Details
from sastf.SASTF.scanners.plugin import ScannerPlugin

logger = get_task_logger(__name__)

__all__ = [
    "schedule_scan",
    "prepare_scan",
    "execute_scan",
]


def schedule_scan(scan: Scan, uploaded_file: File, names: list) -> None:
    """Schedules the given scan."""
    Details.objects.create(scan=scan, file=uploaded_file)
    scan.file = uploaded_file
    for name in names:
        Scanner.objects.create(name=name, scan=scan)

    if not scan.start_date:
        scan.start_date = datetime.now()

    scan.save()
    if scan.start_date.date() == datetime.today().date():
        scan.status = "Active"
        scan.is_active = True
        scan.save()
        task_uuid = uuid.uuid4()
        global_task = ScanTask(
            task_uuid=task_uuid, scan=scan, name="Scan Preparation Task"
        )
        global_task.save()
        logger.info("Started global scan task on %s", scan.pk)

        result: AsyncResult = prepare_scan.delay(str(task_uuid), names)
        global_task.celery_id = result.id
        global_task.save()


@shared_task(bind=True)
def prepare_scan(self, scan_task_id: str, selected_scanners: list) -> AsyncResult:
    task = ScanTask.objects.get(pk=scan_task_id)
    logger.info(
        "Scan Peparation: Setting up directories of scan %s", task.scan.scan_uuid
    )

    observer = Observer(self, scan_task=task)
    scan = task.scan

    observer.update("Directory setup...", current=10)
    # Setup of special directories in our project directory:
    file_dir = scan.project.dir(scan.file.internal_name)
    file_path = scan.file.file_path

    # The first directory will store decompiled source code files,
    # and the second will store data that has been extracted initially.
    src = file_dir / "src"
    contents = file_dir / "contents"

    src.mkdir(exist_ok=True)
    contents.mkdir(exist_ok=True)
    observer.update("Extracting files...", current=30)
    # a default handler based on the scan type should be used.
    handler = TaskFileHandler.from_scan(file_path, scan.scan_type)
    if not handler:
        # cancel scan
        _, meta = observer.fail("Could not find matching MIME-Type handler")
        logger.warning("Could not load file handler for MIME-Type: %s", file_path)
        return meta.get("description")

    handler.apply(pathlib.Path(file_path), file_dir, settings, observer=observer)
    observer.update("Creating scanner specific ScanTask objects.", current=80)

    plugins = ScannerPlugin.all()
    for name in selected_scanners:
        scanner = Scanner.objects.get(scan=scan, name=name)
        # Note that we're creating scan tasks before calling the asynchronous
        # group. The 'execute_scan' task will set the celery_id when it gets
        # executed.
        plugin = plugins[name]
        ScanTask.objects.create(
            task_uuid=uuid.uuid4(), scan=scan, scanner=scanner, name=plugin.name
        )

    tasks = group(
        [execute_scan.s(str(scan.scan_uuid), name) for name in selected_scanners]
    )
    # We actually don't need the group result object, we just have to execute
    # .get()
    result: GroupResult = tasks()
    _, meta = observer.success("Scanners have been started")
    logger.info("Started scan in Group: %s", result.id)

    # Rather delete the finished task than setting its state to finished
    return meta.get("description")


@shared_task(bind=True)
def execute_scan(self, scan_uuid: str, plugin_name: str) -> AsyncResult:
    try:
        logger.info("Running scan_task of <Scan %s, name='%s'>", scan_uuid, plugin_name)

        plugin = ScannerPlugin.all()[plugin_name]
        scan = Scan.objects.get(scan_uuid=scan_uuid)

        scanner = Scanner.objects.get(scan=scan, name=plugin.internal_name)
        task = ScanTask.objects.get(scan=scan, scanner=scanner)
        observer = Observer(self, scan_task=task)

        # Before calling the actual task, the celery ID must be set in order
        # to fetch the current status.
        task.celery_id = self.request.id
        task.save()

        plugin_task = plugin.task
        instance = plugin_task
        if isinstance(plugin_task, type):
            instance = plugin_task()

        if isinstance(instance, Callable):
            rvalue = instance(task, observer)
            _, meta = observer.success("[%s] Finished scanner task", plugin_name)
            ScanTask.finish_scan(scan, task)
            rvalue = rvalue or meta
            return rvalue
        else:
            raise TypeError(
                "Unexpected task type %s; expected Callable[None, [Scan, ScanTask, Observer]]",
                type(instance),
            )
    except Exception as err:
        msg = "(%s) Unhandled worker exeption: %s" % (err.__class__.__name__, str(err))
        logger.exception(msg)
        _, meta = observer.exception(err, msg)
        ScanTask.finish_scan(scan, task)
        return meta.get("description")
