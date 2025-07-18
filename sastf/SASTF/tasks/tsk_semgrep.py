from __future__ import annotations

import os
import pathlib
import subprocess
import json

from celery import shared_task
from celery.utils.log import get_task_logger

from sastf.core.progress import Observer

from sastf.SASTF import settings
from sastf.SASTF.models import ScanTask, FindingTemplate, Finding, Snippet, File

logger = get_task_logger(__name__)

__all__ = ["perform_semgrep_scan"]


@shared_task(bind=True)
def perform_semgrep_scan(
    self, scan_task_id: str, rules_dir: str, file_dir: str
) -> dict:
    scan_task = ScanTask.objects.get(task_uuid=scan_task_id)
    scan_task.celery_id = self.request.id
    scan_task.save()
    observer = Observer(self, scan_task=scan_task)

    scan = scan_task.scan
    out_file = scan.project.directory / f"semgrep-{scan.file.internal_name}.json"
    if out_file.exists():
        os.remove(str(out_file))

    cmd = [  # cd rules_dir && semgrep -c rules_dir --output out_file --json file_dir
        "cd",
        # Rather change the current working directory as .semgrepignore may be defined there
        # REVISIT: maybe use cwd=... in run()
        rules_dir,
        "&&",
        "semgrep",
        "scan",
        "-c",
        rules_dir,
        "--json",
        "--output",
        str(out_file),
        file_dir,
    ]
    try:
        observer.update("Running semgrep...", do_log=True)
        result = subprocess.run(" ".join(cmd), capture_output=True, shell=True)
        result.check_returncode()

        observer.update("Finished semgrep, inspecing results...", do_log=True)
        with open(str(out_file), "r") as fp:
            data = json.load(fp)

        for result in data["results"]:
            # internal title := extra.metadata.area "-" extra.metadata.category "-(" check_id ")"
            internal_name = "%s-%s-(%s)" % (
                result["extra"]["metadata"]["area"].lower(),
                result["extra"]["metadata"]["category"].lower(),
                result["check_id"]
                .split(".", 2)[-1]
                .lower(),  # always something like "rules.storage.MSTG-STORAGE-7.2"
            )

            try:
                template = FindingTemplate.objects.get(
                    internal_id__icontains=internal_name
                )
                path = pathlib.Path(result["path"])
                start = result["start"]["line"]
                end = result["end"]["line"]
                # Structure:
                #   - either the current line number
                #   - or a range separated by '-'
                if (end - start) > 1:
                    lines = f"{start}-{end}"
                else:
                    lines = ",".join([str(x) for x in range(start, end + 1)])

                snippet = Snippet.objects.create(
                    sys_path=str(path),
                    language=path.suffix.removeprefix("."),
                    file_name=path.name,
                    file_size=path.stat().st_size,
                    lines=lines,
                )
                if not template.is_contextual:
                    Finding.create(template, snippet, scan_task.scanner)
                else:
                    Finding.create(
                        template, snippet, scan_task.scanner, text=result["message"]
                    )

            except FindingTemplate.DoesNotExist:
                logger.warning(
                    "Could not find FindingTemplate for ID: %s", internal_name
                )
            except FindingTemplate.MultipleObjectsReturned:
                logger.warning(
                    "Multiple FindingTemplate objects with ID: %s", internal_name
                )

        _, meta = observer.success("Finished semgrep scan!")
        return meta
    except subprocess.CalledProcessError as err:
        _, meta = observer.exception(err, "Failed to execute semgrep!")
        return meta
    except Exception as oserr:
        _, meta = observer.exception(oserr, "Failed to read from semgrep results!")
        return meta.get("description")
