import os
import subprocess
import apkInspector


def extractrsc(apk_path: str, dest_path: str, apktool_path: str = "apktool") -> None:
    run_apktool_decode(apk_path, dest_path, apktool_path, force=True, sources=False)


def run_apktool_decode(
    apk_path: str,
    dest_path: str,
    apktool_path: str = "apktool",
    force: bool = True,
    sources: bool = True,
    resources: bool = True,
) -> None:
    """
    Decodes the specified APK file using apktool.

    :param apk_path: The path to the APK file to decode.
    :type apk_path: str
    :param dest_path: The path to the directory where the decoded files will be placed.
    :type dest_path: str
    :param apktool_path: The path to the apktool executable. Defaults to "apktool".
    :type apktool_path: str, optional
    :param force: Whether to force overwrite existing files. Defaults to True.
    :type force: bool, optional
    :param sources: Whether to decode sources. Defaults to True.
    :type sources: bool, optional
    :param resources: Whether to decode resources. Defaults to True.
    :type resources: bool, optional
    :raises RuntimeError: If apktool fails to decode the APK file.
    """
    cmd = [f"{apktool_path} d {apk_path} -o {dest_path}"]
    if force:
        cmd.append("-f")

    if not sources:
        cmd.append("--no-src")

    if not resources:
        cmd.append("--no-res")

    try:
        subprocess.run(" ".join(cmd), shell=True, capture_output=True, check=True)
    except subprocess.CalledProcessError as err:
        # Raise a RuntimeError if apktool fails to decode the APK file
        raise RuntimeError(err.stdout.decode()) from err


def apkinspector_extract(apk: apkInspector.headers.ZipEntry, dest_path: str) -> None:
    cd = apk.central_directory
    lh = apk.local_headers
    error = apkInspector.extract.extract_all_files_from_central_directory(
        apk, cd, lh, dest_path
    )
    if error != 0:
        raise RuntimeError(f"Failed to extract files from APK. error={error}")

    # convert manifest file
    manifest_file = os.path.join(dest_path, "AndroidManifest.xml")
    with open(manifest_file, "rb") as f:
        xml_data = f.read()

    with open(manifest_file, "w", encoding="utf-8") as f:
        f.write(apkInspector.axml.get_manifest(xml_data))
