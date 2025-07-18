__version__ = (0, 0, 2)
__tag__ = "a0"
__release__ = (2024, 1)


def get_full_version() -> str:
    release = ".".join([str(x) for x in __release__])
    version = ".".join([str(x) for x in __version__])
    if __tag__:
        version = f"{version}-{__tag__}"

    return f"v{version} ({release})"
