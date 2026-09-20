"""ProvTrail command-line entry points."""

from importlib.metadata import PackageNotFoundError, version

try:
    PROVTRAIL_VERSION = version("provtrail")
except PackageNotFoundError:
    PROVTRAIL_VERSION = "development"
