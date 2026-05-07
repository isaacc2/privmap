"""privmap - Linux privilege graph engine."""
from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("privmap")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"