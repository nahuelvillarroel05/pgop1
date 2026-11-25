"""Messages exchanged by the local panel and its presentation."""
from dataclasses import dataclass


class StopFlow(Exception):
    """The user canceled a pending editor or the workspace was reset."""


@dataclass(frozen=True)
class Page:
    title: str
    body: str = ""
    options: tuple = ()
    back: str = "0"
    markdown: bool = False


@dataclass(frozen=True)
class Prompt:
    title: str
    body: str
    field: bool = False
    value: str = ""
    alternative: str = ""

