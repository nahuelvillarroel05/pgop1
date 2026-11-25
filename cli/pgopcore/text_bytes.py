"""Project UTF-8 text while preserving offsets into the captured source."""

from codecs import BOM_UTF8


def content_start(raw):
    return len(BOM_UTF8) if raw.startswith(BOM_UTF8) else 0


def decode(raw):
    return raw[content_start(raw):].decode("utf-8")
