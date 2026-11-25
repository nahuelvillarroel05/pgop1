"""Small, read-only project sampling within the workspace's native scope."""

from collections import Counter
from pathlib import PureWindowsPath
import re
import time

from . import panel_views as views, workspace as ws
from .source_paths import excluded_name
from .text_bytes import decode


AREAS = {"docs", "doc", "documentation", "src", "lib", "app", "tests", "test"}
ENTRIES = {"__main__.py", "main.py", "app.py", "cli.py", "manage.py"}
METADATA = {"package.json", "project.json", "manifest.json", "composer.json", "deno.json"}
DOCS = {"about", "overview", "index", "introduction", "intro", "manual", "getting-started"}
SAMPLE = 6


def priority(path):
    name = PureWindowsPath(path).name.lower()
    stem, suffix = PureWindowsPath(name).stem, PureWindowsPath(name).suffix
    if stem == "readme" and suffix in (".md", ".txt"):
        return int("/" in path)
    if suffix in (".md", ".txt") and stem in DOCS:
        return 2
    if name in METADATA:
        return 3
    if name in ENTRIES:
        return 4
    if suffix == ".py":
        return 5 if not path.lower().startswith(("test/", "tests/")) else 7
    if suffix == ".md":
        return 6
    return 8


def preview(root):
    entries, pages = ws.LIMITS["entries"], ws.LIMITS["pages"]
    deadline = time.monotonic() + ws.LIMITS["cooperative_seconds"]
    candidates = []
    areas = []
    skipped = Counter()
    types = Counter()
    pending = []

    def check_time():
        if time.monotonic() >= deadline:
            raise ws.io.SafeIOError("DISCOVERY_COOPERATIVE_TIMEOUT")

    def peek(directory, prefix=""):
        nonlocal entries, pages
        if entries <= 0 or pages <= 0:
            skipped["ENTRY_OR_PAGE_LIMIT"] += 1
            return
        trace = []
        try:
            rows = ws.native.enumerate_directory(directory.handle, {"max_entries": entries, "max_pages": pages},
                                                 trace, deadline=check_time, allow_unsupported_names=True)
        except ws.io.SafeIOError as exc:
            skipped[exc.code] += 1
            return
        finally:
            entries -= sum(event["decoded_entries"] or 0 for event in trace)
            pages -= len(trace)
        for row in rows:
            name = row["name"]
            if excluded_name(name) or row["tag"] or row["attributes"] & ws.EXCLUDED_ATTRIBUTES:
                skipped["EXCLUDED"] += 1
                continue
            try:
                ws.io.component(name)
            except ws.io.SafeIOError:
                skipped["UNSAFE_PATH"] += 1
                continue
            path = f"{prefix}/{name}" if prefix else name
            if row["attributes"] & 16:
                if not prefix:
                    areas.append(name)
                    if name.lower() in AREAS:
                        pending.append((name, row))
                continue
            suffix = PureWindowsPath(name).suffix
            if suffix not in ws.text.FORMATS:
                skipped["UNSUPPORTED_FORMAT"] += 1
                continue
            types[suffix] += 1
            if row["size"] > ws.LIMITS["source_bytes"]:
                skipped["SOURCE_LIMIT"] += 1
                continue
            if len(root.path) + len(path) + 1 > ws.LIMITS["path_characters"]:
                skipped["PATH_BUDGET"] += 1
                continue
            candidates.append((path, row))

    peek(root)
    for name, row in pending:
        if entries <= 0 or pages <= 0:
            skipped["ENTRY_OR_PAGE_LIMIT"] += 1
            break
        try:
            with ws.child(root, name, source=True) as directory:
                ws.native.matches(row, ws.safe_meta(directory.handle, True))
                peek(directory, name)
        except ws.io.SafeIOError as exc:
            skipped[exc.code] += 1
    ws.visible_directories(root)
    candidates.sort(key=lambda item: (priority(item[0]), item[0].count("/"), item[0].lower(), item[0]))
    selection = candidates[:SAMPLE]
    # Keep at least one Python candidate when documentary metadata fills the sample.
    if not any(path.endswith(".py") for path, _ in selection):
        python = next((item for item in candidates if item[0].endswith(".py")), None)
        if python:
            selection = [*selection[:SAMPLE - 1], python]
    return selection, [path for path, _ in candidates], types, sorted(areas), skipped


def documented_purpose(source):
    """Select an original documentary paragraph or a front matter description."""
    path, raw, breaks = source.row["path"], source.raw, source.breaks
    if PureWindowsPath(path).suffix not in (".md", ".txt") or priority(path) > 2:
        return None
    lines = re.split(r"\r\n|[\r\n]", decode(raw))
    offsets = views.line_offsets(raw, breaks)
    front = views.front_matter_end(lines) if path.endswith(".md") else 0
    for index, line in enumerate(lines[1:front - 1], 1) if front else ():
        if re.match(r"description:[ \t]+[^>|]", line, re.I):
            return views.Unit("Descripción documentada", "markdown_front_matter",
                              index + 1, index + 1, offsets[index], offsets[index + 1])
    headings = {line for line, _, _ in views.markdown_sections(decode(raw))} if path.endswith(".md") else set()
    preamble = views.metadata_preamble_end(lines) if path.endswith(".md") else 0
    start = None
    fence = False
    for index, line in enumerate(lines[preamble:len(offsets) - 1], preamble):
        if views.FENCE.match(line):
            fence = not fence
        prose = (not fence and index + 1 not in headings and line.strip()
                 and not line.lstrip().startswith(("#", "!", "[", "<", "|", ">", "`", "~", "- ", "* "))
                 and not views.SETEXT.match(line))
        if prose and start is None:
            start = index
        if start is not None and not prose:
            break
    else:
        index = len(offsets) - 1
    if start is not None:
        return views.Unit("Propósito documentado", "documented_purpose",
                          start + 1, index, offsets[start], offsets[index])
