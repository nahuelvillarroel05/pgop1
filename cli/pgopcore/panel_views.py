"""Bounded, inert projections of bytes already read by the a7 workspace."""

import csv
from dataclasses import dataclass
from io import StringIO
import json
import re

from .cli import safe
from .text_bytes import content_start, decode


DELIMITERS = {",": "coma", ";": "punto y coma", "\t": "tabulación", "|": "barra vertical"}
CSV_ROWS = 4096
CSV_COLUMNS = 128
CSV_CELLS = 32768
LINE_WIDTH = 120
SECRET_FIELD = (
    r"(?:(?:[a-z0-9]+)[_-])*(?:password|passwd|contrase(?:ñ|n)a|secret|"
    r"api[_ -]?key|access[_ -]?token|refresh[_ -]?token|private[_ -]?key|"
    r"client[_ -]?secret|authorization|credential(?:s)?)"
)
SENSITIVE = re.compile(
    rf"(?im)(?:\b{SECRET_FIELD}[\"']?\s*[:=]|"
    r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----|"
    r"\b(?:Bearer\s+[^\s,\"']+|(?:AKIA|ASIA)[A-Z0-9]{16}|"
    r"(?:gh[pousr]_|github_pat_|sk-proj-)[a-z0-9_-]{12,})|"
    r"\b[a-z][a-z0-9+.-]*://[^\s/@:]+:[^\s/@]+@)"
)
SENSITIVE_CSV_HEADER = re.compile(rf"(?i)(?:^|[,;\t|])\s*[\"']?(?:{SECRET_FIELD}|token)"
                                  r"[\"']?\s*(?=[,;\t|]|$)")
SENSITIVE_KEY = re.compile(rf"(?i)(?:{SECRET_FIELD}|token)")
ATX = re.compile(r"^ {0,3}(#{1,6})(?:[ \t]+(.*)|$)")
FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
SETEXT = re.compile(r"^ {0,3}(=+|-+)[ \t]*$")
YAML_FIELD = re.compile(r"^([A-Za-z_][A-Za-z0-9_.-]*):(?:$| +([^ ].*))")
YAML_PLAIN = re.compile(r"[+-]?[\w./][^\[\]{},#]*")
YAML_SINGLE = re.compile(r"'(?:[^']|'')*'")
YAML_DOUBLE = re.compile(r'"(?:[^"\\]|\\["\\nrt])*"')
YAML_UNSUPPORTED_CHAR = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029\ufffe\uffff]")
BLOCK = re.compile(r"^(?: {4}|\t| {0,3}(?:[>]|[-+*] |[0-9]+[.)] ))")


def guard(raw, path):
    text = decode(raw)
    if SENSITIVE.search(text) or (path.endswith(".csv") and SENSITIVE_CSV_HEADER.search(
            text.partition("\n")[0].partition("\r")[0])):
        raise ValueError("PANEL_SENSITIVE_CONTENT")
    if path.endswith(".json"):
        # Source JSON has already passed the strict extractor. Check escaped keys/values too.
        values = [json.loads(text)]
        while values:
            item = values.pop()
            if isinstance(item, dict):
                if any(SENSITIVE_KEY.fullmatch(key) for key in item):
                    raise ValueError("PANEL_SENSITIVE_CONTENT")
                values.extend(item.values())
            elif isinstance(item, list):
                values.extend(item)
            elif isinstance(item, str) and SENSITIVE.search(item):
                raise ValueError("PANEL_SENSITIVE_CONTENT")


def safe_text(text):
    return "\n".join(safe(line) for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"))


def short(value, limit=96):
    text = safe(value)
    return text if len(text) <= limit else text[:limit - 1] + "…"


@dataclass(frozen=True)
class TextSegment:
    line: int
    start: int
    end: int
    text: str


def segments(raw, breaks):
    start = content_start(raw)
    for line, end in enumerate(breaks + ([len(raw)] if len(raw) > start and breaks[-1:] != [len(raw)] else []), 1):
        body = raw[start:end].decode("utf-8")
        display = body.rstrip("\r\n")
        cursor = start
        for offset in range(0, max(len(display), 1), LINE_WIDTH):
            chunk = display[offset:offset + LINE_WIDTH]
            next_cursor = end if offset + LINE_WIDTH >= len(display) else cursor + len(chunk.encode("utf-8"))
            yield TextSegment(line, cursor, next_cursor, chunk)
            cursor = next_cursor
        start = end


def metadata_preamble_end(lines):
    """Find a closed, mapping-shaped Markdown preamble for literal display."""
    if not lines or lines[0] != "---":
        return 0
    looks_like_mapping = False
    for index, line in enumerate(lines[1:], 2):
        if line in ("---", "..."):
            return index if looks_like_mapping else 0
        if looks_like_mapping or not line.strip() or line.lstrip().startswith("#"):
            continue
        looks_like_mapping = YAML_FIELD.match(line) is not None
        if not looks_like_mapping:
            return 0
    return 0


def yaml_scalar(value):
    """Accept single-line scalar spellings whose syntax we can check completely."""
    return bool(YAML_SINGLE.fullmatch(value) or YAML_DOUBLE.fullmatch(value) or (
        YAML_PLAIN.fullmatch(value) and not value.endswith(":") and ": " not in value
    ))


def front_matter_end(lines):
    """Recognize unique flat keys with simple scalars or one-line scalar lists."""
    end = metadata_preamble_end(lines)
    keys = set()
    for line in lines[1:end - 1] if end else ():
        if YAML_UNSUPPORTED_CHAR.search(line):
            return 0
        if not line.strip() or line.lstrip(" ").startswith("#"):
            continue
        match = YAML_FIELD.fullmatch(line.rstrip(" "))
        if not match or not match[2] or match[1].lower() in keys:
            return 0
        key, value = match.groups()
        keys.add(key.lower())
        if value.startswith("[") and value.endswith("]"):
            middle = value[1:-1].strip(" ")
            if middle and not all(yaml_scalar(item.strip(" ")) for item in middle.split(",")):
                return 0
        elif not yaml_scalar(value):
            return 0
    return end if keys else 0


def markdown_sections(text):
    """Yield ATX and Setext headings outside front matter and fenced code."""
    lines = re.split(r"\r\n|[\r\n]", text)
    front = metadata_preamble_end(lines)
    fence, previous, previous_line = "", [], None
    for number, line in enumerate(lines[front:], front + 1):
        marker = FENCE.match(line)
        if fence:
            if marker and marker[1][0] == fence[0] and len(marker[1]) >= len(fence) and not marker[2].strip():
                fence = ""
        elif marker and (marker[1][0] != "`" or "`" not in marker[2]):
            fence = marker[1]
        elif heading := ATX.match(line):
            title = re.sub(r"[ \t]+#+[ \t]*$", "", heading[2] or "").strip()
            yield number, len(heading[1]), title
        elif (underline := SETEXT.fullmatch(line)) and previous:
            yield previous_line, 1 if underline[1][0] == "=" else 2, " ".join(previous)
        elif line.strip() and not BLOCK.match(line) and not SETEXT.fullmatch(line) and not re.fullmatch(
                r" {0,3}([*_])(?:[ \t]*\1){2,}[ \t]*", line):
            if not previous:
                previous_line = number
            previous.append(line.strip())
            continue
        previous = []


@dataclass(frozen=True)
class Unit:
    title: str
    kind: str
    start_line: int
    end_line: int
    start: int
    end: int
    facts: dict | None = None

    def selector(self):
        selector = {"kind": self.kind, "title": self.title, "line_start": self.start_line,
                    "line_end": self.end_line, "byte_start": self.start, "byte_end": self.end}
        return {**selector, **(self.facts or {})}


def line_offsets(raw, breaks):
    return [content_start(raw), *breaks, *([len(raw)] if breaks[-1:] != [len(raw)] else [])]


def markdown_units(raw, breaks):
    text = decode(raw)
    offsets = line_offsets(raw, breaks)
    front = front_matter_end(re.split(r"\r\n|[\r\n]", text))
    headings = list(markdown_sections(text))
    endings = {}
    pending = []
    for line, level, _ in headings:
        while pending and pending[-1][1] >= level:
            endings[pending.pop()[0]] = line - 1
        pending.append((line, level))
    units = []
    if front:
        units.append(Unit("Metadatos (YAML)", "markdown_front_matter", 1, front, offsets[0], offsets[front]))
    first = headings[0][0] if headings else len(offsets)
    if first > front + 1 and raw[offsets[front]:offsets[first - 1]].strip():
        units.append(Unit("Introducción" if headings else "Documento", "markdown_section",
                          front + 1, first - 1, offsets[front], offsets[first - 1]))
    for line, _, title in headings:
        end_line = endings.get(line, len(offsets) - 1)
        units.append(Unit(title, "markdown_section", line, end_line, offsets[line - 1], offsets[end_line]))
    return units


def paragraphs(raw, breaks):
    """Select complete nonblank paragraphs without changing line or byte offsets."""
    offsets = line_offsets(raw, breaks)
    first = None
    for index in range(len(offsets)):
        occupied = index + 1 < len(offsets) and raw[offsets[index]:offsets[index + 1]].strip()
        if occupied and first is None:
            first = index
        elif not occupied and first is not None:
            yield Unit(f"Párrafo desde la línea {first + 1}", "text_paragraph",
                       first + 1, index, offsets[first], offsets[index])
            first = None


@dataclass(frozen=True)
class JsonNumber:
    lexeme: str


def json_value(raw):
    """Project strictly validated source bytes, preserving original number tokens."""
    return json.loads(decode(raw), parse_int=JsonNumber, parse_float=JsonNumber)


def render_json(value, depth=0):
    if isinstance(value, JsonNumber):
        return value.lexeme
    if isinstance(value, dict) and value:
        items = [f"{render_json(key)}: {render_json(item, depth + 1)}" for key, item in value.items()]
        start, end = "{", "}"
    elif isinstance(value, list) and value:
        items = [render_json(item, depth + 1) for item in value]
        start, end = "[", "]"
    else:
        return json.dumps(value, ensure_ascii=False, allow_nan=False)
    indent = "  " * depth
    return start + "\n" + ",\n".join(indent + "  " + item for item in items) + "\n" + indent + end


def json_kind(value):
    if isinstance(value, dict):
        return f"objeto · {len(value)} campos"
    if isinstance(value, list):
        return f"lista · {len(value)} elementos"
    return {str: "texto", bool: "booleano", type(None): "nulo", JsonNumber: "número"}[type(value)]


def json_pointer(parts):
    return "".join("/" + str(part).replace("~", "~0").replace("/", "~1") for part in parts)


class CSVError(ValueError):
    pass


@dataclass(frozen=True)
class CSVRow:
    first_line: int
    last_line: int
    fields: tuple


def csv_rows(text, delimiter):
    rows = []
    previous = columns = cells = 0
    reader = csv.reader(StringIO(text, newline=""), delimiter=delimiter, strict=True)
    try:
        for record in reader:
            if not rows:
                columns = len(record)
            cells += len(record)
            if len(rows) >= CSV_ROWS or columns > CSV_COLUMNS or cells > CSV_CELLS:
                raise CSVError("CSV_STRUCTURE_LIMIT")
            if not columns or len(record) != columns:
                raise CSVError("CSV_NONRECTANGULAR")
            rows.append(CSVRow(previous + 1, reader.line_num, tuple(record)))
            previous = reader.line_num
    except csv.Error as exc:
        raise CSVError("CSV_INVALID") from exc
    if not rows:
        raise CSVError("CSV_EMPTY")
    return rows


def detect_csv(text):
    supported = []
    for delimiter in DELIMITERS:
        try:
            rows = csv_rows(text, delimiter)
        except CSVError:
            continue
        if len(rows[0].fields) > 1:
            supported.append((delimiter, rows))
    if len(supported) != 1:
        raise CSVError("CSV_DELIMITER_UNCERTAIN")
    return supported[0]
