"""Select original source spans for the installed AST V2 observations."""

import ast
import codecs
from io import BytesIO, StringIO
import re
import tokenize

from .panel_views import Unit, guard, line_offsets
from .runtime.candidate import static_ast_v2
from .text_bytes import decode


IGNORED = {tokenize.COMMENT, tokenize.NL}


def records(report, kind):
    cursor = None
    while True:
        page = static_ast_v2.page(report, kind, cursor, limit=1000)
        yield from page["items"]
        cursor = page["cursor"]
        if cursor is None:
            return


def token_index(tokens, lines):
    """Locate declaration headers and their decorator starts by UTF-8 column."""
    declarations = {}
    start = True
    decorator = None
    for index, token in enumerate(tokens):
        if token.type in IGNORED | {tokenize.INDENT, tokenize.DEDENT}:
            continue
        if token.type == tokenize.NEWLINE:
            start = True
        elif start:
            line, column = token.start
            if token.string == "@":
                decorator = decorator or line
            else:
                if token.string in ("def", "class", "async"):
                    byte_column = len(lines[line - 1][:column].encode("utf-8"))
                    declarations[(line, byte_column)] = (index, decorator or line)
                decorator = None
            start = False
    return declarations


def docstring(tokens, index):
    """Read a literal first statement using only string tokens."""
    strings = []
    parentheses = 0
    for position in range(index, len(tokens)):
        token = tokens[position]
        if token.type in IGNORED | {tokenize.INDENT}:
            continue
        if token.type == tokenize.STRING:
            strings.append(token.string)
        elif token.string == "(" and not strings:
            parentheses += 1
        elif token.string == ")" and parentheses:
            parentheses -= 1
        elif (token.type in {tokenize.NEWLINE, tokenize.ENDMARKER} or token.string == ";") and not parentheses:
            break
        else:
            return None
    if not strings:
        return None
    try:
        values = [ast.literal_eval(literal) for literal in strings]
        if any(type(value) is not str for value in values):
            return None
        value = "".join(values)
        guard(value.encode("utf-8"), "")
        return value
    except (ValueError, SyntaxError, UnicodeError, RecursionError):
        return None


def body_start(tokens, header):
    depth = 0
    for index in range(header, len(tokens)):
        token = tokens[index]
        if token.type == tokenize.NEWLINE:
            return None
        if token.type != tokenize.OP:
            continue
        if token.string in ("(", "[", "{"):
            depth += 1
        elif token.string in (")", "]", "}"):
            depth -= 1
        elif token.string == ":" and depth == 0:
            start = index + 1
            while tokens[start].type in IGNORED:
                start += 1
            return start + (tokens[start].type == tokenize.NEWLINE)
    return None


def analyze(source):
    row, raw, breaks = source.row, source.raw, source.breaks
    report = static_ast_v2.analyze_captured(raw, row["path"], row["sha256"])
    if report["status"] not in ("COMPLETE", "PARTIAL"):
        return report, [], None
    encoding, _ = tokenize.detect_encoding(BytesIO(raw).readline)
    if codecs.lookup(encoding).name not in ("utf-8", "utf-8-sig", "ascii"):
        return report, [], None
    text = decode(raw)
    lines = re.split(r"\r\n|[\r\n]", text)
    offsets = line_offsets(raw, breaks)
    try:
        tokens = list(tokenize.generate_tokens(StringIO(text, newline=None).readline))
    except (SyntaxError, tokenize.TokenError):
        tokens = []
    declarations = token_index(tokens, lines)
    units = []
    for item in records(report, "declarations"):
        line, last = item["line"], item["end_line"]
        header, first = declarations.get((line, item["column"]), (None, line))
        if item["decorated"] and first == line:
            continue  # Never present a decorator-less slice as a complete unit.
        if not 1 <= first <= line <= last < len(offsets):
            continue
        start, end = offsets[first - 1], offsets[last - 1] + item["end_column"]
        if not start < end <= offsets[last]:
            continue
        try:
            raw[start:end].decode("utf-8")
        except UnicodeError:
            continue
        body = body_start(tokens, header) if header is not None else None
        facts = {"declaration_id": item["id"], "declaration_kind": item["node"],
                 "declaration_line": line, "scope": [scope["name"] for scope in item["scope_chain"]],
                 "ast_snapshot": report["snapshot_id"], "ast_status": report["status"],
                 "ast_schema": report["schema"]}
        description = docstring(tokens, body) if body is not None else None
        if description:
            facts["documented_description"] = description
        units.append(Unit(item["qualified_name"], "python_declaration", first, last, start, end, facts))
    return report, units, docstring(tokens, 0) if tokens else None


def imports(report):
    for relation in records(report, "relations"):
        if relation["kind"] == "imports":
            names = ", ".join(alias["name"] + (" as " + alias["asname"] if alias["asname"] else "")
                              for alias in relation["aliases"])
            origin = "." * relation["level"] + (relation["module"] or "")
            yield f'{relation["line"]} · ' + (f"from {origin} import {names}" if origin else f"import {names}")
