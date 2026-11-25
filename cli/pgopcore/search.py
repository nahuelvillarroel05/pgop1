"""One-execution admission and projection for the installed literal engine."""

import errno
from pathlib import PureWindowsPath
import re

from .literal_projection import citation, comparable, occurrences
from .runtime.candidate import acquisition_text_v1 as text
from .runtime.candidate import search_v1 as literal_search
from .runtime.candidate import selection_contract_v1 as contract
from .runtime.candidate import windows_directory_enumeration_v1 as native_capture
from .runtime.candidate import windows_safe_io_v2 as native_io
from .runtime.candidate.text_input import TextInput
from .search_contract import (
    LIMITATIONS, LIMITS, MAX_BYTES, MAX_LINES, MAX_QUERY_CHARACTERS, OPTIONS_SCHEMA, SCHEMA, failure,
)
from .source_paths import canonical, excluded_name, path_parts, protected_name


# The six shipped acquisition files, pinned from the reviewed source rather than the local installation.
CODE_SHA256 = "8122488ea65ba240a698ea7c5d3acd62e2543c735b99529059548042a53cf724"
LINE_BREAK = re.compile(rb"\r\n|[\r\n]")
NON_TEXT_BYTES = re.compile(rb"[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]")


def failed_read(code, winerror, *, admitted):
    if code == "ACCESS_DENIED" or winerror == 5:
        status = "PERMISSION_DENIED"
    elif winerror in (2, 3):
        status = "STALE" if admitted else "FILE_NOT_FOUND"
    elif code.startswith(("UNSAFE_PATH", "SENSITIVE_PATH", "UNSUPPORTED_WINDOWS")) or code in {
        "ROOT_OVERLAP", "OUTPUT_OVERLAPS_INPUT", "UNSUPPORTED_FILESYSTEM",
        "UNSUPPORTED_SAFE_READ_PLATFORM",
    } or winerror in (267, 1142, 1920, 1921, 4390, 4392, 4393, 4394, 4395):
        status = "UNSUPPORTED_PATH"
    elif winerror in (32, 33) or code in {
        "SOURCE_CHANGED", "SOURCE_IDENTITY_CHANGED", "SOURCE_SIZE_CHANGED",
        "SOURCE_HASH_MISMATCH", "ROOT_IDENTITY_CHANGED", "STALE_RECEIPT",
    }:
        status = "STALE"
    elif code.startswith("JSON_") or code in {
        "BOM_REJECTED", "NUL_REJECTED", "UTF8_INVALID", "BINARY_CONTROLS", "SIZE_LIMIT", "SOURCE_LIMIT",
        "NOT_REGULAR_FILE", "UNSUPPORTED_FORMAT", "LINE_LIMIT", "QUERY_LIMIT", "QUERY_INVALID",
    }:
        status = "INVALID_SOURCE"
    else:
        status = "INTERNAL_ERROR"
    return failure(status, code, winerror)


def selected_file(raw):
    drive, parts = path_parts(raw)
    canonical(drive, parts)
    if not parts:
        raise ValueError("UNSAFE_PATH")
    if excluded_name(parts[-1]) or any(protected_name(part) for part in parts[:-1]):
        raise ValueError("SENSITIVE_PATH")
    name = parts[-1]
    fmt = text.path(name)
    parent = canonical(drive, parts[:-1])
    return parent, name, fmt


def line_breaks(raw):
    return [match.end() for match in LINE_BREAK.finditer(raw)]


def code_matches():
    try:
        return text.code_digest() == CODE_SHA256
    except ValueError as exc:
        if str(exc) == "INSTALLED_CODE_UNAVAILABLE":
            return False
        raise


def admit(raw_path):
    parent, name, fmt = selected_file(raw_path)
    # Verify the externally pinned code map before capturing any source bytes.
    contract.need(code_matches(), "CODE_CHANGED")
    with native_io.Directory(text.PRODUCT) as product, native_io.Directory(parent) as root:
        native_io.reject_membership(root, product)
        native_io.reject_membership(product, root)
        native_capture.validate_visible(root)
        with native_capture.open_metadata(root.handle, name, directory=False) as retained:
            meta = native_capture.visible_metadata(retained, False)
            contract.need(meta.size <= MAX_BYTES, "SOURCE_LIMIT")
            raw = native_capture.capture(root.handle, name, retained, meta, MAX_BYTES)
            contract.need(NON_TEXT_BYTES.search(raw) is None, "BINARY_CONTROLS")
            breaks = line_breaks(raw)
            lines = len(breaks) + bool(raw and (not breaks or breaks[-1] != len(raw)))
            contract.need(lines <= MAX_LINES, "LINE_LIMIT")
            native_capture.validate_visible(root)
            product.validate()
        root_identity = list(root.ids[-1])

    identity = {"root_id": "cli-file", "source_root": parent}
    row = {"path": name, "sha256": contract.digest(raw), "bytes": len(raw),
           "identity": list(meta.identity), "times": list(meta.times)}
    schema = text.schema_for([fmt])
    catalog = contract.canonical(dict(identity, schema=schema + ".candidate",
                                     scope=".", sources=[row]))
    policy = contract.canonical(dict(identity, schema=schema + ".policy",
                                    scope=".", root_identity=root_identity, enabled=True,
                                    formats=[fmt], allow_exact=[name], deny_exact=[],
                                    deny_prefixes=[]))
    authority = dict(identity, catalog_sha256=contract.digest(catalog),
                     policy_sha256=contract.digest(policy), code_sha256=CODE_SHA256)
    grant = contract.canonical(dict(authority, schema=schema + ".external-grant",
                                   formats=[fmt], batch_id="cli-file",
                                   external_admission_ref="explicit-file-argument"))
    return TextInput(catalog, policy, grant,
                     text.Authority(**authority, grant_sha256=contract.digest(grant)))


def search(query, files, *, limit=None, ignore_case=False):
    if files is None or len(files) != 1:
        return failure("INVALID_SOURCE", "EXACTLY_ONE_EXPLICIT_FILE_REQUIRED")
    if limit is not None and not 1 <= limit <= 10:
        return failure("INVALID_SOURCE", "OUTPUT_LIMIT")
    if not 1 <= len(query) <= MAX_QUERY_CHARACTERS or "\x00" in query:
        return failure("INVALID_SOURCE", "QUERY_LIMIT")
    try:
        needle = query.encode("utf-8", errors="strict")
    except UnicodeError:
        return failure("INVALID_SOURCE", "QUERY_INVALID")
    try:
        admitted = admit(files[0])
    except native_io.SafeIOError as exc:
        return failed_read(exc.code, exc.winerror, admitted=False)
    except OSError as exc:
        code = "ACCESS_DENIED" if exc.errno in (errno.EACCES, errno.EPERM) else "SOURCE_READ_FAILED"
        return failed_read(code, getattr(exc, "winerror", None), admitted=False)
    except ValueError as exc:
        code = str(exc)
        if not re.fullmatch("[A-Z][A-Z0-9_]{0,79}", code):
            code = "ADMISSION_FAILED"
        return failed_read(code, None, admitted=False)

    final = []
    response = literal_search.search([admitted], query, limit=1, _verified=final, _visible=True)
    if response["status"] not in ("COMPLETE", "NO_MATCH"):
        return failed_read(response["status"], response.get("winerror"), admitted=True)
    record, = final
    receipt = record["receipt"]
    path = str(PureWindowsPath(receipt["source_root"], receipt["relative_path"]))
    source = {"source_id": receipt["source_id"], "path": path,
              "sha256": receipt["source_hash"], "bytes": receipt["bytes"]}
    raw = record["report"]["text"].encode("utf-8")
    effective_limit = 1 if limit is None else limit
    count, spans = occurrences(comparable(raw, ignore_case), comparable(needle, ignore_case), effective_limit)
    breaks = line_breaks(raw) if count else []
    results = [citation(raw, breaks, start, end) for start, end in spans]
    remaining = count - len(results)
    payload = {
        "schema_version": SCHEMA, "status": "FOUND" if results else "NO_MATCH",
        "results": results, "source": source, "timestamp": response["timestamp"],
        "integrity_scope": response["currentness"], "limits": dict(LIMITS),
        "truncated": bool(remaining), "remaining_occurrences": remaining,
        "limitations": list(LIMITATIONS), "error": None,
    }
    if ignore_case or limit is not None:
        payload.update(schema_version=OPTIONS_SCHEMA, matching="ASCII_IGNORE_CASE" if ignore_case else "EXACT",
                       verified_occurrences=count, limits={**LIMITS, "results": effective_limit})
        if ignore_case:
            payload["limitations"][0] = "Plegado de mayúsculas ASCII (A–Z). La validez semántica queda sin evaluar."
    return payload, 0
