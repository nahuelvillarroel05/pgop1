"""Current evidence from the exact set of registered NTFS identities."""

from contextlib import ExitStack, contextmanager
from itertools import zip_longest
import time

from . import workspace as ws
from .literal_projection import citation, comparable, occurrences
from .text_bytes import content_start

OPTIONS_SCHEMA = "pgop.workspace-search.v2"
EXACT = "EXACT"
ASCII_IGNORE_CASE = "ASCII_IGNORE_CASE"
FIRST_PER_SOURCE = "FIRST_PER_SOURCE"
ALL_MATCHES = "ALL_MATCHES"

CANONICAL_LIMITATIONS = [
    "Coincidencia literal sensible a mayúsculas; validez semántica y ejecución sin evaluar.",
    "Registro local como alcance; archivos nuevos requieren otro scan.",
    "Revalidación por fuente durante la operación; sin instantánea multiarchivo ni vigencia futura.",
]


def needle_for(query):
    if not 1 <= len(query) <= ws.LIMITS["query_characters"] or "\0" in query:
        raise ws.WorkspaceError("INVALID_QUERY", "Indicá entre 1 y 256 caracteres de texto sin NUL.")
    try:
        return query.encode("utf-8")
    except UnicodeError:
        raise ws.WorkspaceError("INVALID_QUERY", "Indicá texto UTF-8 válido.") from None


def capture(root, row, on_read):
    _, raw, breaks = capture_file(root, row["path"], row=row, on_read=on_read)
    return raw, breaks


@contextmanager
def opened_file(root, path):
    fmt = ws.supported_path(root.path, path)
    *parts, filename = ws.io.relative(path)
    with ExitStack() as stack:
        current = root
        for component in parts:
            current = stack.enter_context(ws.child(current, component, source=True))
        retained = stack.enter_context(ws.native.open_metadata(current.handle, filename, directory=False))
        before = ws.safe_meta(retained, False)
        ws.visible_directories(current)
        yield fmt, current, filename, retained, before


def preview_file(root, path):
    with opened_file(root, path) as (_, _, _, _, before):
        ws.contract.need(before.size <= ws.LIMITS["source_bytes"], "SOURCE_LIMIT")
        return before


def capture_file(root, path, *, row=None, expected=None, listed=None, on_read=None):
    """Read one file through the same native path as a registered source."""
    with opened_file(root, path) as (fmt, current, filename, retained, before):
        if expected is not None:
            ws.contract.need(before == expected, "SOURCE_CHANGED")
        if listed is not None:
            ws.native.matches(listed, before)
        if row is not None:
            ws.contract.need(list(before.identity) == row["identity"], "SOURCE_IDENTITY_CHANGED")
            ws.contract.need(before.size == row["bytes"], "SOURCE_SIZE_CHANGED")
            ws.contract.need(list(before.times) == row["times"], "SOURCE_CHANGED")
        ws.contract.need(before.size <= ws.LIMITS["source_bytes"], "SOURCE_LIMIT")
        raw = ws.native.capture(current.handle, filename, retained, before, before.size)
        if on_read is not None:
            on_read(len(raw))
        sha = ws.contract.digest(raw)
        if row is not None:
            ws.contract.need(sha == row["sha256"], "SOURCE_HASH_MISMATCH")
        _, breaks = ws.validated_text(raw, fmt)
        ws.safe_meta(retained, False)
        ws.visible_directories(current)
        policy = ws.row_policy(fmt, raw)
        if row is None:
            binding = [root.path, list(root.ids[-1]), path, list(before.identity), list(before.times), sha]
            row = {"id": "capture-" + ws.contract.digest(ws.contract.canonical(binding)), "path": path,
                   "bytes": len(raw), "sha256": sha, "identity": list(before.identity),
                   "times": list(before.times), "captured_at": ws.now(), "policy": policy, "status": "OBSERVED"}
        else:
            ws.contract.need(row["policy"] == policy, "SOURCE_CHANGED")
        return row, raw, breaks


def limitations(ignore_case):
    if not ignore_case:
        return CANONICAL_LIMITATIONS
    return ["Plegado de mayúsculas ASCII (A–Z). Validez semántica y ejecución sin evaluar.",
            *CANONICAL_LIMITATIONS[1:]]


def observed_source(row):
    return {"id": row["id"], "path": row["path"], "bytes": row["bytes"], "sha256": row["sha256"]}


def near_hit(raw, breaks, hit, lines):
    first = max(1, hit["line_start"] - lines)
    last = hit["line_end"] + lines
    start, end = hit["byte_start"], hit["byte_end"]
    left = raw[breaks[first - 2] if first > 1 else content_start(raw):start].decode("utf-8")
    right = raw[end:breaks[last - 1] if last <= len(breaks) else len(raw)].decode("utf-8")
    shown_start = start - len(left[-500:].encode("utf-8"))
    shown_end = end + len(right[:500].encode("utf-8"))
    return {**citation(raw, breaks, shown_start, shown_end),
            "shortened": len(left) > 500 or len(right) > 500}


def projected_hits(raw, breaks, source, needle, budget, ignore_case, context_lines):
    prefix = content_start(raw)
    count, spans = occurrences(comparable(raw[prefix:], ignore_case), needle, budget)
    hits = []
    for start, end in spans:
        hit = {**source, **citation(raw, breaks, start + prefix, end + prefix),
               "additional_occurrences_in_source": count - min(count, budget)}
        if context_lines is not None:
            hit["context"] = near_hit(raw, breaks, hit, context_lines)
        hits.append(hit)
    return count, hits


def observe_file(root, row, query, *, ignore_case, all_matches, context_lines, source_guard):
    """Revalidate one explicit capture without assigning it a registry row."""
    needle = comparable(needle_for(query), ignore_case)
    reference = observed_source(row)
    raw, breaks = capture(root, row, lambda _: None)
    source_guard(raw, row["path"])
    limit = ws.LIMITS["results"] if all_matches else 1
    count, hits = projected_hits(raw, breaks, reference, needle, limit, ignore_case, context_lines)
    truncated = all_matches and count > limit
    data = {"scope": "EXPLICIT_FILE_CAPTURE", "revision": None, "registered_scan": None,
            "limits": {**ws.LIMITS, "effective_results": limit}, "partial": False, "truncated": truncated,
            "verified": [reference], "unavailable": [], "removed": [], "started_with_active_sources": 1,
            "checked_sources": 1, "results": hits, "matched_sources": int(bool(count)),
            "verified_occurrences": count, "omitted_occurrences": count - len(hits),
            "omitted_matching_sources": 0, "observed_at": ws.now()}
    return ws.payload("search", "TRUNCATED" if truncated else "FOUND" if hits else "NO_MATCH", data)


def observe(registry, *, query=None, limit=None, ignore_case=False, all_matches=False,
            selected=None, context_lines=None, source_guard=None, diverse=False):
    if registry.value["scanned_at"] is None:
        raise ws.WorkspaceError("SCAN_REQUIRED", "Registrá las fuentes con pgop scan y repetí la operación.")
    needle = comparable(needle_for(query), ignore_case) if query is not None else None
    limit = ws.LIMITS["results"] if limit is None else limit
    if not 1 <= limit <= ws.LIMITS["results"]:
        raise ws.WorkspaceError("INVALID_RESULT_LIMIT", "Usá entre 1 y 10 resultados con --limit.")
    if not ws.search.code_matches():
        raise ws.WorkspaceError("CODE_CHANGED", "Reinstalá la wheel antes de leer fuentes.", 1)

    rows = registry.value["rows"]
    if selected is not None:
        rows = [row for row in rows if row["id"] in selected]
    active = [row for row in rows if row["status"] == "REGISTERED"]
    removed = [observed_source(row) for row in rows if row["status"] == "REMOVED"]
    deadline = time.monotonic() + ws.LIMITS["cooperative_seconds"]
    attempted = read = reads = 0
    failed = {}
    hits, matched_sources, verified_occurrences = [], 0, 0
    groups = []

    def record_read(size):
        nonlocal read, reads
        read += size
        reads += 1

    # Observe each registered version twice. A change or failure affects only its own file.
    for pass_number in (1, 2):
        for row in active:
            key = row["id"]
            if key in failed:
                continue
            source = observed_source(row)
            if time.monotonic() >= deadline:
                failed[key] = {**source, "status": "NOT_VERIFIED", "code": "SEARCH_TIME_LIMIT"}
                continue
            attempted += row["bytes"]
            try:
                raw, breaks = capture(registry.root, row, record_read)
                if source_guard is not None and pass_number == 2:
                    source_guard(raw, row["path"])
            except (ws.io.SafeIOError, ValueError, OSError) as exc:
                failed[key] = {**source, **ws.classify(exc)}
                continue
            if pass_number == 2 and needle is not None:
                budget = limit if diverse else limit - len(hits)
                if not all_matches:
                    budget = min(1, budget)
                count, source_hits = projected_hits(raw, breaks, source, needle, budget, ignore_case, context_lines)
                verified_occurrences += count
                matched_sources += bool(count)
                if diverse and source_hits:
                    groups.append(source_hits)
                else:
                    hits.extend(source_hits)
    registry.root.validate()
    if diverse:
        for batch in zip_longest(*groups):
            hits.extend(hit for hit in batch if hit is not None)
            if len(hits) >= limit:
                break
        hits = hits[:limit]
        displayed = {}
        for hit in hits:
            displayed[hit["id"]] = displayed.get(hit["id"], 0) + 1
        for group in groups:
            omitted = group[0]["additional_occurrences_in_source"] + len(group) - displayed.get(group[0]["id"], 0)
            for hit in group:
                hit["additional_occurrences_in_source"] = omitted

    available = [observed_source(row) for row in active if row["id"] not in failed]
    scan = registry.value["scan"]
    partial = bool(failed) or scan["partial"]
    truncated = (verified_occurrences if all_matches else matched_sources) > limit
    if partial:
        outcome = "PARTIAL"
    elif truncated:
        outcome = "TRUNCATED"
    elif query is None:
        outcome = "PASS" if active else "EMPTY"
    else:
        outcome = "FOUND" if hits else "NO_MATCH"
    data = {
        "revision": registry.revision, "registered_scan": scan,
        "policy": ws.POLICY, "scope": "ACTIVE_REGISTERED_SOURCES",
        "limits": {**ws.LIMITS, "effective_results": limit},
        "started_with_active_sources": len(active), "checked_sources": len(available),
        "logical_corpus_bytes": sum(row["bytes"] for row in active),
        "logical_attempted_bytes": attempted, "successful_native_captured_bytes": read,
        "successful_native_captures": reads, "partial": partial, "truncated": truncated,
        "verified": available, "unavailable": list(failed.values()), "removed": removed,
        "observed_at": ws.now(), "limitations": limitations(ignore_case),
    }
    if query is not None:
        data.update(query=query, results=hits, matched_sources=matched_sources,
                    omitted_matching_sources=matched_sources - len({hit["id"] for hit in hits}),
                    verified_occurrences=verified_occurrences, omitted_occurrences=verified_occurrences - len(hits))
    result = ws.payload("verify" if query is None else "search", outcome, data)
    if ignore_case or all_matches:
        result["schema"] = OPTIONS_SCHEMA
        data.update(matching=ASCII_IGNORE_CASE if ignore_case else EXACT,
                    result_mode=ALL_MATCHES if all_matches else FIRST_PER_SOURCE)
    return result, 3 if partial or truncated else 0


def human_lines(result):
    data, outcome = result["data"], result["outcome"]
    lines = [f'{outcome} · {data["checked_sources"]}/{data["started_with_active_sources"]} fuentes vigentes durante la lectura.']
    if "results" in data:
        lines.extend(
            f'{hit["path"]}:{hit["line_start"]}-{hit["line_end"]} · {hit["excerpt"]} · SHA-256 {hit["sha256"]}'
            for hit in data["results"]
        )
        if outcome == "NO_MATCH":
            lines.append("El texto no apareció en las fuentes registradas con las opciones elegidas.")
        if data["omitted_matching_sources"]:
            lines.append(f'{data["omitted_matching_sources"]} fuentes con coincidencias quedaron fuera del tope de salida.')
        if data["omitted_occurrences"]:
            lines.append(f'Coincidencias adicionales sin cita: {data["omitted_occurrences"]}.')
    for row in data["unavailable"]:
        lines.append(f'  {row["path"]} · {row["status"]} ({row["code"]})')
    if data["partial"]:
        lines.append("Cobertura parcial. Revisá los permisos y usá pgop scan --refresh si querés registrar los cambios.")
    elif not data["started_with_active_sources"]:
        lines.append("El registro activo está vacío. Usá pgop scan para buscar fuentes elegibles.")
    return lines
