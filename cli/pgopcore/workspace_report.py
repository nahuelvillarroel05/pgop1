"""Content-bound workspace search exports with exclusive local publication."""

import re

from pathlib import PureWindowsPath

from . import workspace as ws
from . import workspace_search
from .literal_projection import comparable

LEGACY_SCHEMA = "pgop.workspace-search-report.v1"
SCHEMA = "pgop.workspace-search-report.v2"
ID = re.compile(r"ws-report-([a-f0-9]{64})")
MAX_BYTES = 512 * 1024
LEGACY_POLICY = "local-ntfs-text-v1"
LEGACY_LIMITS = {
    "directories_deep": 5, "path_characters": 1024, "entries": 1000, "pages": 256,
    "registered_rows": 100, "corpus_bytes": 8 * 1024 * 1024, "source_bytes": 262144,
    "source_lines": 16384, "query_characters": 256, "results": 10,
    "cooperative_seconds": 30, "journal_entries": 512,
}
V2_EVIDENCE_FIELDS = {
    "revision", "registered_scan", "policy", "scope", "limits", "started_with_active_sources",
    "checked_sources", "logical_corpus_bytes", "logical_attempted_bytes", "successful_native_captured_bytes",
    "successful_native_captures", "partial", "truncated", "verified", "unavailable", "removed",
    "observed_at", "limitations", "query", "results", "matched_sources", "omitted_matching_sources",
    "verified_occurrences", "omitted_occurrences", "matching", "result_mode",
}


def create(registry, query, *, limit=None, ignore_case=False, all_matches=False):
    result, code = workspace_search.observe(registry, query=query, limit=limit,
                                            ignore_case=ignore_case, all_matches=all_matches)
    evidence = result["data"]
    if result["schema"] != workspace_search.OPTIONS_SCHEMA:
        evidence.update(matching=workspace_search.EXACT, result_mode=workspace_search.FIRST_PER_SOURCE)
    validate_evidence(registry.root, result["outcome"], evidence, SCHEMA)
    report = {
        "schema": SCHEMA, "type": "workspace-search", "status": result["outcome"],
        "workspace_identity": list(registry.root.ids[-1]),
        "source_currentness": "AT_CAPTURE_ONLY",
        "evidence": evidence,
    }
    raw = ws.contract.canonical(report)
    report_id = "ws-report-" + ws.contract.digest(raw)
    name = report_id + ".json"
    if len(raw) > MAX_BYTES:
        raise ws.WorkspaceError("REPORT_LIMIT", "El informe superó el tamaño permitido.", 3)
    with ws.io.created_file(registry.reports, name, raw):
        pass
    return ws.payload("report", result["outcome"], {
        **receipt(registry, report_id, raw, report), "action": "create",
    }), code


def receipt(registry, report_id, raw, report):
    return {
        "report_id": report_id, "sha256": report_id.removeprefix("ws-report-"),
        "artifact": "REPORT.json", "artifact_path": str(PureWindowsPath(registry.reports.path, report_id + ".json")),
        "bytes": len(raw), "integrity": "PASS", "author_identity": "NOT_VERIFIED",
        "current_sources_verified_by_this_receipt": False,
        "observed_at": report["evidence"]["observed_at"], "search_outcome": report["status"],
    }


def read(registry, report_id, *, show, offset=0, limit=8000):
    match = ID.fullmatch(report_id)
    if not match:
        raise ws.WorkspaceError("INVALID_REPORT_ID", "Usá el ID exacto que devolvió pgop report create.")
    if not (0 <= offset <= MAX_BYTES and 1 <= limit <= 16000):
        raise ws.WorkspaceError("INVALID_PAGE", "Usá un offset válido y una página de hasta 16000 caracteres.")
    try:
        raw = ws.read_bytes(registry.reports, report_id + ".json", MAX_BYTES)
    except ws.io.SafeIOError as exc:
        if exc.winerror in (2, 3):
            raise ws.WorkspaceError("REPORT_NOT_FOUND", "El informe no existe en este espacio de trabajo.", 4) from exc
        if exc.code == "SIZE_LIMIT":
            raise invalid_report() from exc
        raise
    if ws.contract.digest(raw) != match[1]:
        raise invalid_report()
    try:
        report = ws.contract.strict(raw)
        ws.contract.need(type(report) is dict and set(report) == {
            "schema", "type", "status", "workspace_identity", "source_currentness", "evidence",
        } and report["schema"] in (LEGACY_SCHEMA, SCHEMA) and report["type"] == "workspace-search"
            and report["workspace_identity"] == list(registry.root.ids[-1])
            and report["source_currentness"] == "AT_CAPTURE_ONLY", "REPORT_SCHEMA")
        ws.contract.need(ws.contract.canonical(report) == raw, "REPORT_CANONICAL")
        validate_evidence(registry.root, report["status"], report["evidence"], report["schema"])
        data = receipt(registry, report_id, raw, report)
    except (ValueError, RecursionError, KeyError, TypeError, ws.WorkspaceError) as exc:
        raise invalid_report() from exc
    if show:
        data.update(action="show", report=report)
    else:
        end = min(len(raw), offset + limit)
        data.update(action="read", content=raw[offset:end].decode("ascii"), offset=offset,
                    next_offset=end if end < len(raw) else None)
    return ws.payload("report", "VERIFIED_REPORT", data), 0


def verify_sources(root, evidence, limits, *, legacy):
    by_status, seen = {}, set()
    for name in ("verified", "unavailable", "removed"):
        sources = evidence[name]
        ws.contract.need(type(sources) is list and len(sources) <= limits["registered_rows"], "REPORT_SOURCES")
        rows = {}
        for row in sources:
            ws.supported_path(root.path, row["path"], legacy=legacy)
            ws.contract.need(row["id"] == ws.source_id(root, row["path"]) and row["id"] not in seen
                             and ws.contract.hash_value(row["sha256"])
                             and type(row["bytes"]) is int and 0 <= row["bytes"] <= limits["source_bytes"],
                             "REPORT_SOURCE")
            if name == "unavailable":
                ws.contract.need(type(row["status"]) is str and type(row["code"]) is str, "REPORT_SOURCE_STATUS")
            seen.add(row["id"])
            rows[row["id"]] = row
        by_status[name] = rows
    ws.contract.need(len(seen) <= limits["registered_rows"], "REPORT_SOURCES")
    return by_status


def validate_evidence(root, status, evidence, schema):
    need = ws.contract.need
    legacy = schema == LEGACY_SCHEMA
    limits = LEGACY_LIMITS if legacy else ws.LIMITS
    need(type(evidence) is dict and evidence["policy"] == (LEGACY_POLICY if legacy else ws.POLICY)
         and evidence["scope"] == "ACTIVE_REGISTERED_SOURCES"
         and type(evidence["observed_at"]) is str and 20 <= len(evidence["observed_at"]) <= 40
         and type(evidence["query"]) is str, "REPORT_EVIDENCE")
    mode, matching, limit = workspace_search.FIRST_PER_SOURCE, workspace_search.EXACT, limits["results"]
    if not legacy:
        need(set(evidence) == V2_EVIDENCE_FIELDS, "REPORT_EVIDENCE")
        mode, matching = evidence["result_mode"], evidence["matching"]
        limit = evidence["limits"]["effective_results"]
        need(type(limit) is int and 1 <= limit <= limits["results"]
             and mode in (workspace_search.FIRST_PER_SOURCE, workspace_search.ALL_MATCHES)
             and matching in (workspace_search.EXACT, workspace_search.ASCII_IGNORE_CASE), "REPORT_OPTIONS")
    need(evidence["limits"] == {**limits, "effective_results": limit}, "REPORT_LIMITS")
    ignore_case = matching == workspace_search.ASCII_IGNORE_CASE
    all_matches = mode == workspace_search.ALL_MATCHES
    if not legacy:
        need(evidence["limitations"] == workspace_search.limitations(ignore_case), "REPORT_LIMITATIONS")
    query = evidence["query"]
    need(1 <= len(query) <= limits["query_characters"] and "\0" not in query, "REPORT_QUERY")
    needle = comparable(query.encode("utf-8"), ignore_case)
    counts = ("checked_sources", "started_with_active_sources", "matched_sources",
              "omitted_matching_sources", "verified_occurrences", "omitted_occurrences")
    need(all(type(evidence[key]) is int and evidence[key] >= 0 for key in counts), "REPORT_COUNTS")
    sources = verify_sources(root, evidence, limits, legacy=legacy)
    hits = evidence["results"]
    verified, unavailable = sources["verified"], sources["unavailable"]
    matched = evidence["matched_sources"]
    occurrence_count = evidence["verified_occurrences"]
    output_total = occurrence_count if all_matches else matched
    need(type(hits) is list and matched <= len(verified) and len(hits) == min(output_total, limit)
         and evidence["checked_sources"] == len(verified)
         and evidence["started_with_active_sources"] == len(verified) + len(unavailable)
         and matched <= occurrence_count <= sum(row["bytes"] // len(needle) for row in verified.values())
         and evidence["omitted_occurrences"] == occurrence_count - len(hits),
         "REPORT_COUNTS")

    visible, end_by_source, previous_key = {}, {}, None
    for hit in hits:
        source = verified[hit["id"]]
        fields = ("byte_start", "byte_end", "line_start", "line_end", "additional_occurrences_in_source")
        need(all(type(hit[field]) is int for field in fields)
             and all(hit[key] == source[key] for key in ("path", "sha256", "bytes"))
             and 0 <= hit["byte_start"] < hit["byte_end"] <= source["bytes"]
             and hit["byte_end"] - hit["byte_start"] == len(needle)
             and type(hit["excerpt"]) is str
             and comparable(hit["excerpt"].encode("utf-8"), ignore_case) == needle
             and 1 <= hit["line_start"] <= hit["line_end"] <= limits["source_lines"]
             and hit["additional_occurrences_in_source"] >= 0, "REPORT_CITATION")
        key = (source["path"], hit["byte_start"])
        source_id = hit["id"]
        omitted = hit["additional_occurrences_in_source"]
        returned, previous_omitted = visible.get(source_id, (0, omitted))
        need((previous_key is None or previous_key < key) and (all_matches or returned == 0)
             and hit["byte_start"] >= end_by_source.get(source_id, 0)
             and omitted == previous_omitted
             and returned + 1 + omitted <= source["bytes"] // len(needle), "REPORT_CITATION_ORDER")
        visible[source_id] = returned + 1, omitted
        end_by_source[source_id] = hit["byte_end"]
        previous_key = key
    unseen = matched - len(visible)
    visible_occurrences = sum(returned + omitted for returned, omitted in visible.values())
    need(evidence["omitted_matching_sources"] == unseen
         and unseen <= occurrence_count - visible_occurrences
         and (unseen != 0 or occurrence_count == visible_occurrences), "REPORT_COUNTS")
    if not legacy:
        capacity = sorted((source["bytes"] // len(needle) for key, source in verified.items()
                           if key not in visible and source["bytes"] >= len(needle)), reverse=True)
        need(unseen <= len(capacity) and occurrence_count - visible_occurrences <= sum(capacity[:unseen]),
             "REPORT_COUNTS")
        validate_observation(evidence, verified, unavailable, limits)
    if all_matches and hits:
        need(all(omitted == 0 for source_id, (_, omitted) in visible.items()
                 if source_id != hits[-1]["id"]), "REPORT_CITATION_ORDER")
    ws.validate_scan_summary(root, evidence["registered_scan"])
    partial = evidence["registered_scan"]["partial"]
    need(type(partial) is bool and type(evidence["partial"]) is bool and type(evidence["truncated"]) is bool
         and evidence["partial"] == (partial or bool(unavailable))
         and evidence["truncated"] == (output_total > limit), "REPORT_COVERAGE")
    expected = "PARTIAL" if evidence["partial"] else "TRUNCATED" if evidence["truncated"] else "FOUND" if hits else "NO_MATCH"
    need(status == expected, "REPORT_STATUS")


def validate_observation(evidence, verified, unavailable, limits):
    fields = ("revision", "logical_corpus_bytes", "logical_attempted_bytes",
              "successful_native_captured_bytes", "successful_native_captures")
    need = ws.contract.need
    need(all(type(evidence[key]) is int for key in fields), "REPORT_OBSERVATION")
    revision, logical, attempted, captured, reads = (evidence[key] for key in fields)
    checked_bytes = sum(row["bytes"] for row in verified.values())
    corpus_bytes = checked_bytes + sum(row["bytes"] for row in unavailable.values())
    need(1 <= revision <= limits["journal_entries"] // 2
         and logical == corpus_bytes <= limits["corpus_bytes"]
         and 2 * checked_bytes <= captured <= attempted <= 2 * logical
         and 2 * len(verified) <= reads <= 2 * (len(verified) + len(unavailable)), "REPORT_OBSERVATION")


def invalid_report():
    return ws.WorkspaceError("REPORT_INTEGRITY", "El archivo del informe no coincide con su ID o su espacio de trabajo.", 3)


def human_lines(result):
    data = result["data"]
    if data["action"] == "read":
        lines = [data["content"]]
        if data["next_offset"] is not None:
            lines.append(f'Página siguiente: pgop report read {data["report_id"]} --offset {data["next_offset"]}')
        return lines
    lines = [
        f'{data["report_id"]} · resultado de búsqueda: {data["search_outcome"]}.',
        f'SHA-256 {data["sha256"]} · {data["bytes"]} bytes · {data["artifact_path"]}',
        "Informe histórico de la búsqueda. La vigencia de las fuentes puede haber cambiado.",
    ]
    if data["action"] == "show":
        evidence = data["report"]["evidence"]
        lines.append(f'{evidence["checked_sources"]} fuentes verificadas al crear el informe.')
        lines.extend(f'{hit["path"]}:{hit["line_start"]}-{hit["line_end"]} · {hit["excerpt"]}'
                     for hit in evidence["results"])
    else:
        lines.append(f'Para verlo: pgop report show {data["report_id"]}')
    return lines
