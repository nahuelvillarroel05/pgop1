"""Opt-in located literal retrieval over externally admitted text acquisitions.

No source admission, directory discovery, index, AST, report renderer or model.
Caller-held current authority and trusted code/host remain prerequisites.
"""
from datetime import datetime, timezone
from pathlib import Path
import errno
import re

from .text_input import TextInput
from . import acquisition_text_v1 as T
from . import selection_contract_v1 as C

SCHEMA = 'pgop1.search.literal.v1'
VERSION = '1.0.0-experimental'
MAX_BATCHES = 32
MAX_SOURCES = 1024
MAX_BYTES = 16777216
MAX_OUTPUT_BYTES = 65536


def _acquire(value, visible=False):
    return T.acquire(value.catalog_raw, value.policy_raw, value.grant_raw, value.authority, visible=visible)


def _fingerprint(result):
    # Durations vary. Every source identity, metadata time, pin and exact captured
    # extraction must stay identical across the two independently checked reads.
    return C.digest(C.canonical([
        {'report': row['report'],
         'receipt': {k: v for k, v in row['receipt'].items()
                     if k not in {'read_ms', 'extract_ms'}}}
        for row in result['records']]))


def literal_span(raw, needle):
    # Shared first-match location and nonoverlapping exact-match count.
    start = raw.find(needle)
    if start >= 0:
        return start, start + len(needle), raw.count(needle)
    return None


def _filter(value, maximum, allowed=None):
    if value is None:
        return None
    C.need(type(value) in (list, tuple) and 1 <= len(value) <= maximum
           and all(type(v) is str for v in value), 'FILTER_SCHEMA')
    C.need(len(set(value)) == len(value), 'FILTER_SCHEMA')
    if allowed is not None:
        C.need(set(value) <= set(allowed), 'SOURCE_NOT_ADMITTED')
    return frozenset(value)


def search(source_inputs, literal, *, roots=None, paths=None, formats=None,
           limit=10, max_output_bytes=MAX_OUTPUT_BYTES, _verified=None,
           _exact_sources=None, _visible=False):
    """Return one first byte span per matching document, with stable ranking.

    Score is the number of nonoverlapping, case-sensitive UTF8 occurrences.
    All inputs are authenticated before source captures. Any failure suppresses
    the entire current result. Revalidation is an interval, not a future ACK or
    atomic multisource snapshot. No returned match is a documentary truth claim.
    """
    try:
        C.need(type(literal) is str and 1 <= len(literal) <= 256, 'QUERY_LIMIT')
        try:
            needle = literal.encode('utf8', errors='strict')
        except UnicodeError:
            raise ValueError('QUERY_INVALID') from None
        C.need(b'\x00' not in needle, 'QUERY_INVALID')
        C.need(type(limit) is int and 1 <= limit <= 10, 'OUTPUT_LIMIT')
        C.need(type(max_output_bytes) is int
               and 128 <= max_output_bytes <= MAX_OUTPUT_BYTES, 'OUTPUT_LIMIT')
        C.need(type(source_inputs) in (list, tuple)
               and 1 <= len(source_inputs) <= MAX_BATCHES, 'BATCH_LIMIT')
        inputs = tuple(source_inputs)
        catalogs = []
        root_bindings = {}
        source_keys = set()
        total_bytes = 0
        for value in inputs:
            C.need(type(value) is TextInput, 'SOURCE_CONTEXT_REQUIRED')
            catalog, policy, _ = T.authenticate(value.catalog_raw, value.policy_raw,
                                                value.grant_raw, value.authority)
            rid = value.authority.root_id
            binding = (value.authority.source_root, tuple(policy['root_identity']),
                       value.authority.policy_sha256)
            C.need(rid not in root_bindings or root_bindings[rid] == binding,
                   'ROOT_AUTHORITY')
            root_bindings[rid] = binding
            C.need(len(root_bindings) <= 4, 'ROOT_LIMIT')
            for row in catalog['sources']:
                key = (rid, row['path'].lower())
                C.need(key not in source_keys, 'DUPLICATE_SOURCE')
                source_keys.add(key)
                total_bytes += row['bytes']
            C.need(len(source_keys) <= MAX_SOURCES and total_bytes <= MAX_BYTES,
                   'BUDGET_EXCEEDED')
            catalogs.append(catalog)
        bindings = list(root_bindings.values())
        for i, (root, identity, _) in enumerate(bindings):
            for other, other_identity, _ in bindings[i + 1:]:
                a, b = Path(root), Path(other)
                C.need(identity != other_identity and not a.is_relative_to(b)
                       and not b.is_relative_to(a), 'ROOT_OVERLAP')
        wanted_roots = _filter(roots, 4, root_bindings)
        wanted_paths = _filter(paths, 128)
        if wanted_paths is not None:
            for name in wanted_paths:
                T.path(name)
        wanted_formats = _filter(formats, len(T.FORMATS), T.FORMATS)
        selected = [v for v in inputs
                    if wanted_roots is None or v.authority.root_id in wanted_roots]
        first = [_acquire(v, _visible) for v in selected]
        hits = []
        searched = 0
        for value, result in zip(selected, first):
            for row in result['records']:
                receipt = row['receipt']
                name = receipt['relative_path']
                if _exact_sources is not None and (receipt['root_id'], name) not in _exact_sources:
                    continue
                if wanted_paths is not None and name not in wanted_paths:
                    continue
                if wanted_formats is not None and receipt['format'] not in wanted_formats:
                    continue
                searched += 1
                raw = row['report']['text'].encode('utf8')
                span = literal_span(raw, needle)
                if span is None:
                    continue
                start, end, score = span
                hits.append(dict(
                    source_ref=receipt['root_id'] + '/' + name,
                    source_id=receipt['source_id'], root_id=receipt['root_id'],
                    relative_path=name, sha256=receipt['source_hash'],
                    format=receipt['format'], byte_start=start,
                    byte_end=end, quote=literal,
                    score=score, score_reason='EXACT_LITERAL_OCCURRENCES',
                    catalog_sha256=receipt['catalog_digest'],
                    policy_sha256=receipt['policy_digest'],
                    currentness='REVALIDATED_READ_INTERVAL_NOT_FUTURE_ACK',
                    truth='NOT_PROVEN', execution='NOT_PERFORMED'))
        hits.sort(key=lambda h: (-h['score'], h['root_id'],
                                 h['relative_path'], h['byte_start']))
        # Reacquisition uses original current caller-held authority, never a
        # cached extraction or a grant recovered from stored search output.
        verified = []
        for value, before in zip(selected, first):
            after = _acquire(value, _visible)
            C.need(_fingerprint(before) == _fingerprint(after), 'STALE_RECEIPT')
            if _verified is not None:
                verified.extend(after['records'])
        result = dict(schema=SCHEMA, version=VERSION,
                      status='COMPLETE' if hits else 'NO_MATCH',
                      hits=hits[:limit], total_matches=len(hits),
                      remaining=max(0, len(hits) - limit),
                      admitted_sources=sum(len(r['records']) for r in first),
                      searched_sources=searched,
                      logical_source_bytes=sum(row['receipt']['bytes']
                                               for r in first for row in r['records']) * 2,
                      currentness='REVALIDATED_READ_INTERVAL_NOT_ATOMIC_OR_FUTURE_ACK',
                      claim_verdict='NOT_APPLICABLE', authority_effect='NONE',
                      timestamp=datetime.now(timezone.utc).isoformat())
        C.need(len(C.canonical(result)) <= max_output_bytes, 'BUDGET_EXCEEDED')
        if _verified is not None:
            _verified.extend(verified)
        return result
    except (ValueError, OSError, KeyError, TypeError) as exc:
        code = getattr(exc, 'code', str(exc))
        if not isinstance(exc, ValueError) or not re.fullmatch('[A-Z][A-Z0-9_]{0,79}', code):
            if isinstance(exc, OSError):
                code = ('ACCESS_DENIED' if exc.errno in (errno.EACCES, errno.EPERM)
                        else 'SOURCE_READ_FAILED')
            else:
                code = 'SOURCE_UNAVAILABLE'
        return dict(schema=SCHEMA, version=VERSION, status=code, hits=[],
                    winerror=getattr(exc, 'winerror', None),
                    current_content_returned=False, authority_effect='NONE')
