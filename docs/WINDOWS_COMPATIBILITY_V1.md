# Windows compatibility V1 - explicit migration, PARTIAL

Base: `83aa90a45546eba3fdd41f9fcda3667bed9a17a0`.
This additive API preserves original tests, V2 artifact schemas, V1 results,
MCP names, persistent memory and the Windows I/O provider unchanged.

## Read observation contract

`read_registered` returns only bounded captured bytes matching the supplied pin.
It does not attest freshness at ACK. An attempted write is not an effective
mutation. Callers and attack fixtures must record whether the write succeeded,
the actual bytes before/after, and whether a writer exception propagated into
the reader. Ordinary Windows sharing denial is commonly surfaced by Python CRT
as `PermissionError` with errno 13 and no winerror, not necessarily winerror 32.

| Observation | Required classification |
| --- | --- |
| Ordinary concurrent write blocked; actor handles denial; reader completes | Original pinned bytes may succeed; no `SOURCE_CHANGED` |
| Write denial propagates out of injected `os.read` | Existing `SOURCE_READ_FAILED`; bytes unchanged |
| Actual I/O failure while reading | `SOURCE_READ_FAILED`, without inferring mutation |
| Effective identity/metadata/size change observed during held-handle read | `SOURCE_CHANGED` |
| Completed read closes; bytes then change; next read uses old pin | `SOURCE_HASH_MISMATCH` (or independently observed change during that next read) |
| Bytes captured before later edit | Historical captured bytes remain valid as that observation |

The fourth row specifies evidence-driven behavior, not permission to weaken
Windows sharing to force a write. No native effective in-read mutation is claimed
by the acceptance suite: the ordinary writer is denied. Writable mappings,
malicious filters/admin/raw disk remain unqualified. POSIX code is unchanged;
no Linux run was performed. This is a common semantic contract with
platform-specific prevention/detection mechanisms, not universal OS qualification.

The original `test_toctou_changed_during_and_after_read` remains FAIL on Windows:
its mutation never succeeds, so its `SOURCE_CHANGED` assumption is incompatible.
Its later old-pin assertion is not reached. The separate V1 acceptance suite
performs and confirms an effective edit after close and checks the old pin.

## Publication migration

Import the opt-in API from `tools.source_publication_v1` in the repository:

```python
from tools.source_publication_v1 import publish_audit_v1, publish_verification_v1

report, manifest = publish_audit_v1(source_root, catalog, catalog_sha256, new_directory)
exit_code = publish_verification_v1(source_root, new_directory, new_verification_file)
```

Pass absolute ordinary drive paths on Windows. Output parents must already exist
and be physically disjoint from source/product trees; verifier output must also
be disjoint from artifacts. Use a fresh accessible D: TEMP outside the product
tree for tests that publish outputs. Existing CLI transactions are also supported.

`publish_audit_v1` delegates to `audit_and_write` and returns `(report, manifest)`
only after fresh admission, capture, publication, validation and handle close.
Failures raise; destinations are exclusively created, never overwritten/resumed.
`publish_verification_v1` reopens artifacts and sources inside `execute` custody,
prints the existing result envelope and returns its exit code: 0 PASS, 1 failure.
Invalid raw path arguments can raise before execute. Neither API accepts a report,
verification body or transferable/reusable custody session as authority.

Directory chains are held before admission/verification through publication and
close. This prevents root relocation; it does not hold every file through ACK.
Partial or unacknowledged output can remain after failure; presence of a manifest
or result file is not a success receipt. A saved FAIL is also possible. Consume
the whole operation return/exit status, then inspect its scoped result.

`write_artifacts` and `write_verification` still refuse on Windows with
`WINDOWS_SPLIT_PUBLICATION_REQUIRES_TRANSACTION` (explicit input collision may
retain `OUTPUT_OVERLAPS_INPUT`). Read-only audit/verification calls remain usable.
The historical split success tests remain ERROR: retaining their success contract
would reintroduce the demonstrated between-call relocation gap. There is no
transparent safe migration from an already serialized report to live custody.
The caller must explicitly select fresh transactional capture/verification.

`SOURCE_CURRENT_AT_ACK=NOT_PROVEN`.
`ARTIFACT_CURRENT_AT_ACK=NOT_PROVEN`.
Security qualification and overall historical compatibility remain PARTIAL.

## Validation separation

Historical suite membership comes from the exact base Git tree (227 tests).
`tests/test_windows_compatibility_v1.py` is an additional 8-test Windows acceptance
suite, not a replacement or exemption for historical failures. Full discovery
includes both (235 tests). A passing acceptance result cannot make the historical
or full suite PASS. Independent Sol XHigh attack evidence is delivered separately.
