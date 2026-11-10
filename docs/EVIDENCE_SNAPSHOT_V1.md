# Historical evidence snapshot v1 (opt-in, PARTIAL security qualification)

The new `tools/audit_snapshot_v1.py` captures each explicitly pinned source once,
then analyzes immutable in-memory bytes. It publishes SNAPSHOT.json (hex bytes,
path/hash/length inventory and content ID), the existing V2 REPORT.json, a fixed
scope handoff and a versioned manifest. No target code executes. This does not
add RealEvidenceProfile V2 or change V1, memory.v1, public MCP or old artifacts.

Supply a catalog with sources sorted by path, claims sorted by claim_id and
canonical ASCII JSON (sorted keys, compact separators, no NaN or trailing
newline). `--catalog-sha256` pins exactly those bytes. Keep that hash outside the
bundle as a trusted authorization anchor; it covers paths, kinds, claims and
source pins. No secrets or automatic source discovery is involved.

```powershell
& .\.venv\Scripts\python.exe tools/audit_snapshot_v1.py --source-root SOURCE --catalog CATALOG --catalog-sha256 TRUSTED_HASH --output NEW_DIRECTORY
& .\.venv\Scripts\python.exe tools/verify_snapshot_v1.py --artifacts DIRECTORY --catalog-sha256 TRUSTED_HASH --output NEW_EXTERNAL_FILE
& .\.venv\Scripts\python.exe tools/verify_snapshot_v1.py --artifacts DIRECTORY --catalog-sha256 TRUSTED_HASH --source-root SOURCE
```

Windows arguments must be ordinary absolute paths within the existing qualified
native provider scope: AMD64 Windows10 workstation19045, local fixed NTFS,
ASCII path components and exact case, no reparse/junction/ADS/hardlinks. Directory
chains stay under custody from before admission through publication and close;
legacy split writers remain rejected. See [native I/O limits](WINDOWS_SAFE_IO_V2.md).
Linux retains no-follow descriptor reads/writes; this intervention does not claim
Linux execution unless independently recorded. POSIX rename races across reopened
directory paths do not gain the Windows transaction qualification from this API.

The independent verifier imports no producer, Engine or AST evaluator. It reads
each bundle member once, validates the external catalog pin, lengths/hashes and
snapshot ID, then recomputes AST units/coverage/relations and documentary claims
from the captured bytes. Fixed handoff prose is rederived exactly, so rehashing a
forged temporal claim cannot make it verified. It shares CPython AST and the
native I/O provider; it is not an independent parser, OS or provenance signer.

Successful statuses are `SNAPSHOT_ARTIFACTS_WRITTEN` and `SNAPSHOT_VERIFIED`.
They mean historical content and derivation, subject to declared partial AST
coverage/abstentions. Both `source_current_at_ack` and
`artifact_current_at_ack` are `NOT_PROVEN`. `--mode CURRENT_AT_ACK` rejects with
`SOURCE_CURRENT_AT_ACK_NOT_PROVEN`; historical bundles remain independently
verifiable. Optional source comparison returns per-path MATCH/MISMATCH,
CHANGED, READ_FAILED or UNAVAILABLE_OR_UNSAFE under
POINT_OBSERVATIONS_NOT_INVARIANCE. A successful MATCH does not mean invariance
to ACK. A mismatch after ACK does not invalidate previously captured content.

Snapshot ID is the SHA256 of the versioned path/hash/length inventory, not a
timestamp, physical object ID or atomic multi-file instant. Separate pinned
files may have been read at separate times. Caller pins authenticate content
only; origin is CALLER_PIN_NOT_SIGNED_ATTESTATION. Recreating coherent identical
bytes later proves neither continuous retention nor a previous successful ACK.
Raw disk, hostile admin/kernel, arbitrary filters and preexisting writable
mappings remain unqualified. No WORM disk or signed observation is promised.

Each output uses exclusive creation, flush/readback and manifest-last writes.
An exception in validation/flush/readback/close or cancellation emits no success.
Partial output stays preserved and retry refuses; a manifest or saved verifier
body alone is CONTENT_ONLY_ACK_REQUIRED. Only a successful outer return or CLI
ACK after close establishes operation completion. Files can change after their
handles close before ACK; even artifact currency at ACK is NOT_PROVEN. stdout
delivery and power-loss persistence are not proven by an internal return.

Bounds: 64 sources and 64 claims, 262144 bytes/source and canonical catalog;
snapshot JSON <=36MB, report <=512MB, handoff/manifest <=1MB each. Existing AST
node/depth/unit/output budgets and <=6s worker timeout remain. JSON/hex creates
memory copies; there is no total operation deadline, disk quota, verifier memory
isolation or independent per-source verifier timeout. Unmeasured peak memory is
NOT_MEASURED. These limits and the unchanged Windows negative tests prevent a
full security or full-suite PASS claim by implication.
