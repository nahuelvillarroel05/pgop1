# Windows safe I/O V2 - experimental, PARTIAL qualification

The opt-in AST V2 producer and independent source verifier select
`runtime/candidate/windows_safe_io_v2.py` on Windows. V1, captured-report memory,
public profiles, schemas, receipts and the six MCP tools retain their contracts.
The POSIX implementation body is preserved. Linux regression has not been run
for this intervention; publication requires that separate validation.

Qualified observations are limited to native AMD64 Windows 10 workstation build
19045 with local fixed NTFS. Other builds, emulation, architectures, nonfixed
volumes and non-NTFS fail closed. All Windows CLI filesystem arguments must be
absolute ordinary drive paths; relative roots are currently unsupported. The
provider validates components before normalization: ASCII letters/digits,
underscore/dot/hyphen/interior spaces; no reserved DOS names, ADS, tilde/8.3,
trailing dot/space, traversal, UNC/NT/device namespaces, NUL or Unicode filename
aliases. Returned basename must match exact case. Unicode source CONTENT and
Python identifiers are unaffected. This is a deliberately narrower filename
scope, not Unicode/case normalization.

A drive-root handle is validated; descendants open one component at a time via
NtCreateFile RootDirectory, OPEN_REPARSE_POINT and OBJ_DONT_REPARSE. Every actual
handle is checked for disk type, directory/file type, reparse/tag, offline/recall/
encryption attributes, volume/128-bit identity, size and link count. Data is read
through a CRT descriptor owning that same handle. Sources with multiple hardlinks
are rejected; no claim about external hardlink provenance is made. Bytes are
bounded, rechecked on the same handle and SHA-256-pinned. Ancestors remain open
through completion and are rechecked. No resolve/stat/prefix check authorizes a
later path data open.

FILE_SHARE_READ excludes ordinary concurrent writers and deletion/rename. It does
NOT freeze attribute-only opens: a controlled attribute-only handle successfully
turned existing and newly created empty directories into junctions on this host.
Subsequent relative reads/creates rejected; no exterior sentinel was read or
changed. Directory/target/output rename actors and direct file/directory symlinks,
junction chains, hardlinks, output collisions and injected partial writes are
covered by native tests. Finite fixture observations are not a formal race proof.

Writers use FILE_CREATE, never overwrite. Output identity ancestry is checked
against source/repository (and artifact input for verifier). A newly created
artifact directory cannot already contain the existing catalog; exclusive
creation prevents replacing its file or existing parent directory. The catalog
parent is not categorically prohibited: catalog and output may be siblings.
Verifier report/pages output names remain excluded even if input disappeared.
All artifact file handles remain exclusive through manifest publication; each
file is flushed and read back by its own handle. Manifest is last. Failed writes
may retain partial or complete-but-unacknowledged files, including a manifest if
a later check/flush/close fails. Writer success requires its return/exit status;
manifest existence alone is not a success receipt. No path-based rollback or
retry over an existing output is performed. A separate verifier must reopen and
recompute sources, AST, spans, coverage, identities, membership and hashes.
It shares the low-level I/O provider, not producer AST/evaluation code.

Global result remains PARTIAL. API documentation has omissions concerning the
specific directory options/OBJECT_ATTRIBUTES combination; exact-host behavior
does not establish support across Windows. Arbitrary filters, malicious OS/admin,
raw disk and preexisting writable mappings are unqualified. NTFS alone does not
identify every filter/provider; cloud reparse/offline/recall objects are rejected,
but absence of those markers does not certify a pristine filesystem. No atomic
snapshot, I/O wall-time guarantee, disk quota or verifier resource isolation is
claimed. Parser subprocess timeout and existing finite budgets remain in force.

The original POSIX mutation test is retained unchanged. On Windows its attempted
write is denied, so its assumption that the source changed is false; the suite
retains a FAIL instead of weakening sharing or changing the expected result.
Default owner-profile TEMP ancestry may be unreadable to a sandbox account;
use an explicitly selected accessible local NTFS fixture TEMP to qualify that
scope, recording both the failed attempt and selected environment. Do not change
ACL, elevation or script policy to hide an inaccessible ancestry.

Design references:
- [NtCreateFile](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile)
- [CreateFileW sharing](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [Handle information](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfileinformationbyhandleex)
- [OBJECT_ATTRIBUTES](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wudfwdm/ns-wudfwdm-_object_attributes)
- [Reparse operations model](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/4aeefef8-92c3-4abc-af7a-a610caf8a165)

Cross-operation root identity qualification: CLI producer retains the original
source and catalog-parent handle chains from before analysis through publication;
CLI verifier retains source and artifact/input parent chains through output.
This prevents rename/replacement of those root objects during each CLI transaction.
Split library calls (audit_catalog followed later by write_artifacts, or
verify_report followed later by write_verification) do not carry root identity in
the published report schema. Their caller must retain a Directory context across
both calls if it needs transaction-wide object disjointness. The old split API
alone remains unqualified for hostile replacement BETWEEN calls; independent
review reproduced that gap before the CLI transaction fix. Its source bytes were
not overwritten, but output landed inside the renamed original admitted root.
Per-operation safe path traversal does not establish cross-operation root custody.
This is another explicit reason the whole intervention remains PARTIAL.

## E1 custody convergence update (2026-11-10)

The preceding split-call guidance is historical. On Windows, `write_artifacts`
and `write_verification` now refuse split publication with
`WINDOWS_SPLIT_PUBLICATION_REQUIRES_TRANSACTION` (an existing explicit input-name
collision can still report `OUTPUT_OVERLAPS_INPUT`). Keeping a caller-owned
Directory does not exempt a split writer. Serialized reports carry no custody.

Use `tools.audit_source_v2.audit_and_write(source_root, catalog_path,
catalog_sha256, output)` or the existing producer CLI. This complete operation
opens source, product, catalog-parent and output-parent ancestor chains before
admission, captures internally and returns `(report, manifest)` only after all
handles close. Catalog parent is retained; its entire subtree is not excluded.
The source/product trees must be physically disjoint from the new destination.

Verifier CLI and `tools.verify_source_v2.execute(args)` retain source, product,
artifact/report/pages parents and output-parent chains before verification through
output/close. A verifier never accepts a caller-supplied verification body as
publication authority. Read-only verify_report/read_artifacts remain available.

There are no transferable custody tokens or reusable sessions. Each whole call
owns fresh handles; concurrent calls share no operation state and exclusive
creation arbitrates destination collisions. Private byte sinks and low-level
safe_create primitives do not attest provenance and are not isolation boundaries
against arbitrary Python running inside the process. No public MCP names, report
schemas, POSIX I/O bodies, error classifications or V1/memory behavior changed.
The two original Windows split-writer success expectations intentionally fail;
original test files remain unchanged. Full suite is not declared PASS.

Independent E1 boundary observation: ordinary source-file bytes can change after
verify_report finishes and before the verification file is written; the verifier
can still return PASS for its earlier observation. Directory custody prevents
root/ancestry relocation; it does not retain every source-file handle or provide
an atomic snapshot through output/ACK. A later independent verification detects
the changed pin. Do not interpret a saved PASS as proof that source bytes remain
unchanged at publication time or afterward.
