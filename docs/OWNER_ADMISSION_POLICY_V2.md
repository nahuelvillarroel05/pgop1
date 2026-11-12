# Owner source admission V2 — opt-in bounded Windows contract

E7 V1 is preserved byte for byte. LEGACY_V1_DOES_NOT_ENFORCE_OWNER_DENY.
V1's caller-authenticated catalog accepts private/canary.py if otherwise valid.
N17 V1 remains an exposed campaign-policy failure, not an NTFS bypass or a blind
holdout. V2 adds an explicit mandatory owner-policy boundary to its own API,
producer CLI and independent verifier. It does not retrofit guarantees onto V1,
E3/E4/snapshot APIs, the six public MCP tools or arbitrary caller filesystem I/O.

## Authority and input format

The caller constructs candidate.admission_contract_v2.AuthorityContext with
source_root, catalog_sha256, selection_policy_sha256, admission_policy_sha256,
code_sha256. These anchors must come from the owner's trusted channel, separately
from the catalog. V2 does not authenticate a human, provide signatures or resist
hostile Python running in its process. A caller who forges/replaces this context
controls authorization. A hash supplied by the catalog is not owner authority.

Direct API: candidate.source_selection_v2.select_catalog(catalog_raw,
selection_policy_raw, admission_policy_raw, code_raw, authority) returns the V2
plan, captured bytes and AST reports. All raw inputs are canonical ASCII JSON
bytes, at most262144 bytes each; dictionaries, missing context, missing policy,
wrong pins, duplicate keys, noncanonical JSON and unknown fields are rejected.
The unchanged V1 catalog/selection-policy/code-manifest schemas still apply;
code closure must additionally include all four V2 runtime/CLI/verifier files.
Actual code bytes are checked using the installed Windows provider before any
source content capture. Product and source roots must be physically disjoint.
The returned dictionary is not a publication receipt.

Owner policy schema pgop1.selection-admission-policy.v2 has exactly these keys:
schema, source_root, scope, case, deny_prefixes, deny_components, deny_exact,
allow_exact. case must be ascii-insensitive. source_root and scope must equal the
caller-authorized root and catalog scope; root separator spelling may differ.
Root case is exact; provider case validation remains exact. Rules use root-relative
forward-slash paths. Only the existing provider's restricted ASCII names are
supported; no traversal, ADS, drive/UNC/device path, Unicode filename alias,
wildcard, implicit pattern expansion or normalization repair. V1 sensitive path
restrictions and budgets also apply, including the32-selected limit.

Each rule list is sorted, has at most256 strings of at most1024 characters and
has no duplicate/case collision. Prefix directory components must be identifiers
and end in /. Exact paths must be valid .py module paths. Component rules are
single valid provider components. Prefixes and exact rules must be descendants
of scope when scope is not '.'. Component rules inherit at all depths inside
scope. No rule can broaden scope. Empty lists are explicit, valid choices.
Canonical policy normalization preserves root/scope and lowercases and sorts the
four rule lists; both raw owner-policy and normalized-policy SHA256 are reported.

Deny wins over allow. deny_prefixes=['private/'] rejects private/a.py and
Private/a.py, including private/__init__.py; it permits privateer.py and
pkg/private/a.py. deny_components=['private'] also rejects pkg/private/a.py.
deny_exact matches the full relative filename case-insensitively. allow_exact=[]
permits every otherwise valid path; a nonempty allow_exact restricts catalog
membership to those full relative paths, still subject to all denies. There is
no unconditional global private-directory ban. Owner policies can admit private/
when no deny applies. Prefix matching observes the terminating slash boundary.

## Ordering, I/O and evidence

V2 authenticates the owner policy first, then all caller inputs and the complete
catalog. Any forbidden catalog member rejects the WHOLE invocation with
OWNER_CATALOG_DENIED before any source file open/read, source parsing, capture,
recheck or output publication. A late member, unreached seed or member beyond
budget still rejects, before an earlier allowed file is opened. Rejected output
contains no source bytes, snippets, rejected path or source-content hash derived
by reading a rejected file. Caller-supplied catalog hashes are metadata, not
observations of denied content. Error reasons do not echo arbitrary input.

After policy admission, an identity/ancestry pass checks EVERY catalog path using
the unchanged Windows provider before any source-content safe_read. The provider
opens file handles with FILE_READ_DATA even for this metadata pass: those count
as source-open attempts in instrumentation. No os.read/capture occurs in this
pass. It is not a metadata-only-access API. Reparse/hardlink/case/volume/identity
or metadata failure rejects the operation before source CONTENT reads; it may
already have opened other allowed members for metadata. Do not claim zero opens
for such failures. No provider changes or fallback opens were introduced.

The unchanged V1 selector then only reaches admitted catalog members through
seeds, required parent initializers, FIFO offers, lexical fill, capture and
recheck. Missing catalog membership is not project absence. Owner-denied import
references outside catalog get OWNER_DENIED_REFERENCE annotations with hashes of
path locators, not file contents. No destination is read or confirmed as
LOCAL_MODULE_MATCH. Selection remains syntax-only, not object identity,
execution, binding or causal authority. Allowed captures can contain import
spellings; they are not bytes read from the referenced destination.

CLI inputs/config must be outside the source root. Use
python tools/source_selection_v2.py --source-root ROOT --catalog CATALOG
--catalog-sha256 SHA --policy V1_POLICY --policy-sha256 SHA
--admission-policy OWNER_POLICY --admission-policy-sha256 OWNER_SHA
--code-manifest CODE_MANIFEST --code-sha256 CODE_SHA --output NEW_OUTPUT.
All paths must be absolute ordinary local NTFS paths. Config inputs are explicit
caller-authorized control bytes, not source catalog members. Directory custody
and physical output disjointness follow the existing provider. The complete
execute(catalog_path,policy_path,admission_policy_path,code_path,output,authority)
operation retains source/product/config/output-parent chains until publication
and returns manifest_sha256 only after completion. Existing outputs are refused;
partial failures are retained. There is no rollback or overwrite retry.

Independent verification: tools.verify_selection_v2.verify(artifacts,
admission_policy_raw,authority,manifest_sha256), or its CLI with --artifacts,
--source-root, --catalog-sha256, --policy-sha256, --admission-policy,
--admission-policy-sha256, --code-sha256, --manifest-sha256. The owner-policy bytes
and SHA come from the caller, and the artifact-manifest SHA must be held outside
the bundle. Metadata pins are checked before reading captures/reports; admission
is recomputed with an independent component-based evaluator. The verifier then
checks source identities, captures, independently replays all ordered selection
transitions and AST, and compares the complete envelope, including stages and
reference denials. It imports neither selection producer. It shares schemas,
CPython AST, Windows provider and independent V1 replay. Rehashed surface
consistency does not establish admission/selection correctness. A denied catalog
rejects before opening any source or capture/report member. Arbitrary bytes
already embedded in a caller-authorized artifact are not process-isolated.

Tests instrument provider requests, native provider opens, CRT-descriptor os.read
and Python audit opens from before admission, with positive reads as controls.
They do not observe the kernel globally, unrelated processes or arbitrary native
extensions. AST workers receive captured bytes; target source is never executed.
Policies are immutable raw-byte snapshots per invocation; changing policy in a
later invocation requires a new caller anchor. No global policy daemon exists.

## Preserved limits

No E8 enumeration/root discovery, stable physical source identity between reads,
atomic multifile snapshot, SOURCE_CURRENT_AT_ACK, ARTIFACT_CURRENT_AT_ACK,
I/O wall-time guarantee, independent verifier parser isolation, general Windows
security, Linux qualification or publication authority is established. The
provider's exact Windows10 AMD64 build19045/local-fixed-NTFS limits remain.
WINDOWS_SECURITY=PARTIAL; PUBLICATION_READY=NO. Historical three Windows negatives
remain unchanged and the full suite remains NOT_PASS when they recur. Docker V3
is external owner simulation evidence, not Codex execution or actual E7/Linux.
No benchmarks, Docker/WSL, models/training, E8, release or promotion occur here.