# Windows root source discovery V1 — opt-in E8 experimental

`candidate.root_source_discovery_v1.discover(owner_raw, selection_raw, code_raw,
DiscoveryAuthority(...), limits=None)` produces an **unadmitted** E7-format
catalog candidate. Root, scope, package root, owner/selection policy and code
anchors must come from an authorized caller. They do not authenticate a human.
No E7/V1/V2 API, Windows provider, public MCP name or default behavior changes.

This Windows 10 build19045 native AMD64/local fixed D: NTFS implementation queries
retained directory handles with ntdll!NtQueryDirectoryFile, class60, bounded
IO_STATUS_BLOCK.Information/offset/UTF16 parsing. No path walker or enumeration
fallback exists. Exclusions precede denied-file opens, including metadata opens.
allow_exact prunes irrelevant subtrees; prefix/component rules observe boundaries.
Sensitive E7 paths and nonmodule directories are omitted without source reads.
Owner-denied locators are hashed in private trace. This is eligible-source
observation, not a complete raw inventory or evidence about omitted contents.

All admitted file metadata handles use READ_ATTRIBUTES|SYNCHRONIZE (0x100080),
not FILE_READ_DATA. Directories use LIST_DIRECTORY|READ_ATTRIBUTES|SYNCHRONIZE
(0x100081). All candidate metadata/ancestry remains retained before any source
content capture. Enumeration IDs, exact case, volume, attributes, type, links and
metadata consistency are checked; capture uses a verified same-object data
handle and checks before/after. Hardlinks/reparse/ambiguous names/access or budget
failure return INCOMPLETE and catalog=null, never a prefix catalog. A mismatch
detected after a read may have consumed bytes which are discarded; it cannot
retroactively establish zero reads. Empty eligibility yields DISCOVERY_EMPTY_CATALOG,
not proof that the project has no Python sources.

Ceilings:8192 physical entries,256 directories,1024 queries,256 eligible files,
depth5,262144 bytes/file,16MiB captured bytes,1024 relative path characters,
255 component characters,4096 default buffer(up to65536),30s cooperative checks.
Budgets can be lowered; explicit buffer sizes96..65536 aligned8 are accepted.
Blocking native I/O has no wall-time/cancel guarantee. Overflow, pending or
success0 are failures, not EOF. Only STATUS_NO_MORE_FILES with zero bytes ends.
The global remaining page budget is enforced before each query. Every completed
native call retains status/returned length in trace even if parsing or a later
budget check fails. physical_entries counts fully decoded non-dot entries;
unparsed_pages records pages whose entry denominator is unknown. A native page
is the metadata observation unit: it can expose more entries than the remaining
entry acceptance budget before INCOMPLETE; no content is then captured. Memory
for that extra metadata is bounded by one configured buffer. Such counts are
observations, not accepted-catalog counts. Code pins are checked before opening
the source-root directory handle.

CLI `tools/discover_sources_v1.py` requires --source-root, --admission-policy,
--admission-policy-sha256, --policy, --policy-sha256, --code-manifest,
--code-sha256, --output; optional --scope and --package-root default '.'. All
filesystem paths are ordinary absolute local paths. Configuration/output must
be outside source and output physically outside product/config directories.
execute retains the complete transaction and exclusively creates a new output,
manifest last, no overwrite/rollback. Partial failures remain. CLI exit2 means
an INCOMPLETE evidence bundle, not successful discovery.

`tools.verify_discovery_v1.verify` takes the bundle, externally held raw inputs,
DiscoveryAuthority and external manifest SHA. It imports neither E8 producer
module, independently queries/parses/traverses/evaluates policy and reconstructs
catalog/hash/trace/identities/counts, including physical bundle membership. It
shares schemas, canonical serialization, CPython and the old Windows provider.
It compares two bounded observations, not an atomic multi-file snapshot.

Stage2 is a **later** unchanged E7 V2 call with externally admitted catalog SHA
in AuthorityContext. No automatic bridge or owner self-authorization is supplied.
AUTONOMOUS_FROM_ROOT=PARTIAL_TWO_STAGE. E7 selection remains<=32 and AST-only;
E3/E4 are unchanged. SOURCE_CURRENT_AT_ACK, ARTIFACT_CURRENT_AT_ACK, runtime
binding and causal authority remain NOT_PROVEN. Historical four E7 physical
REFERENCE_MISMATCH rows and three Windows negative tests remain intact.
