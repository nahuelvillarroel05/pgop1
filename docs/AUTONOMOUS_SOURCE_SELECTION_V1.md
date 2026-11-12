# Autonomous source selection v1 — E7 opt-in experimental partial capability

This version accepts an externally authorized catalog, not an autonomous directory
inventory. AUTONOMOUS_FROM_ROOT=BLOCKED_NOT_IMPLEMENTED. Windows Native Safe I/O
has Directory, safe_read, exclusive creation and transaction ancestry custody, but
no qualified directory enumeration API. No Path.rglob, os.walk, scandir, Git file
listing or ordinary source open is a discovery fallback in this component.
Historical E6 metadata is an exposed external input, not a safe discovery receipt.

The seven required implementation files form a minimal pinned code closure.
The actual E7 freeze pins the entire tracked product snapshot plus all additions,
tests, policy, eligible catalog and evaluation harnesses before real selection.
No E3/E4 prediction, exposed U2 membership or reviewer label enters selection.

Contracts:
- pgop1.selection-catalog.v1: exact source_root, scope, package_root and sorted
  source path/SHA256/byte pins. Up to256 externally enumerated Python files.
  It asserts caller authorization of the listed bytes; completeness is NOT_PROVEN.
- pgop1.selection-policy.v1: strict normalized rules and distinct budgets.
- pgop1.selection-code.v1: caller-held SHA of canonical path/size/hash manifest.
- pgop1.autonomous-source-selection.v1: catalog identity, plan, FIFO membership,
  every decision trace, captures/AST states, read accounting and typed failures.
- pgop1.selection-artifacts.v1: six fixed payload names and manifest-last hashes.
- pgop1.selection-verification.v1: independent selection replay and point recapture.

The CLI tools/source_selection_v1.py requires --source-root, --catalog,
--catalog-sha256, --policy, --policy-sha256, --code-manifest, --code-sha256,
--output. All filesystem arguments use the installed Windows provider. Output is
a new disjoint directory. Inputs and product directory chains remain held from
admission through publication and close. Omitting --catalog fails with a typed
SAFE_DIRECTORY_ENUMERATION_UNAVAILABLE status. Nothing is registered as MCP.

tools/verify_selection_v1.py requires --artifacts and the three caller-held
catalog/policy/code SHA256 anchors. It never imports the selection producer.
It independently reconstructs groups, seeds, list-cursor FIFO, candidate paths,
deduplication, fill, budgets and complete ordered trace. It calls the installed
independent AST verifier on pinned captured bytes, not the AST producer; producer
imports can be blocked in a fresh verifier process. It recaptures requested source
pins via Safe I/O. It rejects semantic tampering even after member rehash. Extra
AST metadata is rejected. RESOURCE_ERROR/UNKNOWN/UNSUPPORTED worker claims cannot
be independently rederived and therefore block full selection verification.

The verification path shares schema serialization, CPython AST, installed
independent AST verifier and Windows I/O. It has no independent parser timeout
or OS memory isolation. It verifies the fixed artifact membership in the manifest,
not unlisted physical directory entries: secure listing remains unavailable.
A valid result cannot certify complete project discovery or original denial
events under changing access conditions. The point recapture can detect drift;
it does not create an atomic multi-file snapshot or currency at ACK.

Policy catalog-fifo-e6-compat-v1.0.0:
1. Require exact-case, collision-free, explicit relative .py paths under scope.
   Only ordinary absolute fixed local NTFS paths supported by the installed
   provider; reject special namespaces, traversal, ADS, dangerous hardlinks,
   reparse/aliases/case and sensitive path components. No namespace repair.
2. Seed the sorted set of existing scope/__init__.py and first noninit module
   directly in scope and in each immediate child directory. Sorting is global
   across this seed set: uppercase names may precede __init__.py.
3. Admit existing initializer parents shallow-first with the target atomically.
   Missing namespace initializers remain missing. Every admitted parent costs
   one selected slot and joins FIFO. Duplicate bytes retain distinct paths.
4. Finish seed admissions before FIFO expansion. Parse each admitted file with
   AST V2 defaults or lower:262144 bytes,50000 nodes,depth160,12000 nodes/unit,
   6s worker timeout. Only COMPLETE reports supply planning candidates.
   Conditional/nested imports are syntax candidates; hazards are never bindings.
   Import offers its spelling; from offers base and possible base.alias (except
   wildcard, nonidentifier or withheld alias). Relative escape explicitly abstains.
   Both module.py and module/__init__.py may be proposed when listed.
5. Sort candidates per source by exact path, keeping statement/alias encounter
   order among equal paths. This is not a global breadth-level path priority.
   Every reference records offered paths or NO_CALLER_CATALOG_CANDIDATE, which
   is not absence from the project. Deduplicated paths still emit trace decisions.
6. After empty FIFO, lexicographically fill noninit candidates, skip rejected
   groups, resume FIFO. At32 finish the selected queue to record all cutoffs;
   do not read additional unadmitted targets. Emit NOT_READ for unreached pins.

Separate limits:256 catalog members,128 attempted planning reads,32 selected,
depth5 under scope,262144 bytes/file and16MiB total source-read reservation.
Every attempted read reserves the declared pin size, even on failure or later
group abortion; the provider cap is at most that size. Admission uses at most
half the total byte budget so an equal-byte final recheck is reserved. Successful
bytes, reserved bytes, attempts, selected files and final rechecks are separate.
This conservative reservation may stop before physical bytes reach16MiB. No
global I/O deadline or memory isolation is claimed. Filesystem calls can block.
Parser subprocesses have the installed per-file timeout; no source code executes.

Source roots supplied to library select_catalog must already be authenticated;
execute/CLI owns validation, pins and the complete publication transaction.
Returned dictionaries alone are not successful publication receipts. Failed
creation/write/flush/close leaves partial evidence and retry refuses existing
output. SOURCE_CURRENT_AT_ACK and ARTIFACT_CURRENT_AT_ACK remain NOT_PROVEN.

Optional E3 integration is caller-owned: construct unchanged E3 catalogs from
selected pins (sorted by path), capture through CodeOnlyProfile, run the unchanged
E4 analyzer on that bundle and independently verify. RAW must use the same bytes
with neutral RAW_NNNN.py aliases. E7 emits no LOCAL_MODULE_MATCH, object identity,
runtime/causal connection or whole-project guarantee. Improvements in cohort
composition are distinct from any E4 algorithm change; E3/E4 are unchanged.

Proposed future directory API (DESIGN ONLY): enumerate_registered(root-handle,
relative-directory, explicit limits) must use a documented handle-relative
Windows directory query, validate each entry and parent identity before/after,
reject reparse/case/volume/provider/name uncertainty, keep ancestry and return
typed bounded cursors and omissions. Independent native adversarial qualification
must precede implementation/use. Directory handle permission alone does not
authorize a path-based enumeration call.
