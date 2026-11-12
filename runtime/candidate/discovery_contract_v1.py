"""Pure opt-in E8 contracts. Discovery never grants catalog authority."""
from dataclasses import dataclass
from . import admission_contract_v2 as A
from . import selection_contract_v1 as C
from . import windows_safe_io_v2 as IO

LIMITS = dict(max_entries=8192, max_directories=256, max_pages=1024,
              max_files=256, max_depth=5, buffer_bytes=4096,
              max_file_bytes=262144, max_total_bytes=16777216,
              max_path_chars=1024, timeout_seconds=30)
CEILINGS = dict(LIMITS, buffer_bytes=65536)
EXTRA_CODE = frozenset({
    'runtime/candidate/discovery_contract_v1.py',
    'runtime/candidate/windows_directory_enumeration_v1.py',
    'runtime/candidate/root_source_discovery_v1.py',
    'tools/discover_sources_v1.py', 'tools/verify_discovery_v1.py',
})
PAYLOADS = frozenset({'DISCOVERY.json', 'CATALOG_CANDIDATE.json', 'OWNER_POLICY.json',
                      'SELECTION_POLICY.json', 'CODE_IDENTITY.json'})

@dataclass(frozen=True)
class DiscoveryAuthority:
    source_root: str
    admission_policy_sha256: str
    selection_policy_sha256: str
    code_sha256: str
    scope: str = '.'
    package_root: str = '.'

    def validate(self):
        drive, _ = IO.absolute(self.source_root)
        C.need(drive == 'D:\\', 'DISCOVERY_D_DRIVE_ONLY')
        for pin in (self.admission_policy_sha256, self.selection_policy_sha256, self.code_sha256):
            C.need(C.hash_value(pin), 'DISCOVERY_AUTHORITY_ANCHOR_REQUIRED')
        for name in (self.scope, self.package_root):
            C.need(type(name) is str, 'DISCOVERY_SCOPE')
            if name != '.':
                IO.relative(name)
                C.need(all(p.isidentifier() for p in name.split('/')), 'DISCOVERY_SCOPE')
        C.need(self.package_root == '.' or self.scope.startswith(self.package_root+'/')
               or self.scope == self.package_root, 'PACKAGE_ROOT_SCOPE')

def limits(value=None):
    C.need(value is None or type(value) is dict, 'DISCOVERY_LIMITS')
    value = {} if value is None else value
    C.need(set(value) <= set(LIMITS), 'DISCOVERY_LIMITS')
    result = dict(LIMITS, **value)
    for key, bound in CEILINGS.items():
        C.need(type(result[key]) is int and 1 <= result[key] <= bound, 'DISCOVERY_LIMIT_'+key)
    C.need(result['buffer_bytes'] >= 96 and result['buffer_bytes'] % 8 == 0, 'DISCOVERY_BUFFER_SIZE')
    return result

def authenticate(owner_raw, selection_raw, code_raw, authority):
    C.need(type(authority) is DiscoveryAuthority, 'DISCOVERY_AUTHORITY_REQUIRED')
    authority.validate()
    a = A.owner_policy(A.pinned(owner_raw, authority.admission_policy_sha256, 'OWNER_POLICY_REQUIRED'))
    C.need(A.same_root(a['source_root'], authority.source_root), 'OWNER_POLICY_ROOT')
    C.need(a['scope'] == authority.scope, 'OWNER_POLICY_SCOPE')
    p = C.policy(A.pinned(selection_raw, authority.selection_policy_sha256, 'SELECTION_POLICY_REQUIRED'))
    code = C.code_manifest(A.pinned(code_raw, authority.code_sha256, 'CODE_MANIFEST_REQUIRED'))
    names = [r['path'] for r in code['files']]
    C.need(A.EXTRA_CODE | EXTRA_CODE <= set(names), 'DISCOVERY_CODE_CLOSURE_REQUIRED')
    C.need(len({n.lower() for n in names}) == len(names), 'CODE_CASE_COLLISION')
    return a, p, code

def directory_denied(path, policy):
    """Prune deny rules and directories with no allowed descendant, before open."""
    name = path.lower()
    if any((name+'/').startswith(s.lower()) for s in policy['deny_prefixes']):
        return True
    if set(name.split('/')) & {s.lower() for s in policy['deny_components']}:
        return True
    return bool(policy['allow_exact']) and not any(s.lower().startswith(name+'/') for s in policy['allow_exact'])

def metadata_row(path, meta):
    return dict(path=path, identity=list(meta.identity), size=meta.size, links=meta.links,
                directory=meta.directory, attributes=meta.attributes, tag=meta.tag, times=list(meta.times))

def result(authority, budget, rows, trace, observations, counts, failure):
    catalog = None
    if failure is None:
        catalog = dict(schema='pgop1.selection-catalog.v1', source_root=authority.source_root,
                       scope=authority.scope, package_root=authority.package_root, sources=rows)
    return dict(schema='pgop1.root-source-discovery.v1',
        status='CATALOG_DISCOVERED' if catalog is not None else 'INCOMPLETE',
        source_root=authority.source_root, scope=authority.scope, package_root=authority.package_root,
        admission_policy_sha256=authority.admission_policy_sha256,
        selection_policy_sha256=authority.selection_policy_sha256, code_sha256=authority.code_sha256,
        limits=budget, catalog=catalog,
        catalog_candidate_sha256=C.digest(C.canonical(catalog)) if catalog is not None else None,
        trace=trace, observations=sorted(observations,key=lambda x:x['path']), counts=counts,
        failure=failure, inventory_completeness='ELIGIBLE_OBSERVATION_ONLY' if catalog is not None else 'INCOMPLETE',
        catalog_authority='CANDIDATE_NOT_EXTERNALLY_ADMITTED', autonomous_from_root='PARTIAL_TWO_STAGE',
        source_current_at_ack='NOT_PROVEN', artifact_current_at_ack='NOT_PROVEN', atomic_snapshot='NOT_PROVEN')
