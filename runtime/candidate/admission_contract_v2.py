"""Pure V2 owner-authority schemas. No source reads, selection or discovery."""
from dataclasses import dataclass
from . import selection_contract_v1 as C
from . import windows_safe_io_v2 as IO

SCHEMA = 'pgop1.selection-admission-policy.v2'
EXTRA_CODE = frozenset({
    'runtime/candidate/admission_contract_v2.py',
    'runtime/candidate/source_selection_v2.py',
    'tools/source_selection_v2.py', 'tools/verify_selection_v2.py',
})
STAGES = ['OWNER_POLICY_AUTHENTICATED', 'CATALOG_AUTHENTICATED',
          'CATALOG_POLICY_ADMITTED', 'CODE_AUTHENTICATED', 'PATH_IDENTITIES_PREFLIGHTED']

@dataclass(frozen=True)
class AuthorityContext:
    """Caller-held authorization, outside catalog authority; no signature service."""
    source_root: str
    catalog_sha256: str
    selection_policy_sha256: str
    admission_policy_sha256: str
    code_sha256: str

    def validate(self):
        IO.absolute(self.source_root)
        for pin in (self.catalog_sha256, self.selection_policy_sha256,
                    self.admission_policy_sha256, self.code_sha256):
            C.need(C.hash_value(pin), 'AUTHORITY_ANCHOR_REQUIRED')

def same_root(a, b):
    IO.absolute(a); IO.absolute(b)
    return a.replace('/', '\\') == b.replace('/', '\\')

def pinned(raw, anchor, missing):
    C.need(type(raw) is bytes and len(raw) <= 262144, missing)
    C.need(C.hash_value(anchor) and C.digest(raw) == anchor, 'EXTERNAL_AUTHORIZATION_ANCHOR')
    return C.strict(raw)

def owner_policy(value):
    fields = {'schema', 'source_root', 'scope', 'case', 'deny_prefixes',
              'deny_components', 'deny_exact', 'allow_exact'}
    C.need(isinstance(value, dict) and set(value) == fields, 'OWNER_POLICY_SCHEMA')
    C.need(value['schema'] == SCHEMA and value['case'] == 'ascii-insensitive', 'OWNER_POLICY_SCHEMA')
    IO.absolute(value['source_root'])
    scope = value['scope']
    C.need(isinstance(scope, str), 'OWNER_POLICY_SCOPE')
    if scope != '.':
        IO.relative(scope)
        C.need(all(p.isidentifier() for p in scope.split('/')), 'OWNER_POLICY_SCOPE')
    for field in ('deny_prefixes', 'deny_components', 'deny_exact', 'allow_exact'):
        rules = value[field]
        C.need(type(rules) is list and len(rules) <= 256 and
               all(type(n) is str and len(n) <= 1024 for n in rules), 'OWNER_POLICY_RULES')
        C.need(rules == sorted(rules) and len({n.lower() for n in rules}) == len(rules),
               'OWNER_POLICY_RULE_COLLISION')
        for name in rules:
            if field == 'deny_prefixes':
                C.need(name.endswith('/'), 'OWNER_POLICY_PREFIX')
                path = name[:-1]; IO.relative(path)
                C.need(all(p.isidentifier() for p in path.split('/')), 'OWNER_POLICY_PREFIX')
            elif field == 'deny_components':
                IO.component(name); path = None
            else:
                C.source_path(name); path = name
            if path is not None and scope != '.':
                C.need(path.lower().startswith(scope.lower() + '/'), 'OWNER_POLICY_RULE_OUTSIDE_SCOPE')
    return value

def authenticate(catalog_raw, selection_policy_raw, admission_policy_raw, code_raw, authority):
    C.need(type(authority) is AuthorityContext, 'AUTHORITY_CONTEXT_REQUIRED')
    authority.validate()
    a = owner_policy(pinned(admission_policy_raw, authority.admission_policy_sha256, 'OWNER_POLICY_REQUIRED'))
    C.need(same_root(a['source_root'], authority.source_root), 'OWNER_POLICY_ROOT')
    p = C.policy(pinned(selection_policy_raw, authority.selection_policy_sha256, 'SELECTION_POLICY_REQUIRED'))
    c = C.catalog(pinned(catalog_raw, authority.catalog_sha256, 'CATALOG_REQUIRED'), p)
    C.need(same_root(c['source_root'], authority.source_root), 'SOURCE_ROOT_AUTHORIZATION')
    C.need(c['scope'] == a['scope'], 'OWNER_POLICY_SCOPE')
    code = C.code_manifest(pinned(code_raw, authority.code_sha256, 'CODE_MANIFEST_REQUIRED'))
    C.need(EXTRA_CODE <= {r['path'] for r in code['files']}, 'V2_CODE_CLOSURE_REQUIRED')
    # One canonical spelling of each code path; aliases cannot substitute code pins.
    names = [r['path'] for r in code['files']]
    C.need(len({n.lower() for n in names}) == len(names), 'CODE_CASE_COLLISION')
    return c, p, a, code

def denied(path, policy):
    """Whole path/prefix components; fixed ASCII provider, deny always wins."""
    parts = path.lower().split('/')
    name = '/'.join(parts)
    if any(name.startswith(p.lower()) for p in policy['deny_prefixes']):
        return True
    if set(parts) & {p.lower() for p in policy['deny_components']}:
        return True
    if name in {p.lower() for p in policy['deny_exact']}:
        return True
    return bool(policy['allow_exact']) and name not in {p.lower() for p in policy['allow_exact']}

def admit_catalog(catalog, policy):
    # No source hashes, bytes, snippets or rejected locator are put in exceptions.
    for row in catalog['sources']:
        C.need(not denied(row['path'], policy), 'OWNER_CATALOG_DENIED')

def receipt(c, a):
    normal = dict(a)
    for key in ('deny_prefixes', 'deny_components', 'deny_exact', 'allow_exact'):
        normal[key] = sorted(s.lower() for s in a[key])
    return dict(schema='pgop1.selection-admission-decision.v2', status='ADMITTED',
                catalog_sha256=C.digest(C.canonical(c)),
                admission_policy_sha256=C.digest(C.canonical(a)),
                normalized_policy_sha256=C.digest(C.canonical(normal)),
                catalog_members=len(c['sources']), stages=list(STAGES))

def references(plan, policy):
    rows = []
    prefix = '' if plan['package_root'] == '.' else plan['package_root'] + '/'
    for event in plan['trace']:
        if event['event'] != 'REFERENCE':
            continue
        blocked = set()
        for spelling in event['requested']:
            if not spelling or 'WITHHELD' in spelling.split('.'):
                continue
            stem = prefix + spelling.replace('.', '/')
            for path in (stem + '.py', stem + '/__init__.py'):
                if denied(path, policy):
                    blocked.add(C.digest(path.encode('utf8')))
        if blocked:
            rows.append(dict(origin=event['origin'], reason='OWNER_DENIED_REFERENCE',
                             locator_sha256=sorted(blocked), authority='SYNTAX_ONLY_NO_BINDING_AUTHORITY'))
    return rows

def envelope(plan, c, a):
    return dict(schema='pgop1.autonomous-source-selection.v2', admission=receipt(c, a),
                admission_references=references(plan, a), legacy_plan=plan,
                legacy_v1='LEGACY_V1_DOES_NOT_ENFORCE_OWNER_DENY')