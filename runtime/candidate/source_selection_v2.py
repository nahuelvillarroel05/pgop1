"""V2 mandatory owner admission before any source access; V1 stays unchanged."""
from contextlib import contextmanager, ExitStack
from pathlib import Path
import os
from . import selection_contract_v1 as C
from . import admission_contract_v2 as A
from . import windows_safe_io_v2 as IO
from . import source_selection_v1 as legacy

PRODUCT = Path(__file__).absolute().parents[2]

def check_code(code):
    for row in code['files']:
        rr = IO.safe_read(PRODUCT, row['path'], row['sha256'], 262144)
        C.need(len(rr.raw) == row['bytes'], 'CODE_CHANGED')

@contextmanager
def path_preflight(catalog):
    """Metadata pass over every admitted path, using the unchanged provider.

    Provider file opens include FILE_READ_DATA; no os.read/content capture occurs
    here. This is not a metadata-only access-rights API or an atomic snapshot.
    """
    with ExitStack() as tx:
        directories = []; identities = set()
        for row in catalog['sources']:
            directory = tx.enter_context(IO.Directory(catalog['source_root']))
            for part in IO.relative(row['path'])[:-1]:
                directory.add(IO.open_component(directory.handle, part, directory=True))
            directories.append(directory)
            with IO.open_component(directory.handle, row['path'].split('/')[-1], directory=False) as handle:
                info = IO.metadata(handle, False)
                C.need(info.identity not in identities, 'CATALOG_IDENTITY_COLLISION')
                C.need(info.size == row['bytes'], 'SOURCE_METADATA_SIZE')
                identities.add(info.identity)
        for directory in directories:
            directory.validate()
        yield
        for directory in directories:
            directory.validate()

def select_catalog(catalog_raw, selection_policy_raw, admission_policy_raw, code_raw, authority):
    """All authority is explicit and caller-held. No publication receipt returned."""
    c, p, a, code = A.authenticate(catalog_raw, selection_policy_raw, admission_policy_raw, code_raw, authority)
    A.admit_catalog(c, a)  # Whole-catalog deny BEFORE code/source opens or parsing.
    C.need(os.name == 'nt', 'WINDOWS_ONLY')
    with IO.Directory(PRODUCT) as product, IO.Directory(authority.source_root) as source:
        IO.reject_membership(source, product)
        IO.reject_membership(product, source)
        check_code(code)
        with path_preflight(c):
            plan, captures, reports = legacy.select_catalog(c, p, authority.code_sha256)
        product.validate()
    return A.envelope(plan, c, a), captures, reports

def outside_source(path, source_root):
    IO.absolute(path)
    text = str(path).replace('/', '\\').lower()
    root = source_root.replace('/', '\\').lower().rstrip('\\')
    C.need(text != root and not text.startswith(root + '\\'), 'CONFIG_OR_OUTPUT_INSIDE_SOURCE')

def execute(catalog_path, policy_path, admission_policy_path, code_path, output, authority):
    C.need(type(authority) is A.AuthorityContext, 'AUTHORITY_CONTEXT_REQUIRED')
    authority.validate()
    for path in (catalog_path, policy_path, admission_policy_path, code_path, output):
        outside_source(path, authority.source_root)
    with ExitStack() as tx:
        configs = [tx.enter_context(IO.Directory(Path(p).parent)) for p in
                   (admission_policy_path, catalog_path, policy_path, code_path)]
        destination = tx.enter_context(IO.Directory(Path(output).parent))
        for directory in configs:
            IO.reject_membership(destination, directory)
        def load(path, pin):
            return IO.safe_read(Path(path).parent, Path(path).name, pin, 262144).raw
        # Authenticate OWNER input first; never let catalog select its authority.
        ar = load(admission_policy_path, authority.admission_policy_sha256)
        a = A.owner_policy(A.pinned(ar, authority.admission_policy_sha256, 'OWNER_POLICY_REQUIRED'))
        C.need(A.same_root(a['source_root'], authority.source_root), 'OWNER_POLICY_ROOT')
        cr = load(catalog_path, authority.catalog_sha256)
        pr = load(policy_path, authority.selection_policy_sha256)
        code_raw = load(code_path, authority.code_sha256)
        c, p, a, code = A.authenticate(cr, pr, ar, code_raw, authority)
        A.admit_catalog(c, a)
        with IO.Directory(authority.source_root) as source, IO.Directory(PRODUCT) as product:
            IO.reject_membership(destination, source); IO.reject_membership(destination, product)
            plan, captures, reports = select_catalog(cr, pr, ar, code_raw, authority)
            files = {'PLAN.json': C.canonical(plan),
                     'CAPTURES.json': C.canonical({n: b.hex() for n, b in sorted(captures.items())}),
                     'AST_REPORTS.json': C.canonical(reports), 'SOURCE_CATALOG.json': cr,
                     'POLICY.json': pr, 'ADMISSION_POLICY.json': ar, 'CODE_IDENTITY.json': code_raw}
            files['MANIFEST.json'] = C.canonical(dict(schema='pgop1.selection-artifacts.v2',
                files={n: dict(bytes=len(b), sha256=C.digest(b)) for n, b in files.items()}))
            for d in configs + [destination, source, product]:
                d.validate()
            IO.safe_create_artifacts(authority.source_root, output, files,
                                     (PRODUCT, *(Path(p).parent for p in
                                       (catalog_path, policy_path, admission_policy_path, code_path))))
            for d in configs + [destination, source, product]:
                d.validate()
    return dict(status='SELECTION_V2_WRITTEN', operation_completed=True,
                plan_sha256=C.digest(files['PLAN.json']), manifest_sha256=C.digest(files['MANIFEST.json']),
                admission_policy_sha256=authority.admission_policy_sha256,
                autonomous_from_root='BLOCKED_NOT_IMPLEMENTED', source_current_at_ack='NOT_PROVEN',
                artifact_current_at_ack='NOT_PROVEN')