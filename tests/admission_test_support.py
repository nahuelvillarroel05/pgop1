"""Synthetic-only fixtures and provider/Python observation for admission tests."""
from contextlib import ExitStack
import copy
import json
import os
from pathlib import Path
import sys
from unittest import mock
from candidate import admission_contract_v2 as A
from candidate import selection_contract_v1 as C
from candidate import windows_safe_io_v2 as IO

PRODUCT = Path(__file__).absolute().parents[1]
CODE_PATHS = sorted(A.EXTRA_CODE | {
    'runtime/candidate/selection_contract_v1.py', 'runtime/candidate/source_selection_v1.py',
    'runtime/candidate/static_ast_v2.py', 'runtime/candidate/windows_safe_io_v2.py',
    'tools/source_selection_v1.py', 'tools/verify_selection_v1.py', 'tools/verify_source_v2.py'})

def code_raw():
    return C.canonical(dict(schema='pgop1.selection-code.v1', files=[
        dict(path=n, bytes=len(b), sha256=C.digest(b))
        for n in CODE_PATHS for b in [(PRODUCT / n).read_bytes()]]))

def owner(root, **changes):
    value = dict(schema=A.SCHEMA, source_root=str(root), scope='.', case='ascii-insensitive',
                 deny_prefixes=['private/'], deny_components=[], deny_exact=[], allow_exact=[])
    value.update(changes)
    return value
class Fixture:
    def __init__(self, base, files, policy_changes=None):
        self.base = Path(base); self.source = self.base / 'source'; self.config = self.base / 'config'
        self.source.mkdir(parents=True); self.config.mkdir()
        rows = []
        for n, body in sorted(files.items()):
            raw = body.encode() if isinstance(body, str) else body
            target = self.source / n; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(raw)
            rows.append(dict(path=n, bytes=len(raw), sha256=C.digest(raw)))
        self.c = dict(schema='pgop1.selection-catalog.v1', source_root=str(self.source),
                      scope='.', package_root='.', sources=rows)
        self.p = copy.deepcopy(C.POLICY); self.a = owner(self.source, **(policy_changes or {}))
        self.refresh()
    def refresh(self):
        self.cr, self.pr, self.ar, self.code = map(C.canonical, (self.c, self.p, self.a, json.loads(code_raw())))
        self.authority = A.AuthorityContext(str(self.source), C.digest(self.cr), C.digest(self.pr),
                                            C.digest(self.ar), C.digest(self.code))
        for name, raw in [('catalog', self.cr), ('policy', self.pr), ('owner', self.ar), ('code', self.code)]:
            (self.config / (name + '.json')).write_bytes(raw)
    def args(self, output):
        return [str(self.config / 'catalog.json'), str(self.config / 'policy.json'),
                str(self.config / 'owner.json'), str(self.config / 'code.json'), str(output), self.authority]
    def cli(self, output):
        return ['--source-root', str(self.source), '--catalog', str(self.config / 'catalog.json'),
                '--catalog-sha256', self.authority.catalog_sha256, '--policy', str(self.config / 'policy.json'),
                '--policy-sha256', self.authority.selection_policy_sha256, '--admission-policy', str(self.config / 'owner.json'),
                '--admission-policy-sha256', self.authority.admission_policy_sha256,
                '--code-manifest', str(self.config / 'code.json'), '--code-sha256', self.authority.code_sha256,
                '--output', str(output)]
    def direct(self):
        from candidate.source_selection_v2 import select_catalog
        return select_catalog(self.cr, self.pr, self.ar, self.code, self.authority)

_ACTIVE = None

def audit(event, args):
    if _ACTIVE is not None and event == 'open':
        name = args[0]
        if isinstance(name, (str, bytes, os.PathLike)):
            _ACTIVE.emit('PYTHON_OPEN_ATTEMPT', path=os.fsdecode(name))
sys.addaudithook(audit)

class Observation:
    """Hooks precede admission. Not kernel telemetry or hostile-process isolation."""
    def __init__(self, source):
        self.source = str(source).replace('/', '\\').lower().rstrip('\\'); self.events = []
        self.handles = {}; self.fds = {}; self.stack = ExitStack()
    def is_source(self, path):
        text = str(path).replace('/', '\\').lower()
        return text == self.source or text.startswith(self.source + '\\')
    def emit(self, event, path='', **fields):
        self.events.append(dict(ordinal=len(self.events) + 1, event=event, path=str(path),
                                source=self.is_source(path), **fields))
    def __enter__(self):
        global _ACTIVE
        self.previous = _ACTIVE; _ACTIVE = self
        enter, component, read, descriptor = IO.Directory.__enter__, IO.open_component, IO.safe_read, IO._descriptor
        osread, osclose = os.read, os.close
        def directory(d):
            result = enter(d); self.handles[d.handle.value] = str(d.path); return result
        def opened(parent, name, **kwargs):
            base = self.handles.get(parent.value, '')
            path = base + '\\' + name if base else name
            if not kwargs.get('directory', False):
                self.emit('NATIVE_FILE_OPEN_ATTEMPT', path=path)
            handle = component(parent, name, **kwargs); self.handles[handle.value] = path; return handle
        def requested(root, name, expected, cap):
            self.emit('PROVIDER_READ_REQUEST', path=str(root) + '\\' + name)
            return read(root, name, expected, cap)
        def fd_for(handle, flags):
            path = self.handles.get(handle.value, '')
            fd = descriptor(handle, flags); self.fds[fd] = path; return fd
        def bytes_read(fd, cap):
            path = self.fds.get(fd, '')
            self.emit('OS_READ_ATTEMPT', path=path, cap=cap)
            raw = osread(fd, cap); self.emit('OS_READ_RETURN', path=path, bytes=len(raw)); return raw
        def close(fd):
            self.fds.pop(fd, None); return osclose(fd)
        for obj, name, fn in [(IO.Directory, '__enter__', directory), (IO, 'open_component', opened),
                              (IO, 'safe_read', requested), (IO, '_descriptor', fd_for),
                              (os, 'read', bytes_read), (os, 'close', close)]:
            self.stack.enter_context(mock.patch.object(obj, name, fn))
        self.emit('OBSERVATION_ACTIVE_BEFORE_ADMISSION')
        return self
    def __exit__(self, *exc):
        global _ACTIVE
        self.stack.close(); _ACTIVE = self.previous
    def source_events(self, event):
        return [e for e in self.events if e['source'] and e['event'] == event]
    def summary(self):
        return dict(native_file_opens=len(self.source_events('NATIVE_FILE_OPEN_ATTEMPT')),
                    provider_requests=len(self.source_events('PROVIDER_READ_REQUEST')),
                    os_read_attempts=len(self.source_events('OS_READ_ATTEMPT')),
                    bytes=sum(e['bytes'] for e in self.source_events('OS_READ_RETURN')),
                    python_opens=len(self.source_events('PYTHON_OPEN_ATTEMPT')),
                    hooks_active_before_admission=True, kernel_observation='NOT_PROVEN')