"""Experimental Windows 10/local NTFS handle-relative I/O, version 2.

No path check authorizes a subsequent path-based data open. See
docs/WINDOWS_SAFE_IO_V2.md for the exact scope and unqualified guarantees.
This module does not parse AST reports or trust producer assertions.
"""
import ctypes as C
from ctypes import wintypes as W
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import struct
import sys


class SafeIOError(ValueError):
    def __init__(self, code, *, winerror=None, ntstatus=None):
        super().__init__(code)
        self.code, self.winerror, self.ntstatus = code, winerror, ntstatus


def component(name):
    if (not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_. -]{1,255}', name)
            or name in ('.', '..') or name.startswith(' ') or name.endswith((' ', '.'))
            or name.split('.')[0].upper() in {'CON', 'PRN', 'AUX', 'NUL', 'CONIN$', 'CONOUT$'}
            or re.fullmatch(r'(COM|LPT)[0-9]', name.split('.')[0], re.I)):
        raise SafeIOError('UNSAFE_PATH')
    return name


def relative(name):
    if not isinstance(name, str):
        raise SafeIOError('UNSAFE_PATH')
    return [component(p) for p in name.split('/')]


def absolute(path):
    text = os.fspath(path)
    # Reject before Path/abspath can erase traversal or namespace spelling.
    if not isinstance(text, str) or text.startswith(('\\\\', '//', '\\??\\')):
        raise SafeIOError('UNSAFE_PATH')
    text = text.replace('/', '\\')
    if not re.match(r'^[A-Za-z]:\\', text):
        raise SafeIOError('UNSAFE_PATH')
    pieces = text[3:].split('\\') if text[3:] else []
    for part in pieces:
        component(part)
    return text[:3], pieces


class UNICODE_STRING(C.Structure):
    _fields_ = [('Length', W.USHORT), ('MaximumLength', W.USHORT), ('Buffer', W.LPWSTR)]


class OBJECT_ATTRIBUTES(C.Structure):
    _fields_ = [('Length', W.ULONG), ('RootDirectory', W.HANDLE),
                ('ObjectName', C.POINTER(UNICODE_STRING)), ('Attributes', W.ULONG),
                ('SecurityDescriptor', W.LPVOID), ('SecurityQualityOfService', W.LPVOID)]


class IO_STATUS_BLOCK(C.Structure):
    # Native union { NTSTATUS Status; PVOID Pointer; } followed by ULONG_PTR.
    _fields_ = [('StatusOrPointer', C.c_void_p), ('Information', C.c_size_t)]


_api = None


def api():
    global _api
    if _api is not None:
        return _api
    if os.name != 'nt' or C.sizeof(C.c_void_p) != 8:
        raise SafeIOError('UNSUPPORTED_SAFE_READ_PLATFORM')
    version = sys.getwindowsversion()
    if (version.major, version.minor, version.build, version.product_type) != (10, 0, 19045, 1):
        raise SafeIOError('UNSUPPORTED_WINDOWS_BUILD')
    if (C.sizeof(UNICODE_STRING), C.sizeof(OBJECT_ATTRIBUTES), C.sizeof(IO_STATUS_BLOCK)) != (16, 48, 16):
        raise SafeIOError('UNSUPPORTED_WINDOWS_ABI')
    k = C.WinDLL('kernel32', use_last_error=True)
    n = C.WinDLL('ntdll', use_last_error=True)
    signatures = {
        'CreateFileW': (W.HANDLE, [W.LPCWSTR, W.DWORD, W.DWORD, W.LPVOID, W.DWORD, W.DWORD, W.HANDLE]),
        'CloseHandle': (W.BOOL, [W.HANDLE]),
        'GetFileType': (W.DWORD, [W.HANDLE]),
        'GetFileInformationByHandleEx': (W.BOOL, [W.HANDLE, C.c_int, W.LPVOID, W.DWORD]),
        'GetVolumeInformationByHandleW': (W.BOOL, [W.HANDLE, W.LPWSTR, W.DWORD, C.POINTER(W.DWORD), C.POINTER(W.DWORD), C.POINTER(W.DWORD), W.LPWSTR, W.DWORD]),
        'GetFinalPathNameByHandleW': (W.DWORD, [W.HANDLE, W.LPWSTR, W.DWORD, W.DWORD]),
        'GetDriveTypeW': (W.UINT, [W.LPCWSTR]),
        'GetCurrentProcess': (W.HANDLE, []),
        'IsWow64Process2': (W.BOOL, [W.HANDLE, C.POINTER(W.USHORT), C.POINTER(W.USHORT)]),
    }
    for name, (result, args) in signatures.items():
        fn = getattr(k, name)
        fn.restype, fn.argtypes = result, args
    process_machine, native_machine = W.USHORT(), W.USHORT()
    if (not k.IsWow64Process2(k.GetCurrentProcess(), C.byref(process_machine), C.byref(native_machine))
            or process_machine.value != 0 or native_machine.value != 0x8664):
        raise SafeIOError('UNSUPPORTED_WINDOWS_ARCHITECTURE')
    n.NtCreateFile.restype = W.LONG
    n.NtCreateFile.argtypes = [C.POINTER(W.HANDLE), W.DWORD, C.POINTER(OBJECT_ATTRIBUTES),
                             C.POINTER(IO_STATUS_BLOCK), W.LPVOID, W.ULONG, W.ULONG,
                             W.ULONG, W.ULONG, W.LPVOID, W.ULONG]
    n.RtlNtStatusToDosError.restype = W.ULONG
    n.RtlNtStatusToDosError.argtypes = [W.LONG]
    _api = k, n
    return _api


def checked(ok, code='WINDOWS_API_FAILED'):
    if not ok:
        raise SafeIOError(code, winerror=C.get_last_error())


class Handle:
    def __init__(self, value):
        self.value = value

    def close(self):
        if self.value is not None:
            value, self.value = self.value, None
            checked(api()[0].CloseHandle(value), 'HANDLE_CLOSE_FAILED')

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def query(handle, kind, size):
    buf = C.create_string_buffer(size)
    checked(api()[0].GetFileInformationByHandleEx(handle.value, kind, buf, size))
    return buf.raw


@dataclass(frozen=True)
class Metadata:
    identity: tuple
    size: int
    links: int
    directory: bool
    attributes: int
    tag: int
    times: tuple


def metadata(handle, directory):
    if api()[0].GetFileType(handle.value) != 1:  # FILE_TYPE_DISK
        raise SafeIOError('NOT_REGULAR_FILE')
    attrs, tag = struct.unpack('<II', query(handle, 9, 8))
    # Reparse, offline, encrypted, recall-on-open/data-access.
    if tag or attrs & (0x400 | 0x1000 | 0x4000 | 0x40000 | 0x400000):
        raise SafeIOError('UNSAFE_PATH_REPARSE_OR_PROVIDER')
    allocation, size, links, deleting, is_dir = struct.unpack('<qqIBB2x', query(handle, 1, 24))
    if bool(is_dir) != directory or deleting or size < 0:
        raise SafeIOError('NOT_REGULAR_FILE')
    if not directory and links != 1:
        raise SafeIOError('UNSAFE_PATH_HARDLINK')
    ident = query(handle, 18, 24)  # FILE_ID_INFO: ULONGLONG + FILE_ID_128
    volume = struct.unpack_from('<Q', ident)[0]
    if not any(ident[8:]):
        raise SafeIOError('UNSUPPORTED_FILE_ID')
    basic = query(handle, 0, 40)
    # Last-access time may change on read; creation/write/change must not.
    creation, access, write, change = struct.unpack_from('<qqqq', basic)
    return Metadata((volume, ident[8:].hex()), size, links, directory, attrs, tag,
                    (creation, write, change))


def basename(handle):
    data = query(handle, 2, 65536)  # FILE_NAME_INFO, bytes length then UTF-16
    length = struct.unpack_from('<I', data)[0]
    if length > 65532 or length % 2:
        raise SafeIOError('INVALID_WINDOWS_NAME_INFO')
    return data[4:4+length].decode('utf-16-le').rsplit('\\', 1)[-1]


def open_component(parent, name, *, directory, create=False, write=False):
    component(name)
    k, n = api()
    buf = C.create_unicode_buffer(name)
    length = len(name.encode('utf-16-le'))
    us = UNICODE_STRING(length, length + 2, C.cast(buf, W.LPWSTR))
    oa = OBJECT_ATTRIBUTES(C.sizeof(OBJECT_ATTRIBUTES), parent.value, C.pointer(us),
                           0x1000, None, None)  # OBJ_DONT_REPARSE, exact case
    ios = IO_STATUS_BLOCK()
    out = W.HANDLE()
    # Explicit DATA/LIST access. Sharing does NOT lock attribute changes.
    access = 0x100000 | 0x80 | 1 | (2 if write else 0)
    options = 0x20 | 0x200000 | (1 if directory else 0x40)
    status = n.NtCreateFile(C.byref(out), access, C.byref(oa), C.byref(ios), None,
                            0x80, 0 if write else 1, 2 if create else 1,
                            options, None, 0)
    if status != 0:
        # Only STATUS_SUCCESS is admitted; never consume a pending handle.
        if out.value:
            k.CloseHandle(out)
        winerror = n.RtlNtStatusToDosError(status)
        if winerror in (80, 183):
            raise FileExistsError(winerror, 'OUTPUT_EXISTS')
        raise SafeIOError('SOURCE_UNAVAILABLE_OR_UNSAFE', winerror=winerror,
                          ntstatus=status & 0xffffffff)
    handle = Handle(out.value)
    try:
        info = metadata(handle, directory)
        if info.identity[0] != metadata(parent, True).identity[0]:
            raise SafeIOError('UNSAFE_PATH_VOLUME_CHANGED')
        if basename(handle) != name:
            raise SafeIOError('UNSAFE_PATH_ALIAS_OR_CASE')
        return handle
    except BaseException:
        handle.close()
        raise


class Directory:
    """Own all ancestors; operations below never resolve a full descendant path."""
    def __init__(self, path):
        self.path = path
        self.stack = ExitStack()
        self.handles = []
        self.ids = []

    def __enter__(self):
        try:
            drive, parts = absolute(self.path)
            k, _ = api()
            if k.GetDriveTypeW(drive) != 3:
                raise SafeIOError('UNSUPPORTED_FILESYSTEM')
            root = k.CreateFileW(drive, 0x100081, 1, None, 3, 0x02200000, None)
            if root == C.c_void_p(-1).value:
                checked(False)
            self.add(Handle(root))
            fs = C.create_unicode_buffer(64)
            checked(k.GetVolumeInformationByHandleW(root, None, 0, None, None, None, fs, 64))
            final = C.create_unicode_buffer(1024)
            count = k.GetFinalPathNameByHandleW(root, final, 1024, 2)
            if (fs.value != 'NTFS' or not 0 < count < 1024
                    or not re.fullmatch(r'\\Device\\HarddiskVolume[0-9]+\\', final.value)):
                raise SafeIOError('UNSUPPORTED_FILESYSTEM')
            for part in parts:
                self.add(open_component(self.handle, part, directory=True))
            return self
        except BaseException:
            self.stack.close()
            raise

    def add(self, handle):
        self.stack.enter_context(handle)
        info = metadata(handle, True)
        self.handles.append(handle)
        self.ids.append(info.identity)

    @property
    def handle(self):
        return self.handles[-1]

    def validate(self):
        for handle, ident in zip(self.handles, self.ids):
            if metadata(handle, True).identity != ident:
                raise SafeIOError('SOURCE_CHANGED')

    def __exit__(self, *exc):
        self.stack.close()


@dataclass(frozen=True)
class ReadResult:
    raw: bytes
    sha256: str
    metadata: Metadata


def _descriptor(handle, flags):
    import msvcrt
    fd = msvcrt.open_osfhandle(handle.value, flags | os.O_BINARY)
    handle.value = None  # CRT fd now owns precisely this handle
    return fd


def safe_read(root, name, expected, max_bytes):
    if type(max_bytes) is not int or not 0 <= max_bytes <= 512_000_000:
        raise SafeIOError('SIZE_LIMIT')
    if expected is not None and (not isinstance(expected, str) or not re.fullmatch('[0-9a-f]{64}', expected)):
        raise SafeIOError('INVALID_HASH')
    parts = relative(name)
    with Directory(root) as directory:
        for part in parts[:-1]:
            directory.add(open_component(directory.handle, part, directory=True))
        with open_component(directory.handle, parts[-1], directory=False) as handle:
            before = metadata(handle, False)
            if before.size > max_bytes:
                raise SafeIOError('SIZE_LIMIT')
            fd = _descriptor(handle, os.O_RDONLY)
            try:
                import msvcrt
                borrowed = Handle(msvcrt.get_osfhandle(fd))
                raw = bytearray()
                try:
                    while len(raw) <= max_bytes:
                        block = os.read(fd, min(65536, max_bytes + 1 - len(raw)))
                        if not block:
                            break
                        raw.extend(block)
                except OSError as exc:
                    raise SafeIOError('SOURCE_READ_FAILED', winerror=getattr(exc, 'winerror', None)) from None
                after = metadata(borrowed, False)
                directory.validate()
                if before != after or len(raw) != after.size:
                    raise SafeIOError('SOURCE_CHANGED')
                if len(raw) > max_bytes:
                    raise SafeIOError('SIZE_LIMIT')
                sha = hashlib.sha256(raw).hexdigest()
                if expected is not None and sha != expected:
                    raise SafeIOError('SOURCE_HASH_MISMATCH')
                return ReadResult(bytes(raw), sha, after)
            finally:
                os.close(fd)


@contextmanager
def created_file(directory, name, body):
    """Exclusive new file, same-handle flush/readback. Partial failure is retained."""
    if not isinstance(body, bytes) or len(body) > 512_000_000:
        raise SafeIOError('SIZE_LIMIT')
    directory.validate()
    with open_component(directory.handle, name, directory=False, create=True, write=True) as h:
        before = metadata(h, False)
        fd = _descriptor(h, os.O_RDWR)
        try:
            offset = 0
            while offset < len(body):
                wrote = os.write(fd, body[offset:offset+65536])
                if wrote <= 0:
                    raise SafeIOError('OUTPUT_WRITE_FAILED')
                offset += wrote
            os.fsync(fd)
            os.lseek(fd, 0, os.SEEK_SET)
            sha = hashlib.sha256()
            count = 0
            while count <= len(body):
                block = os.read(fd, min(65536, len(body)+1-count))
                if not block:
                    break
                sha.update(block)
                count += len(block)
            import msvcrt
            after = metadata(Handle(msvcrt.get_osfhandle(fd)), False)
            directory.validate()
            if (count != len(body) or after.size != count or before.identity != after.identity
                    or sha.digest() != hashlib.sha256(body).digest()):
                raise SafeIOError('OUTPUT_INTEGRITY_FAILED')
            yield after
        finally:
            os.close(fd)


def reject_membership(parent, protected):
    if protected.ids[-1] in parent.ids:
        raise SafeIOError('OUTPUT_OVERLAPS_INPUT')


def safe_create_new(output, body, protected_roots):
    drive, parts = absolute(output)
    if not parts:
        raise SafeIOError('UNSAFE_PATH')
    with ExitStack() as stack:
        protected = [stack.enter_context(Directory(p)) for p in protected_roots]
        parent = stack.enter_context(Directory(drive + '\\'.join(parts[:-1])))
        for source in protected:
            reject_membership(parent, source)
        with created_file(parent, parts[-1], body) as info:
            return info


def safe_create_artifacts(source_root, output, files, protected_roots=()):
    drive, parts = absolute(output)
    if not parts or not isinstance(files, dict) or list(files)[-1:] != ['MANIFEST.json']:
        raise SafeIOError('INVALID_ARTIFACT_SET')
    for name, body in files.items():
        component(name)
        if not isinstance(body, bytes) or len(body) > 512_000_000:
            raise SafeIOError('SIZE_LIMIT')
    with ExitStack() as stack:
        protected = [stack.enter_context(Directory(p)) for p in (source_root, *protected_roots)]
        parent = stack.enter_context(Directory(drive + '\\'.join(parts[:-1])))
        for source in protected:
            reject_membership(parent, source)
        parent.add(open_component(parent.handle, parts[-1], directory=True, create=True))
        for name, body in files.items():
            # Retain every exclusive file handle through final manifest creation.
            stack.enter_context(created_file(parent, name, body))
        parent.validate()
        for source in protected:
            source.validate()
