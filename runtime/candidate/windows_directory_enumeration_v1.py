"""Bounded native Windows handle enumeration and metadata-only preflight.

This additive module does not change the old Windows provider or E7 contracts.
"""
import ctypes as C
from ctypes import wintypes as W
import os
import struct
import time
from . import windows_safe_io_v2 as IO
from . import discovery_contract_v1 as D

UNSAFE_ATTRIBUTES = 0x400 | 0x1000 | 0x4000 | 0x40000 | 0x400000 | 0x40
NO_MORE_FILES = 0x80000006

class DirectoryRecord(C.Structure):
    _fields_ = [('next', W.ULONG), ('index', W.ULONG), ('creation', C.c_longlong),
        ('access', C.c_longlong), ('write', C.c_longlong), ('change', C.c_longlong),
        ('size', C.c_longlong), ('allocation', C.c_longlong), ('attributes', W.ULONG),
        ('length', W.ULONG), ('ea', W.ULONG), ('tag', W.ULONG),
        ('file_id', C.c_ubyte * 16), ('name', W.WCHAR * 1)]

def query_api():
    _, n = IO.api()
    expected = [0,4,8,16,24,32,40,48,56,60,64,68,72,88]
    if ([getattr(DirectoryRecord,key).offset for key,_ in DirectoryRecord._fields_] != expected
            or C.sizeof(DirectoryRecord) != 96 or C.alignment(DirectoryRecord) != 8
            or IO.IO_STATUS_BLOCK.Information.offset != 8):
        raise IO.SafeIOError('UNSUPPORTED_DIRECTORY_ABI')
    fn = n.NtQueryDirectoryFile
    fn.restype = W.LONG
    fn.argtypes = [W.HANDLE,W.HANDLE,W.LPVOID,W.LPVOID,C.POINTER(IO.IO_STATUS_BLOCK),
        W.LPVOID,W.ULONG,C.c_int,C.c_ubyte,C.POINTER(IO.UNICODE_STRING),C.c_ubyte]
    return fn

def parse_page(raw, information):
    if type(raw) is not bytes or type(information) is not int or not 0 < information <= len(raw):
        raise IO.SafeIOError('DIRECTORY_INVALID_LENGTH')
    rows=[]; position=0
    while True:
        if position % 8 or information-position < 88:
            raise IO.SafeIOError('DIRECTORY_MALFORMED_PAGE')
        next_offset = struct.unpack_from('<I',raw,position)[0]
        size = struct.unpack_from('<q',raw,position+40)[0]
        attrs,length,_,tag = struct.unpack_from('<IIII',raw,position+56)
        end = position+88+length
        if not 0 < length <= 510 or length%2 or end > information or size < 0:
            raise IO.SafeIOError('DIRECTORY_MALFORMED_PAGE')
        if next_offset and (next_offset%8 or next_offset < 88+length or position+next_offset >= information):
            raise IO.SafeIOError('DIRECTORY_MALFORMED_PAGE')
        if not next_offset and information-end >= 8:
            raise IO.SafeIOError('DIRECTORY_MALFORMED_PAGE')
        try:
            name=raw[position+88:end].decode('utf-16-le',errors='strict')
        except UnicodeError:
            raise IO.SafeIOError('DIRECTORY_INVALID_NAME') from None
        if name not in ('.','..'):
            IO.component(name)
            ident=raw[position+72:position+88]
            if not any(ident):
                raise IO.SafeIOError('DIRECTORY_INVALID_ID')
            rows.append(dict(name=name,attributes=attrs,tag=tag,size=size,file_id=ident.hex(),
                times=[struct.unpack_from('<q',raw,position+i)[0] for i in (8,24,32)]))
        if next_offset == 0:
            return rows
        position += next_offset

def enumerate_directory(handle, limits=None, trace=None, *, deadline=None):
    budget=D.limits(limits); fn=query_api(); rows=[]; seen=set()
    before=IO.metadata(handle,True)
    started=time.monotonic()
    for page in range(budget['max_pages']):
        if deadline is not None:deadline()
        if time.monotonic()-started>budget['timeout_seconds']:
            raise IO.SafeIOError('DISCOVERY_COOPERATIVE_TIMEOUT')
        buffer=C.create_string_buffer(budget['buffer_bytes'])
        if C.addressof(buffer)%8:
            raise IO.SafeIOError('UNSUPPORTED_DIRECTORY_ABI')
        ios=IO.IO_STATUS_BLOCK()
        status=fn(handle.value,None,None,None,C.byref(ios),buffer,len(buffer),60,0,None,page==0)&0xffffffff
        event=dict(event='QUERY',page=page,ntstatus=status,returned_bytes=ios.Information,
                   decoded_entries=None if ios.Information else 0,page_state='NOT_PARSED')
        if trace is not None:trace.append(event)
        if status == NO_MORE_FILES:
            if ios.Information:
                event['page_state']='INVALID_EOF'
                raise IO.SafeIOError('DIRECTORY_INVALID_EOF')
            event['page_state']='END'
            if IO.metadata(handle,True) != before:
                raise IO.SafeIOError('DIRECTORY_CHANGED')
            return sorted(rows,key=lambda r:r['name'])
        if status != 0:
            event['page_state']='QUERY_FAILED'
            raise IO.SafeIOError('DIRECTORY_QUERY_FAILED',ntstatus=status)
        if not ios.Information:
            event['page_state']='NO_PROGRESS'
            raise IO.SafeIOError('DIRECTORY_NO_PROGRESS')
        try:
            parsed=parse_page(buffer.raw,ios.Information)
        except (ValueError,IO.SafeIOError):
            event['page_state']='MALFORMED_OR_UNSAFE'
            raise
        event.update(decoded_entries=len(parsed),page_state='PARSED')
        if deadline is not None:deadline()
        for row in parsed:
            folded=row['name'].lower()
            if folded in seen:
                raise IO.SafeIOError('DIRECTORY_DUPLICATE_OR_CASE_COLLISION')
            seen.add(folded);rows.append(row)
            if len(rows)>budget['max_entries']:
                raise IO.SafeIOError('DIRECTORY_ENTRY_BUDGET')
    raise IO.SafeIOError('DIRECTORY_PAGE_BUDGET')

def open_metadata(parent, name, *, directory):
    IO.component(name)
    k,n=IO.api(); buffer=C.create_unicode_buffer(name);length=len(name.encode('utf-16-le'))
    us=IO.UNICODE_STRING(length,length+2,C.cast(buffer,W.LPWSTR))
    oa=IO.OBJECT_ATTRIBUTES(C.sizeof(IO.OBJECT_ATTRIBUTES),parent.value,C.pointer(us),0x1000,None,None)
    ios=IO.IO_STATUS_BLOCK();out=W.HANDLE()
    access=0x100080 | (1 if directory else 0)
    options=0x20 | 0x200000 | (1 if directory else 0x40)
    status=n.NtCreateFile(C.byref(out),access,C.byref(oa),C.byref(ios),None,0x80,1,1,options,None,0)
    if status != 0:
        if out.value:k.CloseHandle(out)
        raise IO.SafeIOError('METADATA_OPEN_FAILED',ntstatus=status&0xffffffff,
                             winerror=n.RtlNtStatusToDosError(status))
    handle=IO.Handle(out.value)
    try:
        meta=IO.metadata(handle,directory)
        if meta.identity[0]!=IO.metadata(parent,True).identity[0]:
            raise IO.SafeIOError('UNSAFE_PATH_VOLUME_CHANGED')
        if IO.basename(handle)!=name:
            raise IO.SafeIOError('UNSAFE_PATH_ALIAS_OR_CASE')
        return handle
    except BaseException:
        handle.close();raise

def matches(entry,meta):
    if (entry['file_id'] != meta.identity[1] or entry['attributes'] != meta.attributes
            or entry['tag'] != meta.tag or bool(entry['attributes']&16) != meta.directory
            or (not meta.directory and (entry['size'] != meta.size or entry['times'] != list(meta.times)))):
        raise IO.SafeIOError('ENUMERATED_IDENTITY_CHANGED')

def capture(parent, name, retained, expected, cap):
    if IO.metadata(retained,False)!=expected:
        raise IO.SafeIOError('SOURCE_CHANGED')
    with IO.open_component(parent,name,directory=False) as data:
        if IO.metadata(data,False)!=expected:
            raise IO.SafeIOError('SOURCE_CHANGED')
        fd=IO._descriptor(data,os.O_RDONLY)
        try:
            import msvcrt
            borrowed=IO.Handle(msvcrt.get_osfhandle(fd));raw=bytearray()
            while len(raw)<=cap:
                chunk=os.read(fd,min(65536,cap+1-len(raw)))
                if not chunk:break
                raw.extend(chunk)
            if (len(raw)!=expected.size or len(raw)>cap or IO.metadata(borrowed,False)!=expected
                    or IO.metadata(retained,False)!=expected):
                raise IO.SafeIOError('SOURCE_CHANGED')
            return bytes(raw)
        finally:
            os.close(fd)
