"""Inspect approved wheels without extracting, installing, or importing them."""
import base64
import csv
import io
import re
import stat
import zipfile
import zlib

from audit_distribution import LIMIT, digest, need, path_ok, read, scan, strict

PREFIX = 'releases/windows/0.1.0a12.post3/'
EXTERNAL_PINS_SHA256 = '1ff248f909af22c51ec81d9e3e2f90d97281cbf86ef092a84b32cb3350f1b106'
PLATFORM_WHEEL = PREFIX + 'wheelhouse/platformdirs-4.14.8-py3-none-any.whl'
PUBLIC_EXAMPLE_MEMBER = 'platformdirs/windows.py'
PUBLIC_EXAMPLE_HASH = '9fac74e01b4944f912ff46bb2acb96199ed221a5c5dca11b5e8f7c633ced997a'
PUBLIC_EXAMPLE = b'Public share directory e.g. ``C:' + bytes([92]) + b'Users' + bytes([92]) + b'Public``.'


def load_pins(root, path):
    path = path.absolute()
    need('..' not in path.parts and not path.is_relative_to(root.absolute()),
         'external wheel pins must be outside the audited checkout')
    raw = read(path)
    need(digest(raw) == EXTERNAL_PINS_SHA256, 'external wheel pins SHA-256 mismatch')
    pins = strict(raw)['wheels']
    need(len(pins) == 10, 'expected ten approved wheel pins')
    for name, pin in pins.items():
        path_ok(name)
        need(name.startswith(PREFIX) and name.endswith('.whl'), 'invalid wheel pin path')
        need(set(pin) == {'bytes', 'sha256'} and type(pin['bytes']) is int
             and 0 < pin['bytes'] <= LIMIT and re.fullmatch(r'[0-9a-f]{64}', pin['sha256']),
             'invalid wheel pin')
    return pins


def select_wheels(members, pins):
    """Map object to its sole approved occurrence within the current tree."""
    need({path for path in members if path.casefold().endswith('.whl')} == set(pins),
         'wheel path membership differs from external pins')
    approved = {members[path][1]: path for path in pins}
    for path, (_, oid) in members.items():
        need(oid not in approved or approved[oid] == path, 'wheel blob has an unauthorized path alias')
    return approved


def member_names(infos):
    paths = {}
    names = set()
    for info in infos:
        name = info.filename
        need(name == info.orig_filename and name.isascii() and not info.is_dir()
             and not any(ord(c) < 32 or ord(c) == 127 for c in name), 'invalid wheel member')
        need(not any(c in name for c in '\\:<>"|?*'), 'unsafe wheel path')
        parts = name.split('/')
        for part in parts:
            need(part not in ('', '.', '..') and not part.endswith((' ', '.')), 'unsafe wheel path')
            need(not re.fullmatch(r'(?i)(CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[1-9]|LPT[1-9])(?:\..*)?', part),
                 'reserved wheel path')
        for depth in range(1, len(parts)+1):
            spelling = '/'.join(parts[:depth])
            entry = (spelling, depth == len(parts))
            previous = paths.setdefault(spelling.casefold(), entry)
            need(previous == entry, 'wheel path alias or file/directory collision')
        need(name not in names, 'duplicate wheel path')
        names.add(name)
        need(stat.S_IFMT(info.external_attr >> 16) in (0, stat.S_IFREG)
             and not info.external_attr & 0x410, 'nonregular wheel member')
        need(not info.flag_bits & 0x2041
             and info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
             and 0 <= info.file_size <= LIMIT, 'unsupported wheel member')
        need(not info.comment and not info.extra, 'unexpected wheel member metadata')
    return names


def scan_member(path, name, body):
    if path == PLATFORM_WHEEL and name == PUBLIC_EXAMPLE_MEMBER and digest(body) == PUBLIC_EXAMPLE_HASH:
        need(body.count(PUBLIC_EXAMPLE) == 1, 'public example drift')
        scan(body.replace(PUBLIC_EXAMPLE, b'Public share directory (reviewed public example).', 1))
        return {'member': name, 'sha256': PUBLIC_EXAMPLE_HASH, 'reason': 'EXACT_PUBLIC_WINDOWS_DIRECTORY_EXAMPLE'}
    scan(body)
    return None


def inspect_wheel(path, raw, pins):
    need(path in pins and path.startswith(PREFIX) and path.endswith('.whl'), 'wheel path not authorized')
    identity = {'bytes': len(raw), 'sha256': digest(raw)}
    need(len(raw) <= LIMIT and identity == pins[path], 'wheel pin mismatch')
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            infos = archive.infolist()
            total = sum(info.file_size for info in infos)
            need(0 < len(infos) <= 1000 and total <= 16*1024*1024, 'wheel member budget')
            need(not archive.comment and min(info.header_offset for info in infos) == 0,
                 'unexpected wheel archive metadata')
            names = member_names(infos)
            records = [name for name in names if name.endswith('.dist-info/RECORD')]
            need(len(records) == 1, 'wheel RECORD missing or ambiguous')
            record = records[0]
            bodies = {info.filename: archive.read(info) for info in infos}  # zipfile checks CRC
            need(all(len(bodies[info.filename]) == info.file_size for info in infos), 'wheel member size mismatch')
        rows = list(csv.reader(io.StringIO(bodies[record].decode('utf-8'), newline=''), strict=True))
    except (zipfile.BadZipFile, csv.Error, zlib.error, RuntimeError, EOFError) as exc:
        raise ValueError('invalid wheel archive or RECORD') from exc
    need(len(rows) == len(names) and all(len(row) == 3 for row in rows)
         and {row[0] for row in rows} == names, 'wheel RECORD membership mismatch')
    exceptions = []
    for name, hash_value, size in rows:
        body = bodies[name]
        if name == record:
            need(hash_value == size == '', 'wheel RECORD self row invalid')
        else:
            expected = 'sha256=' + base64.urlsafe_b64encode(bytes.fromhex(digest(body))).decode('ascii').rstrip('=')
            need(hash_value == expected and size == str(len(body)), 'wheel RECORD digest/size mismatch')
        exception = scan_member(path, name, body)
        if exception:
            exceptions.append(exception)
    return {'path': path, **identity, 'members': len(names), 'record_hashed': len(names)-1,
            'uncompressed_bytes': total, 'exceptions': exceptions,
            'privacy_text_scan': 'PASS_WITH_RECORDED_EXCEPTION' if exceptions else 'PASS'}
