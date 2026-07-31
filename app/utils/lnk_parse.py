"""Pure Windows Shell Link (``.lnk``) parsing and heuristics. stdlib only, no I/O.
Structures follow MS-SHLLINK: ShellLinkHeader, LinkTargetIDList, LinkInfo, StringData,
ExtraData.

**The input is attacker-controlled binary and nothing here may raise.** Every count and
length read from the file is clamped against the remaining buffer before it drives a slice
or a loop, and :func:`parse_lnk` reports failure by returning a partial record with
``parsed_ok`` false. Bounds on file-supplied fields:

* ``HeaderSize`` is recorded but never used for arithmetic: the spec fixes the header at
  76 bytes and a lying ``HeaderSize`` is a known evasion, so everything after it is located
  at the constant offset.
* ``IDListSize`` and each ``ItemIDSize`` are clamped to the buffer; an item under 3 bytes
  stops the walk, which is what prevents a zero/one-byte item looping forever. At most
  ``MAX_IDLIST_ITEMS`` items.
* ``LinkInfoSize`` must be at least 0x1C and is clamped to the remaining buffer; every
  offset inside it must fall in that span, and VolumeID / CommonNetworkRelativeLink are
  additionally bounded by their own declared sizes.
* ``CountCharacters`` in StringData is 16-bit, so a lie costs at most 128 KiB of read;
  the byte count is still clamped and the value truncated at ``MAX_FIELD_CHARS``.
* NUL-terminated paths are scanned inside a ``MAX_PATH_CHARS`` window: an unbounded
  ``find(b'\\x00')`` on a file with no NUL yields a "path" the size of the whole file.
* ``BlockSize`` in ExtraData must be at least 4 (smaller is the terminal block) and fit
  the buffer; at most ``MAX_EXTRA_BLOCKS`` blocks are walked.
"""

import re
import struct
from datetime import datetime, timedelta, timezone

from .iocs import extract_iocs

HEADER_SIZE = 76
LNK_CLSID = bytes((
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
))

MAX_IDLIST_ITEMS = 256
MAX_EXTRA_BLOCKS = 64
MAX_FIELD_CHARS = 32768
MAX_PATH_CHARS = 1024
MAX_IOC_TEXT = 64 * 1024
MIN_EXTRA_BLOCK_SIZE = 4

# A shortcut this large is carrying something that is not shortcut metadata.
OVERSIZED_LNK_BYTES = 50 * 1024
# Slack allowed after the ExtraData terminal block before it reads as appended.
APPENDED_SLACK_BYTES = 8
# MAX_PATH. A command line longer than a legal path is not a hand-made shortcut.
MAX_NORMAL_ARG_CHARS = 260
# Above this the header's recorded target size is not a real file size.
MAX_PLAUSIBLE_TARGET_BYTES = 256 * 1024 * 1024

LINK_FLAGS = (
    (0x00000001, 'HasLinkTargetIDList'),
    (0x00000002, 'HasLinkInfo'),
    (0x00000004, 'HasName'),
    (0x00000008, 'HasRelativePath'),
    (0x00000010, 'HasWorkingDir'),
    (0x00000020, 'HasArguments'),
    (0x00000040, 'HasIconLocation'),
    (0x00000080, 'IsUnicode'),
    (0x00000100, 'ForceNoLinkInfo'),
    (0x00000200, 'HasExpString'),
    (0x00000400, 'RunInSeparateProcess'),
    (0x00001000, 'HasDarwinID'),
    (0x00002000, 'RunAsUser'),
    (0x00004000, 'HasExpIcon'),
    (0x00008000, 'NoPidlAlias'),
    (0x00020000, 'RunWithShimLayer'),
    (0x00040000, 'ForceNoLinkTrack'),
    (0x00080000, 'EnableTargetMetadata'),
    (0x00100000, 'DisableLinkPathTracking'),
    (0x00200000, 'DisableKnownFolderTracking'),
    (0x00400000, 'DisableKnownFolderAlias'),
    (0x00800000, 'AllowLinkToLink'),
    (0x01000000, 'UnaliasOnSave'),
    (0x02000000, 'PreferEnvironmentPath'),
    (0x04000000, 'KeepLocalIDListForUNCTarget'),
)

HAS_LINK_TARGET_IDLIST = 0x00000001
HAS_LINK_INFO = 0x00000002
HAS_NAME = 0x00000004
HAS_RELATIVE_PATH = 0x00000008
HAS_WORKING_DIR = 0x00000010
HAS_ARGUMENTS = 0x00000020
HAS_ICON_LOCATION = 0x00000040
IS_UNICODE = 0x00000080
RUN_AS_USER = 0x00002000

FILE_ATTRIBUTES = (
    (0x0001, 'READONLY'),
    (0x0002, 'HIDDEN'),
    (0x0004, 'SYSTEM'),
    (0x0010, 'DIRECTORY'),
    (0x0020, 'ARCHIVE'),
    (0x0080, 'NORMAL'),
    (0x0100, 'TEMPORARY'),
    (0x0200, 'SPARSE_FILE'),
    (0x0400, 'REPARSE_POINT'),
    (0x0800, 'COMPRESSED'),
    (0x1000, 'OFFLINE'),
    (0x2000, 'NOT_CONTENT_INDEXED'),
    (0x4000, 'ENCRYPTED'),
)

ATTR_DIRECTORY = 0x0010

# SW_* values Explorer writes. Anything else is out of spec but does occur.
SHOW_COMMANDS = {
    1: 'SW_SHOWNORMAL',
    3: 'SW_SHOWMAXIMIZED',
    7: 'SW_SHOWMINNOACTIVE',
}
SHOW_HIDDEN = 7

HOTKEY_MODIFIERS = ((0x01, 'SHIFT'), (0x02, 'CTRL'), (0x04, 'ALT'))

LINKINFO_HAS_VOLUME_ID = 0x01
LINKINFO_HAS_NETWORK_RELATIVE_LINK = 0x02
CNRL_VALID_DEVICE = 0x01

EXTRA_BLOCK_NAMES = {
    0xA0000001: 'EnvironmentVariableDataBlock',
    0xA0000002: 'ConsoleDataBlock',
    0xA0000003: 'TrackerDataBlock',
    0xA0000004: 'ConsoleFEDataBlock',
    0xA0000005: 'SpecialFolderDataBlock',
    0xA0000006: 'DarwinDataBlock',
    0xA0000007: 'IconEnvironmentDataBlock',
    0xA0000008: 'ShimDataBlock',
    0xA0000009: 'PropertyStoreDataBlock',
    0xA000000B: 'KnownFolderDataBlock',
    0xA000000C: 'VistaAndAboveIDListDataBlock',
}

_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _u16(data, offset):
    if offset < 0:
        return None
    try:
        return struct.unpack_from('<H', data, offset)[0]
    except struct.error:
        return None


def _u32(data, offset):
    if offset < 0:
        return None
    try:
        return struct.unpack_from('<I', data, offset)[0]
    except struct.error:
        return None


def _u64(data, offset):
    if offset < 0:
        return None
    try:
        return struct.unpack_from('<Q', data, offset)[0]
    except struct.error:
        return None


def _filetime(value):
    """FILETIME to an ISO-8601 UTC string, or None - the shape the rule engines' date
    parsers already accept."""
    if not value:
        return None
    try:
        moment = _FILETIME_EPOCH + timedelta(microseconds=value // 10)
    except (OverflowError, ValueError):
        return None
    try:
        return moment.strftime('%Y-%m-%dT%H:%M:%SZ')
    except (OverflowError, ValueError):
        return None


def _clean(text):
    return (text or '').replace('\x00', '').strip()[:MAX_FIELD_CHARS]


def _ansi_at(buffer, chars=MAX_PATH_CHARS):
    window = buffer[:chars]
    end = window.find(b'\x00')
    if end != -1:
        window = window[:end]
    return _clean(window.decode('latin-1', 'replace'))


def _wide_at(buffer, chars=MAX_PATH_CHARS):
    window = buffer[:chars * 2]
    for index in range(0, len(window) - 1, 2):
        if window[index] == 0 and window[index + 1] == 0:
            window = window[:index]
            break
    return _clean(window.decode('utf-16-le', 'replace'))


def _flag_names(value, table):
    return [name for bit, name in table if value & bit]


def _hotkey(raw):
    if not raw:
        return None
    key = raw & 0xFF
    modifiers = _flag_names((raw >> 8) & 0xFF, HOTKEY_MODIFIERS)
    if 0x30 <= key <= 0x5A:
        label = chr(key)
    elif 0x70 <= key <= 0x87:
        label = f'F{key - 0x6F}'
    else:
        label = f'VK_{key:02X}'
    return '+'.join(modifiers + [label])


def _empty_record():
    return {
        'parsed_ok': False,
        'error': None,
        'parse_warnings': [],
        'lnk_size_bytes': 0,
        'header_size': None,
        'clsid_ok': False,
        'link_flags': 0,
        'link_flag_names': [],
        'file_attributes': 0,
        'file_attribute_names': [],
        'creation_time': None,
        'access_time': None,
        'write_time': None,
        'target_size_bytes': 0,
        'icon_index': 0,
        'show_command': None,
        'show_command_raw': 0,
        'hotkey': None,
        'run_as_user': False,
        'is_unicode': False,
        'idlist_items': [],
        'idlist_path': '',
        'local_base_path': '',
        'common_path_suffix': '',
        'network_share': '',
        'device_name': '',
        'volume_label': '',
        'drive_type': None,
        'drive_serial': None,
        'target_path': '',
        'name': '',
        'relative_path': '',
        'working_dir': '',
        'arguments': '',
        'arguments_length': 0,
        'icon_location': '',
        'extra_blocks': [],
        'env_target': '',
        'icon_env_target': '',
        'darwin_id': '',
        'machine_id': '',
        'shim_layer': '',
        'special_folder_id': None,
        'known_folder_id': '',
        'structures_end': 0,
        'trailing_bytes': 0,
    }


def _shell_item_name(item):
    """Shell items are only partially documented. Two shapes are enough to rebuild a
    target for the common malicious shortcut carrying no LinkInfo at all: a file-entry
    item (class 0x30-0x3F) whose PrimaryName starts at item-data offset 12, and a volume
    item (0x20-0x2F) whose name starts at offset 1. Windows writes the name in ANSI there
    and repeats it as UTF-16 in an extension block, so a one-character ANSI read is the
    tell that this item is the wide variant."""
    if not item:
        return ''
    class_type = item[0]
    if class_type & 0x70 == 0x30:
        body = item[12:]
    elif class_type & 0x70 == 0x20:
        body = item[1:]
    else:
        return ''
    ansi = _ansi_at(body)
    if len(ansi) > 1:
        return ansi
    return _wide_at(body) or ansi


def _join_idlist(names):
    if not names:
        return ''
    head, rest = names[0], names[1:]
    parts = [head.rstrip('\\')] + [part.strip('\\') for part in rest]
    return '\\'.join(part for part in parts if part)


def _parse_idlist(data, offset, warnings):
    size = _u16(data, offset)
    if size is None:
        warnings.append('LinkTargetIDList: truncated size field')
        return offset, [], ''
    declared_end = offset + 2 + size
    if declared_end > len(data):
        warnings.append('LinkTargetIDList: declared size exceeds buffer')
    end = min(declared_end, len(data))
    position = offset + 2
    names = []
    count = 0
    while position + 2 <= end and count < MAX_IDLIST_ITEMS:
        item_size = _u16(data, position)
        if not item_size:
            break
        if item_size < 3 or position + item_size > end:
            warnings.append('LinkTargetIDList: item size out of bounds')
            break
        name = _shell_item_name(data[position + 2:position + item_size])
        if name:
            names.append(name)
        position += item_size
        count += 1
    if count >= MAX_IDLIST_ITEMS:
        warnings.append(f'LinkTargetIDList: stopped after {MAX_IDLIST_ITEMS} items')
    return end, names, _join_idlist(names)


def _read_linkinfo_path(data, base, ansi_offset, wide_offset, span):
    """Prefer the Unicode variant; both offsets are relative to LinkInfo start."""
    if 0 < wide_offset < span:
        wide = _wide_at(data[base + wide_offset:base + span])
        if wide:
            return wide
    if 0 < ansi_offset < span:
        return _ansi_at(data[base + ansi_offset:base + span])
    return ''


def _parse_linkinfo(data, offset, warnings):
    info = {
        'local_base_path': '',
        'common_path_suffix': '',
        'network_share': '',
        'device_name': '',
        'volume_label': '',
        'drive_type': None,
        'drive_serial': None,
        'target_path': '',
    }
    size = _u32(data, offset)
    if size is None:
        warnings.append('LinkInfo: truncated size field')
        return offset, info
    if size < 0x1C:
        warnings.append(f'LinkInfo: implausible size {size}')
        return min(offset + MIN_EXTRA_BLOCK_SIZE, len(data)), info

    available = len(data) - offset
    if size > available:
        warnings.append('LinkInfo: declared size exceeds buffer')
    span = min(size, available)
    base = offset

    header_len = _u32(data, base + 4) or 0
    flags = _u32(data, base + 8) or 0
    volume_offset = _u32(data, base + 12) or 0
    local_offset = _u32(data, base + 16) or 0
    network_offset = _u32(data, base + 20) or 0
    suffix_offset = _u32(data, base + 24) or 0
    local_offset_wide = suffix_offset_wide = 0
    if header_len >= 0x24:
        local_offset_wide = _u32(data, base + 28) or 0
        suffix_offset_wide = _u32(data, base + 32) or 0

    if flags & LINKINFO_HAS_VOLUME_ID:
        info['local_base_path'] = _read_linkinfo_path(
            data, base, local_offset, local_offset_wide, span)
        volume_size = _u32(data, base + volume_offset) if 0 < volume_offset < span else None
        if volume_size and 0x10 <= volume_size and volume_offset + volume_size <= span:
            volume = base + volume_offset
            info['drive_type'] = _u32(data, volume + 4)
            info['drive_serial'] = _u32(data, volume + 8)
            label_offset = _u32(data, volume + 12) or 0
            if label_offset == 0x14:
                label_offset_wide = _u32(data, volume + 16) or 0
                if 0 < label_offset_wide < volume_size:
                    info['volume_label'] = _wide_at(
                        data[volume + label_offset_wide:volume + volume_size])
            elif 0 < label_offset < volume_size:
                info['volume_label'] = _ansi_at(
                    data[volume + label_offset:volume + volume_size])
        elif volume_offset:
            warnings.append('LinkInfo: VolumeID out of bounds')

    info['common_path_suffix'] = _read_linkinfo_path(
        data, base, suffix_offset, suffix_offset_wide, span)

    if (flags & LINKINFO_HAS_NETWORK_RELATIVE_LINK) and 0 < network_offset < span:
        network = base + network_offset
        network_size = _u32(data, network) or 0
        if network_size >= 0x14 and network_offset + network_size <= span:
            network_flags = _u32(data, network + 4) or 0
            name_offset = _u32(data, network + 8) or 0
            device_offset = _u32(data, network + 12) or 0
            # Offsets past the fixed 0x14 header mean the Unicode fields exist.
            if name_offset > 0x14:
                name_offset_wide = _u32(data, network + 20) or 0
                if 0 < name_offset_wide < network_size:
                    info['network_share'] = _wide_at(
                        data[network + name_offset_wide:network + network_size])
            if not info['network_share'] and 0 < name_offset < network_size:
                info['network_share'] = _ansi_at(
                    data[network + name_offset:network + network_size])
            if (network_flags & CNRL_VALID_DEVICE) and 0 < device_offset < network_size:
                info['device_name'] = _ansi_at(
                    data[network + device_offset:network + network_size])
        else:
            warnings.append('LinkInfo: CommonNetworkRelativeLink out of bounds')

    prefix = info['local_base_path'] or info['network_share']
    if prefix:
        suffix = info['common_path_suffix']
        info['target_path'] = (
            prefix.rstrip('\\') + '\\' + suffix.lstrip('\\') if suffix else prefix
        )

    return min(base + span, len(data)), info


def _read_string_data(data, offset, is_unicode, warnings, label):
    count = _u16(data, offset)
    if count is None:
        warnings.append(f'StringData: truncated {label} length')
        return offset, ''
    offset += 2
    declared = count * 2 if is_unicode else count
    available = max(len(data) - offset, 0)
    if declared > available:
        warnings.append(
            f'StringData: {label} claims {declared} bytes, {available} available')
    take = min(declared, available)
    raw = data[offset:offset + take]
    if is_unicode:
        value = raw.decode('utf-16-le', 'replace')
    else:
        value = raw.decode('latin-1', 'replace')
    if len(value) > MAX_FIELD_CHARS:
        warnings.append(f'StringData: {label} truncated at {MAX_FIELD_CHARS} chars')
    return offset + take, _clean(value)


def _guid(buffer):
    if len(buffer) < 16:
        return ''
    try:
        first, second, third = struct.unpack_from('<IHH', buffer, 0)
    except struct.error:
        return ''
    tail = buffer[8:16]
    return '{%08x-%04x-%04x-%s-%s}' % (
        first, second, third, tail[:2].hex(), tail[2:].hex())


def _harvest_extra_block(signature, block, extras):
    """The three "target" blocks (Environment / IconEnvironment / Darwin) share one
    layout: 260 bytes of ANSI path at offset 8, then 520 bytes of UTF-16."""
    if signature in (0xA0000001, 0xA0000007, 0xA0000006):
        key = {
            0xA0000001: 'env_target',
            0xA0000007: 'icon_env_target',
            0xA0000006: 'darwin_id',
        }[signature]
        value = _wide_at(block[268:788]) or _ansi_at(block[8:268])
        if value and not extras.get(key):
            extras[key] = value
    elif signature == 0xA0000003:
        value = _ansi_at(block[16:32])
        if value and not extras.get('machine_id'):
            extras['machine_id'] = value
    elif signature == 0xA0000005:
        extras.setdefault('special_folder_id', _u32(block, 8))
    elif signature == 0xA000000B:
        value = _guid(block[8:24])
        if value and not extras.get('known_folder_id'):
            extras['known_folder_id'] = value
    elif signature == 0xA0000008:
        value = _wide_at(block[8:])
        if value and not extras.get('shim_layer'):
            extras['shim_layer'] = value


def _parse_extradata(data, offset, warnings):
    blocks = []
    extras = {}
    position = offset
    count = 0
    while count < MAX_EXTRA_BLOCKS:
        size = _u32(data, position)
        if size is None:
            break
        if size < MIN_EXTRA_BLOCK_SIZE:
            position += MIN_EXTRA_BLOCK_SIZE
            break
        signature = _u32(data, position + 4)
        if signature is None:
            warnings.append('ExtraData: truncated block signature')
            break
        if position + size > len(data):
            warnings.append('ExtraData: block size exceeds buffer')
            break
        block = data[position:position + size]
        blocks.append({
            'signature': f'0x{signature:08x}',
            'name': EXTRA_BLOCK_NAMES.get(signature, 'Unknown'),
            'size': size,
        })
        _harvest_extra_block(signature, block, extras)
        position += size
        count += 1
    if count >= MAX_EXTRA_BLOCKS:
        warnings.append(f'ExtraData: stopped after {MAX_EXTRA_BLOCKS} blocks')
    return min(position, len(data)), blocks, extras


def parse_lnk(data):
    """Parse ``.lnk`` bytes into a plain dict. Never raises: malformed input returns
    whatever was recovered, ``parse_warnings`` describing each bound that was hit, and
    ``parsed_ok`` false only when the bytes are not a shell link at all."""
    record = _empty_record()
    if isinstance(data, (bytearray, memoryview)):
        data = bytes(data)
    if not isinstance(data, bytes):
        record['error'] = 'input is not bytes'
        return record

    record['lnk_size_bytes'] = len(data)
    if len(data) < HEADER_SIZE:
        record['error'] = f'truncated: {len(data)} bytes, header requires {HEADER_SIZE}'
        return record

    record['header_size'] = _u32(data, 0)
    record['clsid_ok'] = data[4:20] == LNK_CLSID
    if not record['clsid_ok']:
        record['error'] = 'not a shell link: LinkCLSID mismatch'
        return record

    warnings = record['parse_warnings']
    if record['header_size'] != HEADER_SIZE:
        warnings.append(
            f'HeaderSize is {record["header_size"]}, expected {HEADER_SIZE}')

    flags = _u32(data, 20) or 0
    attributes = _u32(data, 24) or 0
    record.update({
        'parsed_ok': True,
        'link_flags': flags,
        'link_flag_names': _flag_names(flags, LINK_FLAGS),
        'file_attributes': attributes,
        'file_attribute_names': _flag_names(attributes, FILE_ATTRIBUTES),
        'creation_time': _filetime(_u64(data, 28)),
        'access_time': _filetime(_u64(data, 36)),
        'write_time': _filetime(_u64(data, 44)),
        'target_size_bytes': _u32(data, 52) or 0,
        'icon_index': _u32(data, 56) or 0,
        'show_command_raw': _u32(data, 60) or 0,
        'hotkey': _hotkey(_u16(data, 64) or 0),
        'run_as_user': bool(flags & RUN_AS_USER),
        'is_unicode': bool(flags & IS_UNICODE),
    })
    record['show_command'] = SHOW_COMMANDS.get(
        record['show_command_raw'], f'0x{record["show_command_raw"]:08x}')

    offset = HEADER_SIZE
    if flags & HAS_LINK_TARGET_IDLIST:
        offset, record['idlist_items'], record['idlist_path'] = _parse_idlist(
            data, offset, warnings)

    if flags & HAS_LINK_INFO:
        offset, info = _parse_linkinfo(data, offset, warnings)
        record.update(info)

    if not record['target_path']:
        record['target_path'] = record['idlist_path']

    is_unicode = record['is_unicode']
    for flag, key in (
        (HAS_NAME, 'name'),
        (HAS_RELATIVE_PATH, 'relative_path'),
        (HAS_WORKING_DIR, 'working_dir'),
        (HAS_ARGUMENTS, 'arguments'),
        (HAS_ICON_LOCATION, 'icon_location'),
    ):
        if flags & flag:
            offset, record[key] = _read_string_data(
                data, offset, is_unicode, warnings, key)
    record['arguments_length'] = len(record['arguments'])

    offset, record['extra_blocks'], extras = _parse_extradata(data, offset, warnings)
    for key, value in extras.items():
        record[key] = value

    record['structures_end'] = offset
    record['trailing_bytes'] = max(len(data) - offset, 0)
    return record


# Execution-capable Windows binaries abused by shortcut lures. Matched with word
# boundaries, never as substrings: a bare `in` test flags `powershell_helper.txt` as
# PowerShell. Two-letter names that are also English words (`at`, `sc`) are deliberately
# absent - noise on ordinary paths, and the argument patterns below already cover them.
LOLBAS_NAMES = (
    'powershell', 'pwsh', 'cmd', 'mshta', 'wscript', 'cscript', 'rundll32',
    'regsvr32', 'regasm', 'regsvcs', 'installutil', 'certutil', 'bitsadmin',
    'msiexec', 'forfiles', 'conhost', 'wmic', 'schtasks', 'msbuild', 'cmstp',
    'mavinject', 'odbcconf', 'pcalua', 'presentationhost', 'xwizard', 'hh',
    'ieexec', 'wmiprvse', 'syncappvpublishingserver', 'dfsvc', 'ftp',
)
_LOLBAS_PATTERNS = tuple(
    (name, re.compile(rf'\b{re.escape(name)}\b', re.IGNORECASE))
    for name in LOLBAS_NAMES
)

_ARGUMENT_PATTERNS = (
    ('encoded_powershell_command', re.compile(
        r'[-/]{1,2}(?:enc|encoded|encodedcommand)\b'
        r'|[-/]{1,2}e(?:c|nc)?\s+[A-Za-z0-9+/=]{20,}', re.IGNORECASE)),
    ('base64_blob_in_arguments', re.compile(r'[A-Za-z0-9+/]{60,}={0,2}')),
    ('frombase64string', re.compile(r'\bfrombase64string\b', re.IGNORECASE)),
    ('invoke_expression', re.compile(r'\b(?:iex|invoke-expression)\b', re.IGNORECASE)),
    ('download_cradle', re.compile(
        r'\b(?:downloadstring|downloadfile|downloaddata|webclient|'
        r'invoke-webrequest|invoke-restmethod|iwr|start-bitstransfer|'
        r'urlcache|curl|wget|bitsadmin)\b', re.IGNORECASE)),
    ('hidden_window_argument', re.compile(
        r'[-/]{1,2}w(?:indow|indowstyle)?\s+hidden\b', re.IGNORECASE)),
    ('execution_policy_bypass', re.compile(
        r'[-/]{1,2}(?:ep|ex|exec|executionpolicy)\s+(?:bypass|unrestricted)\b',
        re.IGNORECASE)),
    ('no_profile_argument', re.compile(
        r'[-/]{1,2}(?:nop|noprofile|noni|noninteractive|nologo)\b', re.IGNORECASE)),
    ('char_code_obfuscation', re.compile(
        r'\[char\]|\bchr\s*\(|\bcharcode\b|\[convert\]|-join\b', re.IGNORECASE)),
    ('env_var_obfuscation', re.compile(
        r'%(?:comspec|temp|tmp|appdata|localappdata|userprofile|windir|'
        r'systemroot|public|programdata)%|\$env:', re.IGNORECASE)),
    ('defender_tamper', re.compile(
        r'\bamsi(?:utils|initfailed|scanbuffer)\b|\b(?:set|add)-mppreference\b'
        r'|\bmpcmdrun\b', re.IGNORECASE)),
    ('persistence_command', re.compile(
        r'\breg(?:\.exe)?\s+add\b|currentversion\\run|\bschtasks\b'
        r'|\\start menu\\programs\\startup', re.IGNORECASE)),
    ('unc_path_in_arguments', re.compile(r'\\\\[A-Za-z0-9._-]{2,}\\')),
)

# User-writable drop locations. `\appdata\local\programs\` is deliberately absent: it is
# where VS Code, Slack and Teams legitimately install.
_USER_WRITABLE_FRAGMENTS = (
    '\\temp\\', '\\tmp\\', '\\appdata\\roaming\\', '\\appdata\\local\\temp\\',
    '\\downloads\\', '\\users\\public\\', '\\programdata\\', '\\windows\\tasks\\',
    '\\recycler\\', '$recycle.bin', '%temp%', '%tmp%', '%appdata%',
    '%localappdata%', '%public%', '%programdata%',
)

_NORMAL_PROGRAM_FRAGMENTS = (
    '\\windows\\', '\\winnt\\', '\\program files\\', '\\program files (x86)\\',
    '\\appdata\\local\\programs\\', '%programfiles%', '%systemroot%', '%windir%',
    '%programw6432%',
)

_DRIVE_PATH_RE = re.compile(r'^[a-z]:\\', re.IGNORECASE)

# Extensions a lure names itself with while the target is an interpreter.
_DOCUMENT_EXTENSIONS = (
    '.pdf', '.doc', '.docx', '.docm', '.xls', '.xlsx', '.xlsm', '.ppt', '.pptx',
    '.rtf', '.txt', '.csv', '.jpg', '.jpeg', '.png', '.one', '.msg', '.eml',
)

# Icon sources that render a document or generic-file glyph.
_DOCUMENT_ICON_HINTS = (
    'shell32.dll', 'imageres.dll', 'packager.dll', 'ieframe.dll', 'winword',
    'excel', 'powerpnt', 'acrord32', 'acrobat', 'notepad', 'wordpad', 'mspaint',
) + _DOCUMENT_EXTENSIONS

SIGNAL_LABELS = {
    'lolbas_target': 'Target is a living-off-the-land binary',
    'lolbas_in_arguments': 'Arguments invoke a living-off-the-land binary',
    'encoded_powershell_command': 'PowerShell encoded command',
    'base64_blob_in_arguments': 'Long base64 blob in arguments',
    'frombase64string': 'Base64 decode call in arguments',
    'invoke_expression': 'Invoke-Expression in arguments',
    'download_cradle': 'Download cradle in arguments',
    'hidden_window_argument': 'Hidden window style requested in arguments',
    'execution_policy_bypass': 'PowerShell execution policy bypass',
    'no_profile_argument': 'PowerShell profile or prompt suppressed',
    'char_code_obfuscation': 'Character-code obfuscation in arguments',
    'env_var_obfuscation': 'Environment-variable indirection in arguments',
    'defender_tamper': 'Defender or AMSI tampering in arguments',
    'persistence_command': 'Persistence command in arguments',
    'unc_path_in_arguments': 'UNC path in arguments',
    'embedded_url': 'Embedded URL',
    'embedded_ip': 'Embedded IP address',
    'hidden_window_show_command': 'ShowCommand hides the execution window',
    'run_as_user': 'RunAsUser flag requests elevation',
    'excessive_argument_length': 'Arguments far longer than typical',
    'document_icon_masquerade': 'Document icon on an interpreter target',
    'document_extension_masquerade': 'Document name on an interpreter target',
    'target_outside_program_locations': 'Target outside normal program locations',
    'target_in_user_writable_path': 'Target in a user-writable location',
    'network_share_target': 'Target is a network share',
    'target_size_mismatch': 'Recorded target size is inconsistent',
    'oversized_lnk_file': 'Shortcut far larger than typical',
    'appended_data_after_structures': 'Data appended after the shell link structures',
    'malformed_header_size': 'HeaderSize does not match the specification',
    'hidden_window_with_network_indicator': 'Hidden window plus a network indicator',
}


def _lolbas_hits(text):
    if not text:
        return []
    return [name for name, pattern in _LOLBAS_PATTERNS if pattern.search(text)]


def lnk_text(parsed):
    """The parsed record's attacker-controlled text, joined and bounded. This is
    the only surface IOC extraction and pattern matching run over."""
    parsed = parsed or {}
    fields = (
        'target_path', 'local_base_path', 'network_share', 'device_name',
        'arguments', 'working_dir', 'name', 'relative_path', 'icon_location',
        'idlist_path', 'env_target', 'icon_env_target', 'darwin_id',
    )
    joined = ' '.join(str(parsed.get(field) or '') for field in fields)
    return joined[:MAX_IOC_TEXT]


def lnk_iocs(parsed, limit=100):
    """URLs, domains and IPs embedded in the shortcut, defanged. Delegates to
    :func:`app.utils.iocs.extract_iocs` - there is exactly one IOC extractor in this
    codebase and this is not it."""
    return extract_iocs(lnk_text(parsed), limit=limit)


def _basename(path):
    return (path or '').replace('/', '\\').rsplit('\\', 1)[-1].lower()


def analyze_signals(parsed):
    """Named heuristic signals over a parsed record. Pure; never raises.
    ``[{'key', 'label', 'detail'}]`` in ``SIGNAL_LABELS`` order, so ``file_rules`` can
    weight ``key`` the way ``scan_rules`` and ``email_rules`` weight theirs. An unparseable
    record yields no signals: absence of evidence must not read as evidence."""
    parsed = parsed or {}
    if not parsed.get('parsed_ok'):
        return []

    present = {}
    details = {}

    def mark(key, detail=None):
        present[key] = True
        if detail and key not in details:
            details[key] = detail

    arguments = str(parsed.get('arguments') or '')
    target = str(parsed.get('target_path') or parsed.get('local_base_path') or '')
    env_target = str(parsed.get('env_target') or '')
    relative = str(parsed.get('relative_path') or '')
    working = str(parsed.get('working_dir') or '')
    icon = str(parsed.get('icon_location') or '')
    name = str(parsed.get('name') or '')
    share = str(parsed.get('network_share') or '')

    target_surface = ' '.join(
        part for part in (target, env_target, relative, parsed.get('idlist_path') or '')
        if part
    )
    target_hits = _lolbas_hits(target_surface)
    argument_hits = _lolbas_hits(arguments)
    if target_hits:
        mark('lolbas_target', ', '.join(target_hits))
    if argument_hits:
        mark('lolbas_in_arguments', ', '.join(argument_hits))
    interpreter_target = bool(target_hits or argument_hits)

    for key, pattern in _ARGUMENT_PATTERNS:
        match = pattern.search(arguments)
        if match:
            mark(key, match.group(0)[:80])

    iocs = lnk_iocs(parsed)
    urls = [item['value'] for item in iocs if item['type'] == 'url']
    ips = [item['value'] for item in iocs if item['type'] == 'ipv4']
    if urls:
        mark('embedded_url', urls[0])
    if ips:
        mark('embedded_ip', ips[0])

    hidden_window = parsed.get('show_command_raw') == SHOW_HIDDEN
    if hidden_window:
        mark('hidden_window_show_command', parsed.get('show_command'))
    if parsed.get('run_as_user'):
        mark('run_as_user')

    argument_length = parsed.get('arguments_length') or len(arguments)
    if argument_length > MAX_NORMAL_ARG_CHARS:
        mark('excessive_argument_length', f'{argument_length} characters')

    if interpreter_target and icon:
        icon_name = _basename(icon)
        lowered_icon = icon.lower()
        if icon_name != _basename(target) and any(
            hint in lowered_icon for hint in _DOCUMENT_ICON_HINTS
        ):
            mark('document_icon_masquerade', icon)

    if interpreter_target:
        for candidate in (name, relative, parsed.get('idlist_path') or ''):
            lowered = _basename(candidate)
            if lowered and lowered.endswith(_DOCUMENT_EXTENSIONS):
                mark('document_extension_masquerade', candidate)
                break

    path_surface = ' '.join(part.lower() for part in (target, working, env_target) if part)
    if any(fragment in path_surface for fragment in _USER_WRITABLE_FRAGMENTS):
        mark('target_in_user_writable_path', target or working or env_target)

    effective_target = target or env_target
    if _DRIVE_PATH_RE.match(effective_target) and not any(
        fragment in effective_target.lower() for fragment in _NORMAL_PROGRAM_FRAGMENTS
    ):
        mark('target_outside_program_locations', effective_target)

    if share:
        mark('network_share_target', share)

    recorded_size = parsed.get('target_size_bytes') or 0
    is_directory = bool((parsed.get('file_attributes') or 0) & ATTR_DIRECTORY)
    # A shortcut Explorer built records the target's real size; a programmatically
    # assembled lure usually leaves it zero, and only a corrupt or fabricated header
    # claims a quarter-gigabyte interpreter. Directories legitimately record zero.
    if recorded_size > MAX_PLAUSIBLE_TARGET_BYTES:
        mark('target_size_mismatch', f'{recorded_size} bytes recorded')
    elif interpreter_target and not is_directory and recorded_size == 0:
        mark('target_size_mismatch', 'interpreter target recorded with size 0')

    if (parsed.get('lnk_size_bytes') or 0) > OVERSIZED_LNK_BYTES:
        mark('oversized_lnk_file', f'{parsed["lnk_size_bytes"]} bytes')
    if (parsed.get('trailing_bytes') or 0) > APPENDED_SLACK_BYTES:
        mark('appended_data_after_structures', f'{parsed["trailing_bytes"]} bytes')

    header_size = parsed.get('header_size')
    if header_size is not None and header_size != HEADER_SIZE:
        mark('malformed_header_size', str(header_size))

    network_indicator = bool(
        urls or ips or share
        or present.get('unc_path_in_arguments')
        or present.get('download_cradle')
    )
    if (hidden_window or present.get('hidden_window_argument')) and network_indicator:
        mark('hidden_window_with_network_indicator')

    return [
        {'key': key, 'label': SIGNAL_LABELS[key], 'detail': details.get(key)}
        for key in SIGNAL_LABELS
        if present.get(key)
    ]


def analyze_lnk(data, ioc_limit=100):
    """Parse and analyze in one call. Pure, never raises."""
    parsed = parse_lnk(data)
    return {
        'parsed': parsed,
        'signals': analyze_signals(parsed),
        'iocs': lnk_iocs(parsed, limit=ioc_limit),
    }
