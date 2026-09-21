"""Offline phone number metadata, from the data bundled in the `phonenumbers` wheel.
Pure: no network, no Flask, no I/O.

This is the always-on base layer. It needs no key and no quota, a deployment that
configures nothing still gets a useful answer, and nothing about the number leaves this
process, which matters for an OSINT tool: a live lookup tells the provider whose number
is being investigated.

Two upstream limits are structural, and this module surfaces them rather than letting a
caller mistake absence for information:

* **libphonenumber ships no carrier data for the NANP**, and cannot separate mobile from
  fixed line there, so every US and Canadian number is FIXED_LINE_OR_MOBILE with an empty
  carrier. ``line_type_resolvable`` is False for those, so the template can say "not
  resolvable offline" instead of rendering a blank a reader takes for "landline".
* **The carrier lookup returns the ORIGINAL range holder**, not the current carrier.
  Google's own ``safe_display_name()`` returns empty for every region with number
  portability, which is most of the developed world. The field is called
  ``range_holder`` here, never ``carrier``, so a template cannot mislabel it without
  someone noticing, and ``range_holder_is_portable`` marks where the distinction bites.
"""

import phonenumbers
from phonenumbers import PhoneNumberFormat, PhoneNumberType, carrier, geocoder, timezone

# Display names, not the enum's own spelling: these reach the page directly.
NUMBER_TYPES = {
    PhoneNumberType.FIXED_LINE: 'fixed line',
    PhoneNumberType.MOBILE: 'mobile',
    PhoneNumberType.FIXED_LINE_OR_MOBILE: 'fixed line or mobile',
    PhoneNumberType.TOLL_FREE: 'toll free',
    PhoneNumberType.PREMIUM_RATE: 'premium rate',
    PhoneNumberType.SHARED_COST: 'shared cost',
    PhoneNumberType.VOIP: 'VOIP',
    PhoneNumberType.PERSONAL_NUMBER: 'personal number',
    PhoneNumberType.PAGER: 'pager',
    PhoneNumberType.UAN: 'UAN',
    PhoneNumberType.VOICEMAIL: 'voicemail',
    PhoneNumberType.UNKNOWN: 'unknown',
}

# The North American Numbering Plan shares one country calling code across the US,
# Canada and much of the Caribbean. The missing carrier data and the unresolvable line
# type are properties of the plan, so they are keyed on the calling code, not the region.
NANP_CALLING_CODE = 1

NANP_NO_CARRIER_DATA = (
    'libphonenumber ships no carrier data for the North American Numbering Plan'
)

NANP_LINE_TYPE_NOTE = (
    'US and Canadian numbers cannot be classified as mobile, fixed line or VOIP from '
    'offline data alone'
)

RANGE_HOLDER_CAVEAT = (
    'the operator the number range was originally allocated to, which is not the '
    'current carrier for any number that has been ported'
)

_PARSE_ERRORS = {
    phonenumbers.NumberParseException.INVALID_COUNTRY_CODE:
        'no country code, and no default region was supplied',
    phonenumbers.NumberParseException.NOT_A_NUMBER:
        'that does not look like a phone number',
    phonenumbers.NumberParseException.TOO_SHORT_AFTER_IDD: 'too short after the IDD',
    phonenumbers.NumberParseException.TOO_SHORT_NSN: 'too short to be a phone number',
    phonenumbers.NumberParseException.TOO_LONG: 'too long to be a phone number',
}


def analyze(raw, default_region=None):
    """Offline metadata for one number.

    Returns ``{'ok': False, 'error': ..., 'raw': ...}`` when the input cannot be parsed
    at all, and ``{'ok': True, ...}`` otherwise. ``ok`` is about parsing, ``valid`` is
    about allocation: a well-formed number in an unassigned range parses fine and is
    still not valid, and both facts are worth showing.

    Never raises. This feeds an HTTP route and the input is attacker-controlled.
    """
    raw = (raw or '').strip()
    if not raw:
        return {'ok': False, 'error': 'no number supplied', 'raw': raw}

    try:
        parsed = phonenumbers.parse(raw, default_region)
    except phonenumbers.NumberParseException as exc:
        return {'ok': False,
                'error': _PARSE_ERRORS.get(exc.error_type, 'could not be parsed'),
                'raw': raw}
    except Exception:
        # Defensive: parse() is not documented to raise anything else, but this is a
        # public route's first touch of untrusted input and a 500 here is worse than a
        # generic message.
        return {'ok': False, 'error': 'could not be parsed', 'raw': raw}

    is_nanp = parsed.country_code == NANP_CALLING_CODE
    number_type = phonenumbers.number_type(parsed)

    # Toll-free and premium rate ARE resolvable inside the NANP; only the
    # mobile/fixed-line/VOIP distinction is not.
    line_type_resolvable = not (
        is_nanp and number_type == PhoneNumberType.FIXED_LINE_OR_MOBILE
    )

    range_holder = carrier.name_for_number(parsed, 'en') or ''
    # safe_display_name() is deliberately empty wherever number portability exists.
    # Comparing the two is how we know to caveat the field rather than hard-coding a
    # country list that would drift.
    portable = bool(range_holder) and not carrier.safe_display_name(parsed, 'en')

    if range_holder:
        range_holder_unavailable_reason = ''
    elif is_nanp:
        range_holder_unavailable_reason = NANP_NO_CARRIER_DATA
    else:
        range_holder_unavailable_reason = 'no carrier data for this range'

    return {
        'ok': True,
        'raw': raw,
        'valid': phonenumbers.is_valid_number(parsed),
        'possible': phonenumbers.is_possible_number(parsed),
        'e164': phonenumbers.format_number(parsed, PhoneNumberFormat.E164),
        'international': phonenumbers.format_number(
            parsed, PhoneNumberFormat.INTERNATIONAL),
        'national': phonenumbers.format_number(parsed, PhoneNumberFormat.NATIONAL),
        'rfc3966': phonenumbers.format_number(parsed, PhoneNumberFormat.RFC3966),
        'country_code': parsed.country_code,
        'national_number': str(parsed.national_number),
        'region': phonenumbers.region_code_for_number(parsed) or '',
        'is_nanp': is_nanp,
        'number_type': NUMBER_TYPES.get(number_type, 'unknown'),
        'line_type_resolvable': line_type_resolvable,
        'line_type_note': '' if line_type_resolvable else NANP_LINE_TYPE_NOTE,
        'range_holder': range_holder,
        'range_holder_is_portable': portable,
        'range_holder_caveat': RANGE_HOLDER_CAVEAT,
        'range_holder_unavailable_reason': range_holder_unavailable_reason,
        'location': geocoder.description_for_number(parsed, 'en') or '',
        'country': geocoder.country_name_for_number(parsed, 'en') or '',
        'timezones': list(timezone.time_zones_for_number(parsed) or ()),
    }
