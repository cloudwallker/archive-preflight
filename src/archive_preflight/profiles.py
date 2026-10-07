"""Versioned delivery policies, not native NTFS/APFS comparison tables."""
import re
import unicodedata

from .model import TargetOptions, TargetProfile


_PROFILES = {
    'windows-win32-conservative-v1': TargetProfile('windows-win32-conservative-v1', 255, 259, 247, 'utf16',
        (('exact', 'config_rule'), ('ascii-case', 'config_rule'), ('windows-trim', 'config_rule'), ('casefold', 'approximation'))),
    'macos-apfs-ci-advisory-v1': TargetProfile('macos-apfs-ci-advisory-v1', 255, 1023, 1023, 'utf8',
        (('exact', 'config_rule'), ('ascii-case', 'config_rule'), ('nfc', 'approximation'), ('casefold', 'approximation'), ('nfc-casefold', 'approximation'))),
    'macos-apfs-cs-advisory-v1': TargetProfile('macos-apfs-cs-advisory-v1', 255, 1023, 1023, 'utf8',
        (('exact', 'config_rule'), ('nfc', 'approximation'))),
    'linux-posix-bytes-v1': TargetProfile('linux-posix-bytes-v1', 255, 4095, 4095, 'utf8',
        (('exact', 'config_rule'), ('casefold', 'advisory'), ('nfc', 'advisory'), ('nfc-casefold', 'advisory'))),
}


def load_profile(profile_id: str) -> TargetProfile:
    try:
        return _PROFILES[profile_id]
    except KeyError:
        raise ValueError('Unknown profile') from None


def validate_options(profile: TargetProfile, options: TargetOptions) -> None:
    if profile != load_profile(profile.profile_id):
        raise ValueError('Modified profile is not supported')
    if type(options.root_units) is not int or options.root_units < 0:
        raise ValueError('root_units must be a nonnegative integer')
    if options.unicode_version != unicodedata.unidata_version:
        raise ValueError('Unicode version mismatch')
    for name in ('component_limit', 'path_limit', 'directory_path_limit'):
        value = getattr(options, name)
        if value is not None and (type(value) is not int or not 0 < value <= getattr(profile, name)):
            raise ValueError('Budgets may only be lowered')


def measure(text: str, profile: TargetProfile) -> int:
    return len(text.encode('utf-16-le', 'strict'))//2 if profile.units == 'utf16' else len(text.encode('utf-8', 'strict'))


def comparison_key(component: str, rule: str) -> str:
    if rule == 'exact':
        return component
    if rule == 'ascii-case':
        return component.translate(str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'))
    if rule == 'windows-trim':
        return comparison_key(component.rstrip(' .'), 'ascii-case')
    if rule == 'casefold':
        return component.casefold()
    if rule == 'nfc':
        return unicodedata.normalize('NFC', component)
    if rule == 'nfc-casefold':
        return unicodedata.normalize('NFC', component.casefold())
    raise ValueError('Unknown comparison rule')


def check_path(parts: tuple[str, ...], directory: bool, profile: TargetProfile, options: TargetOptions) -> tuple[str, ...]:
    validate_options(profile, options)
    codes = []
    maximum = options.component_limit or profile.component_limit
    if any(measure(p, profile) > maximum for p in parts):
        codes.append('COMPONENT_LIMIT')
    if profile.units == 'utf16':
        for part in parts:
            if any(c in '<>:"/\\|?*' or ord(c) < 32 for c in part):
                codes.append('WINDOWS_ILLEGAL_CHARACTER')
            if part.endswith((' ', '.')):
                codes.append('WINDOWS_TRAILING_DOT_SPACE')
            base = part.split('.')[0].rstrip(' .').upper()
            if base in ('CON', 'PRN', 'AUX', 'NUL', 'CONIN$', 'CONOUT$') or re.fullmatch(r'(?:COM|LPT)[1-9¹²³]', base):
                codes.append('WINDOWS_DEVICE_NAME')
    if not options.root_units:
        codes.append('PATH_ROOT_UNKNOWN')
    else:
        maximum = (options.directory_path_limit or profile.directory_path_limit) if directory else (options.path_limit or profile.path_limit)
        if options.root_units + measure('/'.join(parts), profile) > maximum:
            codes.append('PATH_LIMIT')
    return tuple(dict.fromkeys(codes))
