"""Immutable core records and one strict camelCase JSON representation."""
from dataclasses import dataclass, field, fields, is_dataclass
import base64
import json
import math
import platform
import re
import types
import unicodedata
import zlib
from types import MappingProxyType
from typing import Mapping, get_args, get_origin, get_type_hints
from collections.abc import Mapping as AbstractMapping

STATES = frozenset(('ok', 'findings', 'incomplete', 'unsupported', 'invalid', 'stale'))
PROFILE_VERSION = 'portability-v1'
EXTRACT_METADATA_MAXIMA = MappingProxyType({'files': 10000, 'directories': 10000,
                                           'file_bytes': 256*1024**2, 'total_bytes': 1024**3})
_SCAN_MAXIMA = MappingProxyType({'archive_bytes': 8*1024**3, 'central_bytes': 16*1024**2, 'entries': 50000,
                                'name_bytes': 4096, 'depth': 64, 'group_members': 200000,
                                'plan_bytes': 16*1024**2, 'export_bytes': 64*1024**2, 'seconds': 30})


def runtime_info():
    return MappingProxyType({'python': platform.python_version(), 'unicode': unicodedata.unidata_version,
                             'zlib': zlib.ZLIB_RUNTIME_VERSION, 'profileVersion': PROFILE_VERSION})


@dataclass(frozen=True)
class ScanLimits:
    archive_bytes: int = 8 * 1024**3
    central_bytes: int = 16 * 1024**2
    entries: int = 50000
    name_bytes: int = 4096
    depth: int = 64
    group_members: int = 200000
    plan_bytes: int = 16 * 1024**2
    export_bytes: int = 64 * 1024**2
    seconds: int = 30

    def __post_init__(self):
        for f in fields(self):
            value = getattr(self, f.name)
            if type(value) is not int or not 0 < value <= _SCAN_MAXIMA[f.name]:
                raise ValueError('Limits must be positive integers no greater than hard limits')


@dataclass(frozen=True)
class Diagnostic:
    code: str
    severity: str = 'error'
    entry_ids: tuple[str, ...] = ()
    details: Mapping[str, str] = field(default_factory=dict)
    certainty: str = 'config_rule'

    def __post_init__(self):
        if self.severity not in ('info', 'warning', 'error') or self.certainty not in ('config_rule', 'approximation', 'advisory'):
            raise ValueError('Invalid diagnostic enum')
        if any(not isinstance(k, str) or not isinstance(v, str) for k, v in self.details.items()):
            raise ValueError('Diagnostic evidence must be strings')
        object.__setattr__(self, 'details', MappingProxyType(dict(self.details)))


@dataclass(frozen=True)
class RawEntry:
    entry_id: str
    index: int
    central_offset: int
    raw_name: bytes
    raw_extra: bytes
    flags: int
    method: int
    crc32: int
    compressed_bytes: int
    declared_bytes: int
    local_offset: int
    create_system: int
    external_attr: int


@dataclass(frozen=True)
class ArchiveIndex:
    archive_id: str
    label: str
    byte_length: int
    entries: tuple[RawEntry, ...]
    structure_state: str
    diagnostics: tuple[Diagnostic, ...]
    runtime: Mapping[str, str] = field(default_factory=runtime_info)
    fingerprint: tuple[int, ...] = field(default=(), metadata={'internal': True})
    central_offset: int = 0
    central_bytes: int = 0
    limits: ScanLimits = field(default_factory=ScanLimits)

    def __post_init__(self):
        if self.structure_state not in STATES:
            raise ValueError('Invalid structure state')
        object.__setattr__(self, 'runtime', MappingProxyType(dict(self.runtime)))


@dataclass(frozen=True)
class NameCandidate:
    candidate_id: str
    text: str | None
    source: str
    valid: bool
    evidence: tuple[str, ...]
    certainty: str


@dataclass(frozen=True)
class TargetOptions:
    root_units: int = 0
    component_limit: int | None = None
    path_limit: int | None = None
    directory_path_limit: int | None = None
    unicode_version: str = unicodedata.unidata_version


@dataclass(frozen=True)
class TargetProfile:
    profile_id: str
    component_limit: int
    path_limit: int
    directory_path_limit: int
    units: str
    rules: tuple[tuple[str, str], ...]
    version: str = PROFILE_VERSION


@dataclass(frozen=True)
class EntryReport:
    entry_id: str
    index: int
    raw: RawEntry
    candidates: tuple[NameCandidate, ...]
    selected_candidate_id: str | None
    default_display_name: str | None
    name_state: str
    entry_type: str
    source_parts: tuple[str, ...]
    component_units: tuple[int, ...]
    path_units: int | None
    diagnostic_ids: tuple[str, ...]


@dataclass(frozen=True)
class LogicalDirectory:
    node_id: str
    source_parts: tuple[str, ...]
    owner_entry_id: str
    parent_node_id: str | None
    descendant_entry_ids: tuple[str, ...]
    explicit_entry_ids: tuple[str, ...]


@dataclass(frozen=True)
class CollisionGroup:
    group_id: str
    rule_id: str
    entry_ids: tuple[str, ...]
    node_ids: tuple[str, ...]
    original_keys: tuple[str, ...]
    comparison_key: str
    first_different_component: int
    impact: str
    certainty: str


@dataclass(frozen=True)
class PlanTransform:
    reason_codes: tuple[str, ...]
    entry_ids: tuple[str, ...]


@dataclass(frozen=True)
class PreflightReport:
    archive_id: str
    runtime: Mapping[str, str]
    profile: TargetProfile
    options: TargetOptions
    complete: bool
    state: str
    entries: tuple[EntryReport, ...]
    logical_directories: tuple[LogicalDirectory, ...]
    collision_groups: tuple[CollisionGroup, ...]
    summary: Mapping[str, int]
    limits: ScanLimits
    diagnostics: tuple[Diagnostic, ...]
    schema_version: int = 1
    content_verified: bool = False
    local_headers_verified: bool = False
    transformations: tuple[PlanTransform, ...] = ()

    def __post_init__(self):
        if self.state not in STATES or type(self.schema_version) is not int or self.schema_version != 1:
            raise ValueError('Invalid report version/state')
        if self.content_verified is not False or self.local_headers_verified is not False:
            raise ValueError('Preflight cannot claim content or local header verification')
        object.__setattr__(self, 'runtime', MappingProxyType(dict(self.runtime)))
        object.__setattr__(self, 'summary', MappingProxyType(dict(self.summary)))


@dataclass(frozen=True)
class MappingDecision:
    entry_id: str
    action: str
    target_path: str | None
    encoding_candidate_id: str | None
    name_confirmed: bool
    reason: str | None

    def __post_init__(self):
        if self.action not in ('keep', 'rename', 'skip'):
            raise ValueError('Invalid mapping action')
        if ((self.action == 'skip' and self.target_path is not None)
                or (self.action != 'skip' and (type(self.target_path) is not str or not self.target_path))):
            raise ValueError('Invalid action target path')


@dataclass(frozen=True)
class DirectoryMapping:
    node_id: str
    target_path: str


@dataclass(frozen=True)
class MappingInput:
    archive_id: str
    profile_id: str
    target_options: TargetOptions
    decisions: tuple[MappingDecision, ...]
    directory_mappings: tuple[DirectoryMapping, ...] = ()
    schema_version: int = 1
    transformations: tuple[PlanTransform, ...] = field(default=(), metadata={'internal': True})

    def __post_init__(self):
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise ValueError('Invalid mapping version')


@dataclass(frozen=True)
class ValidatedPlan:
    plan_id: str
    archive_id: str
    profile_id: str
    profile_version: str
    unicode_version: str
    target_options: TargetOptions
    decisions: tuple[MappingDecision, ...]
    directory_mappings: tuple[DirectoryMapping, ...]
    resolved_paths: Mapping[str, str]
    extractable: bool
    diagnostics: tuple[Diagnostic, ...]
    remaining_advisories: tuple[Diagnostic, ...]
    schema_version: int = 1

    def __post_init__(self):
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise ValueError('Invalid plan version')
        if self.profile_version != PROFILE_VERSION or self.unicode_version != unicodedata.unidata_version:
            raise ValueError('Invalid plan policy version')
        object.__setattr__(self, 'resolved_paths', MappingProxyType(dict(self.resolved_paths)))


_EXTRACT_MAXIMA = MappingProxyType({**EXTRACT_METADATA_MAXIMA, 'seconds': 60, 'chunk_bytes': 65536})


@dataclass(frozen=True)
class ExtractLimits:
    files: int = EXTRACT_METADATA_MAXIMA['files']
    directories: int = EXTRACT_METADATA_MAXIMA['directories']
    file_bytes: int = EXTRACT_METADATA_MAXIMA['file_bytes']
    total_bytes: int = EXTRACT_METADATA_MAXIMA['total_bytes']
    seconds: int | float = 60
    chunk_bytes: int = 65536

    def __post_init__(self):
        for f in fields(self):
            value = getattr(self, f.name)
            if f.name=='seconds':
                if type(value) not in (int,float) or not math.isfinite(value) or not 0<value<=60:
                    raise ValueError('Invalid extraction limit')
                continue
            if type(value) is not int or not 0 < value <= _EXTRACT_MAXIMA[f.name]:
                raise ValueError('Invalid extraction limit')


@dataclass(frozen=True)
class ContentRange:
    entry_id: str
    data_offset: int
    compressed_bytes: int
    declared_bytes: int
    crc32: int
    method: int
    descriptor_start: int | None = None
    descriptor_end: int | None = None


@dataclass
class OutputBudget:
    actual_bytes: int = 0
    files: int = 0
    directories: int = 0


@dataclass(frozen=True)
class WrittenEntry:
    entry_id: str | None
    target_path: str
    kind: str
    size: int
    crc32: int | None = None
    sha256: str | None = None

    def __post_init__(self):
        if self.kind not in ('file', 'directory') or self.size < 0:
            raise ValueError('Invalid written entry')


@dataclass(frozen=True)
class CleanupResult:
    state: str
    removed_files: int = 0
    removed_directories: int = 0
    diagnostics: tuple[Diagnostic, ...] = ()

    def __post_init__(self):
        if self.state not in ('not_created', 'removed', 'retained_ownership_unknown', 'cleanup_failed', 'not_needed'):
            raise ValueError('Invalid cleanup state')


@dataclass(frozen=True)
class ExtractionResult:
    status: str
    plan_id: str
    archive_id: str
    host_backend: str
    actual_files: int | None
    actual_directories: int | None
    actual_bytes: int | None
    entries: tuple[WrittenEntry, ...]
    skipped_entry_ids: tuple[str, ...]
    diagnostics: tuple[Diagnostic, ...]
    cleanup: CleanupResult
    schema_version: int = 1

    def __post_init__(self):
        if self.status not in ('verified', 'failed', 'unsupported_host') or type(self.schema_version) is not int or self.schema_version != 1:
            raise ValueError('Invalid extraction result')
        counts = (self.actual_files,self.actual_directories,self.actual_bytes)
        if any(value is not None and (type(value) is not int or value<0) for value in counts):
            raise ValueError('Invalid actual count')
        if any(value is None for value in counts):
            if (self.status=='verified' or not all(value is None for value in counts)
                    or not any(d.code=='ACTUAL_COUNTS_UNAVAILABLE' for d in self.diagnostics)):
                raise ValueError('Unavailable actual counts require explicit failure evidence')


def _camel(value):
    head, *tail = value.split('_')
    return head + ''.join(p.title() for p in tail)


_DECIMAL = frozenset(('byte_length', 'central_offset', 'central_bytes', 'compressed_bytes', 'declared_bytes', 'local_offset',
                      'archive_bytes', 'name_bytes', 'plan_bytes', 'export_bytes', 'path_units', 'root_units',
                      'data_offset', 'descriptor_start', 'descriptor_end', 'file_bytes', 'total_bytes', 'chunk_bytes', 'size', 'actual_bytes'))


def to_json_value(value):
    if type(value) is float:
        if not math.isfinite(value):raise ValueError('Nonfinite JSON number')
        return value
    if is_dataclass(value):
        result = {}
        for f in fields(value):
            if f.metadata.get('internal'):
                continue
            item = getattr(value, f.name)
            key = _camel(f.name)
            if isinstance(item, bytes):
                result[key + 'Base64'] = base64.b64encode(item).decode('ascii')
            elif f.name in _DECIMAL and item is not None:
                result[key] = str(item)
            else:
                result[key] = to_json_value(item)
        return result
    if isinstance(value, Mapping):
        return {k: to_json_value(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [to_json_value(v) for v in value]
    if value is None or type(value) in (str, int, bool):
        return value
    raise TypeError('Unsupported JSON value')


def dumps(value, *, max_bytes=64*1024**2):
    if type(max_bytes) is not int or not 0 < max_bytes <= 64*1024**2:
        raise ValueError('Invalid export limit')
    encoder = json.JSONEncoder(ensure_ascii=True, sort_keys=True, separators=(',', ':'))
    parts, count = [], 0
    for part in encoder.iterencode(to_json_value(value)):
        count += len(part)
        if count > max_bytes:
            raise ValueError('EXPORT_LIMIT')
        parts.append(part)
    return ''.join(parts)


def _json_name(f, annotation):
    return _camel(f.name) + ('Base64' if annotation is bytes else '')


def _decode(value, annotation, name=''):
    origin, args = get_origin(annotation), get_args(annotation)
    if origin is types.UnionType:
        if value is None and type(None) in args:
            return None
        choices = [t for t in args if t is not type(None)]
        if name=='seconds' and set(choices)=={int,float}:
            if type(value) not in (int,float) or not math.isfinite(value) or not 0<value<=60:
                raise ValueError('Invalid extraction seconds')
            return value
        if len(choices) != 1:
            raise ValueError('Unsupported union')
        return _decode(value, choices[0], name)
    if is_dataclass(annotation):
        if type(value) is not dict:
            raise ValueError('Expected object')
        hints, kwargs = get_type_hints(annotation), {}
        expected = {_json_name(f, hints[f.name]) for f in fields(annotation) if not f.metadata.get('internal')}
        optional = {'directoryMappings'} if annotation is MappingInput else set()
        if set(value)-expected or expected-set(value)-optional:
            raise ValueError('Missing or unknown fields')
        for f in fields(annotation):
            if not f.metadata.get('internal'):
                key = _json_name(f, hints[f.name])
                if key in value:
                    kwargs[f.name] = _decode(value[key], hints[f.name], f.name)
        return annotation(**kwargs)
    if origin is tuple:
        if type(value) is not list:
            raise ValueError('Expected array')
        if len(args) == 2 and args[1] is Ellipsis:
            return tuple(_decode(v, args[0]) for v in value)
        if len(value) != len(args):
            raise ValueError('Wrong tuple length')
        return tuple(_decode(v, t) for v, t in zip(value, args, strict=True))
    if origin is AbstractMapping:
        if type(value) is not dict:
            raise ValueError('Expected mapping')
        return MappingProxyType({_decode(k, args[0]): _decode(v, args[1]) for k, v in value.items()})
    if annotation is int and name in _DECIMAL:
        if type(value) is not str or re.fullmatch(r'0|[1-9][0-9]*', value) is None:
            raise ValueError('Expected canonical decimal string')
        return int(value)
    if annotation is bytes:
        if type(value) is not str:
            raise ValueError('Expected base64 string')
        try:
            decoded = base64.b64decode(value, validate=True)
        except (ValueError, base64.binascii.Error):
            raise ValueError('Invalid base64') from None
        if base64.b64encode(decoded).decode('ascii') != value:
            raise ValueError('Noncanonical base64')
        return decoded
    if type(value) is not annotation or (annotation is int and value < 0):
        raise ValueError('Wrong JSON type or negative count')
    if name == 'structure_state' and value not in STATES:
        raise ValueError('Invalid state')
    if name == 'name_state' and value not in ('unambiguous', 'ambiguous', 'selected', 'blocked', 'nonstandard'):
        raise ValueError('Invalid name state')
    if name == 'entry_type' and value not in ('file', 'directory', 'symlink', 'special', 'contradictory'):
        raise ValueError('Invalid entry type')
    if name == 'certainty' and value not in ('config_rule', 'approximation', 'advisory'):
        raise ValueError('Invalid certainty')
    if name == 'action' and value not in ('keep', 'rename', 'skip'):
        raise ValueError('Invalid mapping action')
    return value


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('Duplicate JSON key')
        value[key] = item
    return value


def loads_report(text: str, *, max_bytes=64*1024**2) -> PreflightReport:
    """Decode the strict report schema. A report never grants extraction authority."""
    if type(max_bytes) is not int or not 0 < max_bytes <= 64*1024**2:
        raise ValueError('Invalid input limit')
    if not isinstance(text, str) or len(text) > max_bytes or len(text.encode('utf-8')) > max_bytes:
        raise ValueError('REPORT_INPUT_LIMIT')
    try:
        value = json.loads(text, object_pairs_hook=_unique_object, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Invalid JSON constant')))
        report = _decode(value, PreflightReport)
    except (TypeError, RecursionError, UnicodeError) as error:
        raise ValueError('Invalid report JSON') from error
    from .profiles import validate_options
    validate_options(report.profile, report.options)
    return report


def _bounded_decimal_pattern(maximum):
    """ECMAScript-compatible canonical decimal strings from 1 through maximum."""
    digits = str(maximum)
    alternatives = [f'[1-9][0-9]{{0,{len(digits)-2}}}'] if len(digits) > 1 else []
    for i, digit in enumerate(digits):
        lower, upper = (1 if i == 0 else 0), int(digit)-1
        if lower <= upper:
            choice = str(lower) if lower == upper else f'[{lower}-{upper}]'
            remaining = len(digits)-i-1
            alternatives.append(digits[:i]+choice+(f'[0-9]{{{remaining}}}' if remaining else ''))
    alternatives.append(digits)
    return '^(?:'+'|'.join(alternatives)+r')(?![\s\S])'


def _schema(root_type):
    """Instance schema for core types and finite policies, using JSON Schema 2020-12.

    JSON text checks (duplicate keys, input byte limits, and integer token syntax)
    still belong to loads_report: a schema validator only sees parsed instances.
    """
    from .profiles import _PROFILES
    profiles = tuple(_PROFILES[key] for key in sorted(_PROFILES))
    definitions = {}
    def option_budget(maximum):
        return {'anyOf': [{'type': 'null'}, {'type': 'integer', 'minimum': 1, 'maximum': maximum}]}

    def describe(annotation, name=''):
        origin, args = get_origin(annotation), get_args(annotation)
        if origin is types.UnionType:
            return {'anyOf': [describe(t, name) for t in args]}
        if annotation is type(None):
            return {'type': 'null'}
        if is_dataclass(annotation):
            key = annotation.__name__
            if key not in definitions:
                definitions[key] = {}
                hints = get_type_hints(annotation)
                props = {_json_name(f, hints[f.name]): describe(hints[f.name], f.name) for f in fields(annotation) if not f.metadata.get('internal')}
                if annotation in (PreflightReport, MappingInput, ValidatedPlan, ExtractionResult):
                    props['schemaVersion'] = {'type': 'integer', 'const': 1}
                if annotation is PreflightReport:
                    props['contentVerified'] = props['localHeadersVerified'] = {'const': False}
                definitions[key] = {'type': 'object', 'properties': props, 'required': list(props), 'additionalProperties': False}
                if annotation is MappingInput:
                    definitions[key]['required'].remove('directoryMappings')
                if annotation is MappingDecision:
                    definitions[key]['allOf'] = [{
                        'if': {'properties': {'action': {'const': 'skip'}}},
                        'then': {'properties': {'targetPath': {'type': 'null'}}},
                        'else': {'properties': {'targetPath': {'type': 'string', 'minLength': 1}}}}]
                if annotation in (ScanLimits, ExtractLimits):
                    for field_name, maximum in (_SCAN_MAXIMA if annotation is ScanLimits else _EXTRACT_MAXIMA).items():
                        props[_camel(field_name)] = ({'type': 'string', 'pattern': _bounded_decimal_pattern(maximum), 'maxLength': len(str(maximum))}
                                                    if field_name in _DECIMAL else {'type': 'integer', 'minimum': 1, 'maximum': maximum})
                    if annotation is ExtractLimits:
                        props['seconds']={'type':'number','exclusiveMinimum':0,'maximum':60}
                elif annotation is CleanupResult:
                    props['state'] = {'enum': ['not_created', 'removed', 'retained_ownership_unknown', 'cleanup_failed', 'not_needed']}
                elif annotation is ExtractionResult:
                    props['status'] = {'enum': ['verified', 'failed', 'unsupported_host']}
                    count_names = ('actualFiles','actualDirectories','actualBytes')
                    definitions[key]['allOf'] = [
                        {'if': {'properties': {'status': {'const':'verified'}}},
                         'then': {'properties': {name:{'not':{'type':'null'}} for name in count_names}}},
                        {'if': {'anyOf':[{'properties':{name:{'type':'null'}}} for name in count_names]},
                         'then': {'properties': {**{name:{'type':'null'} for name in count_names},
                                                'diagnostics':{'contains':{'properties':{'code':{'const':'ACTUAL_COUNTS_UNAVAILABLE'}},'required':['code']}}}}}]
                elif annotation is WrittenEntry:
                    props['kind'] = {'enum': ['file', 'directory']}
                elif annotation is TargetProfile:
                    definitions[key]['enum'] = [to_json_value(profile) for profile in profiles]
                elif annotation is TargetOptions:
                    props['unicodeVersion'] = {'const': unicodedata.unidata_version}
                    for field_name in ('component_limit', 'path_limit', 'directory_path_limit'):
                        props[_camel(field_name)] = option_budget(max(getattr(profile, field_name) for profile in profiles))
                elif annotation is PreflightReport:
                    definitions[key]['allOf'] = [
                        {'if': {'properties': {'profile': {'properties': {'profileId': {'const': profile.profile_id}}}}},
                         'then': {'properties': {'options': {'properties': {
                             _camel(field_name): option_budget(getattr(profile, field_name))
                             for field_name in ('component_limit', 'path_limit', 'directory_path_limit')}}}}}
                        for profile in profiles]
                elif annotation in (MappingInput, ValidatedPlan):
                    props['profileId'] = {'enum': [profile.profile_id for profile in profiles]}
                    definitions[key]['allOf'] = [
                        {'if': {'properties': {'profileId': {'const': profile.profile_id}}},
                         'then': {'properties': {'targetOptions': {'properties': {
                             _camel(field_name): option_budget(getattr(profile, field_name))
                             for field_name in ('component_limit', 'path_limit', 'directory_path_limit')}}}}}
                        for profile in profiles]
                    if annotation is ValidatedPlan:
                        props['profileVersion'] = {'const': PROFILE_VERSION}
                        props['unicodeVersion'] = {'const': unicodedata.unidata_version}
            return {'$ref': '#/$defs/'+key}
        if origin is tuple:
            if len(args) == 2 and args[1] is Ellipsis:
                return {'type': 'array', 'items': describe(args[0])}
            return {'type': 'array', 'prefixItems': [describe(a) for a in args], 'items': False, 'minItems': len(args), 'maxItems': len(args)}
        if origin is AbstractMapping:
            return {'type': 'object', 'additionalProperties': describe(args[1])}
        if annotation is bytes:
            return {'type': 'string', 'contentEncoding': 'base64',
                    'pattern': r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/][AQgw]==|[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=)?(?![\s\S])'}
        if annotation is int and name in _DECIMAL:
            return {'type': 'string', 'pattern': r'^(?:0|[1-9][0-9]*)(?![\s\S])'}
        if name in ('state', 'structure_state'):
            return {'enum': sorted(STATES)}
        if name == 'certainty':
            return {'enum': ['config_rule', 'approximation', 'advisory']}
        if name == 'name_state':
            return {'enum': ['unambiguous', 'ambiguous', 'selected', 'blocked', 'nonstandard']}
        if name == 'entry_type':
            return {'enum': ['file', 'directory', 'symlink', 'special', 'contradictory']}
        if name == 'severity':
            return {'enum': ['info', 'warning', 'error']}
        if name == 'action':
            return {'enum': ['keep', 'rename', 'skip']}
        return {'type': {str: 'string', int: 'integer', bool: 'boolean',float:'number'}[annotation], **({'minimum': 0} if annotation is int else {})}
    root = describe(root_type)
    return {'$schema': 'https://json-schema.org/draft/2020-12/schema', **root, '$defs': definitions}


def report_schema():
    return _schema(PreflightReport)


def mapping_schema():
    return _schema(MappingInput)


def validated_plan_schema():
    return _schema(ValidatedPlan)


def _plan_integer(token):
    if re.fullmatch(r'0|[1-9][0-9]*', token) is None:
        raise ValueError('Noncanonical JSON integer')
    return int(token)


def _loads_plan(text, annotation, max_bytes):
    if type(max_bytes) is not int or not 0 < max_bytes <= 16*1024**2:
        raise ValueError('Invalid plan input limit')
    if type(text) is not str or len(text) > max_bytes or len(text.encode('utf-8')) > max_bytes:
        raise ValueError('PLAN_INPUT_LIMIT')
    try:
        value = json.loads(text, object_pairs_hook=_unique_object, parse_int=_plan_integer,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Invalid JSON constant')))
        plan = _decode(value, annotation)
        from .profiles import load_profile, validate_options
        validate_options(load_profile(plan.profile_id), plan.target_options)
        return plan
    except (TypeError, RecursionError, UnicodeError) as error:
        raise ValueError('Invalid plan JSON') from error


def loads_mapping(text: str, *, max_bytes=16*1024**2) -> MappingInput:
    return _loads_plan(text, MappingInput, max_bytes)


def loads_validated_plan(text: str, *, max_bytes=16*1024**2) -> ValidatedPlan:
    return _loads_plan(text, ValidatedPlan, max_bytes)


def extraction_result_schema():
    return _schema(ExtractionResult)


def loads_extraction_result(text: str) -> ExtractionResult:
    if type(text) is not str or len(text) > 64*1024**2 or len(text.encode('utf-8')) > 64*1024**2:
        raise ValueError('RESULT_INPUT_LIMIT')
    try:
        return _decode(json.loads(text, object_pairs_hook=_unique_object, parse_int=_plan_integer,
                                  parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Invalid JSON constant'))), ExtractionResult)
    except (TypeError, RecursionError, UnicodeError) as error:
        raise ValueError('Invalid extraction result') from error
