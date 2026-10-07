"""Deterministic naming drafts and complete, write-free plan revalidation."""
from dataclasses import replace
import hashlib
import re
import unicodedata

from .analyze import analyze, path_evidence
from .model import (ArchiveIndex, Diagnostic, DirectoryMapping, MappingDecision,
                    MappingInput, PROFILE_VERSION, PreflightReport, ValidatedPlan,
                    EXTRACT_METADATA_MAXIMA, PlanTransform, dumps, loads_mapping, loads_validated_plan, to_json_value)
from .profiles import check_path, comparison_key, load_profile, measure


class MappingValidationError(ValueError):
    """Controlled rejection carrying immutable diagnostics without private paths."""
    def __init__(self, code):
        super().__init__(code)
        self.diagnostics = (Diagnostic(code),)


def _parts(path):
    if type(path) is not str or not path or path.startswith('/') or path.endswith('/'):
        raise ValueError('INVALID_TARGET_PATH')
    parts = tuple(path.split('/'))
    if any(p in ('', '.', '..') for p in parts) or any(code in path_evidence(path) for code in
            ('NUL_NAME', 'ABSOLUTE_OR_DEVICE_PATH', 'PATH_TRAVERSAL', 'BACKSLASH_PATH')):
        raise ValueError('INVALID_TARGET_PATH')
    # Surrogates cannot name a portable UTF-8 path.
    path.encode('utf-8', 'strict')
    return parts


def _rules(profile):
    return tuple(rule for rule, certainty in profile.rules if certainty != 'advisory')


def _keys(name, profile):
    return tuple((rule, comparison_key(name, rule)) for rule in _rules(profile))


def _unsafe_target(parts, directory, profile, options):
    # Even an unknown root cannot make a path fit if its minimum possible
    # rooted length already exceeds the policy. It still remains ineligible.
    measured_options = options if options.root_units else replace(options, root_units=1)
    codes = check_path(parts, directory, profile, measured_options)
    if not directory and len(parts) > 1:
        codes += check_path(parts[:-1], True, profile, measured_options)
    return bool(codes)


def _clean(name, profile):
    codes = []
    if profile.units == 'utf16':
        replaced = ''.join('_' if c in '<>:"/\\|?*' or ord(c) < 32 else c for c in name)
        if replaced != name:
            codes.append('WINDOWS_ILLEGAL_CHARACTER')
        name = replaced
        trimmed = name.rstrip(' .')
        if trimmed != name:
            codes.append('WINDOWS_TRAILING_DOT_SPACE')
        name = trimmed
        base = name.split('.')[0].rstrip(' .').upper()
        if base in ('CON', 'PRN', 'AUX', 'NUL', 'CONIN$', 'CONOUT$') or re.fullmatch(r'(?:COM|LPT)[1-9¹²³]', base):
            name = '_'+name
            codes.append('WINDOWS_DEVICE_NAME')
    if not name or name in ('.', '..'):
        name = 'unnamed'
        codes.append('EMPTY_COMPONENT')
    return name, tuple(codes)


def _truncate(text, budget, profile):
    result, units = [], 0
    for char in text:
        cost = measure(char, profile)
        if units+cost > budget:
            break
        result.append(char)
        units += cost
    return ''.join(result)


def _fit(name, suffix, profile, maximum):
    stem, dot, extension = name.rpartition('.')
    if not dot or not stem:
        stem, extension = name, ''
    else:
        extension = '.'+extension
    if measure(stem+suffix+extension, profile) <= maximum:
        return stem+suffix+extension
    extension = _truncate(extension, 32, profile)
    suffix_units = measure(suffix, profile)
    # Require a real stem character; a suffix alone loses all original evidence.
    if suffix_units >= maximum:
        raise ValueError('SUFFIX_BUDGET_TOO_SMALL')
    extension = _truncate(extension, max(0, maximum-suffix_units-1), profile)
    stem = _truncate(stem, maximum-suffix_units-measure(extension, profile), profile)
    if not stem:
        raise ValueError('SUFFIX_BUDGET_TOO_SMALL')
    return stem+suffix+extension


def _safe_fit(name, suffix, profile, maximum):
    result = _fit(name, suffix, profile, maximum)
    codes = ('COMPONENT_LIMIT',) if measure(name, profile)+measure(suffix, profile) > maximum else ()
    while True:
        cleaned, extra = _clean(result, profile)
        if cleaned == result:
            return result, tuple(dict.fromkeys(codes))
        codes += extra
        result = _fit(cleaned, '', profile, maximum)


def suggest_plan(report: PreflightReport) -> MappingInput:
    """Produce an auditable draft. Ambiguous evidence still needs a user choice."""
    profile, options = report.profile, report.options
    maximum = options.component_limit or profile.component_limit
    entries = tuple(sorted(report.entries, key=lambda e: e.index))
    by_id = {e.entry_id: e for e in entries}
    active = {e.entry_id for e in entries if e.name_state != 'blocked' and e.source_parts
              and e.raw.method in (0, 8) and not e.raw.flags & (1 | 0x40 | 0x2000)}
    directories = tuple(d for d in report.logical_directories
                        if active.intersection(d.explicit_entry_ids+d.descendant_entry_ids))
    mapped, dir_reasons, used = {}, {}, {}
    transforms = []

    def allocate(name, owner, parent, reservations):
        clean, codes = _clean(name, profile)
        fitted, fit_codes = _safe_fit(clean, '', profile, maximum)
        codes += fit_codes
        busy = used.setdefault(parent, set())
        keys = _keys(fitted, profile)
        preserve = fitted == name
        if any(k in busy or (not preserve and k in reservations) for k in keys):
            count = 1
            while True:
                suffix = '_'+owner+('' if count == 1 else '_'+str(count))
                fitted, fit_codes = _safe_fit(clean, suffix, profile, maximum)
                keys = _keys(fitted, profile)
                if not any(k in busy or k in reservations for k in keys):
                    break
                count += 1
            codes += fit_codes+('NAME_COLLISION',)
        codes = tuple(dict.fromkeys(codes))
        busy.update(keys)
        return fitted, codes

    # Every valid original sibling is reserved before allocating any new spelling.
    reserved = {}
    original_names = [(d.source_parts[:-1], d.source_parts[-1]) for d in directories]
    original_names += [(e.source_parts[:-1], e.source_parts[-1]) for e in entries
                       if e.entry_id in active and e.entry_type == 'file']
    for parent, name in original_names:
        if _clean(name, profile)[0] == name and measure(name, profile) <= maximum:
            reserved.setdefault(parent, set()).update(_keys(name, profile))

    for directory in sorted(directories, key=lambda d: (len(d.source_parts), by_id[d.owner_entry_id].index, d.source_parts)):
        parent = mapped.get(directory.source_parts[:-1], ())
        name, codes = allocate(directory.source_parts[-1], directory.owner_entry_id, parent,
                               reserved.get(directory.source_parts[:-1], set()))
        mapped[directory.source_parts] = parent+(name,)
        dir_reasons[directory.source_parts] = dir_reasons.get(directory.source_parts[:-1], ())+codes
        if codes:
            transforms.append(PlanTransform(codes, tuple(sorted(active.intersection(
                directory.explicit_entry_ids+directory.descendant_entry_ids)))))
    decisions = []
    for entry in entries:
        candidate_id = entry.selected_candidate_id
        confirmed = entry.name_state in ('unambiguous', 'selected')
        if entry.entry_id not in active:
            decisions.append(MappingDecision(entry.entry_id, 'skip', None,
                                             candidate_id, confirmed, None))
            transforms.append(PlanTransform(('SOURCE_BLOCKED',), (entry.entry_id,)))
            continue
        if entry.entry_type == 'directory':
            parts = mapped[entry.source_parts]
            codes = dir_reasons[entry.source_parts]
        else:
            parent = mapped.get(entry.source_parts[:-1], ())
            name, codes = allocate(entry.source_parts[-1], entry.entry_id, parent,
                                   reserved.get(entry.source_parts[:-1], set()))
            if codes:
                transforms.append(PlanTransform(codes, (entry.entry_id,)))
            parts = parent+(name,)
            codes = dir_reasons.get(entry.source_parts[:-1], ())+codes
        original = '/'.join(entry.source_parts)
        target = '/'.join(parts)
        if 'PATH_LIMIT' in check_path(parts, entry.entry_type == 'directory', profile, options):
            codes += ('PATH_LIMIT_EXPLICIT_MAPPING_REQUIRED',)
            transforms.append(PlanTransform(('PATH_LIMIT_EXPLICIT_MAPPING_REQUIRED',), (entry.entry_id,)))
        decisions.append(MappingDecision(entry.entry_id, 'keep' if target == original else 'rename', target,
                                         candidate_id, confirmed, None))
    directory_mappings = tuple(DirectoryMapping(d.node_id, '/'.join(mapped[d.source_parts]))
                               for d in sorted(directories, key=lambda d: d.node_id)
                               if mapped[d.source_parts] != d.source_parts)
    return MappingInput(report.archive_id, profile.profile_id, options, tuple(decisions), directory_mappings,
                        transformations=tuple(transforms))


def plan_id_projection(plan: ValidatedPlan):
    """The sole public fingerprint projection; diagnostics and locale are excluded."""
    value = to_json_value(plan)
    return {key: value[key] for key in ('schemaVersion', 'archiveId', 'profileId', 'profileVersion',
            'unicodeVersion', 'targetOptions', 'decisions', 'directoryMappings', 'resolvedPaths', 'extractable')}


def _plan_id(plan):
    return hashlib.sha256(dumps(plan_id_projection(plan)).encode('ascii')).hexdigest()


def extraction_inventory(entries, resolved_paths):
    """The single producer of retained files, unique directories and declared bytes."""
    files, directories, total = [], set(), 0
    for entry in entries:
        if entry.entry_id not in resolved_paths:
            continue
        target = tuple(resolved_paths[entry.entry_id].split('/'))
        if entry.entry_type == 'file':
            files.append(entry)
            total += entry.raw.declared_bytes
        for depth in range(1,len(target)+(entry.entry_type=='directory')):
            directories.add(target[:depth])
    return tuple(files), frozenset(directories), total


def validate_plan(index: ArchiveIndex, mapping: MappingInput) -> ValidatedPlan:
    """Recompute evidence and the complete target trie; never trust draft safety."""
    try:
        return _validate_plan(index, mapping)
    except MappingValidationError:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError) as error:
        code = str(error) if re.fullmatch('[A-Z][A-Z0-9_]*', str(error)) else 'INVALID_MAPPING_INPUT'
        raise MappingValidationError(code) from None


def _validate_plan(index, mapping):
    mapping = loads_mapping(dumps(mapping), max_bytes=index.limits.plan_bytes)
    if mapping.archive_id != index.archive_id or not index.archive_id:
        raise ValueError('ARCHIVE_ID_MISMATCH')
    profile = load_profile(mapping.profile_id)
    raw_ids = [e.entry_id for e in sorted(index.entries, key=lambda e: e.index)]
    decisions_by_id = {d.entry_id: d for d in mapping.decisions}
    if len(decisions_by_id) != len(mapping.decisions) or set(decisions_by_id) != set(raw_ids):
        raise ValueError('DECISIONS_MUST_COVER_EVERY_ENTRY_ONCE')
    choices = {d.entry_id: d.encoding_candidate_id for d in mapping.decisions if d.encoding_candidate_id is not None}
    report = analyze(index, profile, mapping.target_options, choices)
    if not report.complete or report.state in ('invalid', 'stale', 'incomplete'):
        raise ValueError('INCOMPLETE_OR_INVALID_INDEX')
    by_id = {e.entry_id: e for e in report.entries}
    nodes = {d.node_id: d for d in report.logical_directories}
    nodes_by_parts = {d.source_parts: d for d in report.logical_directories}
    dir_targets = {}
    for rule in mapping.directory_mappings:
        if rule.node_id not in nodes or rule.node_id in dir_targets:
            raise ValueError('UNKNOWN_OR_DUPLICATE_DIRECTORY_NODE')
        parts = _parts(rule.target_path)
        if len(parts) > index.limits.depth or _unsafe_target(parts, True, profile, mapping.target_options):
            raise ValueError('UNSAFE_DIRECTORY_TARGET')
        dir_targets[rule.node_id] = parts

    mapped_sources = {nodes[node_id].source_parts: target for node_id, target in dir_targets.items()}
    propagated = {}
    for node in sorted(nodes.values(), key=lambda n: (len(n.source_parts), n.node_id)):
        parent = propagated.get(node.source_parts[:-1], ())
        inherited = parent+(node.source_parts[-1],)
        target = dir_targets.get(node.node_id, inherited)
        # Child directory mappings may rename their leaf, but cannot disagree with
        # an explicitly mapped ancestor or move a subtree outside that ancestor.
        if node.node_id in dir_targets:
            ancestors = [nodes_by_parts[node.source_parts[:depth]] for depth in range(1, len(node.source_parts))
                         if node.source_parts[:depth] in mapped_sources]
            if ancestors:
                ancestor = max(ancestors, key=lambda n: len(n.source_parts))
                prefix = propagated[ancestor.source_parts]
                if target[:len(prefix)] != prefix or len(target) <= len(prefix):
                    raise ValueError('DIRECTORY_MAPPING_CONFLICT')
        propagated[node.source_parts] = target

    resolved, diagnostics, objects = {}, [], []
    extractable = bool(mapping.target_options.root_units)
    if not extractable:
        diagnostics.append(Diagnostic('PATH_ROOT_UNKNOWN', 'warning', certainty='advisory'))
    explicit_dirs = {}
    for entry_id in raw_ids:
        decision, entry = decisions_by_id[entry_id], by_id[entry_id]
        if 'INVALID_CANDIDATE_CHOICE' in entry.diagnostic_ids:
            raise ValueError('INVALID_CANDIDATE_CHOICE')
        if decision.action == 'skip':
            diagnostics.append(Diagnostic('ENTRY_SKIPPED', 'info', (entry_id,), certainty='advisory'))
            continue
        if entry.name_state == 'blocked' or entry.entry_type not in ('file', 'directory'):
            raise ValueError('SOURCE_ENTRY_BLOCKED')
        if entry.raw.flags & (1 | 0x40 | 0x2000):
            raise ValueError('ENCRYPTED_ENTRY_MUST_SKIP')
        if entry.raw.method not in (0, 8):
            extractable = False
            diagnostics.append(Diagnostic('SOURCE_METHOD_OR_ENCRYPTION_UNSUPPORTED', entry_ids=(entry_id,)))
        for code in ('UNKNOWN_CREATE_SYSTEM', 'MISSING_DIRECTORY_METADATA', 'ZERO_COMPRESSED_NONZERO_OUTPUT'):
            if code in entry.diagnostic_ids:
                extractable = False
                diagnostics.append(Diagnostic(code, entry_ids=(entry_id,)))
        # Path/type findings may replace name_state without resolving encoding.
        # Use the independent evidence retained by the sole analysis producer.
        if 'ENCODING_AMBIGUOUS' in entry.diagnostic_ids and decision.encoding_candidate_id is None and not decision.name_confirmed:
            raise ValueError('ENCODING_CONFIRMATION_REQUIRED')
        target = _parts(decision.target_path)
        if len(target) > index.limits.depth:
            raise ValueError('TARGET_DEPTH_LIMIT')
        if _unsafe_target(target, entry.entry_type == 'directory', profile, mapping.target_options):
            raise ValueError('UNSAFE_TARGET_PATH')
        for code in path_evidence(decision.target_path):
            if code in ('CONTROL_CHARACTER', 'BIDI_CHARACTER'):
                diagnostics.append(Diagnostic('TARGET_'+code, 'warning', (entry_id,), certainty='advisory'))
        if decision.action == 'keep' and decision.target_path != '/'.join(entry.source_parts):
            raise ValueError('KEEP_TARGET_CHANGED')
        source_dir = entry.source_parts if entry.entry_type == 'directory' else entry.source_parts[:-1]
        applicable = [nodes_by_parts[source_dir[:depth]] for depth in range(1, len(source_dir)+1)
                      if source_dir[:depth] in mapped_sources]
        if applicable:
            node = max(applicable, key=lambda n: len(n.source_parts))
            expected = propagated[node.source_parts]+entry.source_parts[len(node.source_parts):]
            # Descendant directory mappings are part of the propagated tree.
            expected = propagated.get(source_dir, expected) + (() if entry.entry_type == 'directory' else (entry.source_parts[-1],))
            # Leaf renaming is independent; ancestor components must agree.
            if entry.entry_type == 'directory':
                agrees = target == expected
            else:
                agrees = target[:-1] == expected[:-1]
            if not agrees:
                raise ValueError('DIRECTORY_ENTRY_MAPPING_CONFLICT')
        if entry.entry_type == 'directory':
            previous = explicit_dirs.setdefault(entry.source_parts, target)
            if previous != target:
                raise ValueError('DUPLICATE_DIRECTORY_MAPPING_CONFLICT')
        resolved[entry_id] = decision.target_path
        objects.append((target, entry_id, entry.entry_type, entry.source_parts))
        if entry.entry_type == 'file':
            if entry.raw.declared_bytes > EXTRACT_METADATA_MAXIMA['file_bytes']:
                extractable = False
                diagnostics.append(Diagnostic('DECLARED_FILE_LIMIT', entry_ids=(entry_id,)))
    kept_files, target_directories, declared_total = extraction_inventory(report.entries,resolved)
    for exceeded, code in ((len(kept_files) > EXTRACT_METADATA_MAXIMA['files'], 'TARGET_FILE_COUNT_LIMIT'),
                           (len(target_directories) > EXTRACT_METADATA_MAXIMA['directories'], 'TARGET_DIRECTORY_COUNT_LIMIT'),
                           (declared_total > EXTRACT_METADATA_MAXIMA['total_bytes'], 'DECLARED_TOTAL_LIMIT')):
        if exceeded:
            extractable = False
            diagnostics.append(Diagnostic(code))

    # Explicit directory records and their descendants describe one shared node.
    for parts, entry_id, kind, source in objects:
        for depth in range(1, len(source)+(kind == 'directory')):
            source_prefix = source[:depth]
            if source_prefix in explicit_dirs:
                expected = explicit_dirs[source_prefix]
                if parts[:len(expected)] != expected or (source != source_prefix and len(parts) <= len(expected)):
                    raise ValueError('DIRECTORY_ENTRY_MAPPING_CONFLICT')

    # Target trie includes implicit parents; directory identity remains source-bound.
    tries = {rule: {} for rule in _rules(profile)}
    count = 0
    for parts, entry_id, kind, source in objects:
        for rule, trie in tries.items():
            node = trie
            for depth, part in enumerate(parts):
                if node.get(None, {}).get('file'):
                    raise ValueError('TARGET_FILE_DIRECTORY_COLLISION')
                node = node.setdefault(comparison_key(part, rule), {})
                leaf = depth == len(parts)-1
                tag = node.setdefault(None, {'file': None, 'dirs': set(), 'spelling': part})
                if tag['spelling'] != part:
                    raise ValueError('TARGET_COMPARISON_COLLISION')
                if leaf and kind == 'file':
                    if tag['file'] or tag['dirs'] or any(k is not None for k in node):
                        raise ValueError('TARGET_FILE_DIRECTORY_COLLISION')
                    tag['file'] = entry_id
                else:
                    if tag['file']:
                        raise ValueError('TARGET_FILE_DIRECTORY_COLLISION')
                    # Explicit duplicate directory records share a logical node.
                    source_depth = len(source) if kind == 'directory' else len(source)-1
                    target_depth = len(parts) if kind == 'directory' else len(parts)-1
                    matched_depth = depth+1-(target_depth-source_depth)
                    source_node = nodes_by_parts.get(source[:matched_depth]) if matched_depth > 0 else None
                    source_directory = (('source', source_node.node_id) if source_node is not None
                                        else ('target', parts[:depth+1]))
                    if tag['dirs'] and source_directory not in tag['dirs']:
                        raise ValueError('TARGET_DIRECTORY_MERGE')
                    tag['dirs'].add(source_directory)
                count += 1
                if count > index.limits.group_members*index.limits.depth:
                    raise ValueError('TARGET_TRIE_LIMIT')
    remaining = [d for d in report.diagnostics if d.certainty != 'config_rule'
                 and (not d.entry_ids or any(e in resolved for e in d.entry_ids))]
    for rule, certainty in profile.rules:
        if certainty != 'advisory':
            continue
        buckets = {}
        for parts, entry_id, kind, source in objects:
            # Include each implicit parent, retaining spellings to distinguish
            # a shared directory from a comparison-induced directory merge.
            for depth in range(1, len(parts)+1):
                prefix = parts[:depth]
                key = tuple(comparison_key(p, rule) for p in prefix)
                bucket = buckets.setdefault(key, {})
                bucket.setdefault(prefix, set()).add(entry_id)
        for key, bucket in sorted(buckets.items()):
            if len(bucket) > 1:
                members = tuple(sorted({entry_id for ids in bucket.values() for entry_id in ids}))
                count += len(members)
                if count > index.limits.group_members*index.limits.depth:
                    raise ValueError('TARGET_TRIE_LIMIT')
                remaining.append(Diagnostic('TARGET_COMPARISON_ADVISORY', 'warning', members,
                                            {'ruleId': rule}, 'advisory'))
    if any(certainty == 'approximation' for _, certainty in profile.rules):
        remaining.append(Diagnostic('PROFILE_COMPARISON_APPROXIMATION', 'warning', certainty='approximation'))
    plan = ValidatedPlan('', index.archive_id, profile.profile_id, PROFILE_VERSION,
                         unicodedata.unidata_version, mapping.target_options,
                         tuple(decisions_by_id[e] for e in raw_ids),
                         tuple(sorted(mapping.directory_mappings, key=lambda d: d.node_id)), resolved,
                         extractable, tuple(diagnostics), tuple(remaining))
    plan = replace(plan, plan_id=_plan_id(plan))
    # A validated export must be importable under the same hard plan budget.
    dumps(plan, max_bytes=index.limits.plan_bytes)
    return plan


def revalidate_imported_plan(index: ArchiveIndex, value) -> ValidatedPlan:
    """Validate both imported and in-memory plans before any future write operation."""
    imported = loads_validated_plan(value if isinstance(value, str) else dumps(value),
                                    max_bytes=index.limits.plan_bytes)
    rebuilt = validate_plan(index, MappingInput(imported.archive_id, imported.profile_id,
                            imported.target_options, imported.decisions, imported.directory_mappings))
    if (imported.resolved_paths != rebuilt.resolved_paths or imported.extractable != rebuilt.extractable
            or imported.plan_id != rebuilt.plan_id):
        raise ValueError('IMPORTED_PLAN_DERIVATION_MISMATCH')
    return rebuilt
