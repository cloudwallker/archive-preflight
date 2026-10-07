"""Name evidence, component tries, logical directory identity, and collision reasons."""
import hashlib
import json
import re
import stat
from types import MappingProxyType
from typing import Mapping

from .encoding import decode_candidates
from .model import ArchiveIndex, CollisionGroup, Diagnostic, EntryReport, LogicalDirectory, PreflightReport, TargetOptions, TargetProfile
from .profiles import check_path, comparison_key, measure, validate_options


def _identity(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode('ascii')).hexdigest()


def path_evidence(text: str) -> tuple[str, ...]:
    """Reject escapes without normpath; recognize alternate Windows separators after decoding."""
    codes = []
    alternate = text.replace('\\', '/')
    if not text:
        codes.append('EMPTY_NAME')
    if '\x00' in text:
        codes.append('NUL_NAME')
    if alternate.startswith('/') or re.match(r'^[A-Za-z]:', alternate):
        codes.append('ABSOLUTE_OR_DEVICE_PATH')
    if '..' in alternate.split('/'):
        codes.append('PATH_TRAVERSAL')
    if '\\' in text:
        codes.append('BACKSLASH_PATH')
    parts = text[:-1].split('/') if text.endswith('/') else text.split('/')
    if '.' in parts or '' in parts:
        codes.append('NONSTANDARD_COMPONENT')
    if any(ord(c) < 32 or ord(c) == 127 for c in text):
        codes.append('CONTROL_CHARACTER')
    if any(c in '\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069' for c in text):
        codes.append('BIDI_CHARACTER')
    return tuple(codes)


_BLOCK = frozenset(('EMPTY_NAME', 'NUL_NAME', 'ABSOLUTE_OR_DEVICE_PATH', 'PATH_TRAVERSAL'))


def _type(entry, text):
    directory = text is not None and text.endswith('/')
    dos_directory = bool(entry.external_attr & 0x10)
    if entry.create_system in (3, 19):
        mode = stat.S_IFMT(entry.external_attr >> 16)
        if mode == stat.S_IFLNK:
            return 'symlink', ('SPECIAL_TYPE',)
        if mode not in (0, stat.S_IFREG, stat.S_IFDIR):
            return 'special', ('SPECIAL_TYPE',)
        if (mode == stat.S_IFREG and directory) or (mode == stat.S_IFDIR and not directory) or (dos_directory and not directory):
            return 'contradictory', ('TYPE_CONFLICT',)
    elif dos_directory and not directory:
        return 'contradictory', ('TYPE_CONFLICT',)
    codes = []
    if entry.create_system not in (0, 3, 19):
        codes.append('UNKNOWN_CREATE_SYSTEM')
    if directory and not dos_directory and (entry.create_system not in (3, 19) or stat.S_IFMT(entry.external_attr >> 16) != stat.S_IFDIR):
        codes.append('MISSING_DIRECTORY_METADATA')
    return ('directory' if directory else 'file'), tuple(codes)


class _Node:
    __slots__ = ('children', 'explicit', 'descendants', 'owner', 'parts')

    def __init__(self, parts=()):
        self.children, self.explicit, self.descendants = {}, [], []
        self.owner, self.parts = None, parts


def build_logical_directories(entries: tuple[EntryReport, ...]) -> tuple[LogicalDirectory, ...]:
    """The shared tree constructor. Identity is bound to all current candidate/default choices."""
    entries = tuple(sorted(entries, key=lambda e: e.index))
    owner_indices = {e.entry_id: e.index for e in entries}
    context = [(e.entry_id, e.selected_candidate_id,
                next((c.candidate_id for c in e.candidates if c.valid and c.text == e.default_display_name), None)) for e in entries]
    # Hash the full canonical projection, reusing the common JSON prefix state
    # rather than serializing/hashing the entire context again for every node.
    context_json = json.dumps(context, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode('ascii')
    prefix_hash = hashlib.sha256(b'{"context":'+context_json)
    root, nodes = _Node(), []
    for entry in entries:
        if not entry.source_parts or entry.name_state == 'blocked':
            continue
        directory_parts = entry.source_parts if entry.entry_type == 'directory' else entry.source_parts[:-1]
        node = root
        for part in directory_parts:
            if part not in node.children:
                node.children[part] = _Node(node.parts+(part,))
                nodes.append(node.children[part])
            node = node.children[part]
            if node.owner is None:
                node.owner = entry.entry_id
            if entry.entry_type == 'directory' and node.parts == entry.source_parts:
                node.explicit.append(entry.entry_id)
            else:
                node.descendants.append(entry.entry_id)
    ids = {}
    for node in nodes:
        tail = json.dumps({'ownerIndex': owner_indices[node.owner], 'sourceParts': node.parts}, ensure_ascii=True,
                          sort_keys=True, separators=(',', ':')).encode('ascii')
        digest = prefix_hash.copy()
        digest.update(b','+tail[1:])
        ids[node.parts] = 'd'+digest.hexdigest()
    return tuple(LogicalDirectory(ids[n.parts], n.parts, n.owner, ids.get(n.parts[:-1]), tuple(n.descendants), tuple(n.explicit))
                 for n in sorted(nodes, key=lambda n: n.parts))


def _collisions(entries, directories, profile, maximum):
    groups, count = [], 0
    objects = [(d.source_parts, d.node_id, d.explicit_entry_ids+d.descendant_entry_ids, 'directory') for d in directories]
    objects.extend((e.source_parts, '', (e.entry_id,), 'file') for e in entries if e.entry_type == 'file' and e.source_parts and e.name_state != 'blocked')
    for rule, certainty in profile.rules:
        # A comparison trie preserves parent merges even when all leaf names differ.
        trie = {}
        for obj in objects:
            node = trie
            for part in obj[0]:
                key = comparison_key(part, rule)
                node = node.setdefault(key, {})
            node.setdefault(None, []).append(obj)
        pending = [((), trie)]
        while pending:
            key, node = pending.pop()
            pending.extend((key+(part,), child) for part, child in node.items() if part is not None)
            bucket = node.get(None, ())
            if len(bucket) < 2:
                continue
            original = {obj[0] for obj in bucket}
            if rule != 'exact' and len(original) < 2:
                continue
            if (rule in ('casefold', 'nfc-casefold')
                    and any(other == 'ascii-case' for other, _ in profile.rules)
                    and all(all(p.isascii() for p in parts) for parts in original)):
                continue
            if rule == 'windows-trim' and not any(any(p.endswith((' ', '.')) for p in parts) for parts in original):
                continue
            entry_ids, node_ids = set(), set()
            for parts, node_id, members, kind in bucket:
                if node_id:
                    node_ids.add(node_id)
                for member in members:
                    entry_ids.add(member)
                    if count+len(entry_ids)+len(node_ids) > maximum:
                        return tuple(groups), True
            kinds = {obj[3] for obj in bucket}
            impact = 'file-directory' if len(kinds) > 1 else ('directory-merge' if 'directory' in kinds else 'file-overwrite')
            first = next((i for i in range(len(key)) if len({parts[i] for parts in original}) > 1), len(key)-1)
            eid, nid = tuple(sorted(entry_ids)), tuple(sorted(node_ids))
            comparison = '/'.join(key)
            gid = 'g'+_identity((rule, comparison, eid, nid))
            groups.append(CollisionGroup(gid, rule, eid, nid, tuple(sorted('/'.join(p) for p in original)), comparison, first, impact, certainty))
            count += len(eid)+len(nid)
    return tuple(sorted(groups, key=lambda g: (g.rule_id, g.comparison_key, g.group_id))), False


def analyze(index: ArchiveIndex, profile: TargetProfile, options: TargetOptions, choices: Mapping[str, str]) -> PreflightReport:
    validate_options(profile, options)
    diagnostics, reports = list(index.diagnostics), []
    if not options.root_units:
        diagnostics.append(Diagnostic('PATH_ROOT_UNKNOWN', 'warning', certainty='advisory'))
    state = index.structure_state
    complete = state in ('ok', 'findings', 'unsupported')
    if set(choices)-{e.entry_id for e in index.entries}:
        diagnostics.append(Diagnostic('UNKNOWN_ENTRY_CHOICE'))
        state = 'invalid'
    for raw in index.entries:
        codes, candidates = [], decode_candidates(raw)
        valid = [c for c in candidates if c.valid]
        chosen = choices.get(raw.entry_id)
        selected = next((c for c in valid if c.candidate_id == chosen), None) if chosen is not None else None
        if chosen is not None and selected is None:
            codes.append('INVALID_CANDIDATE_CHOICE')
        display = selected or (valid[0] if valid else None)
        text = display.text if display else None
        name_state = 'selected' if selected else ('unambiguous' if display and (display.certainty == 'config_rule' or text.isascii()) else 'ambiguous')
        if name_state == 'ambiguous':
            codes.append('ENCODING_AMBIGUOUS')
        for candidate in candidates:
            if not candidate.valid:
                codes.extend(s for s in candidate.evidence if not s.startswith('EXTRA_') or s == 'EXTRA_TRUNCATED')
            if candidate.text is not None:
                codes.extend(c for c in path_evidence(candidate.text) if c in _BLOCK)
        if text is not None:
            codes.extend(path_evidence(text))
        kind, type_codes = _type(raw, text)
        codes.extend(type_codes)
        parts = tuple((text[:-1] if kind == 'directory' else text).split('/')) if text else ()
        if len(parts) > index.limits.depth:
            codes.append('DEPTH_LIMIT')
            complete, state = False, 'incomplete'
        blocked = bool(_BLOCK.intersection(codes)) or not valid or kind in ('symlink', 'special', 'contradictory') or 'INVALID_CANDIDATE_CHOICE' in codes
        if blocked:
            name_state = 'blocked'
            parts = ()
        elif 'BACKSLASH_PATH' in codes or 'NONSTANDARD_COMPONENT' in codes:
            name_state = 'nonstandard'
            parts = ()
        elif 'MISSING_DIRECTORY_METADATA' in codes:
            name_state = 'nonstandard'
        if 'DEPTH_LIMIT' in codes:
            parts = ()
        if parts:
            codes.extend(check_path(parts, kind == 'directory', profile, options))
        if raw.declared_bytes and not raw.compressed_bytes:
            codes.append('ZERO_COMPRESSED_NONZERO_OUTPUT')
        elif raw.declared_bytes > raw.compressed_bytes*100:
            codes.append('DECLARED_RATIO_RISK')
        codes = tuple(dict.fromkeys(codes))
        for code in codes:
            advisory = code in ('PATH_ROOT_UNKNOWN', 'ENCODING_AMBIGUOUS', 'UNKNOWN_CREATE_SYSTEM', 'CONTROL_CHARACTER', 'BIDI_CHARACTER', 'DECLARED_RATIO_RISK')
            details = {'source': display.source if display else 'raw', 'pathInterpretation': 'Windows separator / POSIX literal; explicit mapping required'} if code == 'BACKSLASH_PATH' else {}
            diagnostics.append(Diagnostic(code, 'warning' if advisory else 'error', (raw.entry_id,), details, 'advisory' if advisory else 'config_rule'))
        reports.append(EntryReport(raw.entry_id, raw.index, raw, candidates, selected.candidate_id if selected else None, text, name_state, kind, parts,
                                   tuple(measure(p, profile) for p in parts), options.root_units+measure('/'.join(parts), profile) if options.root_units and parts else None, codes))
    reports = tuple(reports)
    directories = build_logical_directories(reports)
    for directory in directories:
        if len(directory.explicit_entry_ids) > 1:
            diagnostics.append(Diagnostic('DUPLICATE_DIRECTORY_METADATA', 'info', directory.explicit_entry_ids, {'nodeId': directory.node_id}, 'advisory'))
    groups, exceeded = _collisions(reports, directories, profile, index.limits.group_members)
    if exceeded:
        diagnostics.append(Diagnostic('GROUP_MEMBER_LIMIT'))
        complete, state = False, 'incomplete'
    if state == 'ok' and (diagnostics or groups):
        state = 'findings'
    return PreflightReport(index.archive_id, index.runtime, profile, options, complete, state, reports, directories, groups,
                           MappingProxyType({'entries': len(reports), 'directories': len(directories), 'collisionGroups': len(groups)}), index.limits, tuple(diagnostics))
