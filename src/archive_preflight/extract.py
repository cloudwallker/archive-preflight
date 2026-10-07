"""Revalidated plans, complete streams and native owned trees; no implicit extraction."""
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import re
import time
import zlib

from .analyze import analyze
from .content import inspect_ranges,stream_verified
from .mapping import revalidate_imported_plan,extraction_inventory
from .model import (CleanupResult,Diagnostic,ExtractLimits,ExtractionResult,OutputBudget,
                    ScanLimits,WrittenEntry,dumps,to_json_value)
from .profiles import load_profile
from .safe_fs import SafeTree,UnsupportedHost,FileCreatedError,checked_parts
from .zip_index import read_index,_open_regular,_fingerprint,_Reject


def extract_verified(path,plan,accept_plan_id,output,limits: ExtractLimits) -> ExtractionResult:
    """Public entry point: the parent owns one deadline, including plan transport."""
    from .worker import run_worker,WorkerFailure,_failure_result
    started = time.monotonic()
    plan_id,archive_id = getattr(plan,'plan_id',''),getattr(plan,'archive_id','')
    payload = {'plan_id':plan_id,'archive_id':archive_id}
    try:
        if not isinstance(limits,ExtractLimits):
            raise ValueError('INVALID_EXTRACT_LIMITS')
        payload.update(path=str(path),plan=dumps(plan,max_bytes=ScanLimits().plan_bytes),
                       accept_plan_id=accept_plan_id,output=str(output),limits=to_json_value(limits))
        remaining = limits.seconds-(time.monotonic()-started)
        if remaining<=0:
            raise ValueError('WORKER_TIMEOUT')
    except (ValueError,TypeError):
        return ExtractionResult('failed',plan_id,archive_id,'unavailable',0,0,0,(),(),
                                (Diagnostic('EXTRACTION_REQUEST_INVALID'),),CleanupResult('not_created'))
    try:
        return run_worker('extract',payload,seconds=remaining)['result']
    except (WorkerFailure,OSError):
        return _failure_result(payload,'WORKER_FAILED')


def _extract_owned(path,plan,accept_plan_id,output,limits: ExtractLimits) -> ExtractionResult:
    """Worker body only. Its parent provides hard termination; no nested spawn."""
    path,output = Path(path),Path(output)
    tree = None
    budget = OutputBudget()
    written_bytes, files = 0, 0
    entries,skipped,diagnostics = [],(),()
    cleanup = CleanupResult('not_created')
    status,backend = 'failed','unavailable'
    plan_id,archive_id = getattr(plan,'plan_id',''),getattr(plan,'archive_id','')
    attempted_create = False
    try:
        # Also validate programmatic limits before any write, not just JSON inputs.
        if not isinstance(limits,ExtractLimits):
            raise ValueError('INVALID_EXTRACT_LIMITS')
        if accept_plan_id != plan_id:
            raise ValueError('PLAN_ACCEPTANCE_REQUIRED')
        if output.resolve()==path.resolve() or output.exists() or output.is_symlink():
            raise ValueError('OUTPUT_ALREADY_EXISTS_OR_INPUT')
        with _open_regular(path,share_read_only=True) as source:
            initial = _fingerprint(os.fstat(source.fileno()))
            index = read_index(path,ScanLimits())
            if index.fingerprint!=initial:
                raise ValueError('SOURCE_CHANGED')
            plan = revalidate_imported_plan(index,plan)
            if plan.archive_id!=index.archive_id or plan.plan_id!=accept_plan_id:
                raise ValueError('SOURCE_OR_PLAN_CHANGED')
            if not plan.extractable:
                raise ValueError('PLAN_NOT_EXTRACTABLE')
            skipped = tuple(d.entry_id for d in plan.decisions if d.action=='skip')
            choices = {d.entry_id:d.encoding_candidate_id for d in plan.decisions if d.encoding_candidate_id is not None}
            report = analyze(index,load_profile(plan.profile_id),plan.target_options,choices)
            by_id = {e.entry_id:e for e in report.entries}
            retained_files,directories,total = extraction_inventory(report.entries,plan.resolved_paths)
            if (len(retained_files)>limits.files or len(directories)>limits.directories or total>limits.total_bytes
                    or any(e.raw.declared_bytes>limits.file_bytes for e in retained_files)):
                raise ValueError('DECLARED_EXTRACTION_LIMIT')
            for target in plan.resolved_paths.values():
                checked_parts(tuple(target.split('/')))
            ranges = inspect_ranges(source,index,set(plan.resolved_paths))
            if _fingerprint(os.fstat(source.fileno()))!=initial or _fingerprint(path.lstat())!=initial:
                raise ValueError('SOURCE_CHANGED')
            attempted_create = True
            tree = SafeTree.create(output)
            tree.budget,tree.limits = budget,limits
            backend = tree.backend
            for raw in index.entries:
                if raw.entry_id not in plan.resolved_paths:
                    continue
                target = plan.resolved_paths[raw.entry_id]
                parts = tuple(target.split('/'))
                content = ranges[raw.entry_id]
                if by_id[raw.entry_id].entry_type=='directory':
                    # Directory streams must also verify and be empty.
                    for block in stream_verified(source,content,limits,budget):
                        if block:
                            raise ValueError('DIRECTORY_HAS_CONTENT')
                    tree.mkdir(parts)
                    entries.append(WrittenEntry(raw.entry_id,target,'directory',0))
                    continue
                if files>=limits.files:
                    raise ValueError('ACTUAL_FILE_LIMIT')
                try:
                    stream = tree.create_file(parts)
                except FileCreatedError:
                    files += 1
                    budget.files += 1
                    raise
                files += 1
                budget.files += 1
                actual,crc,digest = 0,0,hashlib.sha256()
                try:
                    with stream:
                        for block in stream_verified(source,content,limits,budget):
                            at = 0
                            while at<len(block):
                                count = stream.write(block[at:])
                                if type(count) is not int or count<=0 or count>len(block)-at:
                                    raise OSError('SHORT_WRITE')
                                piece = block[at:at+count]
                                at += count
                                actual += count
                                written_bytes += count
                                crc = zlib.crc32(piece,crc)
                                digest.update(piece)
                finally:
                    entries.append(WrittenEntry(raw.entry_id,target,'file',actual,crc,digest.hexdigest()))
            if _fingerprint(os.fstat(source.fileno()))!=initial or _fingerprint(path.lstat())!=initial:
                raise ValueError('SOURCE_CHANGED')
            listing = tree.list_verified()
            expected_files = {e.target_path:e for e in entries if e.kind=='file'}
            actual_files = {e.target_path:e for e in listing if e.kind=='file'}
            if set(expected_files)!=set(actual_files) or {e.target_path for e in listing if e.kind=='directory'}!={'/'.join(d) for d in directories}:
                raise ValueError('OUTPUT_SET_MISMATCH')
            for target,expected in expected_files.items():
                actual = actual_files[target]
                if (expected.size,expected.crc32,expected.sha256)!=(actual.size,actual.crc32,actual.sha256):
                    raise ValueError('OUTPUT_CONTENT_MISMATCH')
            if budget.actual_bytes!=written_bytes:
                raise ValueError('OUTPUT_BUDGET_MISMATCH')
            # Include implicit directories, while retaining one record per explicit ZIP entry.
            explicit = {e.target_path for e in entries if e.kind=='directory'}
            entries.extend(e for e in listing if e.kind=='directory' and e.target_path not in explicit)
            status,cleanup = 'verified',CleanupResult('not_needed')
    except (ValueError,OSError,_Reject) as error:
        status = 'unsupported_host' if isinstance(error,UnsupportedHost) else 'failed'
        code = str(error) if isinstance(error,ValueError) else getattr(error,'code','EXTRACTION_IO_ERROR')
        code = code if re.fullmatch('[A-Z][A-Z0-9_]{0,95}',code) else 'EXTRACTION_INVALID'
        diagnostics = (Diagnostic(code),)
        if tree is not None:
            cleanup = tree.cleanup_owned()
        elif attempted_create and getattr(error,'tree_created',False):
            # mkdir-to-open could have created a tree with no trustworthy handle.
            cleanup = CleanupResult('retained_ownership_unknown')
    finally:
        if tree is not None:
            try:
                tree.close()
            except OSError:
                status = 'failed'
                diagnostics += (Diagnostic('HANDLE_CLOSE_FAILED'),)
                cleanup = replace(cleanup,state='cleanup_failed')
    return ExtractionResult(status,plan_id,archive_id,backend,files,budget.directories,written_bytes,
                            tuple(entries),skipped,diagnostics,cleanup)
