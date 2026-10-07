"""Spawned, bounded JSON workers with deadlines owned by the parent process."""
from dataclasses import replace
import json
import math
import multiprocessing
from pathlib import Path
import threading
import time

from .model import (CleanupResult,Diagnostic,ExtractionResult,ExtractLimits,ScanLimits,TargetOptions,
                    _decode,dumps,loads_report,loads_mapping,loads_validated_plan,loads_extraction_result)

_MAX_RESPONSE = 64*1024**2


class WorkerFailure(ValueError):
    def __init__(self,code,exit_code=3,diagnostics=()):
        super().__init__(code)
        self.code,self.exit_code,self.diagnostics = code,exit_code,diagnostics or (Diagnostic(code),)


def _child(connection,operation,payload):
    """Only this fixed operation table is dispatched; no archive-supplied callable."""
    try:
        from .analyze import analyze
        from .mapping import suggest_plan,validate_plan,MappingValidationError
        from .profiles import load_profile
        from .zip_index import read_index
        if operation=='inspect':
            index = read_index(Path(payload['path']),ScanLimits())
            report = analyze(index,load_profile(payload['profile_id']),_decode(payload['options'],TargetOptions),{})
            draft = suggest_plan(report)
            report = replace(report,transformations=draft.transformations)
            response = {'report':dumps(report),'draft':dumps(draft,max_bytes=index.limits.plan_bytes)}
        elif operation=='validate':
            index = read_index(Path(payload['path']),ScanLimits())
            if index.structure_state in ('incomplete','stale') or (index.structure_state=='unsupported' and not index.archive_id):
                raise WorkerFailure('SCAN_NOT_COMPLETE',3,index.diagnostics)
            plan = validate_plan(index,loads_mapping(payload['mapping']))
            response = {'plan':dumps(plan,max_bytes=index.limits.plan_bytes)}
        elif operation=='extract':
            from .extract import _extract_owned
            plan = loads_validated_plan(payload['plan'])
            limits = _decode(payload['limits'],ExtractLimits)
            result = _extract_owned(Path(payload['path']),plan,payload['accept_plan_id'],Path(payload['output']),limits)
            response = {'result':dumps(result)}
        else:
            raise ValueError('UNKNOWN_WORKER_OPERATION')
        connection.send_bytes(dumps(response,max_bytes=_MAX_RESPONSE).encode('ascii'))
    except BaseException as error:
        if isinstance(error,WorkerFailure):
            code,exit_code,diagnostics = error.code,error.exit_code,error.diagnostics
        elif isinstance(error,MappingValidationError):
            limited = str(error) in ('PLAN_INPUT_LIMIT','EXPORT_LIMIT','TARGET_TRIE_LIMIT','TARGET_DEPTH_LIMIT')
            code,exit_code,diagnostics = 'MAPPING_INVALID',3 if limited else 2,error.diagnostics
        else:
            code,exit_code,diagnostics = 'WORKER_INPUT_INVALID',2,()
            if str(error) in ('PLAN_INPUT_LIMIT','EXPORT_LIMIT','TARGET_TRIE_LIMIT','TARGET_DEPTH_LIMIT'):
                code,exit_code = 'WORKER_LIMIT',3
        try:
            connection.send_bytes(dumps({'error':code,'exitCode':exit_code,'diagnostics':diagnostics}).encode('ascii'))
        except (OSError,ValueError):
            pass
    finally:
        connection.close()


def _windows_job(process):
    """Best-effort kill-on-close Job Object, in addition to mandatory terminate/join.

    Some embedding jobs disallow assignment. Workers launch no subprocesses, so
    Process.terminate still terminates all work even when assignment is unavailable.
    """
    import os
    if os.name!='nt':
        return None
    import ctypes
    from ctypes import wintypes as w
    k = ctypes.WinDLL('kernel32',use_last_error=True)
    class Basic(ctypes.Structure):
        _fields_ = [('process_time',ctypes.c_longlong),('job_time',ctypes.c_longlong),('flags',w.DWORD),
                    ('min_ws',ctypes.c_size_t),('max_ws',ctypes.c_size_t),('active',w.DWORD),
                    ('affinity',ctypes.c_size_t),('priority',w.DWORD),('scheduling',w.DWORD)]
    class Extended(ctypes.Structure):
        _fields_ = [('basic',Basic),('io',ctypes.c_ulonglong*6),('process_mem',ctypes.c_size_t),
                    ('job_mem',ctypes.c_size_t),('peak_process',ctypes.c_size_t),('peak_job',ctypes.c_size_t)]
    k.CreateJobObjectW.argtypes,k.CreateJobObjectW.restype = (w.LPVOID,w.LPCWSTR),w.HANDLE
    k.SetInformationJobObject.argtypes = (w.HANDLE,ctypes.c_int,w.LPVOID,w.DWORD)
    k.AssignProcessToJobObject.argtypes = (w.HANDLE,w.HANDLE)
    k.CloseHandle.argtypes = (w.HANDLE,)
    handle = k.CreateJobObjectW(None,None)
    if not handle:
        return None
    info = Extended()
    info.basic.flags = 0x2000
    if not k.SetInformationJobObject(handle,9,ctypes.byref(info),ctypes.sizeof(info)) or not k.AssignProcessToJobObject(handle,int(process.sentinel)):
        k.CloseHandle(handle)
        return None
    return k,handle


def _failure_result(payload,code):
    return ExtractionResult('failed',payload.get('plan_id',''),payload.get('archive_id',''),'unavailable',None,None,None,(),(),
                            (Diagnostic(code),Diagnostic('ACTUAL_COUNTS_UNAVAILABLE')),CleanupResult('retained_ownership_unknown'))


def run_worker(operation,payload,*,seconds=None,cancel_event=None):
    started_at = time.monotonic()
    if operation not in ('inspect','validate','extract'):
        raise ValueError('UNKNOWN_WORKER_OPERATION')
    maximum = 60 if operation=='extract' else 30
    seconds = maximum if seconds is None else seconds
    if type(seconds) not in (int,float) or not math.isfinite(seconds) or not 0<seconds<=maximum:
        raise ValueError('INVALID_WORKER_DEADLINE')
    # Primitive bounded JSON in, never a trusted MappingProxyType/ValidatedPlan pickle.
    payload = json.loads(dumps(payload,max_bytes=_MAX_RESPONSE))
    context = multiprocessing.get_context('spawn')
    reader,writer = context.Pipe(duplex=False)
    process = context.Process(target=_child,args=(writer,operation,payload),daemon=True)
    received,ready = [],threading.Event()
    def receive():
        try:
            received.append(reader.recv_bytes(_MAX_RESPONSE))
        except (EOFError,OSError) as error:
            received.append(error)
        finally:
            ready.set()
    deadline = started_at+seconds
    job = None
    failure = None
    started = False
    receiver = None
    try:
        process.start()
        started = True
        writer.close()
        job = _windows_job(process)
        receiver = threading.Thread(target=receive,daemon=True)
        receiver.start()
        while True:
            if cancel_event is not None and cancel_event.is_set():
                failure = 'WORKER_CANCELLED'
                break
            remaining = deadline-time.monotonic()
            if remaining<=0:
                failure = 'WORKER_TIMEOUT'
                break
            if ready.wait(min(0.02,remaining)):
                process.join(max(0,deadline-time.monotonic()))
                if process.is_alive():
                    failure = 'WORKER_TIMEOUT'
                break
    except KeyboardInterrupt:
        failure = 'WORKER_CANCELLED'
    finally:
        if started:
            if process.is_alive():
                process.terminate()
            process.join()
        writer.close()
        if receiver is not None:
            receiver.join(1)
        reader.close()
        if job is not None:
            job[0].CloseHandle(job[1])
        if started:
            process.close()
    if failure:
        if operation=='extract':
            return {'result':_failure_result(payload,failure)}
        raise WorkerFailure(failure)
    try:
        if not received or not isinstance(received[0],bytes):
            raise ValueError('WORKER_NO_RESULT')
        # Strict duplicate-key parsing is supplied by the central model decoder.
        from .model import _unique_object
        value = json.loads(received[0],object_pairs_hook=_unique_object)
        if type(value) is not dict:
            raise ValueError('WORKER_RESPONSE_INVALID')
        if set(value)=={'error','exitCode','diagnostics'}:
            if value['exitCode'] not in (2,3) or type(value['error']) is not str:
                raise ValueError('WORKER_RESPONSE_INVALID')
            diagnostics = _decode(value['diagnostics'],tuple[Diagnostic,...])
            raise WorkerFailure(value['error'],value['exitCode'],diagnostics)
        if operation=='inspect' and set(value)=={'report','draft'}:
            report,draft = loads_report(value['report']),loads_mapping(value['draft'])
            if report.archive_id!=draft.archive_id:
                raise ValueError('WORKER_RESPONSE_INVALID')
            answer = {'report':report,'draft':draft,'report_text':value['report'],'draft_text':value['draft']}
            if time.monotonic()>deadline: raise WorkerFailure('WORKER_TIMEOUT')
            return answer
        if operation=='validate' and set(value)=={'plan'}:
            answer = {'plan':loads_validated_plan(value['plan']),'plan_text':value['plan']}
            if time.monotonic()>deadline: raise WorkerFailure('WORKER_TIMEOUT')
            return answer
        if operation=='extract' and set(value)=={'result'}:
            result = loads_extraction_result(value['result'])
            if result.plan_id!=payload.get('plan_id') or result.archive_id!=payload.get('archive_id'):
                raise ValueError('WORKER_RESPONSE_INVALID')
            return {'result':_failure_result(payload,'WORKER_TIMEOUT') if time.monotonic()>deadline else result}
        raise ValueError('WORKER_RESPONSE_INVALID')
    except WorkerFailure:
        raise
    except (ValueError,TypeError,UnicodeError,RecursionError):
        if operation=='extract':
            return {'result':_failure_result(payload,'WORKER_RESPONSE_INVALID')}
        raise WorkerFailure('WORKER_RESPONSE_INVALID') from None
