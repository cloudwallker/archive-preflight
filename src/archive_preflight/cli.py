"""Read-only inspect and naming validation commands with exclusive JSON exports."""
import argparse
import json
import math
from pathlib import Path
import sys

from .mapping import MappingValidationError
from .model import ScanLimits, TargetOptions, ExtractLimits, dumps, loads_validated_plan, loads_mapping, to_json_value
from .profiles import load_profile, measure
from .worker import run_worker, WorkerFailure
from .extract import extract_verified


_ALIASES = {'windows': 'windows-win32-conservative-v1', 'macos': 'macos-apfs-ci-advisory-v1',
            'linux': 'linux-posix-bytes-v1'}


def _visible(value):
    return json.dumps(str(value), ensure_ascii=True)[1:-1]


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(2, '参数错误: '+_visible(message)+'\n')


def _parser():
    parser = _Parser(prog='archive-preflight')
    parser.add_argument('--version', action='version', version='archive-preflight 0.1.0')
    commands = parser.add_subparsers(dest='command', required=True)
    inspect = commands.add_parser('inspect', help='只读 ZIP 名称预检')
    inspect.add_argument('zip', type=Path)
    inspect.add_argument('--target', required=True)
    inspect.add_argument('--target-root')
    inspect.add_argument('--json', action='store_true')
    inspect.add_argument('--report-json', type=Path)
    inspect.add_argument('--plan', type=Path)
    inspect.add_argument('--html',type=Path)
    inspect.add_argument('--locale', choices=('zh-CN', 'en'), default='zh-CN')
    validate = commands.add_parser('validate-plan', help='完整重验命名计划')
    validate.add_argument('zip', type=Path)
    validate.add_argument('--mapping', type=Path, required=True)
    validate.add_argument('--output', type=Path, required=True)
    extract = commands.add_parser('extract',help='按已接受计划受限验证提取')
    extract.add_argument('zip',type=Path)
    extract.add_argument('--plan',type=Path,required=True)
    extract.add_argument('--accept-plan',required=True)
    extract.add_argument('--output',type=Path,required=True)
    extract.add_argument('--result-json',type=Path)
    extract.add_argument('--seconds',type=float,default=60,help='降低提取墙钟预算（0 < 秒数 <= 60）')
    demo=commands.add_parser('demo',help='生成真实八类风险示例及离线报告')
    demo.add_argument('--output',type=Path,required=True)
    demo.add_argument('--target',default='windows')
    return parser


def _check_outputs(inputs, outputs):
    canonical_inputs = {p.resolve() for p in inputs}
    seen = set()
    for path in (p for p in outputs if p is not None):
        canonical = path.resolve()
        if canonical in canonical_inputs:
            raise ValueError('OUTPUT_EQUALS_INPUT')
        if canonical in seen:
            raise ValueError('OUTPUT_PATHS_DUPLICATE')
        if path.exists() or path.is_symlink():
            raise ValueError('OUTPUT_ALREADY_EXISTS')
        seen.add(canonical)


def _write_new(path, text):
    with path.open('x', encoding='utf-8', newline='\n') as output:
        output.write(text+'\n')


def _scan_exit(report):
    if report.state in ('incomplete', 'unsupported', 'stale'):
        return 3
    if report.state == 'invalid':
        return 2
    if not report.complete:
        return 3
    return int(bool(report.diagnostics or report.collision_groups))


def _emit_diagnostics(diagnostics):
    for diagnostic in diagnostics:
        print(_visible(diagnostic.code), file=sys.stderr)


def _inspect(args):
    profile = load_profile(_ALIASES.get(args.target, args.target))
    _check_outputs((args.zip,), (args.report_json, args.plan,args.html))
    root_units = measure(args.target_root.rstrip('/\\')+'/', profile) if args.target_root else 0
    options = TargetOptions(root_units=root_units)
    response = run_worker('inspect',{'path':str(args.zip),'profile_id':profile.profile_id,'options':to_json_value(options)})
    report = response['report']
    report_text,draft_text = response['report_text'],response['draft_text']
    if args.html is not None:
        from .report import render_html
        _write_new(args.html,render_html(report,loads_mapping(draft_text),args.locale))
    if args.report_json is not None:
        _write_new(args.report_json, report_text)
    if args.plan is not None:
        _write_new(args.plan, draft_text)
    if args.json:
        print(report_text)
    else:
        if args.locale == 'en':
            print(f'ZIP name preflight: {report.state}; entries={len(report.entries)}; content not verified')
        else:
            print(f'ZIP 名称预检: {report.state}；条目={len(report.entries)}；正文尚未验证')
        for entry in report.entries:
            print(entry.entry_id+' '+_visible(entry.default_display_name or '')+' ['+entry.name_state+']')
    _emit_diagnostics(report.diagnostics)
    return _scan_exit(report)


def _validate(args):
    _check_outputs((args.zip, args.mapping), (args.output,))
    limits = ScanLimits()
    with args.mapping.open('rb') as source:
        raw = source.read(limits.plan_bytes+1)
    if len(raw) > limits.plan_bytes:
        raise ValueError('PLAN_INPUT_LIMIT')
    response = run_worker('validate',{'path':str(args.zip),'mapping':raw.decode('utf-8','strict')})
    plan,text = response['plan'],response['plan_text']
    _write_new(args.output, text)
    print('计划已重验: '+plan.plan_id+'；可提取='+str(plan.extractable).lower())
    _emit_diagnostics(plan.diagnostics+plan.remaining_advisories)
    if not plan.extractable:
        return 3
    return int(bool(plan.diagnostics or plan.remaining_advisories))


def _extract(args):
    if not math.isfinite(args.seconds) or not 0<args.seconds<=60:
        raise ValueError('INVALID_EXTRACT_SECONDS')
    _check_outputs((args.zip,args.plan),(args.output,args.result_json))
    if args.result_json is not None and args.result_json.resolve().is_relative_to(args.output.resolve()):
        raise ValueError('RESULT_WITHIN_OUTPUT_TREE')
    with args.plan.open('rb') as source:
        raw = source.read(ScanLimits().plan_bytes+1)
    if len(raw)>ScanLimits().plan_bytes:
        raise ValueError('PLAN_INPUT_LIMIT')
    plan_text = raw.decode('utf-8','strict')
    plan = loads_validated_plan(plan_text)
    limits = ExtractLimits(seconds=args.seconds)
    result = extract_verified(args.zip,plan,args.accept_plan,args.output,limits)
    result_text = dumps(result)
    if args.result_json is not None:
        _write_new(args.result_json,result_text)
    counts = ['未知' if value is None else str(value) for value in (result.actual_files,result.actual_directories,result.actual_bytes)]
    print(f'验证提取: {result.status}；文件={counts[0]}；目录={counts[1]}；字节={counts[2]}；跳过={len(result.skipped_entry_ids)}')
    _emit_diagnostics(result.diagnostics+result.cleanup.diagnostics)
    if result.cleanup.state in ('retained_ownership_unknown','cleanup_failed'):
        print('请检查指定输出目录: '+_visible(args.output),file=sys.stderr)
    return 0 if result.status=='verified' else 4


def _demo(args):
    from .demo import eight_risks_zip
    from .report import render_html
    profile=load_profile(_ALIASES.get(args.target,args.target))
    _check_outputs((),(args.output,))
    args.output.mkdir()
    source=args.output/'demo-eight-risks.zip';source.write_bytes(eight_risks_zip())
    primary=None
    profiles=('windows-win32-conservative-v1','macos-apfs-ci-advisory-v1','macos-apfs-cs-advisory-v1','linux-posix-bytes-v1')
    for profile_id in dict.fromkeys((profile.profile_id,)+profiles):
        response=run_worker('inspect',{'path':str(source),'profile_id':profile_id,'options':to_json_value(TargetOptions(root_units=100))})
        _write_new(args.output/(profile_id+'.json'),response['report_text'])
        if profile_id==profile.profile_id:primary=response
    _write_new(args.output/'report.json',primary['report_text'])
    _write_new(args.output/'draft.json',primary['draft_text'])
    _write_new(args.output/'report.html',render_html(primary['report'],loads_mapping(primary['draft_text']),'zh-CN'))
    print('示例已生成；报告和映射草稿请本地审阅，再运行 validate-plan。')
    return _scan_exit(primary['report'])


def main(argv=None):
    """Return stable exit status. Expected failures never emit exception stacks."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8', errors='strict')
    args = _parser().parse_args(argv)
    try:
        return {'inspect':_inspect,'validate-plan':_validate,'extract':_extract,'demo':_demo}[args.command](args)
    except WorkerFailure as error:
        _emit_diagnostics(error.diagnostics)
        return 4 if args.command=='extract' else error.exit_code
    except MappingValidationError as error:
        _emit_diagnostics(error.diagnostics)
        return 3 if str(error) in ('PLAN_INPUT_LIMIT', 'EXPORT_LIMIT', 'TARGET_TRIE_LIMIT', 'TARGET_DEPTH_LIMIT') else 2
    except (ValueError, UnicodeError, RecursionError) as error:
        if str(error) in ('PLAN_INPUT_LIMIT', 'EXPORT_LIMIT'):
            print('计划或导出超出限制', file=sys.stderr)
            return 3
        print('参数、JSON 或命名计划无效', file=sys.stderr)
        return 2
    except OSError:
        print('输入或输出文件访问失败', file=sys.stderr)
        return 2
