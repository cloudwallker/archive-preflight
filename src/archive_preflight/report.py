"""Single-file offline view of existing engine evidence and editable naming drafts."""
import base64
import hashlib
from html import escape
from pathlib import Path

from .model import ScanLimits,dumps,to_json_value,ExtractLimits


def render_html(report,draft,locale):
    if locale not in ('zh-CN','en') or (report.archive_id,report.profile.profile_id,report.options)!=(draft.archive_id,draft.profile_id,draft.target_options):
        raise ValueError('REPORT_DRAFT_BINDING_INVALID')
    assets=Path(__file__).parent/'assets'
    js=(assets/'report.js').read_text(encoding='utf-8')
    css=(assets/'report.css').read_text(encoding='utf-8')
    digest=lambda text:base64.b64encode(hashlib.sha256(text.encode('utf-8')).digest()).decode('ascii')
    csp="default-src 'none'; script-src 'sha256-"+digest(js)+"'; style-src 'sha256-"+digest(css)+"'; connect-src 'none'; img-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'"
    payload=dumps({'report':report,'draft':draft,'locale':locale,'extractLimits':to_json_value(ExtractLimits())})
    payload=payload.replace('<','\\u003c').replace('>','\\u003e').replace('&','\\u0026')
    title='ZIP 名称审阅' if locale=='zh-CN' else 'ZIP name review'
    html=f'''<!doctype html><html lang="{locale}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="{escape(csp,quote=True)}"><title>{title} · ArchivePreflight</title><style>{css}</style></head><body>
<a class="skip" href="#entries">Skip to entries / 跳到条目</a>
<header><div class="brand">AP / ArchivePreflight</div><div class="offline">OFFLINE · LOCAL</div></header>
<main><section class="intro"><p class="eyebrow">ZIP PORTABILITY / 名称可移植性</p><h1>{title}</h1><p id="subtitle"></p></section>
<section id="summary" class="summary" aria-label="Report summary"></section>
<section class="panel"><h2 id="policy-title"></h2><div id="policy"></div><details><summary id="runtime-title"></summary><pre id="runtime"></pre></details></section>
<section class="panel"><h2 id="groups-title"></h2><div id="groups"></div></section>
<section class="panel editor"><h2 id="draft-title"></h2><p id="draft-warning"></p><button id="export" type="button"></button><p id="edit-status" role="status" aria-live="polite"></p><details><summary id="directories-title"></summary><div id="directories"></div></details></section>
<section class="panel"><h2 id="entries-title"></h2><div class="filters"><label><span id="search-label"></span><input id="search" type="search"></label><label><span id="risk-label"></span><select id="risk"></select></label><label><span id="type-label"></span><select id="kind"></select></label><label><span id="collision-label"></span><select id="collision"></select></label></div><p id="count" role="status"></p><div id="entries" tabindex="-1"></div><div class="pager"><button id="previous" type="button"></button><button id="next" type="button"></button></div></section>
<footer>ArchivePreflight 0.1.0 · 原创合成或本地归档 / Local archive evidence · validate-plan</footer></main>
<script id="report-data" type="application/json">{payload}</script><script>{js}</script></body></html>'''
    if len(html.encode('utf-8'))>ScanLimits().export_bytes:
        raise ValueError('EXPORT_LIMIT')
    return html
