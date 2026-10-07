'use strict';
(() => {
  const payload=JSON.parse(document.getElementById('report-data').textContent);
  const report=payload.report,draft=payload.draft,zh=payload.locale==='zh-CN';
  const t=(cn,en)=>zh?cn:en;
  const visible=value=>String(value??'').replace(/[\x00-\x1f\x7f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069\u2028\u2029]/g,c=>'\\u'+c.charCodeAt(0).toString(16).padStart(4,'0'));
  const node=(tag,text)=>{const e=document.createElement(tag);if(text!==undefined)e.textContent=visible(text);return e;};
  const jsonBox=value=>{const e=document.createElement('pre');e.textContent=JSON.stringify(value,null,2).replace(/[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g,c=>'\\u'+c.charCodeAt(0).toString(16).padStart(4,'0'));return e;};
  const el=id=>document.getElementById(id);
  const text=(id,cn,en)=>el(id).textContent=t(cn,en);
  text('subtitle','审阅原始名称、编码证据和目标映射，再导出草稿进行完整重验。正文及局部头尚未验证。','Review original names, encoding evidence and target mappings. Export a draft for full revalidation. Content and local headers are unverified.');
  text('policy-title','目标配置与预算','Target policy and budgets');text('runtime-title','运行环境与资源上限','Runtime and resource limits');
  text('groups-title','冲突原因与成员定位','Collision reasons and member navigation');text('draft-title','名称映射草稿','Naming draft');
  text('draft-warning','编辑与导出只产生 draft；运行 validate-plan 完整重验后，使用新的 planId 接受提取。选择编码可能改变目录节点身份，需要重新审阅目录映射。','Editing and exporting produce a draft. Run validate-plan for full revalidation, then accept the new planId. Encoding choices may change directory identities; review directory mappings again.');
  text('export','导出草稿 JSON','Export draft JSON');text('directories-title','目录映射（展开后可编辑）','Directory mappings (expand to edit)');text('entries-title','归档条目','Archive entries');
  text('search-label','搜索名称、ID 或诊断','Search name, ID or diagnostic');text('risk-label','风险','Risk');text('type-label','类型','Type');text('collision-label','碰撞','Collision');text('previous','上一页','Previous');text('next','下一页','Next');
  const metric=(label,value)=>{const box=node('div');box.className='metric';box.append(node('strong',value),node('span',label));el('summary').append(box);};
  metric(t('状态','State'),report.state);metric(t('条目','Entries'),report.entries.length);metric(t('碰撞组','Collision groups'),report.collisionGroups.length);metric(t('正文验证','Content verification'),t('尚未验证','Unverified'));
  el('policy').append(node('p',report.profile.profileId+' · '+report.profile.version),node('p',t('比较依据：','Comparison basis: ')+report.profile.rules.map(r=>r.join(' / ')).join('; ')),node('p',t('配置规则、近似与提示分别标注；宿主提取须通过原生校验。','Configuration rules, approximations and advisories are labeled separately. Extraction requires native host checks.')),
    node('p',t('目标根计量：','Target root units: ')+report.options.rootUnits+' · '+report.profile.units+' · '+t('组件/路径上限：','Component/path limits: ')+(report.options.componentLimit??report.profile.componentLimit)+' / '+(report.options.pathLimit??report.profile.pathLimit)));
  el('runtime').textContent=JSON.stringify({runtime:report.runtime,scanLimits:report.limits,extractionLimits:payload.extractLimits,contentVerified:report.contentVerified,localHeadersVerified:report.localHeadersVerified},null,2);
  const engineEvidence=node('details');engineEvidence.append(node('summary',t('引擎变换原因与整体诊断','Engine transformation reasons and archive diagnostics')),jsonBox({transformations:report.transformations,diagnostics:report.diagnostics.filter(d=>!d.entryIds.length)}));el('policy').append(engineEvidence);
  const decisions=new Map(draft.decisions.map(d=>[d.entryId,d]));let page=0;
  const dirty=()=>{el('edit-status').textContent=t('已修改 · 草稿尚未重验','Modified · draft not revalidated');};
  const select=(choices,value,onchange)=>{const s=node('select');for(const [v,label] of choices){const o=node('option',label);o.value=v;s.append(o);}s.value=value;s.addEventListener('change',()=>onchange(s.value));return s;};
  const field=(label,control)=>{const l=node('label');l.append(node('span',label),control);return l;};
  const groupsByEntry=new Map();
  for(const group of report.collisionGroups){
    const box=node('div');box.className='group';box.append(node('h3',group.ruleId+' · '+group.certainty),node('p',t('不同组件索引：','Different component index: ')+group.firstDifferentComponent+' · '+group.impact),jsonBox({originalKeys:group.originalKeys,comparisonKey:group.comparisonKey,nodeIds:group.nodeIds}));
    for(const id of group.entryIds){if(!groupsByEntry.has(id))groupsByEntry.set(id,[]);groupsByEntry.get(id).push(group.groupId);const b=node('button',id);b.type='button';b.addEventListener('click',()=>{el('search').value=id;el('risk').value='all';el('kind').value='all';el('collision').value='all';page=0;render();el('entries').focus();});box.append(b);}el('groups').append(box);
  }
  if(!report.collisionGroups.length)el('groups').append(node('p',t('当前配置无碰撞组','No collision groups for this policy')));
  for(const mapping of draft.directoryMappings){const input=node('input');input.value=mapping.targetPath;input.addEventListener('input',()=>{mapping.targetPath=input.value;dirty();});const row=field(mapping.nodeId,input);row.className='directory';el('directories').append(row);}
  const options=(id,choices)=>{for(const [v,label] of choices){const o=node('option',label);o.value=v;el(id).append(o);}el(id).addEventListener('change',()=>{page=0;render();});};
  options('risk',[['all',t('全部','All')],['findings',t('有诊断','With diagnostics')],['blocked',t('安全阻断','Blocked')],['nonstandard',t('非标准','Nonstandard')]]);
  options('kind',[['all',t('全部','All')],...['file','directory','symlink','special','contradictory'].map(v=>[v,v])]);
  options('collision',[['all',t('全部','All')],['yes',t('有碰撞','In collision')],['no',t('无碰撞','No collision')]]);
  const showEvidence=(entry,box)=>{
    const raw=entry.raw,bytes=Uint8Array.from(atob(raw.rawNameBase64),c=>c.charCodeAt(0));
    const evidence=node('div');evidence.className='evidence';
    const rawBox=node('div');rawBox.append(node('h3',t('原始字节与长度','Raw bytes and lengths')),jsonBox({hex:Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join(' '),base64:raw.rawNameBase64,flags:raw.flags,method:raw.method,declaredBytes:raw.declaredBytes,compressedBytes:raw.compressedBytes,componentUnits:entry.componentUnits,pathUnits:entry.pathUnits}));
    const candidates=node('div');candidates.append(node('h3',t('候选及证据','Candidates and evidence')));
    for(const c of entry.candidates)candidates.append(jsonBox(c));
    evidence.append(rawBox,candidates);box.append(evidence);
  };
  const render=()=>{
    const q=el('search').value.toLowerCase(),risk=el('risk').value,kind=el('kind').value,collision=el('collision').value;
    const entries=report.entries.filter(e=>{const d=decisions.get(e.entryId),has=groupsByEntry.has(e.entryId);return (!q||[e.entryId,e.defaultDisplayName,d?.targetPath,...e.diagnosticIds].join(' ').toLowerCase().includes(q))&&(risk==='all'||risk==='findings'&&e.diagnosticIds.length||risk===e.nameState)&&(kind==='all'||kind===e.entryType)&&(collision==='all'||collision==='yes'&&has||collision==='no'&&!has);});
    const pageSize=50,first=page*pageSize;el('entries').replaceChildren();
    el('count').textContent=t('匹配 ','Matches ')+entries.length+' · '+t('显示 ','Showing ')+(entries.length?first+1:0)+'–'+Math.min(first+pageSize,entries.length);
    for(const entry of entries.slice(first,first+pageSize)){
      const d=decisions.get(entry.entryId),box=node('article');box.className='entry';box.id=entry.entryId;
      const heading=node('div');heading.className='entry-head';heading.append(node('h3',entry.entryId+' / '+(entry.defaultDisplayName??t('无法解码','Undecodable'))));const tag=node('span',entry.nameState+' · '+entry.entryType);tag.className='tag';heading.append(tag);box.append(heading,node('p',entry.diagnosticIds.join(' · ')));
      if(d){const controls=node('div');controls.className='entry-controls';const input=node('input');input.value=d.targetPath??'';input.disabled=d.action==='skip';
        const action=select(['keep','rename','skip'].map(v=>[v,v]),d.action,v=>{d.action=v;d.targetPath=v==='skip'?null:input.value;input.disabled=v==='skip';dirty();});
        input.addEventListener('input',()=>{d.targetPath=input.value;d.action='rename';action.value='rename';dirty();});
        controls.append(field(t('动作','Action'),action),field(t('目标相对路径','Relative target path'),input));box.append(controls);
        const candidate=select([['',t('未选择','No selection')],...entry.candidates.filter(c=>c.valid&&c.text!==null).map(c=>[c.candidateId,c.source+' · '+visible(c.text)])],d.encodingCandidateId??'',v=>{d.encodingCandidateId=v||null;d.nameConfirmed=!!v;confirmed.checked=d.nameConfirmed;dirty();});box.append(field(t('编码候选（引擎提供）','Encoding candidate (engine evidence)'),candidate));
        const confirmed=node('input');confirmed.type='checkbox';confirmed.checked=d.nameConfirmed;confirmed.addEventListener('change',()=>{d.nameConfirmed=confirmed.checked;dirty();});box.append(field(t('确认名称解释','Confirm name interpretation'),confirmed));
      }
      const details=node('details');details.append(node('summary',t('展开原始字节、候选与诊断','Expand raw bytes, candidates and diagnostics')));showEvidence(entry,details);
      details.append(jsonBox(report.diagnostics.filter(d=>d.entryIds.includes(entry.entryId))));box.append(details);el('entries').append(box);
    }
    el('previous').disabled=page===0;el('next').disabled=first+pageSize>=entries.length;
  };
  el('search').addEventListener('input',()=>{page=0;render();});el('previous').addEventListener('click',()=>{page--;render();});el('next').addEventListener('click',()=>{page++;render();});
  el('export').addEventListener('click',()=>{
    const data=JSON.stringify(draft,null,2),blob=new Blob([data+'\n'],{type:'application/json'});
    if(blob.size>Number(report.limits.planBytes)){el('edit-status').textContent=t('草稿超出计划字节上限','Draft exceeds the plan byte limit');return;}
    const url=URL.createObjectURL(blob),a=node('a');a.href=url;a.download='archive-preflight-draft.json';document.body.append(a);a.click();a.remove();URL.revokeObjectURL(url);el('edit-status').textContent=t('已导出 draft · 请运行 validate-plan','Draft exported · run validate-plan');
  });
  render();
})();
