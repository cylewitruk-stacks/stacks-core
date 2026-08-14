#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {readFileSync, writeFileSync} from 'node:fs';

function readEvents(path) {
  const contents = readFileSync(path, 'utf8').trim();
  if (!contents) return [];
  if (contents.startsWith('{')) {
    const parsed = JSON.parse(contents);
    return parsed.events ?? [parsed];
  }
  return contents.split('\n').filter(Boolean).map(line => JSON.parse(line));
}

function summarize(events) {
  const kinds = {};
  const campaigns = new Set();
  const actors = new Set();
  let failures = 0;
  for (const event of events) {
    kinds[event.kind] = (kinds[event.kind] ?? 0) + 1;
    if (event.campaign) campaigns.add(event.campaign);
    if (event.actor) actors.add(event.actor);
    if (event.kind === 'invariant.observed' && event.details?.passed !== true) failures += 1;
  }
  return {
    runId: events.at(-1)?.runId ?? 'unknown',
    network: events.at(-1)?.network ?? 'unknown',
    startedAt: events[0]?.occurredAt ?? null,
    finishedAt: events.at(-1)?.occurredAt ?? null,
    eventCount: events.length,
    campaigns: campaigns.size,
    actors: actors.size,
    invariantFailures: failures,
    timelineSha256: createHash('sha256').update(events.map(event => JSON.stringify(event)).join('\n')).digest('hex'),
    kinds,
  };
}

export function renderReport(events) {
  const ordered = [...events].sort((left, right) => (left.sequence ?? 0) - (right.sequence ?? 0));
  const summary = summarize(ordered);
  // Escaping '<' prevents an event payload from closing the script element.
  const data = JSON.stringify({summary, events: ordered}).replaceAll('<', '\\u003c');
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Stacks Attacknet ${summary.runId}</title>
<style>
:root{color-scheme:dark;--bg:#101216;--panel:#191c22;--muted:#9aa3b2;--text:#edf0f5;--line:#303744;--blue:#72a7ff;--red:#ff6577;--green:#58d68d;--orange:#f6b84a}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 ui-sans-serif,system-ui,-apple-system,sans-serif}header{position:sticky;top:0;z-index:2;background:#101216ee;border-bottom:1px solid var(--line);padding:20px 28px;backdrop-filter:blur(8px)}h1{font-size:22px;margin:0 0 4px}header p{color:var(--muted);margin:0}.wrap{max-width:1500px;margin:auto;padding:20px 28px 60px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:18px}.card{background:var(--panel);border:1px solid var(--line);border-radius:9px;padding:13px}.card .value{font-size:25px;font-weight:650}.card .label{color:var(--muted)}.controls{display:flex;gap:10px;flex-wrap:wrap;margin:12px 0 18px}.controls input,.controls select{background:var(--panel);border:1px solid var(--line);border-radius:6px;color:var(--text);padding:8px 10px}.timeline{position:relative;margin-left:14px}.timeline:before{content:"";position:absolute;left:8px;top:8px;bottom:8px;width:2px;background:var(--line)}.event{position:relative;margin:0 0 10px 32px;background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:11px 13px}.event:before{content:"";position:absolute;left:-29px;top:15px;width:10px;height:10px;border-radius:50%;background:var(--blue);border:3px solid var(--bg)}.event[data-kind="fault.injected"]:before{background:var(--orange)}.event[data-kind="invariant.observed"][data-outcome="fail"]:before{background:var(--red)}.event[data-kind="recovery.complete"]:before,.event[data-outcome="pass"]:before{background:var(--green)}.topline{display:flex;gap:9px;align-items:baseline;flex-wrap:wrap}.kind{font-weight:700}.time,.meta{color:var(--muted);font-size:12px}.pill{background:#293244;border-radius:20px;padding:2px 8px;color:#cbd8f4}.details{margin:8px 0 0;white-space:pre-wrap;color:#cdd3dd;font:12px/1.45 ui-monospace,SFMono-Regular,monospace;overflow:auto}.empty{color:var(--muted);padding:30px;text-align:center}.trust{border-left:3px solid var(--blue);padding:10px 14px;background:#172135;margin-bottom:18px;color:#cbd8f4}@media(max-width:700px){header,.wrap{padding-left:14px;padding-right:14px}.event{margin-left:22px}.timeline:before{left:2px}.event:before{left:-26px}}
</style></head><body><header><h1>Stacks Attacknet incident timeline</h1><p id="subtitle"></p></header><main class="wrap"><section class="cards" id="cards"></section><div class="trust">Timeline events are orchestrator-observed and bearer-authenticated at ingestion. Stacks node and signer metrics shown in Grafana are actor-self-reported and must not be treated as authoritative when malicious images are under test.</div><section class="controls"><input id="search" type="search" placeholder="Filter campaign, actor, details…"><select id="kind"><option value="">All event kinds</option></select><select id="phase"><option value="">All phases</option></select></section><section class="timeline" id="timeline"></section></main>
<script>const DATA=${data};const qs=id=>document.getElementById(id);const esc=v=>String(v??'');
qs('subtitle').textContent=DATA.summary.runId+' · '+DATA.summary.network+' · '+(DATA.summary.startedAt??'no events')+' → '+(DATA.summary.finishedAt??'no events');
  const cards=[['Events',DATA.summary.eventCount],['Campaigns',DATA.summary.campaigns],['Actors observed',DATA.summary.actors],['Invariant failures',DATA.summary.invariantFailures]];for(const [label,value] of cards){const node=document.createElement('div');node.className='card';const number=document.createElement('div');number.className='value';number.textContent=value;const caption=document.createElement('div');caption.className='label';caption.textContent=label;node.append(number,caption);qs('cards').append(node)}
for(const [id,values] of [['kind',[...new Set(DATA.events.map(e=>e.kind))]],['phase',[...new Set(DATA.events.map(e=>e.phase))]]])for(const value of values.sort()){const option=document.createElement('option');option.value=value;option.textContent=value;qs(id).append(option)}
function draw(){const query=qs('search').value.toLowerCase(),kind=qs('kind').value,phase=qs('phase').value,timeline=qs('timeline');timeline.replaceChildren();const selected=DATA.events.filter(e=>(!kind||e.kind===kind)&&(!phase||e.phase===phase)&&(!query||JSON.stringify(e).toLowerCase().includes(query)));if(!selected.length){const empty=document.createElement('div');empty.className='empty';empty.textContent='No events match this filter.';timeline.append(empty);return}for(const event of selected){const article=document.createElement('article');article.className='event';article.dataset.kind=event.kind;article.dataset.outcome=event.outcome??(event.details?.passed===true?'pass':event.details?.passed===false?'fail':'');const top=document.createElement('div');top.className='topline';const eventKind=document.createElement('span');eventKind.className='kind';eventKind.textContent='#'+event.sequence+' '+event.kind;const time=document.createElement('span');time.className='time';time.textContent=event.occurredAt;top.append(eventKind,time);for(const value of [event.phase,event.campaign,event.actor,event.instructionId])if(value){const pill=document.createElement('span');pill.className='pill';pill.textContent=value;top.append(pill)}article.append(top);const meta=document.createElement('div');meta.className='meta';meta.textContent='recorded '+event.recordedAt+(event.eventId?' · id '+event.eventId:'');article.append(meta);if(event.details&&Object.keys(event.details).length){const details=document.createElement('pre');details.className='details';details.textContent=JSON.stringify(event.details,null,2);article.append(details)}timeline.append(article)}}
for(const id of ['search','kind','phase'])qs(id).addEventListener('input',draw);draw();</script></body></html>`;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [input, output] = process.argv.slice(2);
  if (!input || !output) throw new Error('usage: report.mjs TIMELINE_JSON_OR_JSONL OUTPUT_HTML');
  const events = readEvents(input);
  writeFileSync(output, renderReport(events));
  writeFileSync(`${output}.summary.json`, `${JSON.stringify(summarize(events), null, 2)}\n`);
  console.log(`Rendered ${events.length} events to ${output}`);
}
