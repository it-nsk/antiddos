async function loadPanel() {
  configState = await requestAPI('config');
  initSources(uiSources());
  initActions();
  initRules(uiRules(), uiSources());
  const blocks = [], frames = [], incidents = [], logFrames = [], records = {};
  const names = configState.config.rules.map(r=>r.id);
  const palette = ['#d78c34','#10828f','#9370b5','#4385f5'];
  const rules = names.map((name,index)=>({name,color:palette[index%palette.length]}));
  const sources = configState.config.sources.map(s=>s.id);
  const renderBlocks = initBlocks(blocks);
  const range = initIncidents({snapshot:Date.now(),rules,frames},incidents);
  initLogs({sources,frames:logFrames},records,range);
  let sequence = 0, controllerBusy = false;
  async function refresh() {
    const seq = ++sequence;
    const [start,end] = range.current();
    const query = new URLSearchParams({from:String(Math.floor(start/1000)),to:String(Math.ceil(end/1000))});
    try {
      const data = await requestAPI('dashboard?'+query);
      if(seq !== sequence) return;
      if ((data.from * 1000 !== Math.floor(start / 1000) * 1000 || data.to * 1000 !== Math.ceil(end / 1000) * 1000) && range.set) {
        range.set(data.from * 1000, data.to * 1000);
        return;
      }
      const detections = [...(data.detections || [])];
      let cursor = data.next_before;
      // A historical range can contain hundreds of thousands of detections.
      // Do not turn every refresh into hundreds of serial socket requests.
      const journalPages = end - start > 24 * 60 * 60 * 1000 ? 0 : 4;
      for(let page=0;cursor && page<journalPages;page++) {
        const next = await requestAPI('dashboard?'+query+'&before='+cursor);
        if(seq !== sequence) return;
        detections.push(...(next.detections || []));
        if(cursor === next.next_before) break;
        cursor = next.next_before;
      }
      const byTime = new Map();
      for(const point of data.rule_points || []) {
        const i = names.indexOf(point.rule);
        if(i < 0) continue;
        if(!byTime.has(point.time)) byTime.set(point.time,{time:point.time*1000,counts:names.map(()=>0)});
        byTime.get(point.time).counts[i] += point.count;
      }
      frames.splice(0,frames.length,...byTime.values());
      const traffic = new Map();
      for(const source of data.source_points || []) {
        const i=sources.indexOf(source.source_id);
        if(i<0) continue;
        for(const point of source.points || []) {
          if(!traffic.has(point.time)) traffic.set(point.time,{time:point.time*1000,counts:sources.map(()=>0),responseSizes:sources.map(()=>0)});
          traffic.get(point.time).counts[i]=point.requests;
          traffic.get(point.time).responseSizes[i]=point.bytes;
        }
      }
      logFrames.splice(0,logFrames.length,...traffic.values());
      blocks.splice(0,blocks.length,...(data.blocks || []));
      incidents.splice(0,incidents.length,...detections.map(d=>({start:Date.parse(d.event_time),rule:{name:d.rule},hits:1,
        ips:d.ip?[d.ip]:[],requests:d.count,blocked:null,delay:null})));
      for(const source of sources) records[source]=[];
      for(const d of detections) {
        (records[d.source_id] ||= []).push({id:d.id,time:Date.parse(d.event_time),ip:d.ip,method:d.method,status:d.status,
          path:d.path+(d.raw_query?'?'+d.raw_query:''),summary:d.reason || d.raw_event,raw:d.raw_event});
      }
      renderBlocks();
      document.dispatchEvent(new Event('logban-data'));
    } catch(error) { if(seq === sequence) showBackendStatus(error.message); }
  }
  document.addEventListener('logban-range',refresh);
  await refresh();
  setInterval(async()=>{
    if(document.hidden || controllerBusy) return;
    const [start, end] = range.current();
    if(end - start > 24 * 60 * 60 * 1000) return;
    controllerBusy=true;
    try { range.advance(0,Date.now());await refresh(); }
    finally { controllerBusy=false; }
  },10000);
  if(configState.restart_required) showBackendStatus('Настройки сохранены. Перезапустите antiddos для применения.');
}
