const fs    = require('fs');
const sharp = require('sharp');
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  Header, Footer, AlignmentType, BorderStyle, WidthType, ShadingType,
  VerticalAlign, PageBreak, TabStopType, TabStopPosition,
} = require('docx');

const payload  = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const data     = payload.report;
const sections = payload.sections;
const rangeFrom= payload.range_from ? new Date(payload.range_from) : null;
const rangeTo  = payload.range_to   ? new Date(payload.range_to)   : null;
const outPath  = process.argv[3];

const G = {
  GREEN:"00FF41", BLACK:"000000", WHITE:"FFFFFF", AMBER:"FFAA00",
  RED:"FF4141", DIM:"888888", G2:"1A1A1A", G4:"2A2A2A", G5:"333333",
};

// ── device icons (base64) ─────────────────────────────────────
const ICON_DIR = '/app/icons';
function loadIcon(name) {
  try { return fs.readFileSync(`${ICON_DIR}/${name}`).toString('base64'); }
  catch(e) { return null; }
}
const ICONS = {
  FIREWALL:   loadIcon('firewall.png'),
  ROUTER:     loadIcon('router.png'),
  SWITCH:     loadIcon('switch.png'),
  WORKSTATION:loadIcon('desktop.png'),
  LAPTOP:     loadIcon('laptop.png'),
  'VIRTUAL MACHINE (VM)': loadIcon('vm.png'),
  DEFAULT:    loadIcon('desktop.png'),
};
function iconFor(type) {
  const u = (type || '').toUpperCase();
  return ICONS[u] || ICONS.DEFAULT;
}

const bdr  = { style: BorderStyle.SINGLE, size: 1, color: G.G5 };
const bdrs = { top: bdr, bottom: bdr, left: bdr, right: bdr };

function cell(text, { bold=false, color=G.WHITE, bg=G.G5, width=2000,
                       align=AlignmentType.LEFT, size=18 }={}) {
  return new TableCell({
    borders: bdrs, width: { size: width, type: WidthType.DXA },
    shading: { fill: bg, type: ShadingType.CLEAR },
    margins: { top: 80, bottom: 80, left: 120, right: 120 },
    verticalAlign: VerticalAlign.CENTER,
    children: [new Paragraph({
      alignment: align,
      children: [new TextRun({ text: String(text??'—'), bold, color, font:"Courier New", size })],
    })],
  });
}
function hdr(text, opts={}) { return cell(text, { bold:true, color:G.GREEN, bg:G.G2, ...opts }); }

function para(text, { bold=false, color=G.WHITE, size=20, before=0, after=120 }={}) {
  return new Paragraph({
    spacing: { before, after },
    children: [new TextRun({ text: String(text??''), bold, color, font:"Courier New", size })],
  });
}
function sHead(text) {
  return new Paragraph({
    spacing: { before: 400, after: 180 },
    border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: G.GREEN, space: 2 } },
    children: [new TextRun({ text: text.toUpperCase(), bold:true, color:G.GREEN, font:"Courier New", size:28 })],
  });
}
function divider() {
  return new Paragraph({
    spacing: { before:60, after:60 },
    border: { bottom: { style: BorderStyle.SINGLE, size:1, color:"333333", space:1 } },
    children: [],
  });
}
function verdictBg(v) {
  const u=(v||'').toUpperCase();
  if(u==='MALICIOUS') return '3A0000';
  if(u==='NON_MALICIOUS') return '003318';
  return G.G5;
}
function verdictColor(v) {
  const u=(v||'').toUpperCase();
  if(u==='MALICIOUS') return G.RED;
  if(u==='NON_MALICIOUS') return G.GREEN;
  return G.DIM;
}
function sLabel(s) {
  return {CLOSED:'Closed',PENDING_REVIEW:'Pending Review',
          IN_PROGRESS:'In Progress',UNCLAIMED:'Unclaimed'}[(s||'').toUpperCase()]||s||'—';
}
function fmt(n) { return (n??0).toLocaleString(); }
function pct(a,b) { return b ? ((a/b)*100).toFixed(1)+'%' : '0%'; }

// ── cover ─────────────────────────────────────────────────────
function cover() {
  const gen = data.generated_at ? new Date(data.generated_at).toUTCString() : new Date().toUTCString();
  return [
    new Paragraph({ spacing:{before:2160,after:120}, children:[
      new TextRun({ text:"ORCA DFIR PLATFORM", bold:true, color:G.GREEN, font:"Courier New", size:64 })]}),
    new Paragraph({ spacing:{after:80}, children:[
      new TextRun({ text:"INVESTIGATION REPORT", bold:true, color:G.WHITE, font:"Courier New", size:40 })]}),
    divider(), para(''),
    new Paragraph({ spacing:{after:80}, children:[
      new TextRun({text:"CASE:            ",color:G.DIM,font:"Courier New",size:24}),
      new TextRun({text:(data.case_name||'').toUpperCase(),bold:true,color:G.WHITE,font:"Courier New",size:24})]}),
    new Paragraph({ spacing:{after:80}, children:[
      new TextRun({text:"FOCUS COUNTRY:   ",color:G.DIM,font:"Courier New",size:24}),
      new TextRun({text:(data.focus_country||'UNKNOWN').toUpperCase(),bold:true,color:G.AMBER,font:"Courier New",size:24})]}),
    new Paragraph({ spacing:{after:80}, children:[
      new TextRun({text:"GENERATED:       ",color:G.DIM,font:"Courier New",size:24}),
      new TextRun({text:gen,color:G.WHITE,font:"Courier New",size:24})]}),
    new Paragraph({ spacing:{after:80}, children:[
      new TextRun({text:"CLASSIFICATION:  ",color:G.DIM,font:"Courier New",size:24}),
      new TextRun({text:"CONFIDENTIAL",bold:true,color:G.RED,font:"Courier New",size:24})]}),
    para(''), divider(),
    new Paragraph({ children:[new PageBreak()] }),
  ];
}

// ── summary ───────────────────────────────────────────────────
function renderSummary() {
  const s=data.summary||{};
  const cw=3120;
  const tiles=[
    {l:"TOTAL TECHNIQUES",v:fmt(s.total_techniques)},
    {l:"CLOSED",v:fmt(s.closed)},
    {l:"WITH EVIDENCE",v:fmt(s.with_evidence)},
    {l:"NO ARTIFACTS",v:fmt(s.no_artifacts),c:G.DIM},
    {l:"PENDING",v:fmt(s.pending),c:G.AMBER},
    {l:"COMPLETION",v:pct(s.closed,s.total_techniques)},
    {l:"MALICIOUS",v:fmt(s.malicious),c:G.RED},
    {l:"NON-MALICIOUS",v:fmt(s.non_malicious),c:G.GREEN},
    {l:"EVIDENCE FOUND",v:fmt(s.evidence_found||0),c:"aa44ff"},
    {l:"NO ARTIFACTS",v:fmt(s.no_artifacts),c:G.DIM},
    {l:"PENDING",v:fmt(s.pending),c:G.AMBER},
  ];
  const rows=[];
  for(let i=0;i<tiles.length;i+=3){
    const sl=tiles.slice(i,i+3);
    while(sl.length<3) sl.push({l:'',v:''});
    rows.push(new TableRow({children:sl.map(t=>new TableCell({
      borders:bdrs,width:{size:cw,type:WidthType.DXA},
      shading:{fill:G.G2,type:ShadingType.CLEAR},
      margins:{top:140,bottom:140,left:200,right:200},
      children:[
        new Paragraph({spacing:{after:40},children:[new TextRun({text:t.l,color:G.DIM,font:"Courier New",size:16})]}),
        new Paragraph({children:[new TextRun({text:String(t.v??'—'),bold:true,color:t.c||G.WHITE,font:"Courier New",size:40})]}),
      ],
    }))}));
  }
  return [sHead("Investigation Summary"),
    new Table({width:{size:9360,type:WidthType.DXA},columnWidths:[cw,cw,cw],rows}),
    para('')];
}

// ── daily ─────────────────────────────────────────────────────
function renderDaily(detail) {
  const out=[sHead("Daily Update")];
  if(!rangeFrom||!rangeTo){out.push(para("No date range specified.",{color:G.DIM}));return out;}
  const rf=rangeFrom.getTime(),rt=rangeTo.getTime();
  out.push(new Paragraph({spacing:{after:80},children:[
    new TextRun({text:`PERIOD: ${rangeFrom.toUTCString()}  \u2192  ${rangeTo.toUTCString()}`,color:G.AMBER,font:"Courier New",size:18}),
  ]}));
  const closed=(data.techniques||[]).filter(t=>{
    const v=(t.verdict||'').toUpperCase();
    if(!v||v==='UNDETERMINED')return false;
    if(t.closed_at){const ts=new Date(t.closed_at).getTime();return ts>=rf&&ts<=rt;}
    return true;
  });
  const notes=(data.timeline||[]).filter(n=>{
    const ts=new Date(n.created_at).getTime();return ts>=rf&&ts<=rt;
  });
  const malCount=closed.filter(t=>(t.verdict||'').toUpperCase()==='MALICIOUS').length;
  const cw=3120;
  const hTiles=[
    {l:"TECHNIQUES CLOSED",v:fmt(closed.length),c:G.WHITE},
    {l:"ANALYST ENTRIES",v:fmt(notes.length),c:G.AMBER},
    {l:"MALICIOUS FINDS",v:fmt(malCount),c:malCount>0?G.RED:G.DIM},
  ];
  out.push(new Table({width:{size:9360,type:WidthType.DXA},columnWidths:[cw,cw,cw],rows:[
    new TableRow({children:hTiles.map(t=>new TableCell({
      borders:bdrs,width:{size:cw,type:WidthType.DXA},
      shading:{fill:G.G2,type:ShadingType.CLEAR},
      margins:{top:140,bottom:140,left:200,right:200},
      children:[
        new Paragraph({spacing:{after:40},children:[new TextRun({text:t.l,color:G.DIM,font:"Courier New",size:16})]}),
        new Paragraph({children:[new TextRun({text:t.v,bold:true,color:t.c,font:"Courier New",size:40})]}),
      ],
    }))}),
  ]}));
  out.push(para(''));
  // per-asset breakdown
  const byAsset={};
  for(const t of closed){
    const aid=t.asset_id||'unknown';
    if(!byAsset[aid]) byAsset[aid]={hostname:t.hostname||String(aid),closed:0,mal:0,nonmal:0};
    byAsset[aid].closed++;
    if((t.verdict||'').toUpperCase()==='MALICIOUS') byAsset[aid].mal++;
    if((t.verdict||'').toUpperCase()==='NON-MALICIOUS') byAsset[aid].nonmal++;
  }
  const arows=Object.values(byAsset);
  if(arows.length){
    const cols=[3000,2000,2180,2180];
    out.push(new Table({width:{size:9360,type:WidthType.DXA},columnWidths:cols,rows:[
      new TableRow({tableHeader:true,children:[hdr("ASSET",{width:cols[0]}),hdr("CLOSED",{width:cols[1]}),hdr("MALICIOUS",{width:cols[2]}),hdr("NON-MALICIOUS",{width:cols[3]})]}),
      ...arows.map((a,i)=>{const bg=i%2?G.G4:G.G5;return new TableRow({children:[
        cell(a.hostname,{bg,width:cols[0]}),cell(a.closed,{bg,width:cols[1],color:G.GREEN}),
        cell(a.mal,{bg,width:cols[2],color:a.mal>0?G.RED:G.DIM}),cell(a.nonmal,{bg,width:cols[3],color:G.GREEN}),
      ]});}),
    ]}));
    out.push(para(''));
  }
  if(detail&&notes.length){
    out.push(new Paragraph({spacing:{before:160,after:80},children:[new TextRun({text:"ANALYST NOTES IN RANGE",bold:true,color:G.AMBER,font:"Courier New",size:20})]}));
    for(const n of notes){
      const init=(n.initials||n.author||'??').toUpperCase();
      out.push(new Paragraph({spacing:{before:100,after:40},children:[
        new TextRun({text:`[${init}]  [${n.t_code||'CASE'}]  ${new Date(n.created_at).toUTCString()}`,bold:true,color:G.AMBER,font:"Courier New",size:18}),
      ]}));
      out.push(para(n.text,{size:20,after:80}));
      out.push(divider());
    }
  }
  return out;
}

// ── assets ────────────────────────────────────────────────────
function renderAssets() {
  const out=[sHead("Asset Breakdown")];
  const s=data.summary||{};
  for(const asset of (data.assets||[])){
    const techs=(data.techniques||[]).filter(t=>t.asset_id===asset.id);
    const closed=techs.filter(t=>{const v=(t.verdict||'').toUpperCase();return v&&v!=='UNDETERMINED';}).length;
    const mal=techs.filter(t=>(t.verdict||'').toUpperCase()==='MALICIOUS').length;
    const total=techs.length||s.total_techniques||1;
    out.push(new Paragraph({spacing:{before:160,after:60},children:[
      new TextRun({text:asset.hostname,bold:true,color:G.GREEN,font:"Courier New",size:24}),
      new TextRun({text:`  ${asset.os}  \u00B7  ${asset.asset_type}  \u00B7  ${asset.analysis_mode}`,color:G.DIM,font:"Courier New",size:18}),
    ]}));
    const cols=[3000,2000,2180,2180];
    out.push(new Table({width:{size:9360,type:WidthType.DXA},columnWidths:cols,rows:[
      new TableRow({children:[
        cell(`${closed} / ${total} CLOSED`,{bg:G.G2,width:cols[0],color:G.GREEN}),
        cell(pct(closed,total),{bg:G.G2,width:cols[1],color:G.GREEN}),
        cell(`${mal} MALICIOUS`,{bg:G.G2,width:cols[2],color:mal>0?G.RED:G.DIM}),
        cell(`${total-closed} REMAINING`,{bg:G.G2,width:cols[3],color:G.AMBER}),
      ]}),
    ]}));
    out.push(para(''));
  }
  return out;
}

// ── BLUF ──────────────────────────────────────────────────────
function renderBluf() {
  const out=[sHead("Executive Summary (BLUF)")];
  const notes=data.bluf_notes||[];
  if(!notes.length){out.push(para("No BLUF notes recorded.",{color:G.DIM}));return out;}
  for(const n of notes){
    out.push(new Paragraph({spacing:{before:160,after:60},children:[
      new TextRun({text:`[${(n.author||'ANALYST').toUpperCase()}]  ${n.created_at?new Date(n.created_at).toUTCString():''}`,bold:true,color:G.AMBER,font:"Courier New",size:18}),
    ]}));
    out.push(para(n.text,{size:20,after:80}));
    out.push(divider());
  }
  return out;
}

// ── timeline ─────────────────────────────────────────────────
function renderTimeline(detail) {
  const out=[sHead("Analyst Timeline")];
  const entries=data.timeline||[];
  if(!entries.length){out.push(para("No timeline entries.",{color:G.DIM}));return out;}
  if(!detail){
    const cols=[2200,900,1200,5060];
    out.push(new Table({width:{size:9360,type:WidthType.DXA},columnWidths:cols,rows:[
      new TableRow({tableHeader:true,children:[hdr("TIMESTAMP",{width:cols[0]}),hdr("BY",{width:cols[1]}),hdr("T-CODE",{width:cols[2]}),hdr("NOTE",{width:cols[3]})]}),
      ...entries.map((e,i)=>{const bg=i%2?G.G4:G.G5;return new TableRow({children:[
        cell(e.created_at?new Date(e.created_at).toUTCString():'',{bg,width:cols[0],size:14}),
        cell((e.initials||'??').toUpperCase(),{bg,width:cols[1],color:G.GREEN}),
        cell(e.t_code||'CASE',{bg,width:cols[2],color:G.AMBER}),
        cell(e.text,{bg,width:cols[3]}),
      ]});}),
    ]}));
  } else {
    for(const e of entries){
      const init=(e.initials||e.author||'??').toUpperCase();
      out.push(new Paragraph({spacing:{before:140,after:40},children:[
        new TextRun({text:`[${init}]  [${e.t_code||'CASE'}]  ${e.created_at?new Date(e.created_at).toUTCString():''}`,bold:true,color:G.GREEN,font:"Courier New",size:18}),
      ]}));
      out.push(para(e.text,{size:20,after:80}));
      out.push(divider());
    }
  }
  return out;
}

// ── verdicts ──────────────────────────────────────────────────
function renderVerdicts() {
  const cols=[1440,3360,1440,1680,940];
  const out=[sHead("Technique Verdicts")];
  out.push(new Table({width:{size:9360,type:WidthType.DXA},columnWidths:cols,rows:[
    new TableRow({tableHeader:true,children:[
      hdr("T-CODE",{width:cols[0]}),hdr("TECHNIQUE",{width:cols[1]}),
      hdr("VERDICT",{width:cols[2]}),hdr("STATUS",{width:cols[3]}),hdr("EVID.",{width:cols[4]}),
    ]}),
    ...(data.techniques||[]).map(t=>{
      const bg=verdictBg(t.verdict),vc=verdictColor(t.verdict);
      return new TableRow({children:[
        cell(t.t_code,{bg,width:cols[0],color:G.GREEN,bold:true}),
        cell(t.technique_name,{bg,width:cols[1]}),
        cell(t.verdict||'\u2014',{bg,width:cols[2],color:vc,bold:true}),
        cell(sLabel(t.technique_status),{bg,width:cols[3],color:G.DIM}),
        cell(t.evidence_imported?'\u2713':'\u2014',{bg,width:cols[4],color:t.evidence_imported?G.GREEN:G.DIM,align:AlignmentType.CENTER}),
      ]});
    }),
  ]}));
  out.push(para(''));
  return out;
}

// ── header/footer ─────────────────────────────────────────────
const docHeader={default:new Header({children:[new Paragraph({
  border:{bottom:{style:BorderStyle.SINGLE,size:4,color:G.GREEN,space:2}},
  spacing:{after:100},
  children:[
    new TextRun({text:"ORCA DFIR",bold:true,color:G.GREEN,font:"Courier New",size:20}),
    new TextRun({text:"  //  INVESTIGATION REPORT  //  ",color:G.DIM,font:"Courier New",size:20}),
    new TextRun({text:(data.case_name||'').toUpperCase(),bold:true,color:G.WHITE,font:"Courier New",size:20}),
  ],
})]})};

const docFooter={default:new Footer({children:[new Paragraph({
  border:{top:{style:BorderStyle.SINGLE,size:2,color:"333333",space:2}},
  spacing:{before:80},
  tabStops:[{type:TabStopType.RIGHT,position:TabStopPosition.MAX}],
  children:[
    new TextRun({text:"CONFIDENTIAL \u2014 AUTHORIZED USE ONLY",color:G.DIM,font:"Courier New",size:16}),
    new TextRun({text:"\t",font:"Courier New",size:16}),
  ],
})]})};

// ── assemble ─────────────────────────────────────────────────

// ── network map ───────────────────────────────────────────────
function buildNetworkSVG(nodes, links){
  const W=900, NODE_W=170, NODE_H=76;
  const ICON=36, ICON_X=6, ICON_Y=20, TEXT_X=50;
  const H=Math.max(440, Math.ceil(nodes.length/4)*(NODE_H+80)+80);
  const positioned=nodes.map((n,i)=>({...n,
    px:n.x||(60+(i%4)*(NODE_W+40)),
    py:n.y||(60+Math.floor(i/4)*(NODE_H+70)),
  }));
  const xs=positioned.map(n=>n.px),ys=positioned.map(n=>n.py);
  const minX=Math.min(...xs),maxX=Math.max(...xs);
  const minY=Math.min(...ys),maxY=Math.max(...ys);
  const scaleX=maxX>minX?(W-NODE_W-60)/(maxX-minX):1;
  const scaleY=maxY>minY?(H-NODE_H-80)/(maxY-minY):1;
  const scaled=positioned.map(n=>({...n,
    sx:30+(n.px-minX)*scaleX,
    sy:40+(n.py-minY)*scaleY,
  }));
  const byId={};
  scaled.forEach(n=>{byId[n.hostname]=n;if(n.id)byId[n.id]=n;});
  const osCol=os=>{
    const l=(os||'').toLowerCase();
    if(l.includes('windows'))return'#4fa3e0';
    if(l.includes('linux'))return'#00ff41';
    if(l.includes('firmware')||l.includes('network'))return'#ff8800';
    return'#ffaa00';
  };
  const parts=[
    `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}">`,
    `<rect width="${W}" height="${H}" fill="#050505"/>`,
    `<defs>`,
    `  <filter id="grn" color-interpolation-filters="sRGB">`,
    `    <feColorMatrix type="matrix" values="0 0 0 0 0  0 0 0 0 0.8  0 0 0 0 0.25  0 0 0 0 1"/>`,
    `    <feComposite in2="SourceGraphic" operator="in"/>`,
    `  </filter>`,
    `</defs>`,
  ];
  for(const lnk of links){
    const src=byId[lnk.source]||byId[lnk.source_id];
    const tgt=byId[lnk.target]||byId[lnk.target_id];
    if(!src||!tgt)continue;
    const x1=src.sx+NODE_W/2,y1=src.sy+NODE_H/2,x2=tgt.sx+NODE_W/2,y2=tgt.sy+NODE_H/2;
    const dash=lnk.link_type==='VPN'?'stroke-dasharray="8,4"':lnk.link_type==='WIRELESS'?'stroke-dasharray="3,3"':'';
    const lCol=lnk.link_type==='VPN'?'#9b59ff':lnk.link_type==='WIRELESS'?'#00aaff':'#333';
    parts.push(`<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="${lCol}" stroke-width="1.5" ${dash}/>`);
    parts.push(`<text x="${(x1+x2)/2}" y="${(y1+y2)/2-4}" fill="#555" font-size="9" font-family="Courier New" text-anchor="middle">${lnk.link_type||'WIRED'}</text>`);
  }
  for(const n of scaled){
    const col=osCol(n.os);
    const name=(n.hostname||'?').substring(0,16).toUpperCase();
    const b64=iconFor(n.type);
    parts.push(`<rect x="${n.sx}" y="${n.sy}" width="${NODE_W}" height="${NODE_H}" fill="#0d0d0d" stroke="${col}" stroke-width="1.5" rx="3"/>`);
    if(b64){
      parts.push(`<image x="${n.sx+ICON_X}" y="${n.sy+ICON_Y}" width="${ICON}" height="${ICON}" href="data:image/png;base64,${b64}" filter="url(#grn)"/>`);
    }
    parts.push(`<text x="${n.sx+TEXT_X}" y="${n.sy+22}" fill="${col}" font-size="11" font-family="Courier New" font-weight="bold">${name}</text>`);
    parts.push(`<text x="${n.sx+TEXT_X}" y="${n.sy+38}" fill="#888" font-size="9" font-family="Courier New">${(n.type||'DEVICE').toUpperCase().substring(0,14)}</text>`);
    parts.push(`<text x="${n.sx+TEXT_X}" y="${n.sy+53}" fill="#555" font-size="8" font-family="Courier New">${(n.ip||'—').substring(0,18)}</text>`);
    parts.push(`<text x="${n.sx+TEXT_X}" y="${n.sy+67}" fill="#333" font-size="7" font-family="Courier New">${(n.os||'').substring(0,20).toUpperCase()}</text>`);
  }
  parts.push('</svg>');
  return parts.join('\n');
}

function renderNetworkMap(){
  const mapData=data.map_data||{nodes:[],links:[]};
  const nodes=mapData.nodes||[];
  const links=mapData.links||[];
  const elems=[sHead('Network Map'),para('Asset topology at time of report generation.',{color:G.DIM})];
  if(nodes.length===0){
    elems.push(para('No network map data saved for this investigation.',{color:G.DIM}));
    return elems;
  }
  try{
    const W=900,NODE_H=64;
    const H=Math.max(400,Math.ceil(nodes.length/4)*(NODE_H+70)+80);
    const svgStr=buildNetworkSVG(nodes,links);
    const os=require('os'),cp=require('child_process');
    const tmpSvg=os.tmpdir()+'/orca_map_'+Date.now()+'.svg';
    const tmpPng=tmpSvg.replace('.svg','.png');
    fs.writeFileSync(tmpSvg,svgStr,'utf8');
    const res=cp.spawnSync('node',['-e',`const sharp=require('sharp'),fs=require('fs');sharp(fs.readFileSync('${tmpSvg.replace(/\\/g,'/')}'),{density:150}).png().toFile('${tmpPng.replace(/\\/g,'/')}',e=>{if(e){process.stderr.write(e.message);process.exit(1);}});`],{timeout:20000});
    if(res.status===0&&fs.existsSync(tmpPng)){
      const{ImageRun}=require('docx');
      const imgData=fs.readFileSync(tmpPng);
      elems.push(new Paragraph({children:[new ImageRun({data:imgData,transformation:{width:620,height:Math.round(620*(H/W))},type:'png'})]}));
      try{fs.unlinkSync(tmpSvg);fs.unlinkSync(tmpPng);}catch(e){}
    } else {
      throw new Error((res.stderr&&res.stderr.toString())||'sharp failed');
    }
  }catch(e){
    process.stderr.write('[WARN] map image: '+e.message+'\n');
    elems.push(para('Map image unavailable: '+e.message,{color:G.AMBER}));
  }
  return elems;
}

// ── behavioral analysis ───────────────────────────────────────
function renderBehavioral(){
  const out=[sHead('Behavioral Analysis')];
  const behavioral=data.behavioral_by_asset||{};
  const hasAny=Object.values(behavioral).some(b=>
    (b.capa_techniques&&b.capa_techniques.length)||
    (b.floss_iocs&&b.floss_iocs.length)||
    (b.speakeasy_network&&b.speakeasy_network.length)
  );
  if(!hasAny){out.push(para('No behavioral analysis results available.',{color:G.DIM}));return out;}
  for(const asset of (data.assets||[])){
    const b=behavioral[String(asset.id)];
    if(!b) continue;
    out.push(new Paragraph({spacing:{before:160,after:60},children:[
      new TextRun({text:asset.hostname,bold:true,color:G.GREEN,font:'Courier New',size:22}),
      new TextRun({text:'  BEHAVIORAL ANALYSIS',color:G.DIM,font:'Courier New',size:16}),
    ]}));
    // CAPA ATT&CK Techniques
    if(b.capa_techniques&&b.capa_techniques.length){
      out.push(new Paragraph({spacing:{before:80,after:40},children:[new TextRun({text:'ATT&CK TECHNIQUES (CAPA)',bold:true,color:G.AMBER,font:'Courier New',size:18})]}));
      const cols=[1440,3600,2160,760];
      out.push(new Table({width:{size:9360,type:WidthType.DXA},columnWidths:cols,rows:[
        new TableRow({tableHeader:true,children:[hdr('T-CODE',{width:cols[0]}),hdr('TECHNIQUE',{width:cols[1]}),hdr('TACTIC',{width:cols[2]}),hdr('SEV',{width:cols[3]})]}),
        ...b.capa_techniques.map((t,i)=>{const bg=i%2?G.G4:G.G5;return new TableRow({children:[
          cell(t.technique_id||'—',{bg,width:cols[0],color:G.GREEN,bold:true}),
          cell(t.technique_name||'—',{bg,width:cols[1]}),
          cell(t.tactic_name||'—',{bg,width:cols[2],color:G.DIM}),
          cell((t.severity||'—').toUpperCase(),{bg,width:cols[3],color:t.severity==='high'?G.RED:t.severity==='medium'?G.AMBER:G.DIM}),
        ]});}),
      ]}));
      out.push(para(''));
    }
    // FLOSS IOCs (capped at 50)
    if(b.floss_iocs&&b.floss_iocs.length){
      out.push(new Paragraph({spacing:{before:80,after:40},children:[new TextRun({text:`EXTRACTED IOCS (${b.floss_iocs.length}${b.floss_iocs.length>=50?' — truncated at 50':''})`,bold:true,color:G.RED,font:'Courier New',size:18})]}));
      const cols=[1440,7920];
      out.push(new Table({width:{size:9360,type:WidthType.DXA},columnWidths:cols,rows:[
        new TableRow({tableHeader:true,children:[hdr('TYPE',{width:cols[0]}),hdr('VALUE',{width:cols[1]})]}),
        ...b.floss_iocs.map((ioc,i)=>{const bg=i%2?G.G4:G.G5;return new TableRow({children:[
          cell(ioc.ioc_type||'—',{bg,width:cols[0],color:G.AMBER}),
          cell(ioc.string_value||'—',{bg,width:cols[1],size:16}),
        ]});}),
      ]}));
      out.push(para(''));
    }
    // Speakeasy network events
    if(b.speakeasy_network&&b.speakeasy_network.length){
      out.push(new Paragraph({spacing:{before:80,after:40},children:[new TextRun({text:`EMULATED NETWORK EVENTS (${b.speakeasy_network.length})`,bold:true,color:G.GREEN,font:'Courier New',size:18})]}));
      const cols=[900,3060,720,4680];
      out.push(new Table({width:{size:9360,type:WidthType.DXA},columnWidths:cols,rows:[
        new TableRow({tableHeader:true,children:[hdr('PROTO',{width:cols[0]}),hdr('HOST',{width:cols[1]}),hdr('PORT',{width:cols[2]}),hdr('URL',{width:cols[3]})]}),
        ...b.speakeasy_network.map((ev,i)=>{const bg=i%2?G.G4:G.G5;return new TableRow({children:[
          cell((ev.protocol||'—').toUpperCase(),{bg,width:cols[0],color:G.GREEN}),
          cell(ev.host||'—',{bg,width:cols[1]}),
          cell(ev.port?String(ev.port):'—',{bg,width:cols[2],color:G.DIM}),
          cell(ev.url||'—',{bg,width:cols[3],size:14}),
        ]});}),
      ]}));
      out.push(para(''));
    }
    // Top API calls
    if(b.speakeasy_top_api&&b.speakeasy_top_api.length){
      out.push(new Paragraph({spacing:{before:80,after:40},children:[new TextRun({text:'TOP API CALLS (EMULATION)',bold:true,color:G.GREEN,font:'Courier New',size:18})]}));
      const cols=[5760,3600];
      out.push(new Table({width:{size:9360,type:WidthType.DXA},columnWidths:cols,rows:[
        new TableRow({tableHeader:true,children:[hdr('FUNCTION',{width:cols[0]}),hdr('CALL COUNT',{width:cols[1]})]}),
        ...b.speakeasy_top_api.map((a,i)=>{const bg=i%2?G.G4:G.G5;return new TableRow({children:[
          cell(a.func_name||'—',{bg,width:cols[0],color:G.GREEN}),
          cell(String(a.call_count||0),{bg,width:cols[1],color:G.AMBER}),
        ]});}),
      ]}));
      out.push(para(''));
    }
    out.push(divider());
  }
  return out;
}

const RENDERERS={
  summary:()=>renderSummary(),
  network:()=>renderNetworkMap(),
  daily:(d)=>renderDaily(d),
  assets:()=>renderAssets(),
  bluf:()=>renderBluf(),
  timeline:(d)=>renderTimeline(d),
  verdicts:()=>renderVerdicts(),
  behavioral:()=>renderBehavioral(),
};

const children=[...cover()];
for(const sec of sections){
  if(RENDERERS[sec.id]) children.push(...RENDERERS[sec.id](sec.detail));
}

const doc=new Document({
  background:{color:G.BLACK},
  sections:[{
    properties:{page:{size:{width:12240,height:15840},margin:{top:1080,right:1080,bottom:1080,left:1080}}},
    headers:docHeader,footers:docFooter,children,
  }],
});

Packer.toBuffer(doc)
  .then(buf=>{fs.writeFileSync(outPath,buf);process.stdout.write('OK\n');})
  .catch(e=>{process.stderr.write(e.message+'\n');process.exit(1);});