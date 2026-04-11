'use strict';
// ════════════════════════════════════════════════════════════════════════════
// XlsxRenderer  (.xlsx .xlsm .xls .ods)  — SheetJS powered
// ════════════════════════════════════════════════════════════════════════════
class XlsxRenderer {
  render(buffer, fileName) {
    const wrap = document.createElement('div'); wrap.className = 'xlsx-view';
    let wb;
    try { wb = XLSX.read(new Uint8Array(buffer), {type:'array',cellStyles:true,cellDates:true,sheetRows:10001}); }
    catch(e) { return this._err(wrap,'Failed to parse spreadsheet',e.message); }
    if (!wb.SheetNames.length) { wrap.textContent='No sheets found.'; return wrap; }
    const tabBar = document.createElement('div'); tabBar.className='sheet-tab-bar'; wrap.appendChild(tabBar);
    const area   = document.createElement('div'); area.className='sheet-content-area'; wrap.appendChild(area);
    const panes  = wb.SheetNames.map((name,i) => {
      const tab  = document.createElement('button'); tab.className='sheet-tab'; tab.textContent=name; tabBar.appendChild(tab);
      const pane = document.createElement('div'); pane.className='sheet-content'; pane.style.display='none'; area.appendChild(pane);
      const p = {tab,pane,done:false};
      tab.addEventListener('click', () => {
        panes.forEach(x => { x.tab.classList.remove('active'); x.pane.style.display='none'; });
        tab.classList.add('active'); pane.style.display='block';
        if (!p.done) { this._renderSheet(wb.Sheets[name],pane); p.done=true; }
      });
      return p;
    });
    panes[0].tab.click();
    return wrap;
  }

  _renderSheet(ws, container) {
    if (!ws||!ws['!ref']) { const p=document.createElement('p'); p.style.cssText='color:#888;padding:20px'; p.textContent='Empty sheet'; container.appendChild(p); return; }
    const rng=XLSX.utils.decode_range(ws['!ref']), maxR=Math.min(rng.e.r,rng.s.r+9999);
    const merges=ws['!merges']||[], cols=ws['!cols']||[];
    const mStart=new Map(), mSkip=new Set();
    for(const m of merges){
      mStart.set(`${m.s.r},${m.s.c}`,{cs:m.e.c-m.s.c+1,rs:m.e.r-m.s.r+1});
      for(let r=m.s.r;r<=m.e.r;r++) for(let c=m.s.c;c<=m.e.c;c++) if(r!==m.s.r||c!==m.s.c) mSkip.add(`${r},${c}`);
    }
    const scr=document.createElement('div'); scr.style.cssText='overflow:auto;max-height:calc(100vh - 160px)';
    const tbl=document.createElement('table'); tbl.className='xlsx-table';
    const thead=document.createElement('thead'), hRow=document.createElement('tr');
    const corner=document.createElement('th'); corner.className='xlsx-corner'; hRow.appendChild(corner);
    for(let c=rng.s.c;c<=rng.e.c;c++){
      const th=document.createElement('th'); th.className='xlsx-col-header'; th.textContent=XLSX.utils.encode_col(c);
      const w=cols[c-rng.s.c]; if(w&&w.wch) th.style.minWidth=Math.max(40,Math.round(w.wch*7))+'px';
      hRow.appendChild(th);
    }
    thead.appendChild(hRow); tbl.appendChild(thead);
    const tbody=document.createElement('tbody');
    for(let r=rng.s.r;r<=maxR;r++){
      const tr=document.createElement('tr');
      const rh=document.createElement('th'); rh.className='xlsx-row-header'; rh.textContent=r+1; tr.appendChild(rh);
      for(let c=rng.s.c;c<=rng.e.c;c++){
        const key=`${r},${c}`; if(mSkip.has(key)) continue;
        const td=document.createElement('td'); td.className='xlsx-cell';
        const m=mStart.get(key); if(m){if(m.cs>1)td.colSpan=m.cs;if(m.rs>1)td.rowSpan=m.rs;}
        const cell=ws[XLSX.utils.encode_cell({r,c})];
        if(cell){ td.textContent=cell.w!==undefined?cell.w:(cell.t==='b'?(cell.v?'TRUE':'FALSE'):(cell.t==='e'?'#ERR':String(cell.v??'')));
          if(cell.t==='n') td.style.textAlign='right'; }
        tr.appendChild(td);
      }
      tbody.appendChild(tr);
    }
    if(maxR<rng.e.r){const tr=document.createElement('tr');const td=document.createElement('td');td.colSpan=rng.e.c-rng.s.c+2;td.style.cssText='text-align:center;color:#888;padding:8px;font-style:italic';td.textContent=`… ${rng.e.r-maxR} more rows`;tr.appendChild(td);tbody.appendChild(tr);}
    tbl.appendChild(tbody); scr.appendChild(tbl); container.appendChild(scr);
  }

  async analyzeForSecurity(buffer, fileName) {
    const ext=(fileName||'').split('.').pop().toLowerCase();
    const f={risk:'low',hasMacros:false,macroSize:0,macroHash:'',autoExec:[],modules:[],externalRefs:[],metadata:{}};
    try {
      const wb=XLSX.read(new Uint8Array(buffer),{type:'array',bookVBA:true});
      if(wb.Props) f.metadata={title:wb.Props.Title||'',subject:wb.Props.Subject||'',creator:wb.Props.Author||'',lastModifiedBy:wb.Props.LastAuthor||'',created:wb.Props.CreatedDate?new Date(wb.Props.CreatedDate).toLocaleString():'',modified:wb.Props.ModifiedDate?new Date(wb.Props.ModifiedDate).toLocaleString():''};
      if(wb.vbaraw||['xlsm','xltm','xlam'].includes(ext)){
        f.hasMacros=true; f.risk='medium';
        if(wb.vbaraw) f.macroSize=wb.vbaraw.byteLength||wb.vbaraw.length||0;
        // Extract decoded VBA source via JSZip (xlsm/xlam are ZIPs)
        try {
          const zip=await JSZip.loadAsync(buffer);
          const vbaEntry=zip.file('xl/vbaProject.bin')||zip.file('xl/vbaProject.bin'.replace('xl/',''));
          if(vbaEntry){
            const vbaData=await vbaEntry.async('uint8array');
            if(!f.macroSize) f.macroSize=vbaData.length;
            // Fix 5: store raw binary so download can fall back to .bin if text decoding fails
            f.rawBin=vbaData;
            f.modules=this._parseVBAText(vbaData);
            // check for auto-exec patterns
            for(const m of f.modules){
              if(!m.source) continue;
              const pats=this._autoExecPatterns(m.source);
              if(pats.length){f.autoExec.push({module:m.name,patterns:pats});f.risk='high';}
            }
          }
          // If JSZip entry was missing but SheetJS gave us the raw VBA bytes, use those
          if(!f.rawBin&&wb.vbaraw){
            f.rawBin=wb.vbaraw instanceof Uint8Array?wb.vbaraw:new Uint8Array(wb.vbaraw);
          }
        } catch(e){
          // JSZip failed — still preserve vbaraw bytes if available
          if(!f.rawBin&&wb.vbaraw){
            try{f.rawBin=wb.vbaraw instanceof Uint8Array?wb.vbaraw:new Uint8Array(wb.vbaraw);}catch(_){}
          }
        }
      }
    } catch(e){}
    return f;
  }

  _parseVBAText(data) {
    const txt=new TextDecoder('latin1').decode(data);
    const mods=[];
    const nameRe=/Attribute VB_Name = "([^"]+)"/g; let m;
    while((m=nameRe.exec(txt))!==null) mods.push({name:m[1],source:''});
    const chunks=(txt.match(/[ -~\r\n\t]{40,}/g)||[])
      .filter(c=>/\b(Sub |Function |End Sub|End Function|Dim |Set |If |Then|For |MsgBox|Shell|CreateObject|WScript|AutoOpen|Workbook_Open|Document_Open|Auto_Open)\b/i.test(c));
    const src=chunks.join('\n').trim();
    if(mods.length===0&&src) mods.push({name:'(extracted)',source:src});
    else if(mods.length>0&&src) mods[0].source=src;
    return mods;
  }

  _autoExecPatterns(src) {
    const pats=[[/\bAutoOpen\b/i,'AutoOpen'],[/\bDocument_Open\b/i,'Document_Open'],[/\bAuto_Open\b/i,'Auto_Open'],[/\bWorkbook_Open\b/i,'Workbook_Open'],[/\bShell\s*\(/i,'Shell()'],[/WScript\.Shell/i,'WScript.Shell'],[/\bPowerShell\b/i,'PowerShell'],[/cmd\.exe/i,'cmd.exe'],[/URLDownloadToFile/i,'URLDownloadToFile'],[/XMLHTTP/i,'XMLHTTP'],[/CreateObject\s*\(/i,'CreateObject']];
    return pats.filter(([re])=>re.test(src)).map(([,n])=>n);
  }
  _err(wrap,title,msg){const b=document.createElement('div');b.className='error-box';const h=document.createElement('h3');h.textContent=title;b.appendChild(h);const p=document.createElement('p');p.textContent=msg;b.appendChild(p);wrap.appendChild(b);return wrap;}
}

// ════════════════════════════════════════════════════════════════════════════
// PptxRenderer  (.pptx .pptm)  — JSZip + DrawingML
// ════════════════════════════════════════════════════════════════════════════
class PptxRenderer {
  constructor(){this.PML='http://schemas.openxmlformats.org/presentationml/2006/main';this.DML='http://schemas.openxmlformats.org/drawingml/2006/main';this.DMLR='http://schemas.openxmlformats.org/officeDocument/2006/relationships';this.TBL='http://schemas.openxmlformats.org/drawingml/2006/table';}

  async render(buffer) {
    const wrap=document.createElement('div'); wrap.className='pptx-view';
    let zip; try{zip=await JSZip.loadAsync(buffer);}catch(e){return this._err(wrap,'Failed to parse presentation',e.message);}
    const presXml=await this._xml(zip,'ppt/presentation.xml');
    if(!presXml){wrap.textContent='Could not parse presentation.xml';return wrap;}
    const presRels=await this._xml(zip,'ppt/_rels/presentation.xml.rels');
    const sldSz=presXml.getElementsByTagNameNS(this.PML,'sldSz')[0];
    const emuW=parseInt(sldSz?.getAttribute('cx')||'9144000'), emuH=parseInt(sldSz?.getAttribute('cy')||'5143500');
    const pxW=720, scale=pxW/emuW, pxH=Math.round(emuH*scale);
    const relMap=new Map();
    if(presRels) for(const r of presRels.getElementsByTagNameNS(PKG,'Relationship')) relMap.set(r.getAttribute('Id'),r.getAttribute('Target'));
    const media=await this._loadMedia(zip,'ppt/media/');
    const sldIdLst=presXml.getElementsByTagNameNS(this.PML,'sldIdLst')[0];
    const sldIds=sldIdLst?Array.from(sldIdLst.getElementsByTagNameNS(this.PML,'sldId')):[];
    if(sldIds.length){const lbl=document.createElement('div');lbl.className='pptx-slide-counter';lbl.textContent=`${sldIds.length} slide${sldIds.length!==1?'s':''}`;wrap.appendChild(lbl);}
    for(let i=0;i<sldIds.length;i++){
      const rId=sldIds[i].getAttributeNS(this.DMLR,'id')||sldIds[i].getAttribute('r:id');
      const target=relMap.get(rId); if(!target) continue;
      const sPath='ppt/'+target.replace(/^(\.\.\/)+/,'');
      const sXml=await this._xml(zip,sPath); if(!sXml) continue;
      const sRelPath=sPath.replace(/([^/]+)$/,'_rels/$1.rels'), sRelXml=await this._xml(zip,sRelPath);
      const sMedia=new Map();
      if(sRelXml) for(const r of sRelXml.getElementsByTagNameNS(PKG,'Relationship')){const t=r.getAttribute('Target')||'';const mk='media/'+t.split('media/').pop();const src=media.get(mk);if(src)sMedia.set(r.getAttribute('Id'),src);}
      wrap.appendChild(this._renderSlide(sXml,i+1,sldIds.length,pxW,pxH,scale,sMedia));
    }
    if(!sldIds.length){const p=document.createElement('p');p.style.cssText='color:#888;padding:20px;text-align:center';p.textContent='No slides found.';wrap.appendChild(p);}
    return wrap;
  }

  async _loadMedia(zip,prefix){
    const map=new Map(),MIME={png:'image/png',jpg:'image/jpeg',jpeg:'image/jpeg',gif:'image/gif',bmp:'image/bmp'};
    for(const[path,file] of Object.entries(zip.files)){if(!path.startsWith(prefix)||file.dir)continue;const ext=path.split('.').pop().toLowerCase();if(!MIME[ext])continue;const b64=await file.async('base64');map.set('media/'+path.slice(prefix.length),`data:${MIME[ext]};base64,${b64}`);}
    return map;
  }

  _renderSlide(xml,num,total,w,h,scale,media){
    const slide=document.createElement('div'); slide.className='pptx-slide';
    slide.style.cssText=`width:${w}px;height:${h}px;position:relative;overflow:hidden;`;
    const bg=document.createElement('div'); bg.style.cssText='position:absolute;inset:0;background:white;'; slide.appendChild(bg);
    const trees=xml.getElementsByTagNameNS(this.PML,'spTree');
    for(const tree of Array.from(trees)) this._shapes(tree,slide,scale,media);
    const badge=document.createElement('div'); badge.className='pptx-slide-num'; badge.textContent=`${num}/${total}`; slide.appendChild(badge);
    return slide;
  }

  _shapes(container,parent,scale,media){
    for(const c of Array.from(container.childNodes)){
      if(c.nodeType!==1)continue;
      if(c.localName==='sp') this._sp(c,parent,scale);
      else if(c.localName==='pic') this._pic(c,parent,scale,media);
      else if(c.localName==='grpSp') this._shapes(c,parent,scale,media);
      else if(c.localName==='graphicFrame') this._gf(c,parent,scale);
    }
  }

  _xfrm(el){
    const spPr=el.getElementsByTagNameNS(this.PML,'spPr')[0];
    const xf=spPr?spPr.getElementsByTagNameNS(this.DML,'xfrm')[0]:null; if(!xf)return null;
    const off=xf.getElementsByTagNameNS(this.DML,'off')[0], ext=xf.getElementsByTagNameNS(this.DML,'ext')[0]; if(!off||!ext)return null;
    return{x:parseInt(off.getAttribute('x')||0),y:parseInt(off.getAttribute('y')||0),cx:parseInt(ext.getAttribute('cx')||0),cy:parseInt(ext.getAttribute('cy')||0),rot:parseInt(xf.getAttribute('rot')||0)};
  }
  _pos(el,s,x){el.style.position='absolute';el.style.left=(x.x*s)+'px';el.style.top=(x.y*s)+'px';el.style.width=(x.cx*s)+'px';el.style.height=(x.cy*s)+'px';if(x.rot)el.style.transform=`rotate(${x.rot/60000}deg)`;}

  _sp(sp,parent,scale){
    const x=this._xfrm(sp); if(!x)return;
    const div=document.createElement('div'); div.style.cssText='overflow:hidden;box-sizing:border-box;'; this._pos(div,scale,x);
    const spPr=sp.getElementsByTagNameNS(this.PML,'spPr')[0];
    if(spPr){const sf=spPr.getElementsByTagNameNS(this.DML,'solidFill')[0];if(sf){const sc=sf.getElementsByTagNameNS(this.DML,'srgbClr')[0];if(sc)div.style.background='#'+sc.getAttribute('val');}}
    const txBody=sp.getElementsByTagNameNS(this.PML,'txBody')[0];
    if(txBody) this._txBody(txBody,div,scale);
    parent.appendChild(div);
  }

  _txBody(txBody,container,scale){
    for(const p of Array.from(txBody.getElementsByTagNameNS(this.DML,'p'))){
      const pd=document.createElement('p'); pd.style.cssText='margin:0;padding:0 2px;line-height:1.2;';
      const pPr=p.getElementsByTagNameNS(this.DML,'pPr')[0];
      if(pPr){const a=pPr.getAttribute('algn');if(a==='ctr')pd.style.textAlign='center';else if(a==='r')pd.style.textAlign='right';}
      let has=false;
      for(const r of Array.from(p.getElementsByTagNameNS(this.DML,'r'))){
        const t=r.getElementsByTagNameNS(this.DML,'t')[0]; if(!t)continue;
        const sp=document.createElement('span'); sp.textContent=t.textContent;
        const rPr=r.getElementsByTagNameNS(this.DML,'rPr')[0];
        if(rPr){const sz=rPr.getAttribute('sz');if(sz)sp.style.fontSize=Math.round(parseInt(sz)/100*scale*1.6)+'px';if(rPr.getAttribute('b')==='1')sp.style.fontWeight='bold';if(rPr.getAttribute('i')==='1')sp.style.fontStyle='italic';const fc=rPr.getElementsByTagNameNS(this.DML,'solidFill')[0];if(fc){const sc=fc.getElementsByTagNameNS(this.DML,'srgbClr')[0];if(sc)sp.style.color='#'+sc.getAttribute('val');}}
        pd.appendChild(sp); has=true;
      }
      for(const br of Array.from(p.getElementsByTagNameNS(this.DML,'br'))) pd.appendChild(document.createElement('br'));
      container.appendChild(has?pd:document.createElement('br'));
    }
  }

  _pic(pic,parent,scale,media){
    const x=this._xfrm(pic); if(!x)return;
    const bf=pic.getElementsByTagNameNS(this.PML,'blipFill')[0]; if(!bf)return;
    const blip=bf.getElementsByTagNameNS(this.DML,'blip')[0]; if(!blip)return;
    const rId=blip.getAttributeNS(this.DMLR,'embed')||blip.getAttribute('r:embed');
    const src=media.get(rId); if(!src)return;
    const img=document.createElement('img'); img.src=src; img.alt=''; img.style.objectFit='contain'; this._pos(img,scale,x); parent.appendChild(img);
  }

  _gf(gf,parent,scale){
    const tbl=gf.getElementsByTagNameNS(this.TBL,'tbl')[0]; if(!tbl)return;
    const x=this._xfrm(gf); if(!x)return;
    const wrap=document.createElement('div'); wrap.style.overflow='auto'; this._pos(wrap,scale,x);
    const table=document.createElement('table'); table.style.cssText='border-collapse:collapse;width:100%;';
    for(const tr of Array.from(tbl.getElementsByTagNameNS(this.TBL,'tr'))){
      const row=document.createElement('tr');
      for(const tc of Array.from(tr.getElementsByTagNameNS(this.TBL,'tc'))){
        const td=document.createElement('td'); td.style.cssText='border:1px solid #ccc;padding:2px 4px;vertical-align:top;';
        const gs=parseInt(tc.getAttribute('gridSpan')||1),rs=parseInt(tc.getAttribute('rowSpan')||1);
        if(gs>1)td.colSpan=gs; if(rs>1)td.rowSpan=rs;
        const tbx=tc.getElementsByTagNameNS(this.TBL,'txBody')[0]; if(tbx)this._txBody(tbx,td,scale*0.8);
        row.appendChild(td);
      }
      table.appendChild(row);
    }
    wrap.appendChild(table); parent.appendChild(wrap);
  }

  async _xml(zip,path){try{const f=zip.file(path);if(!f)return null;const d=new DOMParser().parseFromString(await f.async('string'),'text/xml');return d.getElementsByTagName('parsererror').length?null:d;}catch(e){return null;}}

  // Fix 6: VBA text extraction helpers (same pattern as XlsxRenderer)
  _parseVBAText(data){
    const txt=new TextDecoder('latin1').decode(data);
    const mods=[];
    const nameRe=/Attribute VB_Name = "([^"]+)"/g; let m;
    while((m=nameRe.exec(txt))!==null) mods.push({name:m[1],source:''});
    const chunks=(txt.match(/[ -~\r\n\t]{40,}/g)||[])
      .filter(c=>/\b(Sub |Function |End Sub|End Function|Dim |Set |If |Then|For |MsgBox|Shell|CreateObject|WScript|AutoOpen|Workbook_Open|Document_Open|Auto_Open)\b/i.test(c));
    const src=chunks.join('\n').trim();
    if(mods.length===0&&src) mods.push({name:'(extracted)',source:src});
    else if(mods.length>0&&src) mods[0].source=src;
    return mods;
  }
  _autoExecPatterns(src){
    const pats=[[/\bAutoOpen\b/i,'AutoOpen'],[/\bDocument_Open\b/i,'Document_Open'],[/\bAuto_Open\b/i,'Auto_Open'],[/\bWorkbook_Open\b/i,'Workbook_Open'],[/\bShell\s*\(/i,'Shell()'],[/WScript\.Shell/i,'WScript.Shell'],[/\bPowerShell\b/i,'PowerShell'],[/cmd\.exe/i,'cmd.exe'],[/URLDownloadToFile/i,'URLDownloadToFile'],[/XMLHTTP/i,'XMLHTTP'],[/CreateObject\s*\(/i,'CreateObject']];
    return pats.filter(([re])=>re.test(src)).map(([,n])=>n);
  }

  async analyzeForSecurity(buffer,fileName){
    const ext=(fileName||'').split('.').pop().toLowerCase();
    const f={risk:'low',hasMacros:false,macroSize:0,macroHash:'',autoExec:[],modules:[],externalRefs:[],metadata:{}};
    try{
      const zip=await JSZip.loadAsync(buffer);
      const vba=zip.file('ppt/vbaProject.bin');
      if(vba||['pptm','potm','ppam'].includes(ext)){
        f.hasMacros=true;f.risk='medium';
        if(vba){
          const d=await vba.async('uint8array');
          f.macroSize=d.length;
          // Fix 6: store raw binary + attempt text extraction + pattern scan
          f.rawBin=d;
          f.modules=this._parseVBAText(d);
          for(const m of f.modules){
            if(!m.source) continue;
            const pats=this._autoExecPatterns(m.source);
            if(pats.length){f.autoExec.push({module:m.name,patterns:pats});f.risk='high';}
          }
        }
      }
      const core=await this._xml(zip,'docProps/core.xml');
      if(core){const DC='http://purl.org/dc/elements/1.1/',DCP='http://schemas.openxmlformats.org/package/2006/metadata/core-properties';const g=(ns,n)=>core.getElementsByTagNameNS(ns,n)[0]?.textContent?.trim()||'';f.metadata={title:g(DC,'title'),subject:g(DC,'subject'),creator:g(DC,'creator'),lastModifiedBy:g(DCP,'lastModifiedBy'),created:g(DCP,'created'),modified:g(DCP,'modified')};}
      for(const[p,file] of Object.entries(zip.files)){if(!p.endsWith('.rels')||file.dir)continue;const rXml=new DOMParser().parseFromString(await file.async('string'),'text/xml');for(const r of rXml.getElementsByTagNameNS(PKG,'Relationship')){const mode=r.getAttribute('TargetMode'),target=r.getAttribute('Target');if(mode==='External'&&target){const t=(r.getAttribute('Type')||'').split('/').pop();const sv=t==='hyperlink'?'info':'medium';f.externalRefs.push({type:t==='hyperlink'?'Hyperlink':'External',url:target,severity:sv});if(sv!=='info'&&f.risk==='low')f.risk='medium';}}}
    }catch(e){}
    return f;
  }

  _err(wrap,title,msg){const b=document.createElement('div');b.className='error-box';const h=document.createElement('h3');h.textContent=title;b.appendChild(h);const p=document.createElement('p');p.textContent=msg;b.appendChild(p);wrap.appendChild(b);return wrap;}
}

// ════════════════════════════════════════════════════════════════════════════
// CsvRenderer  (.csv .tsv)
// ════════════════════════════════════════════════════════════════════════════
class CsvRenderer {
  render(text,fileName){
    const wrap=document.createElement('div'); wrap.className='csv-view';
    const ext=(fileName||'').split('.').pop().toLowerCase();
    const delim=ext==='tsv'?'\t':this._delim(text);
    const rows=this._parse(text,delim);
    if(!rows.length){wrap.textContent='Empty file.';return wrap;}
    const info=document.createElement('div'); info.className='csv-info';
    const dn=delim==='\t'?'Tab':delim===','?'Comma':delim===';'?'Semicolon':'Pipe';
    info.textContent=`${rows.length} rows × ${rows[0].length} columns · delimiter: ${dn}`; wrap.appendChild(info);
    const scr=document.createElement('div'); scr.style.cssText='overflow:auto;max-height:calc(100vh - 140px)';
    const tbl=document.createElement('table'); tbl.className='xlsx-table csv-table';
    rows.forEach((row,ri)=>{
      if(ri>10000)return;
      const tr=document.createElement('tr');
      const rh=document.createElement(ri===0?'th':'td'); rh.className='xlsx-row-header'; rh.textContent=ri===0?'#':ri; tr.appendChild(rh);
      row.forEach(cell=>{
        const td=document.createElement(ri===0?'th':'td'); td.className=ri===0?'xlsx-col-header csv-header':'xlsx-cell'; td.textContent=cell;
        if(ri>0&&cell.trim()&&!isNaN(parseFloat(cell)))td.style.textAlign='right';
        tr.appendChild(td);
      });
      tbl.appendChild(tr);
    });
    scr.appendChild(tbl); wrap.appendChild(scr); return wrap;
  }
  _delim(text){const line=(text.split('\n')[0]||'');const c={',':0,';':0,'\t':0,'|':0};let inQ=false;for(const ch of line){if(ch==='"'){inQ=!inQ;}else if(!inQ&&c[ch]!==undefined)c[ch]++;}return Object.entries(c).sort((a,b)=>b[1]-a[1])[0][0];}
  _parse(text,delim){const rows=[];for(const line of text.replace(/\r\n/g,'\n').replace(/\r/g,'\n').split('\n')){if(!line.trim())continue;rows.push(this._split(line,delim));}return rows;}
  _split(line,delim){const cells=[];let cur='',inQ=false;for(let i=0;i<line.length;i++){const ch=line[i];if(ch==='"'){if(inQ&&line[i+1]==='"'){cur+='"';i++;}else inQ=!inQ;}else if(ch===delim&&!inQ){cells.push(cur);cur='';}else cur+=ch;}cells.push(cur);return cells;}
  analyzeForSecurity(text){
    const f={risk:'low',hasMacros:false,macroSize:0,macroHash:'',autoExec:[],modules:[],externalRefs:[],metadata:{}};
    if(text.split('\n').slice(0,1000).some(l=>l.trim()&&/^["']?[=+\-@]/.test(l.trim()))){f.risk='medium';f.externalRefs.push({type:'Formula Injection Risk',url:'Cells beginning with =, +, -, or @ (potential formula injection)',severity:'medium'});}
    return f;
  }
}

// ════════════════════════════════════════════════════════════════════════════
// OleCfbParser  (OLE Compound File Binary — shared by .doc and .msg)
// ════════════════════════════════════════════════════════════════════════════
class OleCfbParser {
  constructor(buffer){
    const ab=buffer instanceof ArrayBuffer?buffer:buffer.buffer.slice(buffer.byteOffset,buffer.byteOffset+buffer.byteLength);
    this.buf=new Uint8Array(ab); this.dv=new DataView(ab); this.streams=new Map();
  }

  parse(){
    const M=[0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1];
    for(let i=0;i<8;i++) if(this.buf[i]!==M[i]) throw new Error('Not an OLE Compound File');
    this._ss=1<<this.dv.getUint16(0x1E,true);
    this._ms=1<<this.dv.getUint16(0x20,true);
    this._cut=this.dv.getUint32(0x38,true);
    this._fat=this._buildFAT(this.dv.getUint32(0x2C,true));
    this._mfat=this._buildMFAT(this.dv.getUint32(0x3C,true),this.dv.getUint32(0x40,true));
    this._dir=this._readDir(this.dv.getUint32(0x30,true));
    if(!this._dir.length) throw new Error('OLE: empty directory');
    const root=this._dir[0];
    this._mini=this._chain(root.start,root.size,false);
    if(root.child<0xFFFFFFF0) this._walk(root.child,'',0);
    return this;
  }

  _walk(idx,prefix,depth){
    if(depth>64||idx>=0xFFFFFFF0||idx>=this._dir.length)return;
    const e=this._dir[idx]; if(!e||e.type===0)return;
    const path=prefix?prefix+'/'+e.name:e.name;
    if(e.type===2){const isMini=e.size>0&&e.size<this._cut&&e.start<0xFFFFFFF0;this.streams.set(path.toLowerCase(),this._chain(e.start,e.size,isMini));}
    if(e.type!==2&&e.child<0xFFFFFFF0) this._walk(e.child,e.type===5?'':path,depth+1);
    if(e.lsib<0xFFFFFFF0) this._walk(e.lsib,prefix,depth+1);
    if(e.rsib<0xFFFFFFF0) this._walk(e.rsib,prefix,depth+1);
  }

  _so(sec){return 512+sec*this._ss;}

  _buildFAT(n){
    const fat=[];let done=0;
    const addSec=s=>{if(s>=0xFFFFFFF0)return;const off=this._so(s);for(let i=0;i<this._ss/4;i++)fat.push(this.dv.getUint32(off+i*4,true));done++;};
    for(let i=0;i<109&&done<n;i++){const s=this.dv.getUint32(0x4C+i*4,true);if(s>=0xFFFFFFF0)break;addSec(s);}
    let dif=this.dv.getUint32(0x44,true);
    while(dif<0xFFFFFFF0&&done<n){const off=this._so(dif);for(let i=0;i<this._ss/4-1&&done<n;i++){const s=this.dv.getUint32(off+i*4,true);if(s>=0xFFFFFFF0)break;addSec(s);}dif=this.dv.getUint32(off+this._ss-4,true);}
    return fat;
  }

  _buildMFAT(first,n){const mf=[];let s=first;while(s<0xFFFFFFF0&&n-->0){const off=this._so(s);for(let i=0;i<this._ss/4;i++)mf.push(this.dv.getUint32(off+i*4,true));s=this._fat[s]??0xFFFFFFFE;}return mf;}

  _chain(start,size,mini){
    if(size===0||start>=0xFFFFFFF0)return new Uint8Array(0);
    const res=new Uint8Array(size<0?0:size);
    const sz=mini?this._ms:this._ss,fat=mini?this._mfat:this._fat;
    let sec=start,pos=0;
    while(sec<0xFFFFFFF0&&pos<size){
      const take=Math.min(sz,size-pos);
      if(mini){const off=sec*this._ms;res.set(this._mini.slice(off,off+take),pos);}
      else{const off=this._so(sec);res.set(this.buf.slice(off,off+take),pos);}
      pos+=take;sec=fat[sec]??0xFFFFFFFE;
    }
    return res;
  }

  _readDir(first){
    const dir=[];let sec=first;
    while(sec<0xFFFFFFF0){
      const off=this._so(sec);
      for(let i=0;i<this._ss/128;i++){
        const b=off+i*128,nl=this.dv.getUint16(b+64,true);
        if(!nl||nl>64){dir.push({type:0,name:'',start:0,size:0,child:0xFFFFFFFF,lsib:0xFFFFFFFF,rsib:0xFFFFFFFF});continue;}
        let name='';for(let j=0;j<(nl-2)/2;j++)name+=String.fromCharCode(this.dv.getUint16(b+j*2,true));
        dir.push({name,type:this.buf[b+66],lsib:this.dv.getUint32(b+68,true),rsib:this.dv.getUint32(b+72,true),child:this.dv.getUint32(b+76,true),start:this.dv.getUint32(b+116,true),size:this.dv.getUint32(b+120,true)});
      }
      sec=this._fat[sec]??0xFFFFFFFE;
    }
    return dir;
  }
}

// ════════════════════════════════════════════════════════════════════════════
// DocBinaryRenderer  (.doc — text extraction)
// ════════════════════════════════════════════════════════════════════════════
class DocBinaryRenderer {
  render(buffer){
    const wrap=document.createElement('div'); wrap.className='doc-text-view';
    const banner=document.createElement('div'); banner.className='doc-extraction-banner';
    banner.innerHTML='<strong>Text Extraction Mode</strong> — .doc (Word 97-2003) binary: content shown as plain text only; formatting, images and tables are not rendered.';
    wrap.appendChild(banner);
    let paras=[];
    try{const cfb=new OleCfbParser(buffer).parse();paras=this._extract(cfb);}
    catch(e){const b=document.createElement('div');b.className='error-box';const h=document.createElement('h3');h.textContent='Failed to parse .doc';b.appendChild(h);const p=document.createElement('p');p.textContent=e.message;b.appendChild(p);wrap.appendChild(b);return wrap;}
    const page=document.createElement('div'); page.className='page'; page.style.cssText='width:816px;min-height:1056px;padding:96px;margin:0 auto;';
    for(const text of paras){const p=document.createElement('p');p.className='para';p.style.marginBottom='5px';p.textContent=text||'\u00A0';page.appendChild(p);}
    if(!paras.length){const p=document.createElement('p');p.style.cssText='color:#888;font-style:italic;';p.textContent='No text could be extracted.';page.appendChild(p);}
    wrap.appendChild(page);return wrap;
  }

  _extract(cfb){
    const wd=cfb.streams.get('worddocument');
    if(!wd) throw new Error('No WordDocument stream — not a valid .doc file');
    const dv=new DataView(wd.buffer,wd.byteOffset,wd.byteLength);
    const ccpText=wd.length>72?dv.getUint32(68,true):0;
    const whtbl=wd.length>11?(wd[11]>>1)&1:1;
    const fcClx=wd.length>0x01AA?dv.getUint32(0x01A2,true):0;
    const lcbClx=wd.length>0x01AE?dv.getUint32(0x01A6,true):0;
    const tbl=cfb.streams.get(whtbl?'1table':'0table')||cfb.streams.get('1table')||cfb.streams.get('0table');
    let text='';
    if(tbl&&fcClx>0&&lcbClx>0&&fcClx+lcbClx<=tbl.length) text=this._pieceTable(wd,tbl,fcClx,lcbClx)||'';
    if(!text&&ccpText>0) text=this._direct(wd,dv,ccpText);
    if(!text) text=this._scan(wd,dv);
    return text.split(/[\r\x07]/).map(s=>s.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g,'').replace(/\x13[^\x15]*\x15/g,'').trim()).filter((s,i)=>s.length>0||i>0);
  }

  _pieceTable(wd,tbl,fcClx,lcbClx){
    let pos=fcClx;
    const tdv=new DataView(tbl.buffer,tbl.byteOffset,tbl.byteLength);
    while(pos<fcClx+lcbClx){if(tbl[pos]===0x02)break;if(tbl[pos]===0x01){const cb=tdv.getUint16(pos+1,true);pos+=3+cb;}else break;}
    if(pos>=fcClx+lcbClx||tbl[pos]!==0x02)return '';
    pos++;const lcb=tdv.getUint32(pos,true);pos+=4;
    if(lcb<4)return '';
    const n=Math.floor((lcb-4)/12); if(n<=0)return '';
    const pcdBase=pos+(n+1)*4; let text='';
    const wdv=new DataView(wd.buffer,wd.byteOffset,wd.byteLength);
    for(let i=0;i<n;i++){
      const cpEnd=tdv.getUint32(pos+(i+1)*4,true),pOff=pcdBase+i*8;
      if(pOff+8>tbl.length)break;
      const cpStart=tdv.getUint32(pos+i*4,true),count=cpEnd-cpStart;
      if(count<=0||count>500000)continue;
      const fcRaw=tdv.getUint32(pOff+2,true),isAnsi=(fcRaw&0x40000000)!==0,fc=fcRaw&~0x40000000;
      if(isAnsi){for(let j=0;j<count&&fc+j<wd.length;j++)text+=String.fromCharCode(wd[fc+j]);}
      else{for(let j=0;j<count&&fc+j*2+1<wd.length;j++){const cp=wdv.getUint16(fc+j*2,true);text+=cp?String.fromCharCode(cp):'';}}
    }
    return text;
  }

  _direct(wd,dv,ccpText){
    const fibEnd=892; if(wd.length<=fibEnd)return '';
    let uniScore=0;
    for(let i=fibEnd;i<Math.min(fibEnd+400,wd.length-1);i+=2)if(wd[i]>=32&&wd[i]<127&&wd[i+1]===0)uniScore++;
    const count=Math.min(ccpText,Math.floor((wd.length-fibEnd)/(uniScore>20?2:1)));
    if(uniScore>20){let s='';for(let i=0;i<count&&fibEnd+i*2+1<wd.length;i++)s+=String.fromCharCode(dv.getUint16(fibEnd+i*2,true)||32);return s;}
    let s='';for(let i=0;i<count&&fibEnd+i<wd.length;i++)s+=String.fromCharCode(wd[fibEnd+i]);return s;
  }

  _scan(wd,dv){
    const blocks=[];let cur='';
    for(let i=0;i<wd.length-1;i+=2){const cp=dv.getUint16(i,true);if(cp>=32&&cp<0xD800){if(cp===0x0D){if(cur.trim())blocks.push(cur);cur='';}else cur+=String.fromCharCode(cp);}else if(cur.length>2){blocks.push(cur);cur='';}}
    if(cur.trim())blocks.push(cur);return blocks.join('\r');
  }

  analyzeForSecurity(buffer){
    const f={risk:'low',hasMacros:false,macroSize:0,macroHash:'',autoExec:[],modules:[],externalRefs:[],metadata:{}};
    try{
      const cfb=new OleCfbParser(buffer).parse();
      // Fix 7: collect the actual VBA/macro stream bytes rather than just setting a flag.
      // We keep the largest matching stream as the representative binary to download.
      // Priority: 'vba/vba' (the compressed source stream inside the VBA storage),
      // then any stream whose name contains 'vba' or 'macro'.
      let vbaStream=null;
      for(const [name,data] of cfb.streams.entries()){
        if(name==='vba/vba'||name.includes('vba')||name.includes('macro')){
          f.hasMacros=true; f.risk='medium';
          if(!vbaStream||data.length>vbaStream.length) vbaStream=data;
        }
      }
      if(vbaStream){
        f.macroSize=vbaStream.length;
        f.rawBin=vbaStream;
      }
      const si=cfb.streams.get('\x05summaryinformation');
      if(si) f.metadata=this._si(si);
    }catch(e){}
    return f;
  }

  _si(data){
    const meta={};try{
      const dv=new DataView(data.buffer,data.byteOffset,data.byteLength);
      const off0=dv.getUint32(28,true); if(off0+8>data.length)return meta;
      const count=dv.getUint32(off0+4,true);
      for(let i=0;i<count&&off0+8+i*8+8<=data.length;i++){
        const id=dv.getUint32(off0+8+i*8,true),ofs=dv.getUint32(off0+8+i*8+4,true)+off0;
        if(ofs+8>data.length)continue;const vt=dv.getUint32(ofs,true);if(vt!==0x1E)continue;
        const len=dv.getUint32(ofs+4,true);if(len<=0||ofs+8+len>data.length)continue;
        let s='';for(let j=0;j<len-1;j++)s+=String.fromCharCode(data[ofs+8+j]);
        if(id===2)meta.title=s.trim();else if(id===3)meta.subject=s.trim();else if(id===4)meta.creator=s.trim();
      }
    }catch(e){}return meta;
  }
}

// ════════════════════════════════════════════════════════════════════════════
// MsgRenderer  (.msg — Outlook message)
// ════════════════════════════════════════════════════════════════════════════
class MsgRenderer {
  render(buffer){
    const wrap=document.createElement('div'); wrap.className='msg-view';
    let msg;
    try{const cfb=new OleCfbParser(buffer).parse();msg=this._extract(cfb);}
    catch(e){const b=document.createElement('div');b.className='error-box';const h=document.createElement('h3');h.textContent='Failed to parse .msg';b.appendChild(h);const p=document.createElement('p');p.textContent=e.message;b.appendChild(p);wrap.appendChild(b);return wrap;}
    const page=document.createElement('div'); page.className='page msg-page'; page.style.cssText='width:816px;min-height:300px;padding:40px 60px;margin:0 auto;';
    const fields=[['From',msg.from],['To',msg.to],['CC',msg.cc],['Date',msg.date],['Subject',msg.subject||'(No Subject)']].filter(([,v])=>v);
    if(fields.length){const tbl=document.createElement('table');tbl.className='msg-header-table';for(const[l,v] of fields){const tr=document.createElement('tr');const th=document.createElement('th');th.textContent=l+':';const td=document.createElement('td');td.textContent=v;tr.appendChild(th);tr.appendChild(td);tbl.appendChild(tr);}page.appendChild(tbl);}
    const hr=document.createElement('hr');hr.style.cssText='margin:16px 0;border:none;border-top:1px solid #ddd;';page.appendChild(hr);
    if(msg.bodyHtml){const d=document.createElement('div');d.className='msg-body-html';this._sanitize(msg.bodyHtml,d);page.appendChild(d);}
    else if(msg.body){const d=document.createElement('div');d.style.cssText='white-space:pre-wrap;font-size:10pt;line-height:1.5;';d.textContent=msg.body;page.appendChild(d);}
    else{const p=document.createElement('p');p.style.cssText='color:#888;font-style:italic;';p.textContent='(No message body)';page.appendChild(p);}
    if(msg.attachments.length){const hr2=document.createElement('hr');hr2.style.cssText='margin:16px 0;border:none;border-top:1px solid #ddd;';page.appendChild(hr2);const h4=document.createElement('h4');h4.style.cssText='font-size:11pt;margin-bottom:8px;';h4.textContent=`Attachments (${msg.attachments.length})`;page.appendChild(h4);const ul=document.createElement('ul');ul.style.cssText='margin:0 0 0 20px;font-size:10pt;';for(const a of msg.attachments){const li=document.createElement('li');li.textContent=(a.name||'unnamed')+(a.size?` — ${(a.size/1024).toFixed(1)} KB`:'');ul.appendChild(li);}page.appendChild(ul);}
    wrap.appendChild(page);return wrap;
  }

  _extract(cfb){
    const msg={subject:'',from:'',to:'',cc:'',date:'',body:'',bodyHtml:'',attachments:[]};
    const gs=id=>this._u16(cfb.streams.get(`__substg1.0_${id}001f`));
    msg.subject=gs('0037'); msg.body=gs('1000');
    msg.from=gs('0c1a')||gs('5d01')||gs('0065');
    msg.to=gs('0e04'); msg.cc=gs('0e03');
    const htmlBin=cfb.streams.get('__substg1.0_10130102');
    if(htmlBin){try{msg.bodyHtml=new TextDecoder('utf-8',{fatal:false}).decode(htmlBin);}catch(e){}}
    if(!msg.bodyHtml)msg.bodyHtml=gs('1013');
    if(msg.bodyHtml&&!/<(html|body|div|p|table|span|br)\b/i.test(msg.bodyHtml))msg.bodyHtml='';
    const props=cfb.streams.get('__properties_version1.0');
    if(props&&props.length>=32){
      const dv=new DataView(props.buffer,props.byteOffset,props.byteLength);
      const count=dv.getUint32(16,true);
      for(let i=0;i<count&&32+i*16+16<=props.length;i++){
        const off=32+i*16,pType=dv.getUint16(off,true),pId=dv.getUint16(off+2,true);
        if(pType===0x0040&&(pId===0x0039||pId===0x0E06)){
          const lo=dv.getUint32(off+8,true),hi=dv.getUint32(off+12,true);
          const ms=(hi*4294967296+lo)/10000-11644473600000;
          if(ms>0&&ms<32503680000000){msg.date=new Date(ms).toLocaleString();break;}
        }
      }
    }
    const attPfx=new Set();
    for(const path of cfb.streams.keys()){const m=path.match(/^(__attach_version1\.0_#\d+)\//);if(m)attPfx.add(m[1]);}
    for(const pre of attPfx){
      const name=this._u16(cfb.streams.get(`${pre}/__substg1.0_3707001f`))||this._u16(cfb.streams.get(`${pre}/__substg1.0_3704001f`))||(()=>{const d=cfb.streams.get(`${pre}/__substg1.0_3707001e`);return d?new TextDecoder('latin1').decode(d):'';})()||'attachment';
      const data=cfb.streams.get(`${pre}/__substg1.0_37010102`);
      msg.attachments.push({name,size:data?data.length:0});
    }
    return msg;
  }

  _u16(data){if(!data||!data.length)return '';try{return new TextDecoder('utf-16le').decode(data).replace(/\0+$/,'');}catch(e){return '';}}

  _sanitize(html,container){
    const OK=new Set(['p','br','b','strong','i','em','u','s','span','div','ul','ol','li','table','thead','tbody','tr','th','td','h1','h2','h3','h4','h5','h6','blockquote','pre','code','hr','a','font','center']);
    const ATTR=new Set(['href','style','color','size','face','align','colspan','rowspan']);
    const walk=(node,target)=>{
      for(const c of Array.from(node.childNodes)){
        if(c.nodeType===3){target.appendChild(document.createTextNode(c.textContent));continue;}
        if(c.nodeType!==1)continue;
        const tag=c.tagName.toLowerCase();
        if(['script','style','meta','link','object','iframe','embed'].includes(tag))continue;
        if(!OK.has(tag)){walk(c,target);continue;}
        const el=document.createElement(tag);
        for(const a of Array.from(c.attributes)){const n=a.name.toLowerCase();if(!ATTR.has(n))continue;if(n==='href'){const s=sanitizeUrl(a.value);if(s)el.setAttribute(n,s);}else if(n==='style'){el.setAttribute(n,a.value.replace(/(expression|javascript|vbscript)/gi,''));}else el.setAttribute(n,a.value);}
        walk(c,el);target.appendChild(el);
      }
    };
    const doc=new DOMParser().parseFromString(html,'text/html');if(doc.body)walk(doc.body,container);
  }

  analyzeForSecurity(buffer){
    const f={risk:'low',hasMacros:false,macroSize:0,macroHash:'',autoExec:[],modules:[],externalRefs:[],metadata:{}};
    try{
      const cfb=new OleCfbParser(buffer).parse();
      const msg=this._extract(cfb);
      f.metadata={title:msg.subject,creator:msg.from,created:msg.date};
      for(const a of msg.attachments){
        if(/\.(exe|bat|cmd|vbs|js|ps1|hta|scr|msi|dll|com|jar)$/i.test(a.name)){f.risk='high';f.externalRefs.push({type:'Dangerous Attachment',url:a.name,severity:'high'});}
        else if(/\.(doc[mx]?|xls[mx]?|ppt[mx]?|doc|xls|ppt)$/i.test(a.name)){if(f.risk==='low')f.risk='medium';f.externalRefs.push({type:'Office Attachment',url:a.name,severity:'medium'});}
      }
      if(msg.bodyHtml){
        for(const u of (msg.bodyHtml.match(/https?:\/\/[^\s"'<>()]+/gi)||[]).slice(0,10))f.externalRefs.push({type:'HTML Link',url:u,severity:'info'});
        if(/width=.{0,5}[01].{0,5}height=.{0,5}[01]/i.test(msg.bodyHtml))f.externalRefs.push({type:'Possible Tracking Pixel',url:'1x1 or 0x0 image detected',severity:'medium'});
      }
      if(f.externalRefs.some(r=>r.severity!=='info')&&f.risk==='low')f.risk='medium';
    }catch(e){}
    return f;
  }
}
