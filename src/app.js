'use strict';
// ── Namespace constants ──────────────────────────────────────────────────────
const W    = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main';
const R_NS = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships';
const A_NS = 'http://schemas.openxmlformats.org/drawingml/2006/main';
const WP_NS= 'http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing';
const V_NS = 'urn:schemas-microsoft-com:vml';
const MC_NS= 'http://schemas.openxmlformats.org/markup-compatibility/2006';
const PKG  = 'http://schemas.openxmlformats.org/package/2006/relationships';

// ── Unit helpers ─────────────────────────────────────────────────────────────
const dxaToPx = v => (v / 1440) * 96;
const emuToPx = v => (v / 914400) * 96;
const twipToPt= v => v / 20;

// ── DOM / XML helpers ────────────────────────────────────────────────────────
function wa(el, name) {
  if (!el) return null;
  return el.getAttributeNS(W, name) || el.getAttribute('w:' + name) || null;
}
function ra(el, name) {
  if (!el) return null;
  return el.getAttributeNS(R_NS, name) || el.getAttribute('r:' + name) || null;
}
function wfirst(parent, localName) {
  if (!parent) return null;
  const nl = parent.getElementsByTagNameNS(W, localName);
  return nl.length ? nl[0] : null;
}
function wdirect(parent, localName) {
  if (!parent) return [];
  return Array.from(parent.childNodes).filter(
    n => n.nodeType === 1 && n.localName === localName
  );
}
function sanitizeUrl(url) {
  if (!url) return null;
  try {
    const p = new URL(url, 'https://placeholder.invalid');
    if (['http:', 'https:', 'mailto:'].includes(p.protocol)) return url;
  } catch(e) {}
  return null;
}
function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;')
                  .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function toRoman(n) {
  const v=[1000,900,500,400,100,90,50,40,10,9,5,4,1];
  const s=['M','CM','D','CD','C','XC','L','XL','X','IX','V','IV','I'];
  let r=''; for(let i=0;i<v.length;i++) while(n>=v[i]){r+=s[i];n-=v[i];} return r;
}

// ════════════════════════════════════════════════════════════════════════════
// DocxParser
// ════════════════════════════════════════════════════════════════════════════
class DocxParser {
  async parse(buffer) {
    const zip = await JSZip.loadAsync(buffer);
    const [document, styles, numbering, rels, metadata] = await Promise.all([
      this._xml(zip, 'word/document.xml'),
      this._xml(zip, 'word/styles.xml'),
      this._xml(zip, 'word/numbering.xml'),
      this._xml(zip, 'word/_rels/document.xml.rels'),
      this._xml(zip, 'docProps/core.xml'),
    ]);
    const headers = await this._parseHeaders(zip);
    const footers = await this._parseFooters(zip);
    const media   = await this._extractMedia(zip);
    const macros  = await this._extractMacros(zip);
    return {document, styles, numbering, rels, metadata, headers, footers, media, macros};
  }

  async _xml(zip, path) {
    try {
      const f = zip.file(path); if (!f) return null;
      const t = await f.async('string');
      const d = new DOMParser().parseFromString(t, 'text/xml');
      if (d.getElementsByTagName('parsererror').length) return null;
      return d;
    } catch(e) { return null; }
  }

  async _parseHeaders(zip) {
    const h = {};
    for (const p of Object.keys(zip.files))
      if (/^word\/header\d*\.xml$/.test(p))
        h[p.replace('word/','')] = await this._xml(zip, p);
    return h;
  }

  async _parseFooters(zip) {
    const f = {};
    for (const p of Object.keys(zip.files))
      if (/^word\/footer\d*\.xml$/.test(p))
        f[p.replace('word/','')] = await this._xml(zip, p);
    return f;
  }

  async _extractMedia(zip) {
    const mime = {png:'image/png',jpg:'image/jpeg',jpeg:'image/jpeg',gif:'image/gif',
                  bmp:'image/bmp',svg:'image/svg+xml',emf:'image/x-emf',wmf:'image/x-wmf',
                  tiff:'image/tiff',tif:'image/tiff',webp:'image/webp'};
    const m = {};
    for (const [p, f] of Object.entries(zip.files)) {
      if (p.startsWith('word/media/') && !f.dir) {
        try {
          const data = await f.async('base64');
          const ext  = p.split('.').pop().toLowerCase();
          m[p.replace('word/','')] = `data:${mime[ext]||'application/octet-stream'};base64,${data}`;
        } catch(e) {}
      }
    }
    return m;
  }

  async _extractMacros(zip) {
    const f = zip.file('word/vbaProject.bin');
    if (!f) return null;
    try {
      const data = await f.async('uint8array');
      return {present:true, size:data.length, sha256:await this._sha256(data), modules:this._parseVBA(data)};
    } catch(e) { return {present:true, size:0, sha256:null, modules:[], error:e.message}; }
  }

  async _sha256(data) {
    try {
      const buf = await crypto.subtle.digest('SHA-256', data);
      return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');
    } catch(e) { return null; }
  }

  _parseVBA(data) {
    const txt = new TextDecoder('latin1').decode(data);
    const mods = [];
    const nameRe = /Attribute VB_Name = "([^"]+)"/g;
    let m;
    while ((m = nameRe.exec(txt)) !== null) mods.push({name:m[1], source:''});
    const chunks = (txt.match(/[ -~\r\n\t]{60,}/g)||[])
      .filter(c => /\b(Sub|Function|End Sub|End Function|Dim|Set|If|Then|For|MsgBox|Shell|CreateObject|WScript|PowerShell|AutoOpen|Document_Open|Auto_Open)\b/i.test(c));
    const src = chunks.join('\n').trim();
    if (mods.length === 0 && src) mods.push({name:'(extracted)', source:src});
    else if (mods.length > 0 && src) mods[0].source = src;
    return mods;
  }
}

// ════════════════════════════════════════════════════════════════════════════
// StyleResolver
// ════════════════════════════════════════════════════════════════════════════
class StyleResolver {
  constructor(doc) {
    this.styles = {}; this.defaults = {run:{}, para:{}};
    if (doc) { this._parseDefaults(doc); this._parseStyles(doc); }
  }

  _parseDefaults(doc) {
    const dd = wfirst(doc, 'docDefaults'); if (!dd) return;
    const rDef = wfirst(dd,'rPrDefault'); if(rDef){const r=wfirst(rDef,'rPr');if(r)this.defaults.run=this._rpr(r);}
    const pDef = wfirst(dd,'pPrDefault'); if(pDef){const p=wfirst(pDef,'pPr');if(p)this.defaults.para=this._ppr(p);}
  }

  _parseStyles(doc) {
    for (const s of doc.getElementsByTagNameNS(W,'style')) {
      const id = wa(s,'styleId'); if (!id) continue;
      const bo = wfirst(s,'basedOn');
      this.styles[id] = {
        id, type:wa(s,'type'),
        name: (wfirst(s,'name') && wa(wfirst(s,'name'),'val')) || id,
        basedOn: bo ? wa(bo,'val') : null,
        rPr: wfirst(s,'rPr') ? this._rpr(wfirst(s,'rPr')) : {},
        pPr: wfirst(s,'pPr') ? this._ppr(wfirst(s,'pPr')) : {},
      };
    }
  }

  _rpr(el) {
    if (!el) return {};
    const p = {};
    const bool = (tag, key) => {
      const e = wfirst(el,tag); if(e){ const v=wa(e,'val'); p[key]=(v!=='0'&&v!=='false'); }
    };
    bool('b','bold'); bool('i','italic'); bool('strike','strike');
    bool('dstrike','dstrike'); bool('caps','caps'); bool('smallCaps','smallCaps'); bool('vanish','hidden');
    const u=wfirst(el,'u'); if(u){const v=wa(u,'val'); p.underline=(!!v&&v!=='none');}
    const c=wfirst(el,'color'); if(c){const v=wa(c,'val');if(v&&v!=='auto')p.color='#'+v;}
    const sz=wfirst(el,'sz'); if(sz){const v=parseInt(wa(sz,'val')||'');if(!isNaN(v))p.fontSize=v/2;}
    const rf=wfirst(el,'rFonts'); if(rf) p.fontFamily=wa(rf,'ascii')||wa(rf,'hAnsi')||wa(rf,'cs');
    const hl=wfirst(el,'highlight'); if(hl){const v=wa(hl,'val');if(v&&v!=='none')p.highlight=v;}
    const va=wfirst(el,'vertAlign'); if(va) p.vertAlign=wa(va,'val');
    const rs=wfirst(el,'rStyle'); if(rs) p.rStyleId=wa(rs,'val');
    return p;
  }

  _ppr(el) {
    if (!el) return {};
    const p = {};
    const jc=wfirst(el,'jc'); if(jc) p.jc=wa(jc,'val');
    const ind=wfirst(el,'ind');
    if(ind){
      const lv=wa(ind,'left'),rv=wa(ind,'right'),hv=wa(ind,'hanging'),fv=wa(ind,'firstLine');
      if(lv)p.indLeft=parseInt(lv); if(rv)p.indRight=parseInt(rv);
      if(hv)p.indHanging=parseInt(hv); if(fv)p.indFirstLine=parseInt(fv);
    }
    const sp=wfirst(el,'spacing');
    if(sp){
      const bv=wa(sp,'before'),av=wa(sp,'after'),lv=wa(sp,'line'),lr=wa(sp,'lineRule');
      if(bv)p.spaceBefore=parseInt(bv); if(av)p.spaceAfter=parseInt(av);
      if(lv){p.spaceLine=parseInt(lv); p.spaceLineRule=lr||'auto';}
    }
    const shd=wfirst(el,'shd'); if(shd){const f=wa(shd,'fill');if(f&&f!=='auto')p.bgColor='#'+f;}
    const ps=wfirst(el,'pStyle'); if(ps) p.styleId=wa(ps,'val');
    const pb=wfirst(el,'pageBreakBefore'); if(pb) p.pageBreakBefore=(wa(pb,'val')!=='0'&&wa(pb,'val')!=='false');
    const np=wfirst(el,'numPr');
    if(np){
      const ni=wfirst(np,'numId'),il=wfirst(np,'ilvl');
      if(ni) p.numId=wa(ni,'val');
      p.ilvl = il ? parseInt(wa(il,'val')||'0') : 0;
    }
    const pBdr=wfirst(el,'pBdr');
    if(pBdr){
      p.borders={};
      for(const side of ['top','bottom','left','right']){
        const b=wfirst(pBdr,side);
        if(b){const v=wa(b,'val'),sz=wa(b,'sz'),col=wa(b,'color');
          if(v&&v!=='none') p.borders[side]={
            width:sz?parseInt(sz)/8:1, color:col&&col!=='auto'?'#'+col:'#000', style:'solid'
          };
        }
      }
    }
    return p;
  }

  resolveRunStyle(id, _depth=0) {
    if (!id||!this.styles[id]||_depth>10) return {};
    const s=this.styles[id];
    const base = s.basedOn ? this.resolveRunStyle(s.basedOn,_depth+1) : {...this.defaults.run};
    return {...base,...s.rPr};
  }

  resolveParaStyle(id, _depth=0) {
    if (!id||!this.styles[id]||_depth>10) return {pPr:{...this.defaults.para},rPr:{...this.defaults.run}};
    const s=this.styles[id];
    const base = s.basedOn ? this.resolveParaStyle(s.basedOn,_depth+1) : {pPr:{...this.defaults.para},rPr:{...this.defaults.run}};
    return {pPr:{...base.pPr,...s.pPr}, rPr:{...base.rPr,...s.rPr}};
  }

  isHeading(id) {
    if (!id) return null;
    const s=this.styles[id]; if(!s) return null;
    const name=(s.name||'').toLowerCase().replace(/\s+/g,'');
    const m=name.match(/^heading(\d+)$/); if(m) return parseInt(m[1]);
    const m2=id.match(/^[Hh]eading(\d+)$/); if(m2) return parseInt(m2[1]);
    return null;
  }
}

// ════════════════════════════════════════════════════════════════════════════
// NumberingResolver
// ════════════════════════════════════════════════════════════════════════════
class NumberingResolver {
  constructor(doc) {
    this.abstract={}; this.nums={}; this.counters={};
    if(doc) this._parse(doc);
  }

  _parse(doc) {
    for(const an of doc.getElementsByTagNameNS(W,'abstractNum')){
      const id=wa(an,'abstractNumId'); if(!id) continue;
      const levels={};
      for(const lv of an.getElementsByTagNameNS(W,'lvl')){
        const il=parseInt(wa(lv,'ilvl')||'0');
        const nf=wfirst(lv,'numFmt'), lt=wfirst(lv,'lvlText'), st=wfirst(lv,'start'), pp=wfirst(lv,'pPr');
        let indent=null;
        if(pp){const ind=wfirst(pp,'ind');if(ind)indent={left:parseInt(wa(ind,'left')||'0'),hanging:parseInt(wa(ind,'hanging')||'0')};}
        levels[il]={numFmt:nf?wa(nf,'val'):'bullet', lvlText:lt?wa(lt,'val'):'•', start:st?parseInt(wa(st,'val')||'1'):1, indent};
      }
      this.abstract[id]=levels;
    }
    for(const num of doc.getElementsByTagNameNS(W,'num')){
      const id=wa(num,'numId'); if(!id) continue;
      const abd=wfirst(num,'abstractNumId');
      const overrides={};
      for(const ov of num.getElementsByTagNameNS(W,'lvlOverride')){
        const il=parseInt(wa(ov,'ilvl')||'0'); const so=wfirst(ov,'startOverride');
        if(so) overrides[il]=parseInt(wa(so,'val')||'1');
      }
      this.nums[id]={abstractId:abd?wa(abd,'val'):null, overrides};
    }
  }

  getLvl(numId,ilvl){
    const num=this.nums[numId]; if(!num) return null;
    const abs=this.abstract[num.abstractId]; if(!abs) return null;
    const lv=abs[ilvl]||abs[0]; if(!lv) return null;
    const start=num.overrides[ilvl]!==undefined?num.overrides[ilvl]:lv.start;
    return {...lv,start};
  }

  nextCount(numId,ilvl){
    const key=`${numId}:${ilvl}`;
    for(const k of Object.keys(this.counters)){
      const [kn,ki]=k.split(':').map(Number);
      if(kn===parseInt(numId)&&ki>ilvl) delete this.counters[k];
    }
    const lv=this.getLvl(numId,ilvl); const start=lv?lv.start:1;
    if(!(key in this.counters)) this.counters[key]=start;
    else this.counters[key]++;
    return this.counters[key];
  }

  isOrdered(numId,ilvl){const lv=this.getLvl(numId,ilvl); return lv&&lv.numFmt!=='bullet'&&lv.numFmt!=='none';}

  formatMarker(numId,ilvl,count){
    const lv=this.getLvl(numId,ilvl); if(!lv) return `${count}.`;
    if(lv.numFmt==='bullet'){
      const t=lv.lvlText||'•'; if(!t||t.includes('%')) return '•';
      const MAP={'\u2022':'•','\u2023':'▷','\u25e6':'◦','\u2043':'⁃','\uf0b7':'•','\u00b7':'•'};
      return MAP[t]||t;
    }
    if(lv.numFmt==='none') return '';
    const fmt=lv.lvlText||'%1.';
    const cvt=(n,f)=>{
      switch(f){
        case'lowerLetter': return String.fromCharCode(96+(((n-1)%26)+1));
        case'upperLetter': return String.fromCharCode(64+(((n-1)%26)+1));
        case'lowerRoman':  return toRoman(n).toLowerCase();
        case'upperRoman':  return toRoman(n);
        default:           return String(n);
      }
    };
    return fmt.replace(/%(\d)/g, (_,i)=> cvt(count, i==='1'?lv.numFmt:'decimal'));
  }

  reset(){this.counters={};}
}

// ════════════════════════════════════════════════════════════════════════════
// ContentRenderer
// ════════════════════════════════════════════════════════════════════════════
class ContentRenderer {
  constructor(parsed) {
    this.parsed = parsed;
    this.sr  = new StyleResolver(parsed.styles);
    this.nr  = new NumberingResolver(parsed.numbering);
    this.rels = this._buildRelMap(parsed.rels);
    this.pageNum = 0;
  }

  _buildRelMap(doc) {
    const map={};
    if(!doc) return map;
    for(const rel of doc.getElementsByTagNameNS(PKG,'Relationship')){
      const id=rel.getAttribute('Id');
      if(id) map[id]={type:rel.getAttribute('Type'), target:rel.getAttribute('Target'), mode:rel.getAttribute('TargetMode')};
    }
    return map;
  }

  render() {
    const container=document.createElement('div'); container.className='doc-container';
    if(!this.parsed.document){
      const e=document.createElement('p'); e.className='error-inline'; e.textContent='⚠ Failed to parse document.xml';
      container.appendChild(e); return container;
    }
    const body=this.parsed.document.getElementsByTagNameNS(W,'body')[0];
    if(!body){container.textContent='No document body found.';return container;}

    let curSectPr = wfirst(body,'sectPr');
    let curPage = this._newPage(this._pageProp(curSectPr));
    this.pageNum = 1;
    this._addHeader(curPage, curSectPr);
    container.appendChild(curPage);

    const nextPage = (sp) => {
      this._addFooter(curPage, curSectPr);
      const pg = this._newPage(this._pageProp(sp||curSectPr));
      this.pageNum++;
      this._addHeader(pg, sp||curSectPr);
      container.appendChild(pg);
      if(sp) curSectPr=sp;
      return pg;
    };

    for(const child of Array.from(body.childNodes)){
      if(child.nodeType!==1) continue;
      const ln=child.localName;
      try {
        if(ln==='sectPr'){
          curPage=nextPage(child);
        } else if(ln==='p'){
          const {nodes,pgBrkBefore,pgBrkAfter}=this._para(child);
          if(pgBrkBefore) curPage=nextPage();
          for(const n of nodes) curPage.appendChild(n);
          if(pgBrkAfter) curPage=nextPage();
        } else if(ln==='tbl'){
          curPage.appendChild(this._table(child));
        } else if(ln==='sdt'){
          const sc=wfirst(child,'sdtContent');
          if(sc) this._sdtContent(sc, curPage, ()=>{curPage=nextPage(); return curPage;});
        } else if(ln==='AlternateContent'){
          const fb=child.getElementsByTagNameNS(MC_NS,'Fallback')[0];
          if(fb) for(const c of Array.from(fb.childNodes)){
            if(c.nodeType!==1) continue;
            if(c.localName==='p'){const {nodes}=this._para(c);for(const n of nodes)curPage.appendChild(n);}
            else if(c.localName==='tbl') curPage.appendChild(this._table(c));
          }
        }
      } catch(e){
        const err=document.createElement('span'); err.className='error-inline';
        err.textContent=` ⚠[${ln}: ${e.message}] `; curPage.appendChild(err);
      }
    }
    this._addFooter(curPage, curSectPr);
    return container;
  }

  _sdtContent(sc, curPage, getNewPage) {
    for(const c of Array.from(sc.childNodes)){
      if(c.nodeType!==1) continue;
      if(c.localName==='p'){try{const {nodes}=this._para(c);for(const n of nodes)curPage.appendChild(n);}catch(e){}}
      else if(c.localName==='tbl') try{curPage.appendChild(this._table(c));}catch(e){}
    }
  }

  _pageProp(sectPr) {
    const d={w:12240,h:15840,mt:1440,mr:1440,mb:1440,ml:1440};
    if(!sectPr) return d;
    const pgSz=wfirst(sectPr,'pgSz'); if(pgSz){const w=wa(pgSz,'w'),h=wa(pgSz,'h');if(w)d.w=parseInt(w);if(h)d.h=parseInt(h);}
    const pgMar=wfirst(sectPr,'pgMar');
    if(pgMar){const t=wa(pgMar,'top'),r=wa(pgMar,'right'),b=wa(pgMar,'bottom'),l=wa(pgMar,'left');
      if(t)d.mt=parseInt(t);if(r)d.mr=parseInt(r);if(b)d.mb=parseInt(b);if(l)d.ml=parseInt(l);}
    return d;
  }

  _newPage(pp) {
    const div=document.createElement('div'); div.className='page';
    div.style.width=`${dxaToPx(pp.w)}px`; div.style.minHeight=`${dxaToPx(pp.h)}px`;
    div.style.paddingTop=`${dxaToPx(pp.mt)}px`; div.style.paddingRight=`${dxaToPx(pp.mr)}px`;
    div.style.paddingBottom=`${dxaToPx(pp.mb)}px`; div.style.paddingLeft=`${dxaToPx(pp.ml)}px`;
    return div;
  }

  _getHFXml(sectPr, isHeader) {
    if(!sectPr) return this._firstHF(isHeader);
    const tag = isHeader ? 'headerReference' : 'footerReference';
    const store = isHeader ? this.parsed.headers : this.parsed.footers;
    for(const ref of sectPr.getElementsByTagNameNS(W,tag)){
      const type=wa(ref,'type'), rId=ra(ref,'id');
      if((type==='default'||type==='first')&&rId){
        const rel=this.rels[rId];
        if(rel){ const fn=rel.target.replace(/^\.\.\/word\//,'').split('/').pop(); if(store[fn]) return store[fn]; }
      }
    }
    return this._firstHF(isHeader);
  }

  _firstHF(isHeader) {
    const store = isHeader ? this.parsed.headers : this.parsed.footers;
    const vals = Object.values(store); return vals.length ? vals[0] : null;
  }

  _addHeader(page, sectPr) {
    const xml=this._getHFXml(sectPr,true); if(!xml) return;
    const div=document.createElement('div'); div.className='page-header';
    this._renderHF(div,xml); page.insertBefore(div, page.firstChild);
  }

  _addFooter(page, sectPr) {
    const xml=this._getHFXml(sectPr,false); if(!xml) return;
    const div=document.createElement('div'); div.className='page-footer';
    this._renderHF(div,xml); page.appendChild(div);
  }

  _renderHF(container, xmlDoc) {
    const body=xmlDoc.getElementsByTagNameNS(W,'body')[0]||xmlDoc.documentElement;
    for(const c of Array.from(body.childNodes)){
      if(c.nodeType!==1) continue;
      if(c.localName==='p') try{const {nodes}=this._para(c);for(const n of nodes)container.appendChild(n);}catch(e){}
    }
  }

  // ── Paragraph ─────────────────────────────────────────────────────────────
  _para(pEl) {
    const nodes=[]; let pgBrkBefore=false, pgBrkAfter=false;
    const pPr=wfirst(pEl,'pPr');
    const dirPPr=pPr?this.sr._ppr(pPr):{};
    const styleDef=dirPPr.styleId?this.sr.resolveParaStyle(dirPPr.styleId):{pPr:{},rPr:{}};
    const mergedPPr={...styleDef.pPr,...dirPPr};
    const baseRPr={...styleDef.rPr};
    if(mergedPPr.pageBreakBefore) pgBrkBefore=true;
    const hlv=this.sr.isHeading(dirPPr.styleId||mergedPPr.styleId);
    const tag=hlv&&hlv>=1&&hlv<=6?`h${hlv}`:'p';
    const numId=mergedPPr.numId, ilvl=mergedPPr.ilvl||0;
    const isList=numId&&numId!=='0';

    // Detect page break within runs
    let hasPgBrk=false;
    for(const c of pEl.childNodes){
      if(c.nodeType!==1) continue;
      if(c.localName==='r') for(const br of c.getElementsByTagNameNS(W,'br')) if(wa(br,'type')==='page'){hasPgBrk=true;break;}
      if(hasPgBrk) break;
    }
    if(hasPgBrk) pgBrkAfter=true;

    const el=document.createElement(tag);
    el.className=isList?'list-item':'para';
    this._applyPPr(el,mergedPPr,isList);

    if(isList){
      const lv=this.nr.getLvl(numId,ilvl);
      const count=this.nr.nextCount(numId,ilvl);
      const indL=lv?.indent?.left||((ilvl+1)*720);
      const hang=lv?.indent?.hanging||360;
      el.style.paddingLeft=`${dxaToPx(indL)}px`;
      const mk=document.createElement('span'); mk.className='list-marker';
      mk.style.left=`${dxaToPx(indL-hang)}px`; mk.style.width=`${dxaToPx(hang)}px`;
      mk.textContent=this.nr.formatMarker(numId,ilvl,count);
      el.appendChild(mk);
    }
    const allRuns=Array.from(pEl.childNodes).filter(n=>n.nodeType===1);
    this._renderRuns(el,allRuns,baseRPr);
    nodes.push(el);
    return {nodes,pgBrkBefore,pgBrkAfter};
  }

  // ── Run collection ────────────────────────────────────────────────────────
  _renderRuns(container, runEls, baseRPr) {
    for(const el of runEls){
      if(el.nodeType!==1) continue;
      const ln=el.localName;
      try {
        if(ln==='r') this._run(container,el,baseRPr);
        else if(ln==='hyperlink') this._hyperlink(container,el,baseRPr);
        else if(ln==='bookmarkStart'){
          const anc=document.createElement('a'); const nm=wa(el,'name'); if(nm) anc.id=nm; container.appendChild(anc);
        }
        else if(ln==='ins'){for(const c of el.childNodes){if(c.nodeType===1&&c.localName==='r')this._run(container,c,baseRPr);}}
        else if(ln==='smartTag'||ln==='customXml'){
          for(const c of el.childNodes){if(c.nodeType===1&&c.localName==='r')this._run(container,c,baseRPr);}
        }
        else if(ln==='sdt'){
          const sc=wfirst(el,'sdtContent');
          if(sc) for(const c of sc.childNodes){if(c.nodeType===1&&c.localName==='r')this._run(container,c,baseRPr);}
        }
        else if(ln==='fldSimple'){
          const instr=(wa(el,'instr')||'').trim();
          if(/^\s*PAGE\s*$/i.test(instr)){
            const sp=document.createElement('span'); sp.textContent=String(this.pageNum); container.appendChild(sp);
          } else {
            for(const c of el.childNodes){if(c.nodeType===1&&c.localName==='r')this._run(container,c,baseRPr);}
          }
        }
        else if(ln==='AlternateContent'){
          const fb=el.getElementsByTagNameNS(MC_NS,'Fallback')[0];
          if(fb) for(const c of fb.childNodes){if(c.nodeType===1&&c.localName==='r')this._run(container,c,baseRPr);}
        }
      } catch(e){
        const err=document.createElement('span'); err.className='error-inline'; err.textContent='⚠'; container.appendChild(err);
      }
    }
  }

  // ── Single run ────────────────────────────────────────────────────────────
  _run(container, rEl, baseRPr) {
    const rPr=wfirst(rEl,'rPr');
    const dirRPr=rPr?this.sr._rpr(rPr):{};
    const styleRPr=dirRPr.rStyleId?this.sr.resolveRunStyle(dirRPr.rStyleId):{};
    const merged={...baseRPr,...styleRPr,...dirRPr};
    for(const child of rEl.childNodes){
      if(child.nodeType!==1) continue;
      const ln=child.localName;
      if(ln==='t'){
        const txt=child.textContent; if(!txt) continue;
        const sp=document.createElement('span'); this._applyRPr(sp,merged);
        sp.appendChild(document.createTextNode(txt)); container.appendChild(sp);
      } else if(ln==='br'){
        if(wa(child,'type')!=='page') container.appendChild(document.createElement('br'));
      } else if(ln==='tab'){
        const sp=document.createElement('span'); sp.className='tab'; container.appendChild(sp);
      } else if(ln==='drawing') {
        const img=this._drawing(child); if(img) container.appendChild(img);
      } else if(ln==='pict'){
        const img=this._pict(child); if(img) container.appendChild(img);
      } else if(ln==='sym'){
        const sp=document.createElement('span');
        const font=wa(child,'font'), char=wa(child,'char');
        if(font) sp.style.fontFamily=font;
        if(char) sp.appendChild(document.createTextNode(String.fromCharCode(parseInt(char,16))));
        container.appendChild(sp);
      }
    }
  }

  _hyperlink(container, hlEl, baseRPr) {
    // Rendered as a non-clickable span — URL is captured in the security panel only
    const span=document.createElement('span'); span.className='doc-link';
    const rId=ra(hlEl,'id'), anchor=wa(hlEl,'anchor');
    let href=null;
    if(rId&&this.rels[rId]) href=sanitizeUrl(this.rels[rId].target);
    else if(anchor) href='#'+anchor;
    if(href) span.dataset.href=href;
    for(const c of hlEl.childNodes){if(c.nodeType===1&&c.localName==='r')this._run(span,c,baseRPr);}
    container.appendChild(span);
  }

  _drawing(dwEl) {
    try {
      const blip=dwEl.getElementsByTagNameNS(A_NS,'blip')[0]; if(!blip) return null;
      const rId=blip.getAttributeNS(R_NS,'embed')||blip.getAttribute('r:embed');
      if(!rId||!this.rels[rId]) return null;
      const target=this.rels[rId].target.replace(/^\.\.\/word\//,'').replace(/^\//,'');
      const src=this.parsed.media[target]||this.parsed.media[target.replace(/^media\//,'media/')];
      if(!src) return null;
      const img=document.createElement('img'); img.src=src; img.alt='';
      img.style.maxWidth='100%';
      const ext=dwEl.getElementsByTagNameNS(WP_NS,'extent')[0];
      if(ext){const cx=parseInt(ext.getAttribute('cx')||'0'),cy=parseInt(ext.getAttribute('cy')||'0');
        if(cx>0) img.style.width=`${emuToPx(cx)}px`; if(cy>0) img.style.height=`${emuToPx(cy)}px`;}
      return img;
    } catch(e){ return null; }
  }

  _pict(pictEl) {
    try {
      const idata=pictEl.getElementsByTagNameNS(V_NS,'imagedata')[0]; if(!idata) return null;
      const rId=idata.getAttributeNS(R_NS,'id')||idata.getAttribute('r:id');
      if(!rId||!this.rels[rId]) return null;
      const target=this.rels[rId].target.replace(/^\.\.\/word\//,'').replace(/^\//,'');
      const src=this.parsed.media[target]; if(!src) return null;
      const img=document.createElement('img'); img.src=src; img.alt=''; img.style.maxWidth='100%'; return img;
    } catch(e){ return null; }
  }

  // ── Table ─────────────────────────────────────────────────────────────────
  _table(tblEl) {
    const table=document.createElement('table'); table.className='doc-table';
    const tblPr=wfirst(tblEl,'tblPr'); if(tblPr) this._applyTblPr(table,tblPr);
    const tblGrid=wfirst(tblEl,'tblGrid');
    if(tblGrid){
      const cg=document.createElement('colgroup');
      for(const gc of tblGrid.getElementsByTagNameNS(W,'gridCol')){
        const col=document.createElement('col'); const w=wa(gc,'w');
        if(w) col.style.width=`${dxaToPx(parseInt(w))}px`; cg.appendChild(col);
      }
      table.appendChild(cg);
    }
    const tbody=document.createElement('tbody');
    for(const trEl of wdirect(tblEl,'tr')){
      const tr=document.createElement('tr');
      const trPr=wfirst(trEl,'trPr');
      if(trPr){const trH=wfirst(trPr,'trHeight');if(trH){const v=wa(trH,'val');if(v)tr.style.height=`${dxaToPx(parseInt(v))}px`;}}
      let colIdx=0;
      for(const tcEl of wdirect(trEl,'tc')){
        const tcPr=wfirst(tcEl,'tcPr');
        const vMergeEl=tcPr?wfirst(tcPr,'vMerge'):null;
        const vMergeVal=vMergeEl?wa(vMergeEl,'val'):null;
        const isCont=vMergeEl&&vMergeVal!=='restart';
        if(isCont){const gs=tcPr?wfirst(tcPr,'gridSpan'):null; colIdx+=gs?parseInt(wa(gs,'val')||'1'):1; continue;}
        const gsEl=tcPr?wfirst(tcPr,'gridSpan'):null;
        const colspan=gsEl?parseInt(wa(gsEl,'val')||'1'):1;
        const td=document.createElement('td');
        if(colspan>1) td.setAttribute('colspan',colspan);
        if(vMergeEl&&vMergeVal==='restart'){
          let rs=1, nx=trEl.nextElementSibling;
          while(nx){
            let ci=0,found=false;
            for(const ntc of wdirect(nx,'tc')){
              if(ci===colIdx){
                const nPr=wfirst(ntc,'tcPr'),nvm=nPr?wfirst(nPr,'vMerge'):null;
                if(nvm&&wa(nvm,'val')!=='restart'){rs++;found=true;} break;
              }
              const ngs=wfirst(wfirst(ntc,'tcPr')||ntc,'gridSpan');
              ci+=ngs?parseInt(wa(ngs,'val')||'1'):1;
            }
            if(!found) break; nx=nx.nextElementSibling;
          }
          if(rs>1) td.setAttribute('rowspan',rs);
        }
        if(tcPr) this._applyTcPr(td,tcPr);
        for(const cc of Array.from(tcEl.childNodes)){
          if(cc.nodeType!==1) continue;
          if(cc.localName==='p'){try{const {nodes}=this._para(cc);for(const n of nodes)td.appendChild(n);}catch(e){}}
          else if(cc.localName==='tbl') try{td.appendChild(this._table(cc));}catch(e){}
          else if(cc.localName==='sdt'){
            const sc=wfirst(cc,'sdtContent');
            if(sc) for(const c of sc.childNodes){
              if(c.nodeType===1&&c.localName==='p'){try{const {nodes}=this._para(c);for(const n of nodes)td.appendChild(n);}catch(e){}}
            }
          }
        }
        tr.appendChild(td); colIdx+=colspan;
      }
      tbody.appendChild(tr);
    }
    table.appendChild(tbody); return table;
  }

  // ── Style application ─────────────────────────────────────────────────────
  _applyPPr(el, pp, skipIndent) {
    const jcMap={center:'center',right:'right',both:'justify',distribute:'justify',left:'left'};
    if(pp.jc&&jcMap[pp.jc]) el.style.textAlign=jcMap[pp.jc];
    if(!skipIndent){
      if(pp.indLeft) el.style.marginLeft=`${dxaToPx(pp.indLeft)}px`;
      if(pp.indRight) el.style.marginRight=`${dxaToPx(pp.indRight)}px`;
      if(pp.indHanging){el.style.paddingLeft=`${dxaToPx(pp.indHanging)}px`;el.style.textIndent=`-${dxaToPx(pp.indHanging)}px`;}
      else if(pp.indFirstLine) el.style.textIndent=`${dxaToPx(pp.indFirstLine)}px`;
    }
    if(pp.spaceBefore!==undefined) el.style.marginTop=`${twipToPt(pp.spaceBefore)}pt`;
    if(pp.spaceAfter!==undefined)  el.style.marginBottom=`${twipToPt(pp.spaceAfter)}pt`;
    if(pp.spaceLine!==undefined){
      if(pp.spaceLineRule==='exact'||pp.spaceLineRule==='atLeast') el.style.lineHeight=`${twipToPt(pp.spaceLine)}pt`;
      else el.style.lineHeight=`${pp.spaceLine/240}`;
    }
    if(pp.bgColor) el.style.backgroundColor=pp.bgColor;
    if(pp.borders) for(const[s,b] of Object.entries(pp.borders)){
      el.style[`border${s[0].toUpperCase()+s.slice(1)}`]=`${b.width}px ${b.style} ${b.color}`;
      if(s==='left'||s==='right') el.style[`padding${s[0].toUpperCase()+s.slice(1)}`]='4px';
    }
  }

  _applyRPr(el, rp) {
    if(!rp) return;
    const decs=[];
    if(rp.underline) decs.push('underline');
    if(rp.strike||rp.dstrike) decs.push('line-through');
    if(decs.length) el.style.textDecoration=decs.join(' ');
    if(rp.bold) el.style.fontWeight='bold';
    if(rp.italic) el.style.fontStyle='italic';
    if(rp.color) el.style.color=rp.color;
    if(rp.fontSize) el.style.fontSize=`${rp.fontSize}pt`;
    if(rp.fontFamily) el.style.fontFamily=`"${rp.fontFamily}",sans-serif`;
    if(rp.highlight){
      const hl={yellow:'#FFFF00',green:'#00FF00',cyan:'#00FFFF',magenta:'#FF00FF',blue:'#0000FF',
                red:'#FF0000',darkBlue:'#000080',darkCyan:'#008080',darkGreen:'#008000',
                darkMagenta:'#800080',darkRed:'#800000',darkYellow:'#808000',
                darkGray:'#808080',lightGray:'#C0C0C0',black:'#000000',white:'#FFFFFF'};
      const c=hl[rp.highlight]; if(c) el.style.backgroundColor=c;
    }
    if(rp.vertAlign==='superscript'){el.style.verticalAlign='super';el.style.fontSize='0.75em';}
    else if(rp.vertAlign==='subscript'){el.style.verticalAlign='sub';el.style.fontSize='0.75em';}
    if(rp.caps) el.style.textTransform='uppercase';
    if(rp.smallCaps) el.style.fontVariant='small-caps';
    if(rp.hidden){el.style.backgroundColor='#ffffc0';el.title='Hidden text';}
  }

  _applyTblPr(table, tblPr) {
    table.style.borderCollapse='collapse';
    const tblW=wfirst(tblPr,'tblW');
    if(tblW){const w=wa(tblW,'w'),t=wa(tblW,'type');
      if(t==='pct'&&w) table.style.width=`${parseInt(w)/5000*100}%`;
      else if(t==='dxa'&&w) table.style.width=`${dxaToPx(parseInt(w))}px`;
      else if(t==='auto') table.style.width='auto';}
    const jc=wfirst(tblPr,'jc'); if(jc){const v=wa(jc,'val');
      if(v==='center'){table.style.marginLeft='auto';table.style.marginRight='auto';}
      else if(v==='right') table.style.marginLeft='auto';}
    const shd=wfirst(tblPr,'shd'); if(shd){const f=wa(shd,'fill');if(f&&f!=='auto')table.style.backgroundColor='#'+f;}
  }

  _applyTcPr(td, tcPr) {
    const va=wfirst(tcPr,'vAlign'); if(va){const v=wa(va,'val');td.style.verticalAlign=v==='center'?'middle':v==='bottom'?'bottom':'top';}
    const shd=wfirst(tcPr,'shd'); if(shd){const f=wa(shd,'fill');if(f&&f!=='auto')td.style.backgroundColor='#'+f;}
    const tcBd=wfirst(tcPr,'tcBorders');
    if(tcBd) for(const s of ['top','bottom','left','right']){
      const b=wfirst(tcBd,s); if(b){const v=wa(b,'val'),sz=wa(b,'sz'),c=wa(b,'color');
        if(v&&v!=='none'){const w2=sz?`${parseInt(sz)/8}px`:'1px',col=c&&c!=='auto'?'#'+c:'#ccc';
          td.style[`border${s[0].toUpperCase()+s.slice(1)}`]=`${w2} solid ${col}`;}}
    }
    const tcW=wfirst(tcPr,'tcW'); if(tcW){const w=wa(tcW,'w'),t=wa(tcW,'type');if(t==='dxa'&&w)td.style.width=`${dxaToPx(parseInt(w))}px`;}
    const tcMar=wfirst(tcPr,'tcMar');
    if(tcMar) for(const s of ['top','bottom','left','right']){
      const m=wfirst(tcMar,s); if(m){const w=wa(m,'w');if(w)td.style[`padding${s[0].toUpperCase()+s.slice(1)}`]=`${dxaToPx(parseInt(w))}px`;}
    }
  }
}

// ════════════════════════════════════════════════════════════════════════════
// SecurityAnalyzer
// ════════════════════════════════════════════════════════════════════════════
class SecurityAnalyzer {
  analyze(parsed) {
    const f={hasMacros:false,autoExec:[],externalRefs:[],modules:[],metadata:{},risk:'low',macroSize:0,macroHash:null};
    if(parsed.metadata) f.metadata=this._metadata(parsed.metadata);
    if(parsed.macros?.present){
      f.hasMacros=true; f.modules=parsed.macros.modules||[];
      f.macroSize=parsed.macros.size||0; f.macroHash=parsed.macros.sha256;
      for(const m of f.modules) if(m.source){const p=this._patterns(m.source);if(p.length)f.autoExec.push({module:m.name,patterns:p});}
    }
    f.externalRefs=this._externalRefs(parsed);
    if(f.hasMacros&&f.autoExec.length) f.risk='high';
    else if(f.hasMacros||f.externalRefs.length) f.risk='medium';
    return f;
  }

  _metadata(doc) {
    const g=(ns,nm)=>doc.getElementsByTagNameNS(ns,nm)[0]?.textContent?.trim()||null;
    const DC='http://purl.org/dc/elements/1.1/', CP='http://schemas.openxmlformats.org/package/2006/metadata/core-properties', DT='http://purl.org/dc/terms/';
    return {title:g(DC,'title'),subject:g(DC,'subject'),creator:g(DC,'creator'),
            lastModifiedBy:g(CP,'lastModifiedBy'),revision:g(CP,'revision'),created:g(DT,'created'),modified:g(DT,'modified')};
  }

  _patterns(src) {
    const pats=[
      [/\bAutoOpen\b/i,'AutoOpen (auto-execute)'],[/\bDocument_Open\b/i,'Document_Open (auto-execute)'],
      [/\bAuto_Open\b/i,'Auto_Open (auto-execute)'],[/\bWorkbook_Open\b/i,'Workbook_Open (auto-execute)'],
      [/\bShell\s*\(/i,'Shell()'],[/WScript\.Shell/i,'WScript.Shell'],
      [/CreateObject\s*\(\s*["']WScript/i,'CreateObject(WScript)'],[/CreateObject\s*\(\s*["']Scripting/i,'CreateObject(Scripting)'],
      [/\bPowerShell\b/i,'PowerShell'],[/cmd\.exe/i,'cmd.exe'],[/cmd\s+\/c/i,'cmd /c'],
      [/URLDownloadToFile/i,'URLDownloadToFile'],[/XMLHTTP/i,'XMLHTTP (network)'],[/WinHttpRequest/i,'WinHttpRequest (network)'],
      [/\bRegWrite\b/i,'RegWrite'],[/\bRegDelete\b/i,'RegDelete'],[/\bKill\b/i,'Kill (delete files)'],
      [/\bEnviron\b/i,'Environ'],[/\bGetObject\b/i,'GetObject'],[/\bCallByName\b/i,'CallByName'],
    ];
    return pats.filter(([re])=>re.test(src)).map(([,name])=>name);
  }

  _externalRefs(parsed) {
    const refs=[];
    if(!parsed.rels) return refs;
    const typeNames={
      'hyperlink':'Hyperlink','image':'External Image','oleObject':'OLE Object',
      'frame':'External Frame','subDocument':'Sub-Document','attachedTemplate':'Template Injection','externalLinkPath':'External Link',
    };
    for(const rel of parsed.rels.getElementsByTagNameNS(PKG,'Relationship')){
      const mode=rel.getAttribute('TargetMode'), target=rel.getAttribute('Target'), type=rel.getAttribute('Type')||'';
      if(mode==='External'&&target){
        const typeName=Object.entries(typeNames).find(([k])=>type.endsWith('/'+k))?.[1]||'External';
        refs.push({type:typeName,url:target,severity:typeName==='Hyperlink'?'info':typeName==='External Image'?'medium':'high'});
      }
    }
    return refs;
  }

  highlightVBA(src) {
    const esc=src.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    return esc.replace(/\b(AutoOpen|Document_Open|Auto_Open|Workbook_Open|Shell|WScript\.Shell|PowerShell|cmd\.exe|URLDownloadToFile|XMLHTTP|WinHttpRequest|RegWrite|RegDelete|Kill|CreateObject|GetObject|CallByName|Environ)\b/gi,'<mark class="vba-danger">$&</mark>');
  }
}

// ════════════════════════════════════════════════════════════════════════════
// App
// ════════════════════════════════════════════════════════════════════════════
class App {
  constructor() { this.zoom=100; this.dark=true; this.secExp=false; this.findings=null; }

  init() {
    // Dark mode on by default
    document.body.classList.add('dark');
    document.getElementById('btn-theme').textContent = '☀';
    this._setupDrop();
    this._setupToolbar();
  }

  _setupDrop() {
    const dz=document.getElementById('drop-zone'), fi=document.getElementById('file-input');
    window.addEventListener('dragover',e=>{e.preventDefault();e.stopPropagation();});
    window.addEventListener('drop',e=>{e.preventDefault();e.stopPropagation();this._handleFiles(e.dataTransfer?.files);});
    dz.addEventListener('dragover',e=>{e.preventDefault();dz.classList.add('drag-over');});
    dz.addEventListener('dragleave',()=>dz.classList.remove('drag-over'));
    dz.addEventListener('drop',e=>{e.preventDefault();dz.classList.remove('drag-over');this._handleFiles(e.dataTransfer?.files);});
    dz.addEventListener('click',()=>fi.click());
    fi.addEventListener('change',e=>{const f=e.target.files[0];if(f)this._loadFile(f);fi.value='';});
  }

  _setupToolbar() {
    document.getElementById('btn-open').addEventListener('click',()=>document.getElementById('file-input').click());
    document.getElementById('btn-security').addEventListener('click',()=>this._toggleSecPanel());
    document.getElementById('btn-zoom-out').addEventListener('click',()=>this._setZoom(this.zoom-10));
    document.getElementById('btn-zoom-in').addEventListener('click',()=>this._setZoom(this.zoom+10));
    document.getElementById('btn-theme').addEventListener('click',()=>this._toggleTheme());
    document.getElementById('security-header').addEventListener('click',()=>this._toggleSecBody());
  }

  _handleFiles(files) {
    if(!files||!files.length) return;
    const f=files[0];
    if(!/\.(docx|docm|xlsx|xlsm|xls|ods|pptx|pptm|csv|tsv|doc|msg)$/i.test(f.name)){
      this._toast('Unsupported file type. Supported: .docx .xlsx .xls .pptx .csv .doc .msg and more','error'); return;
    }
    this._loadFile(f);
  }

  async _loadFile(file) {
    this._setLoading(true);
    document.getElementById('file-info').textContent=file.name;
    const ext=file.name.split('.').pop().toLowerCase();
    try {
      const buffer=await file.arrayBuffer();
      let docEl;

      if(['docx','docm'].includes(ext)){
        const parsed=await new DocxParser().parse(buffer);
        const analyzer=new SecurityAnalyzer();
        this.findings=analyzer.analyze(parsed);
        this._renderSecPanel(analyzer);
        docEl=new ContentRenderer(parsed).render();
      } else if(['xlsx','xlsm','xls','ods'].includes(ext)){
        const r=new XlsxRenderer();
        this.findings=await r.analyzeForSecurity(buffer,file.name);
        this._renderSecPanelGeneric();
        docEl=r.render(buffer,file.name);
      } else if(['pptx','pptm'].includes(ext)){
        const r=new PptxRenderer();
        this.findings=await r.analyzeForSecurity(buffer,file.name);
        this._renderSecPanelGeneric();
        docEl=await r.render(buffer);
      } else if(['csv','tsv'].includes(ext)){
        const text=await file.text();
        const r=new CsvRenderer();
        this.findings=r.analyzeForSecurity(text);
        this._renderSecPanelGeneric();
        docEl=r.render(text,file.name);
      } else if(ext==='doc'){
        const r=new DocBinaryRenderer();
        this.findings=r.analyzeForSecurity(buffer);
        this._renderSecPanelGeneric();
        docEl=r.render(buffer);
      } else if(ext==='msg'){
        const r=new MsgRenderer();
        this.findings=r.analyzeForSecurity(buffer);
        this._renderSecPanelGeneric();
        docEl=r.render(buffer);
      } else {
        throw new Error(`Unsupported format: .${ext}`);
      }

      const pc=document.getElementById('page-container');
      pc.innerHTML=''; pc.appendChild(docEl);

      const dz=document.getElementById('drop-zone');
      dz.className='has-document'; dz.innerHTML='';
      const sp=document.createElement('span'); sp.textContent='📁 Drop another file to open'; dz.appendChild(sp);

      const panel=document.getElementById('security-panel'); panel.classList.remove('hidden');
      if(this.findings.risk!=='low'&&!this.secExp) this._toggleSecBody();

      const pages=pc.querySelectorAll('.page').length;
      const pi=pages>0?`  ·  ${pages} page${pages!==1?'s':''}`:'';
      document.getElementById('file-info').textContent=`${file.name}${pi}  ·  ${this._fmtBytes(file.size)}`;
    } catch(e){
      console.error(e);
      this._toast(`Failed to open: ${e.message}`,'error');
      const pc=document.getElementById('page-container');
      pc.innerHTML='';
      const eb=document.createElement('div'); eb.className='error-box';
      const h3=document.createElement('h3'); h3.textContent='Failed to open file'; eb.appendChild(h3);
      const p1=document.createElement('p'); p1.textContent=e.message; eb.appendChild(p1);
      pc.appendChild(eb);
    } finally {
      this._setLoading(false);
    }
  }

  _renderSecPanel(analyzer) {
    const f=this.findings;
    const header=document.getElementById('security-header');
    const body=document.getElementById('security-body');
    const title=document.getElementById('security-title');
    header.className=`security-header risk-${f.risk}`;
    title.textContent=f.risk==='high'?'🔴 HIGH RISK — Macros with auto-execute detected':
                      f.risk==='medium'?(f.hasMacros?'🟡 Macros present in document':'🟡 External references detected'):
                      '🟢 No macros · No external references';
    body.innerHTML=''; // safe – no user content injected here

    // Metadata
    const metaVals=Object.entries(f.metadata).filter(([,v])=>v);
    if(metaVals.length){
      const h3=document.createElement('h3'); h3.textContent='Document Metadata'; body.appendChild(h3);
      const tbl=document.createElement('table'); tbl.className='security-table';
      const labels={title:'Title',subject:'Subject',creator:'Author',lastModifiedBy:'Last Modified By',created:'Created',modified:'Modified',revision:'Revision'};
      for(const [k,v] of metaVals){
        const tr=document.createElement('tr');
        const th=document.createElement('th'); th.textContent=labels[k]||k;
        const td=document.createElement('td'); td.textContent=v;
        tr.appendChild(th); tr.appendChild(td); tbl.appendChild(tr);
      }
      body.appendChild(tbl);
    }

    // Macros
    if(f.hasMacros){
      const h3=document.createElement('h3'); h3.textContent='⚠ Macros Detected'; h3.style.marginTop='14px'; body.appendChild(h3);
      const sz=document.createElement('p'); sz.textContent=`VBA project: ${this._fmtBytes(f.macroSize)}`; body.appendChild(sz);
      if(f.macroHash){const hp=document.createElement('p');hp.style.cssText='font-family:monospace;font-size:11px;word-break:break-all';hp.textContent='SHA-256: '+f.macroHash;body.appendChild(hp);}
      // Download button — always shown when macros are present
      {
        const dlBtn=document.createElement('button'); dlBtn.className='tb-btn';
        dlBtn.style.cssText='margin-top:10px;font-size:12px;display:block;';
        const hasSource=f.modules&&f.modules.some(m=>m.source);
        dlBtn.textContent=hasSource?'💾 Download Macros (.txt)':'💾 Download Macros (binary .bin)';
        dlBtn.title=hasSource?'Save decoded VBA source as .txt':'Save raw vbaProject.bin (source could not be decoded as text)';
        dlBtn.addEventListener('click',()=>this._downloadMacros());
        body.appendChild(dlBtn);
      }
      if(f.autoExec.length){
        const wp=document.createElement('p');wp.style.cssText='color:#721c24;font-weight:bold;margin-top:8px';wp.textContent='🚨 Auto-execute patterns:';body.appendChild(wp);
        const ul=document.createElement('ul');
        for(const {module,patterns} of f.autoExec) for(const pat of patterns){const li=document.createElement('li');li.textContent=`${module}: ${pat}`;ul.appendChild(li);}
        body.appendChild(ul);
      }
      for(const mod of f.modules){
        if(!mod.source) continue;
        const det=document.createElement('details'); det.style.marginTop='8px';
        const sum=document.createElement('summary');sum.style.cursor='pointer';sum.style.fontWeight='600';sum.style.fontSize='12px';
        sum.textContent=`VBA Module: ${mod.name}`; det.appendChild(sum);
        const pre=document.createElement('pre'); pre.className='vba-code';
        pre.innerHTML=analyzer.highlightVBA(mod.source); // safe: content is escaped in highlightVBA
        det.appendChild(pre); body.appendChild(det);
      }
    }

    // External refs
    if(f.externalRefs.length){
      const h3=document.createElement('h3'); h3.textContent='External References'; h3.style.marginTop='14px'; body.appendChild(h3);
      const tbl=document.createElement('table'); tbl.className='security-table';
      const thead=document.createElement('thead'); const htr=document.createElement('tr');
      for(const h of ['Type','URL','Risk']){const th=document.createElement('th');th.textContent=h;htr.appendChild(th);}
      thead.appendChild(htr); tbl.appendChild(thead);
      const tbody=document.createElement('tbody');
      for(const ref of f.externalRefs){
        const tr=document.createElement('tr');
        const td1=document.createElement('td');td1.textContent=ref.type;
        const td2=document.createElement('td');td2.style.cssText='font-family:monospace;font-size:11px;word-break:break-all';
        td2.appendChild(document.createTextNode(ref.url));
        const copyBtn=document.createElement('button');copyBtn.className='copy-url-btn';copyBtn.textContent='📋';copyBtn.title='Copy URL';
        copyBtn.addEventListener('click',(e)=>{e.stopPropagation();this._copyToClipboard(ref.url);});
        td2.appendChild(copyBtn);
        const td3=document.createElement('td');const badge=document.createElement('span');badge.className=`badge badge-${ref.severity}`;badge.textContent=ref.severity;td3.appendChild(badge);
        tr.appendChild(td1);tr.appendChild(td2);tr.appendChild(td3);tbody.appendChild(tr);
      }
      tbl.appendChild(tbody); body.appendChild(tbl);
    }

    if(!f.hasMacros&&!f.externalRefs.length){const ok=document.createElement('p');ok.style.color='#155724';ok.textContent='✅ No security threats found.';body.appendChild(ok);}
  }

  _renderSecPanelGeneric() {
    const f=this.findings;
    const header=document.getElementById('security-header');
    const body=document.getElementById('security-body');
    const title=document.getElementById('security-title');
    header.className=`security-header risk-${f.risk}`;
    title.textContent=f.risk==='high'?'🔴 HIGH RISK — Dangerous content detected':
                      f.risk==='medium'?(f.hasMacros?'🟡 Macros present':'🟡 Potential risks detected'):
                      '🟢 No threats detected';
    body.innerHTML='';
    const metaVals=Object.entries(f.metadata||{}).filter(([,v])=>v);
    if(metaVals.length){
      const h3=document.createElement('h3'); h3.textContent='File Metadata'; body.appendChild(h3);
      const tbl=document.createElement('table'); tbl.className='security-table';
      const labels={title:'Title',subject:'Subject',creator:'Author/Sender',lastModifiedBy:'Last Modified By',created:'Created',modified:'Modified'};
      for(const[k,v] of metaVals){const tr=document.createElement('tr');const th=document.createElement('th');th.textContent=labels[k]||k;const td=document.createElement('td');td.textContent=v;tr.appendChild(th);tr.appendChild(td);tbl.appendChild(tr);}
      body.appendChild(tbl);
    }
    if(f.hasMacros){
      const h3=document.createElement('h3');h3.textContent='⚠ Macros Detected';h3.style.marginTop='14px';body.appendChild(h3);
      if(f.macroSize){const sz=document.createElement('p');sz.textContent=`VBA project: ${this._fmtBytes(f.macroSize)}`;body.appendChild(sz);}
      const dlBtn=document.createElement('button');dlBtn.className='tb-btn';
      dlBtn.style.cssText='margin-top:10px;font-size:12px;display:block;';
      const hasSource=f.modules&&f.modules.some(m=>m.source);
      dlBtn.textContent=hasSource?'💾 Download Macros (.txt)':'💾 Download Macros (.bin)';
      dlBtn.addEventListener('click',()=>this._downloadMacros());
      body.appendChild(dlBtn);
    }
    if(f.externalRefs&&f.externalRefs.length){
      const h3=document.createElement('h3');h3.textContent='References & Risks';h3.style.marginTop='14px';body.appendChild(h3);
      const tbl=document.createElement('table');tbl.className='security-table';
      const thead=document.createElement('thead');const htr=document.createElement('tr');
      for(const h of ['Type','Details','Risk']){const th=document.createElement('th');th.textContent=h;htr.appendChild(th);}
      thead.appendChild(htr);tbl.appendChild(thead);
      const tbody=document.createElement('tbody');
      for(const ref of f.externalRefs){
        const tr=document.createElement('tr');
        const td1=document.createElement('td');td1.textContent=ref.type;
        const td2=document.createElement('td');td2.style.cssText='font-family:monospace;font-size:11px;word-break:break-all';
        td2.appendChild(document.createTextNode(ref.url));
        const copyBtn=document.createElement('button');copyBtn.className='copy-url-btn';copyBtn.textContent='📋';copyBtn.title='Copy URL';
        copyBtn.addEventListener('click',(e)=>{e.stopPropagation();this._copyToClipboard(ref.url);});
        td2.appendChild(copyBtn);
        const td3=document.createElement('td');const badge=document.createElement('span');badge.className=`badge badge-${ref.severity}`;badge.textContent=ref.severity;td3.appendChild(badge);
        tr.appendChild(td1);tr.appendChild(td2);tr.appendChild(td3);tbody.appendChild(tr);
      }
      tbl.appendChild(tbody);body.appendChild(tbl);
    }
    if(!f.hasMacros&&(!f.externalRefs||!f.externalRefs.length)){const ok=document.createElement('p');ok.style.color='#155724';ok.textContent='No security threats found.';body.appendChild(ok);}
  }

  _copyToClipboard(text) {
    if(navigator.clipboard&&navigator.clipboard.writeText){
      navigator.clipboard.writeText(text).then(()=>this._toast('URL copied to clipboard')).catch(()=>this._copyFallback(text));
    } else { this._copyFallback(text); }
  }
  _copyFallback(text) {
    const ta=document.createElement('textarea'); ta.value=text;
    ta.style.cssText='position:fixed;opacity:0;top:0;left:0;';
    document.body.appendChild(ta); ta.focus(); ta.select();
    try{ document.execCommand('copy'); this._toast('URL copied to clipboard'); }
    catch(e){ this._toast('Copy failed — select manually','error'); }
    document.body.removeChild(ta);
  }

  _downloadMacros() {
    const f=this.findings;
    const mods=(f.modules||[]).filter(m=>m.source);
    if(!mods.length){this._toast('No decoded macro source available','error');return;}
    const sep='='.repeat(60);
    const lines=[];
    for(const mod of mods){
      lines.push(`' ${sep}`);
      lines.push(`' VBA Module: ${mod.name}`);
      lines.push(`' ${sep}`);
      lines.push(mod.source);
      lines.push('');
    }
    const blob=new Blob([lines.join('\n')],{type:'text/plain'});
    const url=URL.createObjectURL(blob);
    const a=document.createElement('a');
    a.href=url;
    const info=document.getElementById('file-info').textContent;
    const base=info.split('·')[0].trim().replace(/\.[^.]+$/,'')||'macros';
    a.download=base+'_macros.txt';
    a.click();
    URL.revokeObjectURL(url);
    this._toast('Macro source downloaded');
  }

  _toggleSecPanel(){document.getElementById('security-panel').classList.toggle('hidden');}
  _toggleSecBody(){
    const body=document.getElementById('security-body');
    const arrow=document.querySelector('#security-header .toggle-arrow');
    this.secExp=!this.secExp;
    body.classList.toggle('collapsed',!this.secExp);
    if(arrow) arrow.textContent=this.secExp?'▲':'▼';
  }
  _setZoom(z){
    this.zoom=Math.min(200,Math.max(50,z));
    document.getElementById('zoom-level').textContent=`${this.zoom}%`;
    document.getElementById('page-container').style.transform=`scale(${this.zoom/100})`;
  }
  _toggleTheme(){this.dark=!this.dark;document.body.classList.toggle('dark',this.dark);document.getElementById('btn-theme').textContent=this.dark?'☀':'🌙';}
  _setLoading(on){document.getElementById('loading').classList.toggle('hidden',!on);}
  _toast(msg,type='info'){
    const t=document.getElementById('toast');t.textContent=msg;
    t.className=type==='error'?'toast-error':'';t.classList.remove('hidden');
    setTimeout(()=>t.classList.add('hidden'),3500);
  }
  _fmtBytes(b){if(b<1024)return b+' B';if(b<1048576)return(b/1024).toFixed(1)+' KB';return(b/1048576).toFixed(1)+' MB';}
}

document.addEventListener('DOMContentLoaded', () => new App().init());
