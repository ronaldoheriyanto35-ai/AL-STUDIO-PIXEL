const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = __dirname;
const PUBLIC = path.join(ROOT, 'public');
const DATA = path.join(ROOT, 'data');
const UPLOADS = path.join(ROOT, 'uploads');
const PORT = Number(process.env.PORT || 3000);
const MAX_BODY = 18 * 1024 * 1024;
const MIME = {'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.json':'application/json; charset=utf-8','.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.webp':'image/webp','.svg':'image/svg+xml','.rbxm':'application/octet-stream','.rbxmx':'application/xml; charset=utf-8','.txt':'text/plain; charset=utf-8','.luau':'text/plain; charset=utf-8','.lua':'text/plain; charset=utf-8','.zip':'application/zip'};

function json(res, status, data) {
  res.writeHead(status, {'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});
  res.end(JSON.stringify(data));
}
function readJson(file, fallback=[]) {
  try { return JSON.parse(fs.readFileSync(file,'utf8')); } catch { return fallback; }
}
function writeJson(file, value) {
  fs.writeFileSync(file, JSON.stringify(value, null, 2), 'utf8');
}
function readBody(req) {
  return new Promise((resolve,reject)=>{
    let chunks=[], size=0;
    req.on('data', c=>{size+=c.length;if(size>MAX_BODY){reject(new Error('Request terlalu besar (maksimum 18 MB).'));req.destroy();return;}chunks.push(c);});
    req.on('end',()=>{try{resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')||'{}'));}catch{reject(new Error('JSON tidak valid.'));}});
    req.on('error',reject);
  });
}
function cleanName(s) {
  return String(s||'file').normalize('NFKD').replace(/[^a-zA-Z0-9._-]+/g,'_').replace(/^\.|\.\./g,'_').slice(0,90) || 'file';
}
function sendFile(res, file, download=false) {
  fs.readFile(file,(err,buf)=>{
    if(err){res.writeHead(404);res.end('Not found');return;}
    const ext=path.extname(file).toLowerCase();
    res.writeHead(200, {'Content-Type':MIME[ext]||'application/octet-stream','X-Content-Type-Options':'nosniff',...(download?{'Content-Disposition':`attachment; filename="${path.basename(file)}"`}:{})});
    res.end(buf);
  });
}
function scanLuau(source) {
  const lines=String(source||'').split(/\r?\n/), findings=[];
  const checks=[
    {re:/\bwhile\s+true\s+do\b/i,severity:'warning',title:'Loop tanpa jeda',detail:'Loop while true tanpa task.wait() atau mekanisme yield dapat membuat script berat atau hang.'},
    {re:/\bwhile\s+.+\s+do\b/i,severity:'info',title:'Loop while',detail:'Pastikan loop berhenti saat tidak diperlukan dan memberi kesempatan scheduler berjalan.'},
    {re:/\b(loadstring|HttpGet|GetAsync|PostAsync)\b/i,severity:'warning',title:'Pemanggilan kode/jaringan',detail:'Periksa sumber dan kebutuhan pemanggilan ini. Pola ini tidak otomatis berbahaya, tetapi perlu ditinjau.'},
    {re:/\brequire\s*\(\s*\d+\s*\)/i,severity:'warning',title:'require dengan asset ID',detail:'Pastikan module ID dikenal dan dipercaya. Module eksternal dapat menjalankan kode.'},
    {re:/\b(game|workspace|script)\s*:\s*Destroy\s*\(/i,severity:'warning',title:'Pemanggilan Destroy',detail:'Pastikan objek yang dihancurkan memang target yang benar.'},
    {re:/\bFireServer\s*\(/i,severity:'info',title:'RemoteEvent dari client',detail:'Validasi semua data ini di server; jangan percaya input client.'},
    {re:/\bOnServerEvent\b/i,severity:'info',title:'Handler RemoteEvent',detail:'Pastikan handler memeriksa tipe, jarak, kepemilikan, dan rate limit.'},
    {re:/\bwhile\s+.+\s+do\b/i,severity:'info',title:'Loop perlu ditinjau',detail:'Periksa exit condition dan apakah ada yield di dalam loop.'},
    {re:/\bgetfenv\s*\(|\bsetfenv\s*\(/i,severity:'warning',title:'Environment dinamis',detail:'Fungsi environment dapat membuat alur kode lebih sulit diaudit.'},
    {re:/\bTeleportService\b/i,severity:'info',title:'TeleportService',detail:'Pastikan teleportasi hanya dilakukan pada kondisi yang diharapkan.'},
    {re:/\bDataStoreService\b/i,severity:'info',title:'DataStore',detail:'Tangani kegagalan dengan pcall dan pertimbangkan batas request.'},
    {re:/\bpcall\s*\(/i,severity:'info',title:'Pemanggilan pcall',detail:'Pastikan error tidak disembunyikan tanpa logging atau penanganan yang tepat.'}
  ];
  lines.forEach((line,i)=>checks.forEach(c=>{if(c.re.test(line)){findings.push({line:i+1,severity:c.severity,title:c.title,detail:c.detail,snippet:line.trim().slice(0,180)});}}));
  const opens=(String(source).match(/\b(function|if|for|while|repeat)\b/g)||[]).length;
  const closes=(String(source).match(/\b(end|until)\b/g)||[]).length;
  if(opens>closes+2) findings.push({line:lines.length,severity:'warning',title:'Kemungkinan blok belum ditutup',detail:'Jumlah kata pembuka blok lebih banyak dari penutup. Ini hanya pemeriksaan kasar, bukan parser Luau.'});
  return {lineCount:lines.length,findings,summary:findings.length?`${findings.length} temuan untuk ditinjau`:'Tidak ada pola mencurigakan yang terdeteksi',disclaimer:'Scanner ini berbasis pola dan bukan parser/analisis keamanan lengkap. Hasil bersih bukan jaminan script aman.'};
}
function handleApi(req,res,url) {
  if(req.method==='GET' && url.pathname==='/api/health') return json(res,200,{ok:true,name:'AL STUDIO PIXEL',version:'1.0.0',robloxPublishConfigured:Boolean(process.env.ROBLOX_OPEN_CLOUD_API_KEY && process.env.ROBLOX_CREATOR_ID)});
  if(req.method==='GET' && url.pathname==='/api/assets') return json(res,200,readJson(path.join(DATA,'assets.json'),[]));
  if(req.method==='GET' && url.pathname==='/api/models') return json(res,200,readJson(path.join(DATA,'models.json'),[]));
  if(req.method==='POST' && url.pathname==='/api/scan') {
    return readBody(req).then(body=>json(res,200,scanLuau(body.source||''))).catch(e=>json(res,400,{error:e.message}));
  }
  if(req.method==='POST' && url.pathname==='/api/assets') {
    return readBody(req).then(body=>{
      if(!body.name || !body.dataUrl) return json(res,400,{error:'Nama dan file wajib diisi.'});
      const match=String(body.dataUrl).match(/^data:(image\/(?:png|jpeg|webp|svg\+xml));base64,([A-Za-z0-9+/=]+)$/);
      if(!match) return json(res,400,{error:'Format asset harus PNG, JPG, WEBP, atau SVG.'});
      const ext=({'image/png':'.png','image/jpeg':'.jpg','image/webp':'.webp','image/svg+xml':'.svg'})[match[1]];
      const bytes=Buffer.from(match[2],'base64');
      if(bytes.length>8*1024*1024) return json(res,400,{error:'Ukuran file maksimum 8 MB.'});
      const id=crypto.randomUUID(), filename=id+ext;
      fs.writeFileSync(path.join(UPLOADS,'assets',filename),bytes);
      const items=readJson(path.join(DATA,'assets.json'),[]);
      const item={id,name:String(body.name).slice(0,80),category:String(body.category||'Custom').slice(0,30),description:String(body.description||'Uploaded to local library').slice(0,220),file:`/uploads/assets/${filename}`,size:bytes.length,createdAt:new Date().toISOString()};
      items.unshift(item);writeJson(path.join(DATA,'assets.json'),items);
      return json(res,201,item);
    }).catch(e=>json(res,400,{error:e.message}));
  }
  if(req.method==='POST' && url.pathname==='/api/models') {
    return readBody(req).then(body=>{
      if(!body.name || !body.dataBase64 || !body.filename) return json(res,400,{error:'Nama dan file model wajib diisi.'});
      const filename=cleanName(body.filename), ext=path.extname(filename).toLowerCase();
      if(!['.rbxm','.rbxmx','.zip'].includes(ext)) return json(res,400,{error:'File model harus .rbxm, .rbxmx, atau .zip.'});
      const bytes=Buffer.from(body.dataBase64,'base64');
      if(!bytes.length || bytes.length>12*1024*1024) return json(res,400,{error:'Ukuran model maksimum 12 MB.'});
      const id=crypto.randomUUID(), stored=`${id}_${filename}`;
      fs.writeFileSync(path.join(UPLOADS,'models',stored),bytes);
      const items=readJson(path.join(DATA,'models.json'),[]);
      const item={id,name:String(body.name).slice(0,80),category:String(body.category||'Environment').slice(0,40),description:String(body.description||'').slice(0,300),filename,download:`/uploads/models/${stored}`,size:bytes.length,createdAt:new Date().toISOString()};
      items.unshift(item);writeJson(path.join(DATA,'models.json'),items);
      return json(res,201,item);
    }).catch(e=>json(res,400,{error:e.message}));
  }
  if(req.method==='DELETE' && url.pathname.startsWith('/api/assets/')) {
    const id=url.pathname.split('/').pop(), file=path.join(DATA,'assets.json'), items=readJson(file,[]), found=items.find(x=>x.id===id);
    if(!found) return json(res,404,{error:'Asset tidak ditemukan.'});
    try{fs.unlinkSync(path.join(ROOT,found.file.replace(/^\//,'')));}catch{}
    writeJson(file,items.filter(x=>x.id!==id));return json(res,200,{ok:true});
  }
  if(req.method==='POST' && url.pathname==='/api/publish') {
    return readBody(req).then(body=>{
      // Deliberately do not fake a successful publish. A real Open Cloud publish adapter must be configured for the creator's asset type and permissions.
      if(!process.env.ROBLOX_OPEN_CLOUD_API_KEY || !process.env.ROBLOX_CREATOR_ID) return json(res,501,{ok:false,error:'Publish Roblox belum dikonfigurasi. Tambahkan API key dan Creator ID di environment server pribadi, lalu hubungkan endpoint Open Cloud yang sesuai untuk jenis asset.'});
      return json(res,501,{ok:false,error:'Credential terdeteksi, tetapi adapter upload belum diaktifkan. Tidak ada asset yang dikirim. Endpoint dan permission harus disesuaikan dengan jenis asset Roblox yang ingin diterbitkan.'});
    }).catch(e=>json(res,400,{error:e.message}));
  }
  json(res,404,{error:'API route tidak ditemukan.'});
}
const server=http.createServer((req,res)=>{
  const url=new URL(req.url,'http://localhost');
  if(url.pathname.startsWith('/api/')) return handleApi(req,res,url);
  if(url.pathname.startsWith('/uploads/')) {
    const file=path.resolve(ROOT,url.pathname.slice(1));
    if(!file.startsWith(path.resolve(UPLOADS)+path.sep)) {res.writeHead(403);return res.end('Forbidden');}
    return sendFile(res,file,url.searchParams.get('download')==='1');
  }
  let pathname=decodeURIComponent(url.pathname);
  if(pathname==='/') pathname='/index.html';
  const file=path.resolve(PUBLIC,'.'+pathname);
  if(!file.startsWith(path.resolve(PUBLIC)+path.sep)){res.writeHead(403);return res.end('Forbidden');}
  sendFile(res,file);
});
server.listen(PORT,()=>console.log(`AL STUDIO PIXEL running at http://localhost:${PORT}`));
