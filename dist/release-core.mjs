export function compareVersions(a,b){const parse=v=>{if(!/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(v))throw Error('版本号请使用 x.y.z，例如 0.4.17');const n=v.split('.').map(Number);if(n.some(x=>x>2147483647))throw Error('版本号数值过大');return n;};const x=parse(a),y=parse(b);for(let i=0;i<3;i++)if(x[i]!==y[i])return Math.sign(x[i]-y[i]);return 0;}
export function validateRelease(input,{allowUnpublished=false}={}){
 const version=String(input.version??'').trim();compareVersions(version,version);
 const type=input.type??'zip';if(!['exe','zip'].includes(type))throw Error('安装包类型必须是 EXE 或 ZIP');
 const url=String(input.url??'').trim();if(!(allowUnpublished&&input.published===false&&url==='')){let u;try{u=new URL(url);}catch{throw Error('请填写完整 HTTPS 下载地址');}if(u.protocol!=='https:'||u.username||u.password||u.hash)throw Error('下载地址必须是无用户名、密码或片段的 HTTPS 地址');}
 const size=Number(input.size);if(!Number.isSafeInteger(size)||size<=0||size>512*1024*1024)throw Error('安装包大小必须在 1 字节至 512 MB 之间');
 const sha256=String(input.sha256??'').trim().toLowerCase();if(!/^[a-f0-9]{64}$/.test(sha256))throw Error('请填写安装包的 64 位 SHA256');
 return {format:'MeTN-update',platform:'windows-x64',version,type,url,size,sha256,notes:String(input.notes??'').trim().slice(0,4000),published:!(allowUnpublished&&input.published===false),publishedAt:new Date().toISOString()};
}
export function inferRepository(location){const match=location.hostname.match(/^([a-z0-9-]+)\.github\.io$/i);const repo=location.pathname.split('/').filter(Boolean)[0];return match&&repo&&!repo.includes('.')?{owner:match[1],repo,branch:'main'}:{owner:'',repo:'',branch:'main'};}
export async function verifyEditorPassword(password,config,cryptoApi=globalThis.crypto){
 if(config.algorithm!=='PBKDF2-SHA256'||!Number.isSafeInteger(config.iterations)||config.iterations<100000||config.iterations>1000000||!/^[a-f0-9]{32}$/.test(config.salt)||!/^[a-f0-9]{64}$/.test(config.hash))throw Error('编辑器解锁配置无效');
 const salt=Uint8Array.from(config.salt.match(/../g),v=>parseInt(v,16));const key=await cryptoApi.subtle.importKey('raw',new TextEncoder().encode(password),'PBKDF2',false,['deriveBits']);const bits=new Uint8Array(await cryptoApi.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',iterations:config.iterations,salt},key,256));const expected=Uint8Array.from(config.hash.match(/../g),v=>parseInt(v,16));let different=0;for(let i=0;i<bits.length;i++)different|=bits[i]^expected[i];return different===0;
}
export function encodeContent(value){const bytes=new TextEncoder().encode(JSON.stringify(value,null,2)+'\n');let binary='';for(const byte of bytes)binary+=String.fromCharCode(byte);return btoa(binary);}
export function decodeContent(value){return JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(value.replace(/\s/g,'')),c=>c.charCodeAt(0))));}
export async function publishRelease({owner,repo,branch='main',token,release},request=fetch){
 if(!/^[a-z0-9-]{1,39}$/i.test(owner)||!/^[a-z0-9._-]{1,100}$/i.test(repo)||repo==='.'||repo==='..'||!branch||branch.length>200)throw Error('请填写有效的 GitHub 用户名、仓库名和分支');
 if(!token?.trim())throw Error('在线发布需要当前仓库 Contents: write 授权的 GitHub Token');
 const data=validateRelease(release);const endpoint=`https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/contents/dist/latest.json`;
 const headers={Accept:'application/vnd.github+json',Authorization:`Bearer ${token.trim()}`,'X-GitHub-Api-Version':'2026-03-10'};
 const current=await request(`${endpoint}?ref=${encodeURIComponent(branch)}`,{headers,redirect:'error',cache:'no-store'});let sha;
 if(current.ok){const file=await current.json();sha=file.sha;const previous=decodeContent(file.content);if(compareVersions(data.version,String(previous.version))<0)throw Error('仓库中已有更高版本，已停止发布');}else if(current.status!==404)throw Error(`无法读取仓库（HTTP ${current.status}），请检查仓库及 Token 权限`);
 const response=await request(endpoint,{method:'PUT',headers:{...headers,'Content-Type':'application/json'},redirect:'error',body:JSON.stringify({message:`Release MeTN ${data.version}`,branch,content:encodeContent(data),...(sha?{sha}:{})})});
 if(!response.ok)throw Error(response.status===409?'仓库文件已被其他发布修改，请刷新后重试':`发布失败（HTTP ${response.status}），请检查 Contents 写入权限或分支保护`);
 const result=await response.json();return {release:data,commitUrl:result.commit?.html_url};
}
