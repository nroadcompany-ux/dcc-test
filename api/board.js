const L=require('./_lib');
const KEY='dcc:resource-board:v1';
const SEED=[
{id:'sz-guide-v7',category:'디자인 가이드',title:'생ZONE V7 디자인 가이드 v1.0',description:'모바일 로드맵·체크리스트 및 PC 장부·도움 공통 디자인 기준',url:'/docs/SaengZONE_V7_Design_Guide_v1.0_2026-10-24.md',createdAt:'2026-10-24T00:00:00.000Z',updatedAt:'2026-10-24T00:00:00.000Z',author:'PM 운영실'},
{id:'sz-roadmap-v7',category:'서비스 링크',title:'생ZONE V7 · 창업 로드맵',description:'13단계 로드맵 모바일 상세 화면',url:'https://saengzone-app-v7.vercel.app/#/roadmap/1',createdAt:'2026-10-24T00:00:00.000Z',updatedAt:'2026-10-24T00:00:00.000Z',author:'PM 운영실'},
{id:'sz-ledger-v7',category:'서비스 링크',title:'생존플러스 V7 · 장부',description:'PC 매출/지출/차트·결제수단 화면',url:'https://saengzone-app-v7.vercel.app/plus/#ledger',createdAt:'2026-10-24T00:00:00.000Z',updatedAt:'2026-10-24T00:00:00.000Z',author:'PM 운영실'}
];
function clean(body){const title=String(body.title||'').trim().slice(0,120);const description=String(body.description||'').trim().slice(0,2000);const category=String(body.category||'자료').trim().slice(0,50);const url=String(body.url||'').trim().slice(0,1000);if(!title)throw Error('제목을 입력하세요.');if(url&&!((/^https:\/\/[^\s]+$/i).test(url)||(/^\/[a-zA-Z0-9_./-]+$/).test(url)))throw Error('HTTPS 주소 또는 내부 경로만 허용합니다.');return {title,description,category,url};}
async function current(){const raw=await L.redis(['GET',KEY]);if(raw)return JSON.parse(raw);await L.redis(['SET',KEY,JSON.stringify({version:1,posts:SEED}),'NX']);const saved=await L.redis(['GET',KEY]);return JSON.parse(saved);}
module.exports=async(req,res)=>{try{
const doc=await current();if(req.method==='GET')return L.send(res,200,doc);
if(!['POST','PUT','DELETE'].includes(req.method)){res.setHeader('Allow','GET, POST, PUT, DELETE');return L.send(res,405,{error:'Method not allowed'});}
if(!L.csrfOk(req))return L.send(res,403,{error:'잘못된 요청입니다.'});
const user=await L.auth(req);if(!user)return L.send(res,401,{error:'로그인이 필요합니다.'});
const body=req.body||{};if(body.baseVersion!==doc.version)return L.send(res,409,{error:'다른 사용자가 먼저 변경했습니다. 새로고침 후 재시도하세요.'});
const posts=[...doc.posts];const now=new Date().toISOString();
if(req.method==='POST'){const values=clean(body);posts.unshift({...values,id:require('crypto').randomUUID(),createdAt:now,updatedAt:now,author:user.username});}
if(req.method==='PUT'){const i=posts.findIndex(p=>p.id===body.id);if(i<0)return L.send(res,404,{error:'글을 찾을 수 없습니다.'});posts[i]={...posts[i],...clean(body),updatedAt:now};}
if(req.method==='DELETE'){const i=posts.findIndex(p=>p.id===body.id);if(i<0)return L.send(res,404,{error:'글을 찾을 수 없습니다.'});posts.splice(i,1);}
if(posts.length>500)return L.send(res,400,{error:'글은 최대 500개까지 등록할 수 있습니다.'});
const next={version:doc.version+1,posts};const old=JSON.stringify(doc);
const result=await L.redis(['EVAL',"if redis.call('GET',KEYS[1]) == ARGV[1] then redis.call('SET',KEYS[1],ARGV[2]); return 1 else return 0 end",1,KEY,old,JSON.stringify(next)]);
if(result!==1)return L.send(res,409,{error:'동시 변경이 발생했습니다. 새로고침하세요.'});
return L.send(res,200,next);
}catch(e){console.error(e);return L.send(res,e.message==='storage-not-configured'?503:400,{error:e.message==='storage-not-configured'?'공유 저장소 연결이 필요합니다.':'저장 요청을 처리하지 못했습니다.'});}};