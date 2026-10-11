const crypto = require('crypto');

const KV_URL = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const KV_TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;

async function redis(cmd) {
  if (!KV_URL || !KV_TOKEN) throw new Error('storage-not-configured');
  const res = await fetch(KV_URL, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + KV_TOKEN, 'Content-Type': 'application/json' },
    body: JSON.stringify(cmd),
  });
  const j = await res.json();
  if (j.error) throw new Error(j.error);
  return j.result;
}

function send(res, code, body) {
  res.statusCode = code;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(body));
}

function csrfOk(req) {
  return req.headers['x-requested-with'] === 'dcc';
}

function secret() {
  const s = process.env.SESSION_SECRET;
  if (!s || s.length < 16) throw new Error('session-secret-missing');
  return s;
}

const b64 = (b) => Buffer.from(b).toString('base64url');

function signToken(payload) {
  const body = b64(JSON.stringify(payload));
  const sig = crypto.createHmac('sha256', secret()).update(body).digest('base64url');
  return body + '.' + sig;
}

function verifyToken(token) {
  if (typeof token !== 'string' || token.indexOf('.') < 0) return null;
  const [body, sig] = token.split('.');
  const good = crypto.createHmac('sha256', secret()).update(body).digest('base64url');
  const a = Buffer.from(sig || '');
  const b = Buffer.from(good);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const p = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (!p.exp || p.exp < Date.now()) return null;
    return p;
  } catch (e) {
    return null;
  }
}

function parseCookies(req) {
  const out = {};
  String(req.headers.cookie || '').split(';').forEach((p) => {
    const i = p.indexOf('=');
    if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}

const COOKIE = 'dcc_session';
function setSessionCookie(res, token, maxAge) {
  res.setHeader('Set-Cookie', `${COOKIE}=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`);
}

async function getUser(username) {
  const raw = await redis(['HGET', 'dcc:users', username]);
  return raw ? JSON.parse(raw) : null;
}

async function putUser(rec) {
  await redis(['HSET', 'dcc:users', rec.username, JSON.stringify(rec)]);
}

function hashPassword(password, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}

function checkPassword(password, rec) {
  const { hash } = hashPassword(password, rec.salt);
  const a = Buffer.from(hash, 'hex');
  const b = Buffer.from(rec.hash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function pub(u) {
  return { username: u.username, name: u.name || u.username, role: u.role };
}

async function auth(req) {
  const tok = parseCookies(req)[COOKIE];
  const p = verifyToken(tok);
  if (!p) return null;
  const rec = await getUser(p.u);
  if (!rec) return null;
  if ((rec.pwAt || 0) > p.iat) return null;
  return rec;
}

const SEED = {
  groups: [
    { id: 'nroad', parentId: null, tag: 'NROAD', name: '엔로드', desc: '전체 관제' },
    { id: 'payplay', parentId: 'nroad', tag: '소속', name: 'PayPlay 페이플레이', desc: '' },
    { id: 'return', parentId: 'nroad', tag: '소속', name: 'RETURN 리턴', desc: '' },
  ],
  items: [
    { id: 'n1', groupId: 'nroad', code: 'N-1', title: '엔로드 관제센터 (NROAD 허브)', desc: '각 제품 허브의 기록을 한곳에서 확인', url: 'https://nroad-hub.vercel.app/', stage: 'official', date: '', target: 'new' },
    { id: 'p1', groupId: 'payplay', code: 'P-1', title: 'PayPlay OC · 업데이트 기록', desc: 'OC 버전 모음, 변경 기록, 연결된 원본', url: 'https://payplay-oc-hub.vercel.app', stage: 'official', date: '', target: 'new' },
    { id: 'p2', groupId: 'payplay', code: 'P-2', title: 'PayPlay OSP · 제작 허브', desc: '홈페이지 제작 기록과 사이트 모음', url: 'https://payplay-osp-hub.vercel.app', stage: 'official', date: '', target: 'new' },
    { id: 'p3', groupId: 'payplay', code: 'P-3', title: 'PayPlay 혜택·매장 솔루션', desc: '정부지원사업 탐색 및 매장 운영 솔루션 테스트 화면', url: './payplay.html', stage: 'test', date: '2026-10-11', target: 'same' },
    { id: 'r1', groupId: 'return', code: 'R-1', title: 'RETURN · QA & 업데이트 허브', desc: '최신 버전, QA 현황, 연결 자료, 변경 기록', url: 'https://return-hub-eight.vercel.app', stage: 'official', date: '', target: 'new' },
  ],
};

const STAGES = ['official', 'test', 'plan'];
const ID_RE = /^[a-z0-9_-]{1,40}$/;
function str(v, max) {
  return String(v == null ? '' : v).trim().slice(0, max);
}
function safeUrl(u) {
  u = String(u || '').trim();
  if (!u) return '';
  if (/^https?:\/\/[^\s]+$/i.test(u)) return u.slice(0, 500);
  if (/^(\.\/|\/)[^\s:]*$/.test(u)) return u.slice(0, 500);
  return null;
}

function validate(data) {
  if (!data || !Array.isArray(data.groups) || !Array.isArray(data.items)) throw new Error('데이터 형식이 올바르지 않습니다.');
  if (data.groups.length > 100 || data.items.length > 500) throw new Error('항목이 너무 많습니다.');
  const groups = [];
  const gids = new Set();
  for (const g of data.groups) {
    if (!g || !ID_RE.test(g.id || '') || gids.has(g.id)) throw new Error('그룹 ID가 올바르지 않습니다.');
    gids.add(g.id);
    const name = str(g.name, 60);
    if (!name) throw new Error('그룹 이름이 비어 있습니다.');
    groups.push({ id: g.id, parentId: g.parentId || null, tag: str(g.tag, 12), name, desc: str(g.desc, 80) });
  }
  const byId = new Map(groups.map((g) => [g.id, g]));
  for (const g of groups) {
    if (g.parentId && !byId.has(g.parentId)) throw new Error('상위 그룹이 존재하지 않습니다.');
    let cur = g, n = 0;
    while (cur && cur.parentId) {
      cur = byId.get(cur.parentId);
      if (++n > 10 || cur === g) throw new Error('그룹 구조가 순환하거나 너무 깊습니다.');
    }
  }
  const items = [];
  const iids = new Set();
  for (const it of data.items) {
    if (!it || !ID_RE.test(it.id || '') || iids.has(it.id)) throw new Error('항목 ID가 올바르지 않습니다.');
    iids.add(it.id);
    if (!gids.has(it.groupId)) throw new Error('항목의 소속 그룹이 존재하지 않습니다.');
    const title = str(it.title, 80);
    if (!title) throw new Error('항목 제목이 비어 있습니다.');
    const url = safeUrl(it.url);
    if (url === null) throw new Error('링크는 http(s):// 또는 ./경로 형식만 허용됩니다.');
    const stage = STAGES.includes(it.stage) ? it.stage : '';
    const date = /^\d{4}-\d{2}-\d{2}$/.test(String(it.date || '')) ? it.date : '';
    const target = it.target === 'same' || it.target === 'new' ? it.target : (/^https?:/i.test(url) ? 'new' : 'same');
    items.push({ id: it.id, groupId: it.groupId, code: str(it.code, 12), title, desc: str(it.desc, 160), url, stage, date, target });
  }
  return { groups, items };
}

function diffSummary(oldD, newD) {
  const out = [];
  const cmp = (kind, a, b, label) => {
    const am = new Map(a.map((x) => [x.id, x]));
    const bm = new Map(b.map((x) => [x.id, x]));
    for (const [id, x] of bm) {
      if (!am.has(id)) out.push(`${kind} 추가: ${label(x)}`);
      else if (JSON.stringify(am.get(id)) !== JSON.stringify(x)) out.push(`${kind} 수정: ${label(x)}`);
    }
    for (const [id, x] of am) if (!bm.has(id)) out.push(`${kind} 삭제: ${label(x)}`);
  };
  cmp('그룹', oldD.groups, newD.groups, (g) => g.name);
  cmp('항목', oldD.items, newD.items, (i) => i.title);
  if (!out.length && JSON.stringify(oldD) !== JSON.stringify(newD)) out.push('순서 변경');
  return out.slice(0, 12);
}

module.exports = {
  redis, send, csrfOk, signToken, verifyToken, parseCookies, setSessionCookie, COOKIE,
  getUser, putUser, hashPassword, checkPassword, pub, auth, SEED, validate, diffSummary,
};
