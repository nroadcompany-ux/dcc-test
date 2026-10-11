const crypto = require('crypto');
const L = require('./_lib');

const USERNAME = /^[a-z0-9_.-]{2,32}$/;
const SESSION_MS = 12 * 60 * 60 * 1000;

function safeEq(a, b) {
  const x = crypto.createHash('sha256').update(String(a)).digest();
  const y = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(x, y);
}

async function adminCount() {
  const all = await L.redis(['HGETALL', 'dcc:users']);
  let n = 0;
  for (let i = 1; i < (all || []).length; i += 2) if (JSON.parse(all[i]).role === 'admin') n++;
  return n;
}

module.exports = async (req, res) => {
  try {
    const action = (req.query && req.query.action) || '';
    const method = req.method;
    const body = req.body || {};

    if (method !== 'GET' && !L.csrfOk(req)) return L.send(res, 403, { error: '잘못된 요청입니다.' });

    if (action === 'me' && method === 'GET') {
      const u = await L.auth(req);
      return L.send(res, 200, { user: u ? L.pub(u) : null });
    }

    if (action === 'login' && method === 'POST') {
      const username = String(body.username || '').trim().toLowerCase();
      const password = body.password;
      if (!USERNAME.test(username) || typeof password !== 'string' || !password || password.length > 200) {
        return L.send(res, 400, { error: '아이디와 비밀번호를 확인해 주세요.' });
      }
      const ip = String(req.headers['x-forwarded-for'] || 'unknown').split(',')[0].trim();
      const rlKey = `dcc:rl:${ip}:${username}`;
      const n = await L.redis(['INCR', rlKey]);
      if (n === 1) await L.redis(['EXPIRE', rlKey, 600]);
      if (n > 8) return L.send(res, 429, { error: '로그인 시도가 너무 많습니다. 10분 뒤에 다시 시도해 주세요.' });

      let rec = await L.getUser(username);
      if (!rec) {
        // 최초 관리자 계정 생성: 등록된 계정이 하나도 없을 때만 환경변수 값으로 허용
        const adminName = String(process.env.ADMIN_USERNAME || 'admin').toLowerCase();
        const adminPw = process.env.ADMIN_PASSWORD;
        const count = await L.redis(['HLEN', 'dcc:users']);
        if (count === 0 && adminPw && username === adminName && safeEq(password, adminPw)) {
          const { salt, hash } = L.hashPassword(password);
          rec = { username, name: '관리자', role: 'admin', salt, hash, pwAt: Date.now(), createdAt: new Date().toISOString() };
          await L.putUser(rec);
        } else {
          L.hashPassword(password, 'dummysaltdummysalt'); // 타이밍 평준화
          return L.send(res, 401, { error: '아이디 또는 비밀번호가 올바르지 않습니다.' });
        }
      } else if (!L.checkPassword(password, rec)) {
        return L.send(res, 401, { error: '아이디 또는 비밀번호가 올바르지 않습니다.' });
      }

      await L.redis(['DEL', rlKey]);
      const iat = Math.max(Date.now(), rec.pwAt || 0);
      const token = L.signToken({ u: rec.username, iat, exp: Date.now() + SESSION_MS });
      L.setSessionCookie(res, token, SESSION_MS / 1000);
      return L.send(res, 200, { user: L.pub(rec) });
    }

    if (action === 'logout' && method === 'POST') {
      L.setSessionCookie(res, '', 0);
      return L.send(res, 200, { ok: true });
    }

    // 이하 모두 로그인 필요
    const me = await L.auth(req);
    if (!me) return L.send(res, 401, { error: '로그인이 필요합니다.' });

    if (action === 'history' && method === 'GET') {
      const rows = await L.redis(['LRANGE', 'dcc:history', 0, 99]);
      return L.send(res, 200, { history: (rows || []).map((r) => JSON.parse(r)) });
    }

    if (action === 'password' && method === 'POST') {
      const { oldPassword, newPassword } = body;
      if (typeof newPassword !== 'string' || newPassword.length < 8 || newPassword.length > 200) {
        return L.send(res, 400, { error: '새 비밀번호는 8자 이상이어야 합니다.' });
      }
      if (typeof oldPassword !== 'string' || !L.checkPassword(oldPassword, me)) {
        return L.send(res, 400, { error: '현재 비밀번호가 올바르지 않습니다.' });
      }
      const { salt, hash } = L.hashPassword(newPassword);
      me.salt = salt; me.hash = hash; me.pwAt = Date.now();
      await L.putUser(me);
      const token = L.signToken({ u: me.username, iat: Math.max(Date.now(), me.pwAt), exp: Date.now() + SESSION_MS });
      L.setSessionCookie(res, token, SESSION_MS / 1000);
      return L.send(res, 200, { ok: true });
    }

    // 계정 관리: 관리자만
    if (action === 'users') {
      if (me.role !== 'admin') return L.send(res, 403, { error: '관리자만 사용할 수 있습니다.' });

      if (method === 'GET') {
        const all = await L.redis(['HGETALL', 'dcc:users']);
        const users = [];
        for (let i = 1; i < (all || []).length; i += 2) {
          const u = JSON.parse(all[i]);
          users.push({ ...L.pub(u), createdAt: u.createdAt || '' });
        }
        users.sort((a, b) => a.username.localeCompare(b.username));
        return L.send(res, 200, { users });
      }

      if (method === 'POST') {
        const username = String(body.username || '').trim().toLowerCase();
        const role = body.role === 'admin' ? 'admin' : 'editor';
        const name = String(body.name || '').trim().slice(0, 40) || username;
        if (!USERNAME.test(username)) return L.send(res, 400, { error: '아이디는 영문 소문자/숫자/._- 2~32자로 입력해 주세요.' });
        if (typeof body.password !== 'string' || body.password.length < 8 || body.password.length > 200) {
          return L.send(res, 400, { error: '비밀번호는 8자 이상이어야 합니다.' });
        }
        if (await L.getUser(username)) return L.send(res, 409, { error: '이미 있는 아이디입니다.' });
        const { salt, hash } = L.hashPassword(body.password);
        await L.putUser({ username, name, role, salt, hash, pwAt: Date.now(), createdAt: new Date().toISOString() });
        return L.send(res, 200, { ok: true });
      }

      if (method === 'PUT') {
        const username = String(body.username || '').trim().toLowerCase();
        const rec = await L.getUser(username);
        if (!rec) return L.send(res, 404, { error: '계정을 찾을 수 없습니다.' });
        if (body.role && body.role !== rec.role) {
          if (rec.role === 'admin' && (await adminCount()) <= 1) return L.send(res, 400, { error: '마지막 관리자는 강등할 수 없습니다.' });
          rec.role = body.role === 'admin' ? 'admin' : 'editor';
        }
        if (typeof body.name === 'string' && body.name.trim()) rec.name = body.name.trim().slice(0, 40);
        if (body.password) {
          if (typeof body.password !== 'string' || body.password.length < 8 || body.password.length > 200) {
            return L.send(res, 400, { error: '비밀번호는 8자 이상이어야 합니다.' });
          }
          const { salt, hash } = L.hashPassword(body.password);
          rec.salt = salt; rec.hash = hash; rec.pwAt = Date.now();
        }
        await L.putUser(rec);
        return L.send(res, 200, { ok: true });
      }

      if (method === 'DELETE') {
        const username = String((req.query && req.query.username) || '').trim().toLowerCase();
        if (username === me.username) return L.send(res, 400, { error: '본인 계정은 삭제할 수 없습니다.' });
        const rec = await L.getUser(username);
        if (!rec) return L.send(res, 404, { error: '계정을 찾을 수 없습니다.' });
        if (rec.role === 'admin' && (await adminCount()) <= 1) return L.send(res, 400, { error: '마지막 관리자는 삭제할 수 없습니다.' });
        await L.redis(['HDEL', 'dcc:users', username]);
        return L.send(res, 200, { ok: true });
      }
    }

    return L.send(res, 404, { error: 'not found' });
  } catch (e) {
    console.error(e);
    const msg = e.message === 'storage-not-configured' ? '저장소가 아직 연결되지 않았습니다.'
      : e.message === 'session-secret-missing' ? '서버 설정이 완료되지 않았습니다.' : '서버 오류가 발생했습니다.';
    return L.send(res, 500, { error: msg });
  }
};
