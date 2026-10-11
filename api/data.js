const L = require('./_lib');

module.exports = async (req, res) => {
  try {
    if (req.method === 'GET') {
      const raw = await L.redis(['GET', 'dcc:data']);
      let doc = raw ? JSON.parse(raw) : null;
      if (!doc) {
        doc = { version: 1, updatedAt: new Date().toISOString(), updatedBy: 'system', data: L.SEED };
        await L.redis(['SET', 'dcc:data', JSON.stringify(doc), 'NX']);
      }
      return L.send(res, 200, doc);
    }

    if (req.method === 'PUT') {
      if (!L.csrfOk(req)) return L.send(res, 403, { error: '잘못된 요청입니다.' });
      const user = await L.auth(req);
      if (!user) return L.send(res, 401, { error: '로그인이 필요합니다.' });

      const body = req.body || {};
      let data;
      try {
        data = L.validate(body.data);
      } catch (e) {
        return L.send(res, 400, { error: e.message });
      }

      const raw = await L.redis(['GET', 'dcc:data']);
      const cur = raw ? JSON.parse(raw) : { version: 0, data: { groups: [], items: [] } };
      if (body.baseVersion !== cur.version) {
        return L.send(res, 409, { error: '다른 사람이 먼저 수정했습니다. 최신 내용으로 다시 불러옵니다.', current: cur });
      }

      const doc = {
        version: cur.version + 1,
        updatedAt: new Date().toISOString(),
        updatedBy: user.username,
        data,
      };
      await L.redis(['SET', 'dcc:data', JSON.stringify(doc)]);

      const changes = L.diffSummary(cur.data, data);
      if (changes.length) {
        await L.redis(['LPUSH', 'dcc:history', JSON.stringify({ t: doc.updatedAt, u: user.username, v: doc.version, changes })]);
        await L.redis(['LTRIM', 'dcc:history', 0, 199]);
      }
      return L.send(res, 200, doc);
    }

    res.setHeader('Allow', 'GET, PUT');
    return L.send(res, 405, { error: 'method not allowed' });
  } catch (e) {
    console.error(e);
    const msg = e.message === 'storage-not-configured' ? '저장소가 아직 연결되지 않았습니다.' : '서버 오류가 발생했습니다.';
    return L.send(res, 500, { error: msg });
  }
};
