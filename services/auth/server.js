'use strict';
const http = require('node:http');
const crypto = require('node:crypto');

function settings(env = process.env) {
  for (const key of ['LAB_APP_SECRET', 'SHOP_USERNAME', 'SHOP_PASSWORD']) {
    if (!env[key]) throw new Error(key + ' is required');
  }
  return { secret: env.LAB_APP_SECRET, username: env.SHOP_USERNAME, password: env.SHOP_PASSWORD };
}

function equal(left, right) {
  const a = crypto.createHash('sha256').update(left).digest();
  const b = crypto.createHash('sha256').update(right).digest();
  return crypto.timingSafeEqual(a, b);
}

function token(username, secret, now = Math.floor(Date.now() / 1000)) {
  const payload = Buffer.from(JSON.stringify({ sub: username, iat: now, exp: now + 3600 })).toString('base64url');
  const signature = crypto.createHmac('sha256', secret).update(payload).digest('hex');
  return payload + '.' + signature;
}

function createServer(config = settings()) {
  return http.createServer(async (request, response) => {
    const reply = (status, body) => {
      response.writeHead(status, { 'Content-Type': 'application/json' });
      response.end(JSON.stringify(body));
    };
    if (request.method === 'GET' && request.url === '/health') return reply(200, { status: 'ok', service: 'auth' });
    if (request.method !== 'POST' || request.url !== '/login') return reply(404, { error: 'not found' });
    let size = 0;
    const chunks = [];
    try {
      for await (const chunk of request) {
        size += chunk.length;
        if (size > 4096) { reply(413, { error: 'body too large' }); return; }
        chunks.push(chunk);
      }
      const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (typeof body.username !== 'string' || typeof body.password !== 'string' ||
          !equal(body.username, config.username) || !equal(body.password, config.password)) {
        return reply(401, { error: 'invalid credentials' });
      }
      return reply(200, { token: token(body.username, config.secret), expires_in: 3600 });
    } catch {
      return reply(400, { error: 'invalid request' });
    }
  });
}

if (require.main === module) {
  const server = createServer();
  server.requestTimeout = 5000;
  server.headersTimeout = 5000;
  server.listen(3000, '0.0.0.0');
}
module.exports = { settings, equal, token, createServer };
