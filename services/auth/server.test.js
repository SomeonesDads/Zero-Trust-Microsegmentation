'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { settings, equal, token, createServer } = require('./server');

test('credentials require explicit environment values', () => {
  assert.throws(() => settings({}), /LAB_APP_SECRET/);
  assert.equal(equal('one', 'two'), false);
  assert.equal(equal('one', 'one'), true);
});

test('tokens include bounded expiry and a signed subject', () => {
  const [payload, signature] = token('shopper', 'secret', 1000).split('.');
  assert.deepEqual(JSON.parse(Buffer.from(payload, 'base64url')), { sub: 'shopper', iat: 1000, exp: 4600 });
  assert.equal(signature, crypto.createHmac('sha256', 'secret').update(payload).digest('hex'));
});

test('HTTP login validates credentials and returns a signed token', async (t) => {
  const server = createServer({ secret: 'secret', username: 'shopper', password: 'password' });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const url = 'http://127.0.0.1:' + server.address().port;
  assert.equal((await fetch(url + '/health')).status, 200);
  const login = (body) => fetch(url + '/login', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
  });
  assert.equal((await login({ username: 'shopper', password: 'wrong' })).status, 401);
  const response = await login({ username: 'shopper', password: 'password' });
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(JSON.parse(Buffer.from(body.token.split('.')[0], 'base64url')).sub, 'shopper');
  assert.equal((await fetch(url + '/unknown')).status, 404);
});
