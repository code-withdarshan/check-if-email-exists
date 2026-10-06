// Unit checks for account UI state transitions; these do not replace browser QA.
const { readFileSync } = require('node:fs');
const vm = require('node:vm');
const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const html = readFileSync(path.join(__dirname, '../deploy/ui/index.html'), 'utf8');
const source = readFileSync(path.join(__dirname, '../deploy/ui/account.js'), 'utf8');
const flush = () => new Promise(resolve => setImmediate(resolve));

async function ui(responses) {
  const elements = new Map();
  function element() {
    return {
      hidden: true, value: '', textContent: '', listeners: {},
      addEventListener(type, callback) { this.listeners[type] = callback; },
      querySelectorAll() { return []; },
      focus() {}, reset() {}, removeAttribute() {}, scrollIntoView() {},
      showModal() {}, close() {},
    };
  }
  for (const [, id] of html.matchAll(/\bid="([^"]+)"/g)) elements.set(id, element());
  const main = element(), calls = [], writes = [], events = {};
  const context = {
    document: {
      getElementById(id) { assert.ok(elements.has(id), `Missing DOM element ${id}`); return elements.get(id); },
      querySelector(selector) { assert.equal(selector, 'main'); return main; },
    },
    addEventListener(name, callback) { events[name] = callback; },
    localStorage: { setItem(key, value) { writes.push({ key, value }); } },
    location: { reload() {} },
    Headers, setTimeout,
    fetch: async (url, options) => {
      calls.push({ url, options });
      const response = responses.shift();
      assert.ok(response, `Unexpected request: ${url}`);
      assert.equal(url, response.url);
      return { ok: response.status < 400, status: response.status, json: async () => response.body };
    },
  };
  context.window = context;
  vm.runInNewContext(source, context);
  await flush();
  return { context, elements, main, calls, writes, async submit() {
    await elements.get('authForm').listeners.submit({ preventDefault() {} });
    await flush();
  } };
}
const reply = (action, status, body) => ({ url: '/api/account/' + action, status, body });

test('pending 2FA and failed codes keep the verification UI inaccessible', async () => {
  const responses = [
    reply('status', 200, { enabled: true }), reply('me', 401, {}),
    reply('login', 200, { mfa_required: true, csrf_token: 'pending-csrf' }),
    reply('verify', 401, { error: 'Invalid code' }),
    reply('verify', 200, { csrf_token: 'verified-csrf' }),
    reply('me', 200, { id: 'alice', username: 'alice', csrf_token: 'verified-csrf' }),
  ];
  const page = await ui(responses);
  page.elements.get('authUsername').value = 'alice';
  page.elements.get('authPassword').value = 'a good test password';
  await page.submit();
  assert.equal(page.main.hidden, true);
  assert.equal(page.elements.get('loginFields').hidden, true);
  assert.equal(page.elements.get('authCode').required, true);
  assert.equal(page.elements.get('authPassword').value, '');
  page.elements.get('authCode').value = 'bad';
  await page.submit();
  assert.equal(page.main.hidden, true);
  assert.equal(page.elements.get('authError').textContent, 'Invalid code');
  assert.equal(page.calls[3].options.headers['x-reacher-csrf'], 'pending-csrf');
  page.elements.get('authCode').value = '123456';
  await page.submit();
  assert.equal(page.main.hidden, false);
  assert.equal(page.elements.get('accountGate').hidden, true);
  assert.equal(page.elements.get('accountName').textContent, 'alice');
  assert.equal((await page.context.accountReady).id, 'alice');
  assert.deepEqual(page.writes.map(write => write.key), ['ec.auth-event']);
  responses.push({ url: '/api/bulk', status: 200, body: {} });
  await page.context.accountFetch('/api/bulk', { method: 'POST' });
  assert.equal(page.calls.at(-1).options.headers.get('x-reacher-csrf'), 'verified-csrf');
});

test('registration opens the app only after the account is confirmed by me', async () => {
  const page = await ui([
    reply('status', 200, { enabled: true }), reply('me', 401, {}),
    reply('register', 200, { csrf_token: 'register-csrf' }),
    reply('me', 200, { id: 'new-user', username: 'new-user', csrf_token: 'register-csrf' }),
  ]);
  page.elements.get('authToggle').listeners.click();
  assert.equal(page.elements.get('authPassword').minLength, 12);
  page.elements.get('authUsername').value = 'new-user';
  page.elements.get('authPassword').value = 'a new good password';
  await page.submit();
  assert.equal(page.main.hidden, false);
  assert.equal((await page.context.accountReady).id, 'new-user');
});

test('account service failure fails closed', async () => {
  const page = await ui([reply('status', 503, {})]);
  assert.equal(page.main.hidden, true);
  assert.equal(page.elements.get('authForm').hidden, true);
  assert.match(page.elements.get('authError').textContent, /Could not load account services/);
});

test('legacy standalone mode still opens when accounts are explicitly disabled', async () => {
  const page = await ui([reply('status', 200, { enabled: false })]);
  assert.equal(page.main.hidden, false);
  assert.equal(await page.context.accountReady, null);
});
