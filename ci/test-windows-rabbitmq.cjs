// Run after ci/windows-build-env.ps1 and a native cargo build.
// Requires Node 18+ and Docker Desktop. Only disposable test containers are changed.
const { spawn, execFile } = require('node:child_process');
const { promisify } = require('node:util');
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const { randomUUID } = require('node:crypto');
const exec = promisify(execFile);
const root = path.resolve(__dirname, '..');
const run = `windows-rabbitmq-${Date.now()}`;
const logs = path.join(root, 'target', run);
const password = randomUUID().replaceAll('-', '');
const secret = randomUUID();
const rabbit = `${run}-rabbit`;
const postgres = `${run}-postgres`;
const ownedContainers = [];
const checks = [];
let backend, backendError, base, management, amqpPort, dbPort;
fs.mkdirSync(logs, { recursive: true });
fs.copyFileSync(path.join(root, 'backend', 'backend_config.toml'), path.join(logs, 'backend_config.toml'));
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const docker = async (...args) => (await exec('docker', args, { windowsHide: true, timeout: 120000, maxBuffer: 4 * 1024 * 1024 })).stdout.trim();
async function eventually(fn, timeout = 30000) {
  const deadline = Date.now() + timeout;
  let last;
  while (Date.now() < deadline) {
    try { const value = await fn(); if (value) return value; } catch (error) { last = error; }
    await sleep(300);
  }
  throw new Error(`Condition timed out${last ? ': ' + last.message : ''}`);
}
function check(name, passed, evidence) {
  checks.push({ name, passed: !!passed, evidence });
  console.log(`${passed ? 'PASS' : 'FAIL'} ${name}: ${JSON.stringify(evidence)}`);
}
async function request(url, options = {}) {
  const response = await fetch(url, { ...options, signal: AbortSignal.timeout(12000) });
  const text = await response.text();
  let data; try { data = JSON.parse(text); } catch { data = text; }
  return { status: response.status, data };
}
const api = (route, body, header = secret) => request(base + route, {
  method: body === undefined ? 'GET' : 'POST',
  headers: { 'content-type': 'application/json', ...(header === null ? {} : { 'x-reacher-secret': header }) },
  ...(body === undefined ? {} : { body: JSON.stringify(body) })
});
const admin = (route, method = 'GET', body) => request(management + '/api' + route, {
  method, headers: { authorization: 'Basic ' + Buffer.from('runtime:' + password).toString('base64'), 'content-type': 'application/json' },
  ...(body === undefined ? {} : { body: JSON.stringify(body) })
});
const sql = query => docker('exec', postgres, 'psql', '-U', 'runtime', '-d', 'runtime', '-At', '-c', query);
async function freePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}
async function stopBackend() {
  if (backend && backend.exitCode === null && backend.signalCode === null) {
    const exited = new Promise(resolve => backend.once('exit', resolve));
    backend.kill();
    await exited;
  }
  backend = null;
}
async function startBackend(phase, limit = 1000) {
  await stopBackend();
  const port = await freePort();
  base = `http://127.0.0.1:${port}`;
  const env = { ...process.env };
  for (const key of Object.keys(env)) if (key.toUpperCase().startsWith('RCH__')) delete env[key];
  Object.assign(env, {
    RCH__BACKEND_NAME: phase, RCH__HTTP_HOST: '127.0.0.1', RCH__HTTP_PORT: String(port),
    RCH__HEADER_SECRET: secret, RCH__WORKER__ENABLE: 'true',
    RCH__WORKER__RABBITMQ__URL: `amqp://runtime:${password}@127.0.0.1:${amqpPort}/%2f`,
    RCH__WORKER__RABBITMQ__CONCURRENCY: '3',
    RCH__STORAGE__POSTGRES__DB_URL: `postgres://runtime:${password}@127.0.0.1:${dbPort}/runtime`,
    RCH__THROTTLE__MAX_REQUESTS_PER_MINUTE: String(limit), RCH__THROTTLE__MAX_REQUESTS_PER_DAY: '10000',
    RCH__REQUEST_TIMEOUT: '3', RUST_LOG: 'reacher=info,lapin=warn', RUST_BACKTRACE: '1'
  });
  const stdout = fs.openSync(path.join(logs, phase + '.stdout.log'), 'w');
  const stderr = fs.openSync(path.join(logs, phase + '.stderr.log'), 'w');
  backendError = null;
  backend = spawn(path.join(root, 'target/debug/reacher_backend.exe'), [], {
    cwd: logs, env, windowsHide: true, stdio: ['ignore', stdout, stderr]
  });
  fs.closeSync(stdout); fs.closeSync(stderr);
  backend.on('error', error => { backendError = error; });
  await eventually(async () => {
    if (backendError) throw backendError;
    if (backend.exitCode !== null) throw new Error(`Backend exited: ${backend.exitCode}; see ${phase} logs`);
    return (await request(base + '/')).status === 404;
  });
  await eventually(async () => (await admin('/queues/%2f/check_email')).data.consumers === 1);
}
async function queueEmpty() {
  return eventually(async () => {
    const queue = (await admin('/queues/%2f/check_email')).data;
    return queue.messages === 0 && queue.messages_unacknowledged === 0;
  });
}
async function main() {
  if (process.platform !== 'win32') throw new Error('This harness validates the native Windows backend.');
  fs.accessSync(path.join(root, 'target/debug/reacher_backend.exe'));
  console.log('Starting isolated services; logs: ' + logs);
  await docker('run', '-d', '--name', rabbit, '--label', `reacher-runtime-test=${run}`, '-p', '127.0.0.1::5672', '-p', '127.0.0.1::15672', '-e', 'RABBITMQ_DEFAULT_USER=runtime', '-e', `RABBITMQ_DEFAULT_PASS=${password}`, 'rabbitmq:4.0-management');
  ownedContainers.push(rabbit);
  await docker('run', '-d', '--name', postgres, '--label', `reacher-runtime-test=${run}`, '-p', '127.0.0.1::5432', '-e', 'POSTGRES_USER=runtime', '-e', `POSTGRES_PASSWORD=${password}`, '-e', 'POSTGRES_DB=runtime', 'postgres:14');
  ownedContainers.push(postgres);
  amqpPort = (await docker('port', rabbit, '5672/tcp')).split(':').at(-1);
  dbPort = (await docker('port', postgres, '5432/tcp')).split(':').at(-1);
  management = 'http://' + await docker('port', rabbit, '15672/tcp');
  await eventually(async () => (await admin('/overview')).status === 200, 90000);
  await eventually(async () => (await sql('SELECT 1')) === '1');
  fs.writeFileSync(path.join(logs, 'versions.json'), JSON.stringify({
    platform: process.platform, node: process.version,
    rabbitmq: (await admin('/overview')).data.rabbitmq_version,
    postgres: await sql('SHOW server_version'),
    images: JSON.parse(await docker('image', 'inspect', 'rabbitmq:4.0-management', 'postgres:14')).map(i => ({ id: i.Id, digests: i.RepoDigests }))
  }, null, 2));
  await startBackend('healthy');
  check('Native Windows AMQP connection and consumer', true, { consumers: 1 });
  const first = await api('/v1/check_email', { to_email: 'runtime-single-invalid' });
  check('Queued single request round trip', first.status === 200 && first.data.is_reachable === 'invalid', first);
  await eventually(async () => Number(await sql('SELECT count(*) FROM v1_task_result WHERE job_id IS NULL')) === 1);
  check('Single result persisted', true, { rows: 1 });
  const concurrent = await Promise.all(Array.from({ length: 5 }, (_, i) => api('/v1/check_email', { to_email: `runtime-concurrent-${i}` })));
  check('Five concurrent RPC replies', concurrent.every(r => r.status === 200 && r.data.is_reachable === 'invalid'), concurrent.map(r => r.status));
  const created = await api('/v1/bulk', { input: ['runtime-bulk-a', 'runtime-bulk-b', 'runtime-bulk-c'] });
  if (created.status !== 200) throw new Error('Bulk creation failed: ' + JSON.stringify(created));
  const job = created.data.job_id;
  const progress = await eventually(async () => {
    const response = await api(`/v1/bulk/${job}`);
    return response.data.job_status === 'Completed' && response;
  });
  check('Bulk completion and counts', progress.data.total_processed === 3 && progress.data.summary.total_invalid === 3, progress.data);
  const json = await api(`/v1/bulk/${job}/results`);
  const csv = await api(`/v1/bulk/${job}/results?format=csv`);
  check('JSON and CSV export', json.status === 200 && json.data.results.length === 3 && csv.status === 200 && csv.data.trim().split(/\r?\n/).length === 4, { jsonRows: json.data.results?.length, csvStatus: csv.status });
  const denied = await Promise.all([api(`/v1/bulk/${job}`, undefined, null), api(`/v1/bulk/${job}/results`, undefined, 'wrong-secret')]);
  check('Bulk authentication', denied.every(r => r.status >= 400 && r.status < 500), denied.map(r => r.status));
  await queueEmpty();
  check('Queue drains after successful work', true, { messages: 0 });

  // Force a storage error only in this disposable database, after migration.
  await sql('ALTER TABLE v1_task_result ADD CONSTRAINT runtime_reject_insert CHECK (false) NOT VALID');
  const storageFailure = await api('/v1/check_email', { to_email: 'runtime-storage-failure' });
  await eventually(() => fs.readFileSync(path.join(logs, 'healthy.stdout.log'), 'utf8').includes('runtime_reject_insert'));
  await queueEmpty();
  const stored = Number(await sql("SELECT count(*) FROM v1_task_result WHERE payload->'input'->>'to_email' = 'runtime-storage-failure'"));
  check('Storage failure retains task or returns error', storageFailure.status >= 500 || stored === 1, { httpStatus: storageFailure.status, storedRows: stored, queueMessages: 0 });
  await sql('ALTER TABLE v1_task_result DROP CONSTRAINT runtime_reject_insert');

  await startBackend('throttle-one', 1);
  const throttled = await api('/v1/check_email', { to_email: 'runtime-first-in-quota' });
  check('First queued request fits a quota of one', throttled.status === 200, throttled);
  const second = await api('/v1/check_email', { to_email: 'runtime-over-quota' });
  check('Second request exceeds quota', second.status === 429, second);

  await startBackend('malformed-message');
  const published = await admin('/exchanges/%2f/amq.default/publish', 'POST', { properties: {}, routing_key: 'check_email', payload: '{invalid-json', payload_encoding: 'string' });
  if (!published.data.routed) throw new Error('Malformed test message did not route');
  await sleep(1500);
  const started = Date.now();
  const afterMalformed = await api('/v1/check_email', { to_email: 'runtime-after-malformed' });
  check('Consumer survives malformed delivery', afterMalformed.status === 200, { ...afterMalformed, elapsedMs: Date.now() - started });
  check('Queued request deadline is enforced', afterMalformed.status !== 504 || Date.now() - started < 6000, { status: afterMalformed.status, elapsedMs: Date.now() - started });
  await stopBackend();
  await admin('/queues/%2f/check_email/contents', 'DELETE');

  await startBackend('broker-restart');
  console.log('Restarting the isolated test broker.');
  await docker('restart', rabbit);
  await eventually(async () => (await admin('/overview')).status === 200, 90000);
  await sleep(2000);
  const afterRestart = await api('/v1/check_email', { to_email: 'runtime-after-restart' });
  check('Worker recovers after broker restart', afterRestart.status === 200, afterRestart);
  await stopBackend();
  await startBackend('manual-recovery');
  const recovered = await api('/v1/check_email', { to_email: 'runtime-after-process-restart' });
  check('Backend restart restores processing', recovered.status === 200 && recovered.data.is_reachable === 'invalid', recovered.status);
}
(async () => {
  try { await main(); }
  catch (error) { check('Harness completed all scenarios', false, error.stack); }
  finally {
    await stopBackend();
    for (const container of ownedContainers) {
      try { fs.writeFileSync(path.join(logs, container + '.log'), await docker('logs', container)); } catch {}
      try { await docker('rm', '-f', '-v', container); }
      catch (error) { check('Test container cleanup: ' + container, false, error.message); }
    }
    const report = { run, checks, passed: checks.filter(c => c.passed).length, failed: checks.filter(c => !c.passed).length };
    fs.writeFileSync(path.join(logs, 'report.json'), JSON.stringify(report, null, 2));
    console.log(`Results: ${report.passed} passed, ${report.failed} failed. Report: ${path.join(logs, 'report.json')}`);
    process.exitCode = report.failed ? 1 : 0;
  }
})();