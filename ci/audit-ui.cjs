// Pure-function tests against the actual inline UI source; no browser simulation.
// Regression checks for the UI findings in AUDIT_REPORT.md.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const test = require('node:test');
const assert = require('node:assert/strict');
const html = fs.readFileSync(path.join(__dirname, '../deploy/ui/index.html'), 'utf8');
function section(start, end) {
  const a = html.indexOf(start), b = html.indexOf(end, a);
  assert.ok(a >= 0 && b > a, `Source markers missing: ${start}`);
  return html.slice(a, b);
}
const ctx = vm.createContext({});
vm.runInContext([
  section('function esc(s)', 'function flag('),
  section('const EMAIL_RE', '// ---- Pre-check:'),
  section('function reasonFor(r)', '// ---- Usage counter ----'),
  section('function csvField(v)', 'function download('),
].join('\n'), ctx);
const evaluate = code => JSON.parse(JSON.stringify(vm.runInContext(code, ctx)));

test('CSV retains quoted commas, escaped quotes and multiline cells', () => {
  assert.deepEqual(evaluate('parseCsv(\'email,name,note\\r\\na@example.org,"Doe, Jane","line 1\\nline ""2"""\')'),
    [['email', 'name', 'note'], ['a@example.org', 'Doe, Jane', 'line 1\nline "2"']]);
});
test('CSV import keeps metadata, counts duplicates and blank addresses', () => {
  const result = evaluate('contactsFromCsv("Email,Name\\na@example.org,Alice\\nA@example.org,Duplicate\\n,Blank")');
  assert.equal(result.contacts.length, 1);
  assert.equal(result.contacts[0].contact.Name, 'Alice');
  assert.equal(result.dupes, 1);
  assert.equal(result.blank, 1);
});
test('HTML escaping prevents imported markup from becoming HTML', () => {
  assert.equal(evaluate('esc(\'<img src=x onerror="alert(1)">\')'), '&lt;img src=x onerror=&quot;alert(1)&quot;&gt;');
});
test('CSV export neutralizes a direct spreadsheet formula', () => {
  assert.equal(evaluate('csvField("=1+1")'), "'=1+1");
});
test('Import must preserve a leading hyphen in the mailbox name', () => {
  assert.equal(evaluate('cleanEmail("-sales@example.org")'), '-sales@example.org');
});
test('Pasted addresses must not silently become a different mailbox', () => {
  assert.deepEqual(evaluate('extractEmails("alice!tag@example.org")'), ['alice!tag@example.org']);
});
test('Temporary DNS errors must not claim the domain cannot receive email', () => {
  const reason = evaluate('reasonFor({status:"unknown",result:{mx:{error:{type:"ResolveError",message:"timeout"}}}})');
  assert.doesNotMatch(reason, /has no mail server|cannot receive email/);
});
