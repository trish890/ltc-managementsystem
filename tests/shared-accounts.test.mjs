import assert from 'node:assert/strict';
import { randomBytes, pbkdf2Sync, createCipheriv } from 'node:crypto';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { test } from 'node:test';
import { createSharedStoreHandler } from '../netlify/functions/shared-store.mjs';

const html = readFileSync(new URL('../Luwas_Transport_Corp___Management_System (1).html', import.meta.url), 'utf8');
const script = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(match => match[1]).join('\n');
const clone = value => value == null ? value : structuredClone(value);
const password = () => randomBytes(18).toString('base64url');

// Test double only. Production uses Postgres, including conditional updates.
class TestRepository {
  records = new Map();
  async get(key) { return clone(this.records.get(key)) ?? null; }
  async setJSON(key, value) { this.records.set(key, clone(value)); }
  async delete(key) { this.records.delete(key); }
  async createBundle(bundle) {
    if (this.records.has('shared-bundle')) return false;
    this.records.set('shared-bundle', clone(bundle));
    return true;
  }
  async updateBundle(revision, bundle, session) {
    await new Promise(resolve => setImmediate(resolve));
    if (this.records.get('shared-bundle')?.revision !== revision) return false;
    this.records.set('shared-bundle', clone(bundle));
    if (session) {
      const { key, ...value } = session;
      this.records.set(key, clone(value));
    }
    return true;
  }
}

function encrypt(data, key) {
  const iv = randomBytes(12), cipher = createCipheriv('aes-256-gcm', key, iv);
  return Buffer.concat([iv, cipher.update(data), cipher.final(), cipher.getAuthTag()]).toString('base64');
}

async function fixture() {
  const repository = new TestRepository(), secret = password(), key = randomBytes(32), salt = randomBytes(16);
  const user = { id: 'first-admin', u: 'administrator', salt: salt.toString('base64') };
  const kek = pbkdf2Sync(`${user.u}\n${secret}`, salt, 150000, 32, 'sha256');
  user.wk = encrypt(key, kek);
  const member = { id: user.id, u: user.u, name: 'Administrator', role: 'admin', active: true, legacyReadOnly: false, mc: false };
  await repository.createBundle({ users: { v: 2, users: [user] }, profiles: [member], enc: encrypt(Buffer.from(JSON.stringify({ team: [member] })), key), revision: 1 });
  return { repository, secret, handler: createSharedStoreHandler(repository) };
}

function browser(handler, { blockedStorage = false, failSaves = false } = {}) {
  const notices = [], successes = [], elements = new Map(), local = new Map();
  const storage = {
    getItem(key) { if (blockedStorage) throw Error('Storage unavailable'); return local.get(key) ?? null; },
    setItem(key, value) { if (blockedStorage) throw Error('Storage unavailable'); local.set(key, value); },
    removeItem(key) { local.delete(key); },
  };
  const element = selector => {
    if (!elements.has(selector)) elements.set(selector, { textContent: '', style: {}, innerHTML: '', querySelectorAll: () => [] });
    return elements.get(selector);
  };
  const context = vm.createContext({
    crypto: globalThis.crypto, TextEncoder, TextDecoder, Uint8Array, btoa, atob,
    window: { localStorage: storage, sessionStorage: storage },
    document: { querySelector: element, body: { className: 'locked' } },
    location: { protocol: 'https:', reload() {} },
    addEventListener() {}, setTimeout() {}, clearTimeout() {},
    alert: message => notices.push(message), confirm: () => true,
    FormData: class { constructor(form) { this.values = form.values; } get(key) { return this.values[key]; } },
    fetch: async (url, options) => failSaves && options.method === 'PUT'
      ? Response.json({ error: 'Service unavailable' }, { status: 503 })
      : handler(new Request(`https://example.netlify.app${url}`, options)),
    onToast: message => successes.push(message),
  });
  vm.runInContext(script + `
    render=()=>{};idle=()=>{};chPw=()=>{};toast=onToast;
    globalThis.app={doLogin,userAdd,doChPw,userPwSave,userToggle,userDel,save,
      get state(){return {db,ME,users:getUsers(),token:AUTH_TOKEN,revision:REMOTE_REVISION,error:SAVE_ERROR?.message}},
      async login(username,password){const button={disabled:false};await doLogin({preventDefault(){},target:{u:{value:username},p:{value:password},querySelector:()=>button}})},
      async add(username,password){await userAdd({preventDefault(){},target:{values:{u:username,pw:password,fn:username,role:'finance'},querySelectorAll:()=>[]}})},
      async changePassword(oldPassword,newPassword){await doChPw({preventDefault(){},target:{o:{value:oldPassword},n:{value:newPassword},c:{value:newPassword},querySelectorAll:()=>[]}},true)},
      async resetPassword(id,password){await userPwSave({preventDefault(){},target:{values:{pw:password},querySelectorAll:()=>[]}},id)},
      async snapshot(){return {users:getUsers(),enc:readCache('luwas_enc'),profiles:profileSnapshot(),revision:REMOTE_REVISION}}
    };`, context);
  return { app: context.app, notices, successes, local, elements };
}

test('created account logs in from independent browser caches and survives a backend restart', async () => {
  const f = await fixture(), admin = browser(f.handler), temporary = password();
  await admin.app.login('administrator', f.secret);
  await admin.app.add('new.employee', temporary);
  assert.equal(admin.notices.length, 0);
  assert.match(admin.successes.at(-1), /User saved/);
  for (const blockedStorage of [false, true]) {
    const fresh = browser(createSharedStoreHandler(f.repository), { blockedStorage });
    assert.equal(fresh.local.size, 0);
    await fresh.app.login('NEW.EMPLOYEE', temporary);
    assert.equal(fresh.app.state.ME?.u, 'new.employee');
    assert.equal(fresh.app.state.ME.mc, true);
    assert.equal(fresh.notices.length, 0);
  }
});

test('password changes work in a fresh browser and preserve accounts belonging to other users', async () => {
  const f = await fixture(), admin = browser(f.handler), temporary = password(), updated = password();
  await admin.app.login('administrator', f.secret);
  await admin.app.add('new.employee', temporary);
  const employee = browser(f.handler, { blockedStorage: true });
  await employee.app.login('new.employee', temporary);
  await employee.app.changePassword(temporary, updated);
  assert.equal(employee.notices.length, 0);
  assert.equal(employee.app.state.ME.mc, false);
  assert.equal(await employee.app.save(), true, 'own session remains valid after changing a password');
  const fresh = browser(f.handler);
  await fresh.app.login('new.employee', updated);
  assert.equal(fresh.app.state.ME?.u, 'new.employee');
  const old = browser(f.handler);
  await old.app.login('new.employee', temporary);
  assert.equal(old.app.state.ME, null);
  const anotherAdmin = browser(f.handler);
  await anotherAdmin.app.login('administrator', f.secret);
  assert.equal(anotherAdmin.app.state.ME?.role, 'admin');
});

test('account creation still persists when the administrator browser cannot store a local cache', async () => {
  const f = await fixture(), admin = browser(f.handler, { blockedStorage: true }), temporary = password();
  await admin.app.login('administrator', f.secret);
  await admin.app.add('new.employee', temporary);
  assert.equal(admin.local.size, 0);
  assert.equal(admin.notices.length, 0);
  const fresh = browser(f.handler);
  await fresh.app.login('new.employee', temporary);
  assert.equal(fresh.app.state.ME?.u, 'new.employee');
});

test('a failed save rolls back account creation and never displays success', async () => {
  const f = await fixture(), admin = browser(f.handler, { failSaves: true }), temporary = password();
  await admin.app.login('administrator', f.secret);
  await admin.app.add('unsaved.employee', temporary);
  assert.equal(admin.app.state.db.team.length, 1);
  assert.equal(admin.app.state.users.users.length, 1);
  assert.equal(admin.successes.length, 0);
  assert.match(admin.notices[0], /not saved/);
  const fresh = browser(f.handler);
  await fresh.app.login('unsaved.employee', temporary);
  assert.equal(fresh.app.state.ME, null);
});

test('a failed password save keeps the existing password and does not report success', async () => {
  const f = await fixture(), admin = browser(f.handler, { failSaves: true }), updated = password();
  await admin.app.login('administrator', f.secret);
  await admin.app.changePassword(f.secret, updated);
  assert.equal(admin.successes.length, 0);
  assert.match(admin.notices[0], /not saved/);
  const fresh = browser(f.handler);
  await fresh.app.login('administrator', f.secret);
  assert.equal(fresh.app.state.ME?.role, 'admin');
  const failed = browser(f.handler);
  await failed.app.login('administrator', updated);
  assert.equal(failed.app.state.ME, null);
});

test('queued saves persist snapshots in order', async () => {
  const f = await fixture(), admin = browser(f.handler);
  await admin.app.login('administrator', f.secret);
  admin.app.state.db.co.name = 'First snapshot';
  const first = admin.app.save();
  admin.app.state.db.co.name = 'Latest snapshot';
  const second = admin.app.save();
  assert.deepEqual(await Promise.all([first, second]), [true, true]);
  const fresh = browser(f.handler);
  await fresh.app.login('administrator', f.secret);
  assert.equal(fresh.app.state.db.co.name, 'Latest snapshot');
});

test('simultaneous account saves preserve the winner and reject the stale writer', async () => {
  const f = await fixture(), a = browser(f.handler), b = browser(f.handler), pa = password(), pb = password();
  await Promise.all([a.app.login('administrator', f.secret), b.app.login('administrator', f.secret)]);
  await Promise.all([a.app.add('employee.one', pa), b.app.add('employee.two', pb)]);
  assert.equal(a.successes.length + b.successes.length, 1);
  assert.equal(a.notices.length + b.notices.length, 1);
  const saved = await f.repository.get('shared-bundle');
  assert.equal(saved.users.users.length, 2);
  const winner = saved.users.users.find(user => user.u !== 'administrator');
  const fresh = browser(f.handler);
  await fresh.app.login(winner.u, winner.u === 'employee.one' ? pa : pb);
  assert.equal(fresh.app.state.ME?.u, winner.u);
});

test('reset passwords and disabled/deleted accounts take effect across browsers', async () => {
  const f = await fixture(), admin = browser(f.handler), temporary = password(), reset = password();
  await admin.app.login('administrator', f.secret);
  await admin.app.add('new.employee', temporary);
  const employee = browser(f.handler);
  await employee.app.login('new.employee', temporary);
  const id = employee.app.state.ME.id;
  await admin.app.resetPassword(id, reset);
  assert.equal(admin.notices.length, 0);
  assert.equal(await employee.app.save(), false, 'a password reset revokes an old session');
  const old = browser(f.handler);
  await old.app.login('new.employee', temporary);
  assert.equal(old.app.state.ME, null);
  const fresh = browser(f.handler);
  await fresh.app.login('new.employee', reset);
  assert.equal(fresh.app.state.ME?.u, 'new.employee');
  await admin.app.userToggle(id);
  const disabled = browser(f.handler);
  await disabled.app.login('new.employee', reset);
  assert.equal(disabled.app.state.ME, null);
  await admin.app.userToggle(id);
  await admin.app.userDel(id);
  const deleted = browser(f.handler);
  await deleted.app.login('new.employee', reset);
  assert.equal(deleted.app.state.ME, null);
});

test('sign-out revokes the server session and unauthenticated writes are rejected', async () => {
  const f = await fixture(), admin = browser(f.handler);
  await admin.app.login('administrator', f.secret);
  const snapshot = await admin.app.snapshot(), token = admin.app.state.token;
  const request = (method, authorization) => new Request('https://example.netlify.app/api/shared-store', {
    method, headers: { 'Content-Type': 'application/json', ...(authorization ? { Authorization: `Bearer ${authorization}` } : {}) },
    body: method === 'PUT' ? JSON.stringify(snapshot) : undefined,
  });
  assert.equal((await f.handler(request('PUT'))).status, 401);
  assert.equal((await f.handler(request('DELETE', token))).status, 200);
  assert.equal((await f.handler(request('PUT', token))).status, 401);
});
