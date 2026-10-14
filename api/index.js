// Sentinel v3: moderation and staff management for Roblox games. Vercel + Supabase edition (many games, one site).
// Vercel runs this file as ONE serverless function. Functions forget everything between requests, so all
// state lives in Supabase (table panel_kv). Each request loads the rows it needs, runs, and saves only what
// changed in one all-or-nothing transaction (panel_commit). If two requests collide, the loser re-runs.
// Every game gets its own "workspace": its own rows (w<id>:*), its own members and its own game key.
const fs = require('fs'), path = require('path'), crypto = require('crypto');
const env = process.env, rnd = n => crypto.randomBytes(n).toString('base64url');

const cfg = { service: env.PANEL_SERVICE || 'Sentinel', company: env.PANEL_COMPANY || '', email: env.PANEL_EMAIL || '', country: env.PANEL_COUNTRY || '',
  legalReviewed: /^(1|true|yes)$/i.test(env.LEGAL_REVIEWED || ''), callRetentionDays: +env.CALL_RETENTION_DAYS || 90, updated: env.PANEL_LEGAL_UPDATED || '' };
const ENVNAME = { service: 'PANEL_SERVICE', company: 'PANEL_COMPANY', email: 'PANEL_EMAIL', country: 'PANEL_COUNTRY', callRetentionDays: 'CALL_RETENTION_DAYS' };
const APP_SECRET = env.APP_SECRET || '';
const SB_URL = (env.SUPABASE_URL || '').replace(/\/$/, ''), SB_KEY = env.SUPABASE_SERVICE_KEY || '';
const PROV = {
  google: { id: env.GOOGLE_CLIENT_ID, secret: env.GOOGLE_CLIENT_SECRET, auth: 'https://accounts.google.com/o/oauth2/v2/auth', token: 'https://oauth2.googleapis.com/token', info: 'https://openidconnect.googleapis.com/v1/userinfo', scope: 'openid profile' },
  roblox: { id: env.ROBLOX_CLIENT_ID, secret: env.ROBLOX_CLIENT_SECRET, auth: 'https://apis.roblox.com/oauth/v1/authorize', token: 'https://apis.roblox.com/oauth/v1/token', info: 'https://apis.roblox.com/oauth/v1/userinfo', scope: 'openid profile' },
};
if (env.OAUTH_TEST_BASE) for (const [k, P] of Object.entries(PROV)) Object.assign(P, { auth: `${env.OAUTH_TEST_BASE}/${k}/authorize`, token: `${env.OAUTH_TEST_BASE}/${k}/token`, info: `${env.OAUTH_TEST_BASE}/${k}/userinfo` }); // tests only
const providers = () => Object.keys(PROV).filter(k => PROV[k].id && PROV[k].secret);
const MAX_WORKSPACES = +env.MAX_WORKSPACES || 50, MAX_PER_USER = +env.MAX_WORKSPACES_PER_USER || 3, SIGNUPS_OPEN = !/^(0|false|no)$/i.test(env.SIGNUPS_OPEN || '');
const CONFIG_ERROR = [!SB_URL && 'SUPABASE_URL', !SB_KEY && 'SUPABASE_SERVICE_KEY', APP_SECRET.length < 32 && 'APP_SECRET (at least 32 characters)',
  !providers().length && 'GOOGLE_CLIENT_ID + GOOGLE_CLIENT_SECRET and/or ROBLOX_CLIENT_ID + ROBLOX_CLIENT_SECRET'].filter(Boolean);
const LIVE_MS = 35000, CHAT_MS = 24 * 36e5; // a game server counts as online for 35 s after its last check-in; chat is kept at most 24 h

// ---- rate limiter: counts per key in a time window. Lives in memory, so each serverless instance counts on its own ----
const buckets = new Map();
function limit(key, max, windowMs) { // returns 0 if allowed, otherwise the seconds to wait
  const now = Date.now(); let b = buckets.get(key);
  if (!b || now > b.reset) { b = { n: 0, reset: now + windowMs }; buckets.set(key, b); }
  if (buckets.size > 5000) for (const [k, v] of buckets) if (now > v.reset) buckets.delete(k);
  return ++b.n <= max ? 0 : Math.ceil((b.reset - now) / 1000);
}
const ipOf = req => String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '?').split(',')[0].trim();

// ---- permissions: every rank gets a set of these. The workspace owner always has all of them ----
const PERMS = [
  ['mod.warn', 'Warn players', 'Moderation'], ['mod.kick', 'Kick players', 'Moderation'], ['mod.mute', 'Mute and unmute players', 'Moderation'],
  ['mod.ban', 'Suspend players (timed bans)', 'Moderation', 1], ['mod.permban', 'Ban players permanently', 'Moderation', 1], ['mod.unban', 'Unban players', 'Moderation', 1],
  ['logbook.note', 'Add private notes to players', 'Moderation'], ['logbook.revert', 'Revert logbook entries', 'Moderation', 1],
  ['reports.handle', 'Claim and resolve reports', 'Reports'], ['appeals.review', 'Review ban appeals', 'Reports'], ['chat.view', 'Read live chat', 'Reports'],
  ['announce', 'Announce to every server', 'Game'], ['sessions.host', 'Host sessions', 'Activity'], ['points.manage', 'Give and remove points', 'Activity'],
  ['loa.review', 'Approve or deny leave requests', 'Team'], ['team.manage', 'Invite, remove and re-rank members below them', 'Team', 1], ['ranks.manage', 'Create and edit ranks below their own', 'Team', 1],
  ['rulebook.manage', 'Edit the rulebook', 'Settings'], ['automations.manage', 'Change automations, flagged words and quotas', 'Settings'], ['audit.view', 'See the audit log', 'Settings'],
  ['webhooks.manage', 'Manage Discord notifications', 'Settings', 1], ['privacy.manage', 'Export and erase player data', 'Settings', 1],
];
const ALLP = PERMS.map(p => p[0]);
const defaultRanks = () => ({
  admin: { name: 'Administrator', color: '#635bff', pos: 30, perms: ALLP.slice(), quota: 0, limit: 0 },
  mod: { name: 'Moderator', color: '#0ea5e9', pos: 20, perms: ['mod.warn', 'mod.kick', 'mod.mute', 'mod.ban', 'mod.unban', 'logbook.note', 'reports.handle', 'chat.view', 'announce', 'sessions.host', 'points.manage'], quota: 120, limit: 30 },
  helper: { name: 'Trial Moderator', color: '#10b981', pos: 10, perms: ['mod.warn', 'mod.kick', 'logbook.note', 'reports.handle', 'chat.view', 'sessions.host'], quota: 60, limit: 15 },
});
const DEFAULT_WEBHOOK = () => ({ url: '', events: { reports: true, bans: true, kicks: false, warns: false, loa: true, sessions: false, appeals: true, watch: true } });
const HOOK_RE = /^https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d{5,30}\/[\w-]{20,120}$/;

// ---- storage ----
const freshD = () => ({ meta: null, members: {}, invites: {}, ranks: {}, rulebook: [], loa: [], webhook: null, daily: {},
  bans: {}, mutes: {}, logs: {}, feed: [], stats: { joins: 0, peak: 0, kicks: 0 }, calls: [], callSeq: 0, session: null, sessions: [],
  flagWords: ['scam', 'hack', 'exploit', 'free robux'], play: {}, audit: [], rules: {}, settings: { quotaMinutes: 60 }, appeals: [], watch: {}, hist: {} });
const D = freshD(), R = { servers: {}, cmds: [], history: [], chat: [], flagCount: {}, nextId: 1 };
let OCQ = [], FB = [], U = null, G = { workspaces: 0 }, HOOKS = []; // U = the signed-in person's account, G = global counters, HOOKS = Discord messages to send after saving
const CTX = { uid: null, wid: null };
const setUid = u => { if (!/^[gr]_\d{1,32}$/.test(u)) throw new Error('bad user'); CTX.uid = u; };
const setWid = w => { if (!/^[a-f0-9]{12}$/.test(w)) throw new Error('bad workspace'); CTX.wid = w; };
const save = () => {};
const pruneCalls = () => { const cut = Date.now() - cfg.callRetentionDays * 864e5; D.calls = D.calls.filter(c => c.t > cut); };
const liveServers = () => Object.values(R.servers).filter(s => Date.now() - s.last < LIVE_MS).length;
const CORE_KEYS = ['meta', 'members', 'invites', 'ranks', 'rulebook', 'loa', 'webhook', 'daily', 'bans', 'mutes', 'feed', 'stats', 'callSeq', 'session', 'sessions', 'flagWords', 'audit', 'rules', 'settings', 'appeals', 'watch'];
const ROWS = {
  core: { get: () => Object.fromEntries(CORE_KEYS.map(k => [k, D[k]])), set: v => Object.assign(D, v) },
  logs: { get: () => D.logs, set: v => { D.logs = v; } },
  calls: { get: () => D.calls, set: v => { D.calls = v; } },
  play: { get: () => D.play, set: v => { D.play = v; } },
  live: { get: () => ({ servers: R.servers, history: R.history }), set: v => { R.servers = v.servers || {}; R.history = v.history || []; } },
  cmds: { get: () => ({ cmds: R.cmds, nextId: R.nextId }), set: v => { R.cmds = v.cmds || []; R.nextId = v.nextId || 1; } },
  chat: { get: () => ({ chat: R.chat, flagCount: R.flagCount }), set: v => { R.chat = v.chat || []; R.flagCount = v.flagCount || {}; } },
  user: { get: () => U, set: v => { U = v; } },
  ...Object.fromEntries([...Array(16).keys()].map(i => ['h' + i, { get: () => (D.hist[i] ||= {}), set: v => { D.hist[i] = v || {}; } }])), // per-player playtime history, split in 16 rows so each save stays small
  glob: { get: () => G, set: v => { G = v; } },
  fb: { get: () => FB, set: v => { FB = Array.isArray(v) ? v : []; } }, // feedback and questions from every workspace, answered from the admin page
};
const phys = k => k === 'user' ? 'u:' + CTX.uid : k === 'glob' ? 'g:stats' : k === 'fb' ? 'g:feedback' : `w${CTX.wid}:${k}`;
const NEEDS = { '/api/state': ['play', 'live', 'calls', 'chat'], '/api/lookup': ['play', 'live', 'logs', 'chat', 'calls'], '/api/player': ['play', 'live', 'logs', 'chat', 'calls'],
  '/api/action': ['logs', 'play', 'cmds'], '/api/escalation': ['logs'], '/api/appeals': ['logs', 'cmds', 'play'], '/api/backups': ['logs', 'play', 'calls'], '/api/feedback': ['fb'], '/api/backup/download': ['logs', 'play', 'calls'], '/api/backup/import': ['logs', 'play', 'calls'], '/api/logbook': ['logs', 'play'], '/api/entry': ['logs', 'play', 'cmds'],
  '/api/session': ['play', 'logs', 'cmds', 'live'], '/api/call': ['calls', 'cmds'], '/api/export': ['logs', 'play', 'calls', 'chat'], '/api/erase': ['logs', 'play', 'calls', 'chat'] };
const loaded = {};
const sbf = (u, o) => fetch(u, { ...o, signal: AbortSignal.timeout(8000) }); // never hang forever on the database
const sbHeaders = () => ({ apikey: SB_KEY, ...(SB_KEY.startsWith('eyJ') ? { Authorization: 'Bearer ' + SB_KEY } : {}), 'Content-Type': 'application/json' });
function resetState() {
  for (const k of Object.keys(D)) delete D[k]; Object.assign(D, freshD());
  Object.assign(R, { servers: {}, cmds: [], history: [], chat: [], flagCount: {}, nextId: 1 }); U = null; FB = []; OCQ = []; G = { workspaces: 0 }; HOOKS = []; CTX.uid = CTX.wid = null;
  for (const k of Object.keys(loaded)) delete loaded[k];
}
async function need(...keys) {
  const want = [...new Set(keys)].filter(k => !(k in loaded)); if (!want.length) return;
  const pk = Object.fromEntries(want.map(k => [k, phys(k)]));
  const r = await sbf(`${SB_URL}/rest/v1/panel_kv?select=key,value,version&key=in.(${Object.values(pk).join(',')})`, { headers: sbHeaders() });
  if (!r.ok) throw new Error(`Supabase read failed: HTTP ${r.status} ${(await r.text()).slice(0, 200)}`);
  const rows = Object.fromEntries((await r.json()).map(x => [x.key, x]));
  for (const k of want) {
    const row = rows[pk[k]]; if (row) ROWS[k].set(row.value);
    loaded[k] = { pk: pk[k], ver: row ? row.version : 0, snap: JSON.stringify(ROWS[k].get()) };
    if (k === 'calls') pruneCalls();
    if (k === 'chat') R.chat = R.chat.filter(m => Date.now() - m.t < CHAT_MS);
    if (k === 'core') migrate();
  }
}
async function commit() {
  const changes = [];
  for (const [k, l] of Object.entries(loaded)) { const v = ROWS[k].get(); if (JSON.stringify(v) !== l.snap) changes.push({ key: l.pk, expect: l.ver, value: v }); }
  if (!changes.length) return true;
  const r = await sbf(`${SB_URL}/rest/v1/rpc/panel_commit`, { method: 'POST', headers: sbHeaders(), body: JSON.stringify({ changes }) });
  if (!r.ok) throw new Error(`Supabase save failed: HTTP ${r.status} ${(await r.text()).slice(0, 200)}`);
  return (await r.json()) === true;
}
async function sendHooks() { // Discord notifications, only after the change was saved
  await Promise.all(HOOKS.splice(0).map(h => fetch(h.url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(h.body), signal: AbortSignal.timeout(3000) }).catch(() => {})));
}
function migrate() { // bring older workspaces up to date
  if (!D.meta) return;
  if (!D.ranks || !Object.keys(D.ranks).length) D.ranks = defaultRanks();
  const map = { helper: 'helper', moderator: 'mod', admin: 'admin' };
  for (const m of Object.values(D.members)) if (!m.rank || !D.ranks[m.rank]) { m.rank = map[m.role] && D.ranks[map[m.role]] ? map[m.role] : Object.keys(D.ranks)[0]; delete m.role; }
  for (const i of Object.values(D.invites)) if (!i.rank) { i.rank = map[i.role] || 'helper'; delete i.role; }
  D.appeals ||= []; D.watch ||= {};
  if (D.webhook && D.webhook.events) for (const k of ['appeals', 'watch']) if (!(k in D.webhook.events)) D.webhook.events[k] = true;
  if (!D.meta.v4) { D.meta.v4 = 1; for (const r of Object.values(D.ranks)) if (r.perms.includes('mod.unban') && !r.perms.includes('appeals.review')) r.perms.push('appeals.review'); }
  D.rulebook ||= []; D.loa ||= []; if (!D.daily || Array.isArray(D.daily)) D.daily = {};
}

// ---- who is asking, and what may they do? ----
function who(uid) {
  const m = D.members[uid]; if (!m) return null;
  const owner = D.meta.owner === uid, r = D.ranks[m.rank];
  return { uid, user: m.name, isOwner: owner, rank: m.rank, pos: owner ? 1e9 : (r ? r.pos : 0), perms: new Set(owner ? ALLP : (r ? r.perms : [])), limit: owner ? 0 : (r ? r.limit || 0 : 0) };
}
const has = (u, p) => !!u && u.perms.has(p);
const memberPos = id => id === D.meta.owner ? 1e9 : (D.ranks[(D.members[id] || {}).rank] || { pos: 0 }).pos;
const above = (u, pos) => u.isOwner || u.pos > pos; // you can only manage ranks and people below you
const deny = res => send(res, 403, { error: 'Your rank does not allow that.' });
const ownerOnly = res => send(res, 403, { error: 'Only the workspace owner can do that.' });
const clampInt = (v, lo, hi) => Math.min(hi, Math.max(lo, Math.round(+v) || 0));

// ---- game logic ----
const live = o => !o.expires || o.expires > Date.now();
const feed = (text, by) => { D.feed.unshift({ t: Date.now(), text }); D.feed.length = Math.min(D.feed.length, 50); if (by) audit(by, text); };
const audit = (user, text) => { D.audit.unshift({ t: Date.now(), user, text }); D.audit.length = Math.min(D.audit.length, 300); };
const DEFAULT_RULES = {
  autosuspend: { enabled: true, warns: 3, minutes: 5 }, sessionpoints: { enabled: true, points: 5 },
  flaggedmute: { enabled: false, count: 3, minutes: 5 }, welcome: { enabled: false, text: 'Welcome! Moderators are keeping this game friendly.' },
};
const rule = id => ({ ...DEFAULT_RULES[id], ...(D.rules[id] || {}) });
const weekStart = now => { const d = new Date(now); d.setUTCHours(0, 0, 0, 0); return d.getTime() - ((d.getUTCDay() + 6) % 7) * 864e5; };
const dayKey = t => new Date(t).toISOString().slice(0, 10);
const daily = () => { const k = dayKey(Date.now()), d = (D.daily[k] ||= { j: 0, p: 0, u: 0, a: 0, r: 0 }), ks = Object.keys(D.daily).sort(); if (ks.length > 35) for (const x of ks.slice(0, ks.length - 35)) delete D.daily[x]; return d; };
const fmtMin = m => !m ? 'Permanent' : m < 60 ? `${m} min` : m < 1440 ? `${Math.round(m / 6) / 10} h` : `${Math.round(m / 144) / 10} ${Math.round(m / 144) / 10 === 1 ? 'day' : 'days'}`;
const SH = 16, shOf = id => 'h' + (id % SH), phist = id => ((D.hist[id % SH] ||= {})[id] ||= { d: {}, j: [] });
const closeSession = h => { if (h.cur) { if (h.cur.s >= 5) { h.j.push([h.cur.t, Math.round(h.cur.s), h.cur.sv]); if (h.j.length > 40) h.j.shift(); } h.cur = null; } };
const playOf = (userId, name) => (D.play[userId] ||= { name, total: 0, week: 0, weekStart: 0, points: 0 });
function tick(p, dt, now) {
  const u = playOf(p.userId, p.name), ws = weekStart(now), dk = dayKey(now); u.name = p.name;
  if (u.weekStart !== ws) { u.weekStart = ws; u.week = 0; }
  u.total += dt; u.week += dt; if (u.day !== dk) { u.day = dk; daily().u++; }
  const h = phist(p.userId), di = Math.floor(now / 864e5);
  if (h.cur && now - h.cur.last > 120000) closeSession(h); // the game stopped reporting this player without a leave event
  if (!h.cur) h.cur = { t: now, s: 0, sv: p.sv || '', last: now };
  h.cur.s += dt; h.cur.last = now; h.d[di] = Math.round(((h.d[di] || 0) + dt) * 10) / 10;
  if (!h.pr || h.pr !== ws) { h.pr = ws; for (const k of Object.keys(h.d)) if (+k < di - 182) delete h.d[k]; }
}
let LUA_V = null; // the newest game script version is read from SentinelBridge.lua, so changing that file's SCRIPT_VERSION alerts every workspace
const latestScript = () => { if (LUA_V === null) { try { LUA_V = +((fs.readFileSync(path.join(__dirname, '..', 'SentinelBridge.lua'), 'utf8').match(/^local SCRIPT_VERSION = (\d+)/m) || [])[1]) || 0; } catch { LUA_V = 0; } } return LUA_V; };
const scriptInfo = () => { const v = D.meta.scriptV || (D.meta.connectedAt ? 1 : 0), latest = latestScript(); return { v, latest, outdated: v > 0 && latest > 0 && v < latest }; };
const KEEP_MS = 7 * 864e5; // bans and unbans wait for a server to start, since a banned player can't join to trigger anything
const cmd = c => {
  if ((c.type === 'ban' || c.type === 'unban') && c.userId) { R.cmds = R.cmds.filter(x => !((x.type === 'ban' || x.type === 'unban') && x.userId === c.userId)); c.keep = 1; } // the newest decision for a player replaces older ones
  R.cmds.push({ id: R.nextId++, t: Date.now(), seen: {}, ...c });
};

// ---- Roblox Open Cloud: lifts bans without needing a game server to be running ----
const RBX_API = env.OC_TEST_BASE || 'https://apis.roblox.com'; // OC_TEST_BASE is for tests only
const ocKey = () => crypto.createHash('sha256').update('oc:' + APP_SECRET).digest();
const ocEnc = t => { const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', ocKey(), iv), d = Buffer.concat([c.update(t, 'utf8'), c.final()]); return [iv, c.getAuthTag(), d].map(x => x.toString('base64url')).join('.'); };
const ocDec = t => { try { const [iv, tag, d] = String(t).split('.').map(x => Buffer.from(x, 'base64url')), c = crypto.createDecipheriv('aes-256-gcm', ocKey(), iv); c.setAuthTag(tag); return Buffer.concat([c.update(d), c.final()]).toString('utf8'); } catch { return ''; } };
const unbanCmd = userId => { cmd({ type: 'unban', userId }); if (D.meta && D.meta.oc) OCQ.push(+userId); };
async function ocUniverse() {
  const o = D.meta.oc; if (o.universe) return o.universe;
  const place = D.meta.placeId || D.meta.lastPlace; if (!place) throw new Error('Sentinel does not know your game yet. Enter your Universe ID, or start the game once.');
  const r = await sbf(`${RBX_API}/universes/v1/places/${encodeURIComponent(place)}/universe`); const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.universeId) throw new Error('Could not find the universe for place ' + place); o.uni = String(j.universeId); return o.uni;
}
async function ocPatch(uni, userId, key, mask) {
  const r = await sbf(`${RBX_API}/cloud/v2/universes/${uni}/user-restrictions/${userId}${mask ? '?updateMask=gameJoinRestriction' : ''}`, { method: 'PATCH', headers: { 'x-api-key': key, 'Content-Type': 'application/json' }, body: JSON.stringify({ gameJoinRestriction: { active: false } }) });
  return { r, text: (await r.text().catch(() => '')).slice(0, 300) };
}
async function runOC() {
  if (!OCQ.length || !D.meta || !D.meta.oc) { OCQ = []; return; }
  const ids = [...new Set(OCQ)].slice(0, 5); OCQ = []; const o = D.meta.oc, key = ocDec(o.key);
  for (const id of ids) {
    let ok = false, msg = '';
    try {
      if (!key) throw new Error('The saved Roblox key could not be read. Save it again.');
      const uni = o.universe || o.uni || await ocUniverse(); let x = await ocPatch(uni, id, key, true);
      if (x.r.status === 400) x = await ocPatch(uni, id, key, false);
      ok = x.r.ok; msg = ok ? 'Lifted' : `Roblox said ${x.r.status}${x.r.status === 401 || x.r.status === 403 ? ' (check the key, its permission, and that it covers this experience)' : x.r.status === 404 ? ' (that player has no Roblox ban here, or the Universe ID is wrong)' : ''}: ${x.text.replace(/\s+/g, ' ').slice(0, 140)}`;
      if (x.r.status === 404 && /not.?found/i.test(x.text)) { ok = true; msg = 'No ban found on Roblox, so nothing to lift'; }
    } catch (e) { msg = String(e.message || e).slice(0, 200); }
    o.last = { t: Date.now(), userId: id, ok, msg }; if (!ok) audit('Sentinel', `Could not lift the Roblox ban on ${id}: ${msg}`);
  }
}
const MOD_TYPES = ['Warned', 'Kicked', 'Muted', 'Suspended', 'Banned'];
function logEntry(userId, name, e) {
  const list = (D.logs[userId] ||= []), x = { id: rnd(6), name, status: 'active', time: Date.now(), ...e };
  list.push(x); if (list.length > 500) list.splice(0, list.length - 500);
  if (MOD_TYPES.includes(x.type)) daily().a++;
  return x;
}
function notify(ev, title, desc, fields = [], color = 0x635bff) {
  const w = D.webhook; if (!w || !w.url || !w.events || !w.events[ev]) return;
  HOOKS.push({ url: w.url, body: { username: 'Sentinel', allowed_mentions: { parse: [] }, embeds: [{ title: String(title).slice(0, 250), description: String(desc || '').slice(0, 1000), color,
    fields: fields.filter(f => f[1]).map(([n, v]) => ({ name: n, value: String(v).slice(0, 200), inline: true })), footer: { text: D.meta ? D.meta.name : 'Sentinel' }, timestamp: new Date().toISOString() }] } });
}
function addPoints(userId, name, amount, reason, by, byUid = null) {
  playOf(userId, name).points += amount;
  logEntry(userId, name, { type: 'Points', amount, reason: `${amount > 0 ? '+' : ''}${amount}: ${reason}`, by, byUid });
  feed(`Points ${amount > 0 ? '+' : ''}${amount} for ${name} (${reason})`, by);
  cmd({ type: 'message', kind: amount > 0 ? 'ok' : undefined, title: 'Points', body: `${amount > 0 ? 'You earned' : 'You lost'} ${Math.abs(amount)} points: ${reason}`, userId, text: `${amount > 0 ? 'You earned' : 'You lost'} ${Math.abs(amount)} points: ${reason}` });
}
function allPlayers() {
  const now = Date.now(), out = [];
  for (const [j, s] of Object.entries(R.servers)) { if (now - s.last > LIVE_MS) continue; for (const p of s.players) out.push({ ...p, server: j.slice(0, 8) }); }
  return out;
}
function act({ action, userId, name, reason, minutes, by = 'Automation', byUid = null, ruleId = null }) {
  const expires = minutes > 0 ? Date.now() + minutes * 60000 : null;
  const log = type => { const e = logEntry(userId, name, { type, reason, minutes, by, byUid, ruleId }); feed(`${type}: ${name} (${reason})`, by); return e; };
  if (action === 'ban') {
    const e = log(expires ? 'Suspended' : 'Banned'); D.bans[userId] = { userId, name, reason, time: Date.now(), expires, entry: e.id, by };
    cmd({ type: 'ban', userId, reason, seconds: minutes > 0 ? minutes * 60 : -1 }); notify('bans', `${expires ? 'Suspended' : 'Banned'} ${name}`, reason, [['Length', fmtMin(minutes)], ['By', by]], 0xe5484d);
  } else if (action === 'unban') { delete D.bans[userId]; log('Unbanned'); unbanCmd(userId); notify('bans', `Unbanned ${name}`, reason, [['By', by]], 0x30a46c); }
  else if (action === 'mute') { const e = log('Muted'); D.mutes[userId] = { userId, name, reason, expires, entry: e.id }; const mt = `You can't chat ${expires ? 'for ' + fmtMin(minutes) : 'until a moderator lifts it'}. Reason: ${reason}`; cmd({ type: 'message', kind: 'warn', title: 'You were muted', body: mt, userId, text: mt }); }
  else if (action === 'unmute') { delete D.mutes[userId]; log('Unmuted'); }
  else if (action === 'kick') { D.stats.kicks++; log('Kicked'); cmd({ type: 'kick', userId, reason: 'Kicked: ' + reason }); notify('kicks', `Kicked ${name}`, reason, [['By', by]], 0xf76b15); }
  else if (action === 'warn') {
    log('Warned'); cmd({ type: 'message', kind: 'warn', title: 'Warning', body: reason, userId, text: 'Warning: ' + reason }); notify('warns', `Warned ${name}`, reason, [['By', by]], 0xffc53d);
    let n = 0; // active warnings since the last suspension or ban
    for (const e of [...D.logs[userId]].reverse()) { if (e.status === 'reverted') continue; if (e.type === 'Suspended' || e.type === 'Banned') break; if (e.type === 'Warned') n++; }
    const r = rule('autosuspend');
    if (r.enabled && n >= r.warns) act({ action: 'ban', userId, name, reason: `Automatic: ${r.warns} warnings`, minutes: r.minutes, by: 'Automation' });
  }
}
function sync(b) {
  const now = Date.now(), id = String(b.jobId || 'studio').slice(0, 64), prev = R.servers[id], dt = prev ? Math.min((now - prev.last) / 1000, 30) : 0;
  const players = (Array.isArray(b.players) ? b.players : []).slice(0, 200).filter(p => p && Number.isInteger(p.userId) && p.userId > 0)
    .map(p => ({ userId: p.userId, name: String(p.name || p.userId).slice(0, 40), displayName: String(p.displayName || p.name || '').slice(0, 40) }));
  R.servers[id] = { players, last: now, first: prev ? prev.first || now : now };
  for (const [j, sv] of Object.entries(R.servers)) if (now - sv.last > 6e4) delete R.servers[j];
  for (const p of players) tick({ ...p, sv: id.slice(0, 8) }, dt, now);
  for (const e of (Array.isArray(b.events) ? b.events : []).slice(0, 100)) {
    if (!e) continue;
    const text = String(e.text || '').slice(0, 200), name = String(e.name || '?').slice(0, 40), uid = Number.isInteger(e.userId) ? e.userId : 0;
    if (e.type === 'join' && D.meta && scriptInfo().outdated && Date.now() - (D.meta.scriptAlertAt || 0) > 6 * 36e5) { // tell the owner and anyone who can change settings, in game
      const dev = Object.entries(D.members).some(([mid, m]) => m.robloxId && String(m.robloxId) === String(uid) && (mid === D.meta.owner || has(who(mid), 'automations.manage')));
      if (dev) { D.meta.scriptAlertAt = Date.now(); const msg = 'Your Sentinel game script is out of date. Open Settings, then Game on the website, download the new script and paste it into your game.'; cmd({ type: 'message', kind: 'warn', title: 'Sentinel update available', body: msg, text: 'Sentinel update: ' + msg, userId: uid }); }
    }
    if (e.type === 'join') { D.stats.joins++; daily().j++; feed(`${name} joined`); if (D.watch[uid]) { feed(`Watchlist: ${name} joined (${D.watch[uid].reason || 'no reason'})`); notify('watch', `Watched player joined: ${name}`, D.watch[uid].reason || '', [['Server', String(b.jobId || '').slice(0, 8)]], 0xffc53d); } const w = rule('welcome'); if (w.enabled) cmd({ type: 'message', kind: 'info', userId: uid, text: w.text }); if (uid) { const h = phist(uid); if (h.cur && h.cur.s >= 5) { closeSession(h); h.cur = { t: now, s: 0, sv: id.slice(0, 8), last: now }; } } }
    else if (e.type === 'leave') { feed(`${name} left`); if (uid) closeSession(phist(uid)); }
    else if (e.type === 'chat') { // rolling buffer: latest 300 messages, at most 24 hours
      const flagged = D.flagWords.some(w => text.toLowerCase().includes(w));
      R.chat.push({ t: now, jobId: id, server: id.slice(0, 8), userId: uid, name, text, flagged }); if (R.chat.length > 300) R.chat.shift();
      if (flagged) {
        feed(`Flagged chat from ${name}: ${text}`);
        const r = rule('flaggedmute');
        if (r.enabled && (R.flagCount[uid] = (R.flagCount[uid] || 0) + 1) >= r.count) { R.flagCount[uid] = 0; act({ action: 'mute', userId: uid, name, reason: 'Automatic: repeated flagged chat', minutes: r.minutes, by: 'Automation' }); }
      }
    } else if (e.type === 'attend' && D.session) {
      D.session.attendees[uid] = name; cmd({ type: 'message', kind: 'ok', title: 'Session', body: `You are marked present for ${D.session.type}.`, userId: uid, text: `You are marked present for ${D.session.type}.` });
    } else if (e.type === 'modcall') {
      const call = { id: ++D.callSeq, t: now, from: { userId: uid, name }, text: text || 'No details given', server: id.slice(0, 8), status: 'open', by: null, note: '',
        chat: R.chat.filter(c => c.jobId === id).slice(-15).map(({ t, userId, name, text, flagged }) => ({ t, userId, name, text, flagged })) };
      D.calls.unshift(call); D.calls.length = Math.min(D.calls.length, 100); daily().r++;
      feed(`Report #${call.id} from ${name}: ${call.text}`);
      notify('reports', `Report #${call.id} from ${name}`, call.text, [['Server', id.slice(0, 8)]], 0x635bff);
      cmd({ type: 'message', kind: 'ok', title: 'Report sent', body: `Report #${call.id} sent. A moderator will respond soon.`, userId: uid, text: `Report #${call.id} sent. A moderator will respond soon.` });
    }
  }
  const total = allPlayers().length;
  if (total > D.stats.peak) D.stats.peak = total;
  if (total > ((D.daily[dayKey(now)] || {}).p || 0)) daily().p = total;
  const hist = R.history; if (!hist.length || now - hist[hist.length - 1].t > 6e4) { hist.push({ t: now, n: total }); if (hist.length > 120) hist.shift(); }
  for (const p of players) { const x = D.bans[p.userId]; if (x && live(x) && !R.cmds.some(c => c.type === 'kick' && c.userId === p.userId && now - c.t < 10000)) cmd({ type: 'kick', userId: p.userId, reason: 'Banned: ' + x.reason }); }
  R.cmds = R.cmds.filter(c => now - c.t < (c.keep ? KEEP_MS : 120000) && !(c.type === 'ban' && c.seconds > 0 && now - c.t >= c.seconds * 1000)); if (R.cmds.length > 300) R.cmds = R.cmds.slice(-300);
  if (!prev || now - prev.last > 90000) for (const c of R.cmds) if (c.keep) delete c.seen[id]; // a server that went quiet and came back (or a new Studio test, which always reports the same id) gets bans and unbans again
  const out = R.cmds.filter(c => !c.seen[id]); out.forEach(c => c.seen[id] = 1);
  return { commands: out.map(({ seen, t, keep, ...c }) => c.type === 'ban' && c.seconds > 0 ? { ...c, seconds: Math.max(1, Math.round(c.seconds - (now - t) / 1000)) } : c), muted: Object.values(D.mutes).filter(live).map(m => m.userId) };
}

// ---- Roblox lookups ----
const AV = new Map(), j = (u, o) => fetch(u, { ...o, signal: AbortSignal.timeout(4000) }).then(r => r.json());
async function avatars(ids) {
  const want = ids.filter(i => !AV.has(i)).slice(0, 100);
  if (want.length) try { const r = await j(`https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds=${want.join(',')}&size=150x150&format=Png`); for (const d of r.data || []) if (d.imageUrl) AV.set(d.targetId, d.imageUrl); } catch {}
  return Object.fromEntries(ids.filter(i => AV.has(i)).map(i => [i, AV.get(i)]));
}
async function findId(name) {
  try { const r = await j('https://users.roblox.com/v1/usernames/users', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ usernames: [name], excludeBannedUsers: false }) }); const u = r.data && r.data[0]; if (u) return u.id; } catch {}
  const n = name.toLowerCase(), p = allPlayers().find(p => p.name.toLowerCase() === n); if (p) return p.userId;
  const k = Object.entries(D.play).find(([, x]) => (x.name || '').toLowerCase() === n); return k ? +k[0] : null;
}
function auditExtras(id, online) {
  const h = (D.hist[id % SH] || {})[id] || { d: {}, j: [] }, now = Date.now(), joins = h.j.slice().reverse().map(([t, s, sv]) => ({ t, s, sv }));
  if (h.cur && online) joins.unshift({ t: h.cur.t, s: Math.round(h.cur.s), sv: h.cur.sv, live: true });
  const m = Object.entries(D.members).find(([k, x]) => k === 'r_' + id || String(x.robloxId) === String(id)), muid = m && m[0], r = m && D.ranks[m[1].rank];
  const byThem = muid ? Object.entries(D.logs).flatMap(([uid, list]) => list.filter(e => e.byUid === muid).map(e => ({ userId: +uid, name: e.name, type: e.type, reason: e.reason, time: e.time, minutes: e.minutes, status: e.status }))).sort((a, b) => b.time - a.time).slice(0, 80) : [];
  const last = online ? now : joins[0] ? joins[0].t + joins[0].s * 1000 : (D.play[id] && D.play[id].day ? Date.parse(D.play[id].day) : null);
  return { hist: { days: h.d, joins, today: Math.floor(now / 864e5) }, staff: m ? { rank: D.meta.owner === muid ? 'Owner' : (r ? r.name : 'Staff'), owner: D.meta.owner === muid } : null, byThem, lastSeen: last };
}
async function profile(id) {
  await need(shOf(id));
  let rb = null; try { const x = await j('https://users.roblox.com/v1/users/' + id); if (x && x.id) rb = x; } catch {}
  const local = D.play[id], online = allPlayers().find(p => p.userId === id);
  if (!rb && !local && !online && !D.logs[id]) return null;
  const ban = D.bans[id], mute = D.mutes[id], ws = weekStart(Date.now());
  return { userId: id, name: rb ? rb.name : online ? online.name : local ? local.name : 'User ' + id, displayName: rb ? rb.displayName : online ? online.displayName : '', created: rb ? rb.created : null,
    avatar: (await avatars([id]))[id] || null, online: !!online, server: online ? online.server : null,
    banned: ban && live(ban) ? ban : null, muted: mute && live(mute) ? mute : null, logbook: (D.logs[id] || []).slice().reverse(),
    play: local ? { total: Math.round(local.total), week: local.weekStart === ws ? Math.round(local.week) : 0, points: local.points } : null,
    reports: D.calls.filter(c => c.from.userId === id).slice(0, 20).map(c => ({ id: c.id, t: c.t, text: c.text, status: c.status })),
    chat: R.chat.filter(m => m.userId === id).slice(-60).reverse(), ...auditExtras(id, online), sessions: D.sessions.filter(s => s.attendees.some(a => a.userId === id)).length };
}

// ---- backups: daily snapshots, owner downloads, a 30-day recycle bin and a site-admin console ----
const BK_ROWS = ['core', 'logs', 'play', 'calls'], BK_KEEP_DAYS = 7, TRASH_MS = 30 * 864e5, ADMIN_TOKEN = env.ADMIN_TOKEN || '', CRON_SECRET = env.CRON_SECRET || '';
const sbGet = async q => { const r = await sbf(`${SB_URL}/rest/v1/panel_kv?${q}`, { headers: sbHeaders() }); if (!r.ok) throw new Error('Supabase read failed: HTTP ' + r.status); return r.json(); };
const sbUpsert = async rows => { if (!rows.length) return; const r = await sbf(`${SB_URL}/rest/v1/panel_kv?on_conflict=key`, { method: 'POST', headers: { ...sbHeaders(), Prefer: 'resolution=merge-duplicates,return=minimal' }, body: JSON.stringify(rows) }); if (!r.ok) throw new Error('Supabase write failed: HTTP ' + r.status); };
const sbDel = q => sbf(`${SB_URL}/rest/v1/panel_kv?${q}`, { method: 'DELETE', headers: { ...sbHeaders(), Prefer: 'return=minimal' } });
const bkDay = (t = Date.now()) => dayKey(t).replace(/-/g, '');
async function snapshot(wid, label) { // copy the workspace's important rows into backup rows
  const rows = await sbGet(`select=key,value&key=in.(${BK_ROWS.map(k => `w${wid}:${k}`).join(',')})`);
  if (!rows.some(r => r.key.endsWith(':core'))) return false;
  await sbUpsert(rows.map(r => ({ key: `bk:${label}:${wid}:${r.key.split(':')[1]}`, value: r.value, version: 1 }))); return true;
}
async function listSnapshots(wid) { return (await sbGet(`select=key&key=like.bk:*:${wid}:core`)).map(r => r.key.split(':')[1]).sort().reverse(); }
const labelTime = l => /^\d{8}$/.test(l) ? Date.UTC(+l.slice(0, 4), +l.slice(4, 6) - 1, +l.slice(6, 8)) : /^pre\d+$/.test(l) ? +l.slice(3) * 1000 : 0;
const CORE_FRESH = () => { const f = freshD(); return Object.fromEntries(CORE_KEYS.map(k => [k, f[k]])); };
async function restoreSnapshot(wid, label, by) {
  if (!/^(\d{8}|pre\d+)$/.test(label)) return false;
  const rows = await sbGet(`select=key,value&key=in.(${BK_ROWS.map(k => `bk:${label}:${wid}:${k}`).join(',')})`), snap = Object.fromEntries(rows.map(r => [r.key.split(':')[3], r.value]));
  if (!snap.core) return false;
  await snapshot(wid, 'pre' + Math.floor(Date.now() / 1000)); // a way back from this restore
  setWid(wid); await need(...BK_ROWS); const keepHash = D.meta && D.meta.codeHash, keepOc = D.meta && D.meta.oc;
  Object.assign(D, CORE_FRESH()); ROWS.core.set(snap.core); if (snap.logs) ROWS.logs.set(snap.logs); if (snap.play) ROWS.play.set(snap.play); if (snap.calls) ROWS.calls.set(snap.calls);
  migrate(); if (D.meta) { delete D.meta.deleted; if (keepHash) D.meta.codeHash = keepHash; if (keepOc) D.meta.oc = keepOc; else delete D.meta.oc; } audit(by, `Restored the workspace from the backup of ${label.startsWith('pre') ? 'a safety copy' : label}`); return true;
}
function backupFile() {
  const core = ROWS.core.get(); if (core.meta) { core.meta = { ...core.meta }; delete core.meta.codeHash; delete core.meta.oc; delete core.meta.deleted; }
  return { format: 'sentinel-backup', v: 1, exportedAt: new Date().toISOString(), workspace: { id: CTX.wid, name: D.meta.name }, rows: { core, logs: D.logs, play: D.play, calls: D.calls } };
}
function importBackup(data, uid, name) { // returns an error string, or '' when applied
  if (!data || data.format !== 'sentinel-backup' || data.v !== 1 || !data.rows || !data.rows.core || typeof data.rows.core !== 'object' || !data.rows.core.meta) return 'That is not a Sentinel backup file.';
  const fresh = CORE_FRESH(), c = data.rows.core, core = {};
  for (const k of CORE_KEYS) { if (!(k in c)) { core[k] = fresh[k]; continue; } const a = c[k], f = fresh[k]; if (Array.isArray(f) !== Array.isArray(a) || (f !== null && typeof f === 'object' && (a === null || typeof a !== 'object')) || (f === null && a !== null && typeof a !== 'object')) return `The backup looks damaged (${k}).`; core[k] = a; }
  if (!core.meta || typeof core.meta !== 'object') return 'The backup looks damaged (meta).';
  const keepHash = D.meta.codeHash, keepOc = D.meta.oc, wid = CTX.wid; delete core.meta.deleted; delete core.meta.oc;
  Object.assign(D, core); D.meta.id = wid; D.meta.name = name; D.meta.owner = uid; if (keepHash) D.meta.codeHash = keepHash; else delete D.meta.codeHash; if (keepOc) D.meta.oc = keepOc;
  if (!D.members[uid]) D.members[uid] = { name: U ? U.name : 'Owner', rank: Object.keys(D.ranks)[0] || 'admin', joined: Date.now() };
  const l = data.rows.logs, pl = data.rows.play, ca = data.rows.calls;
  D.logs = l && typeof l === 'object' && !Array.isArray(l) ? l : {}; D.play = pl && typeof pl === 'object' && !Array.isArray(pl) ? pl : {}; D.calls = Array.isArray(ca) ? ca : [];
  migrate(); return '';
}
async function cronRun() {
  const t0 = Date.now(), today = bkDay(), list = await sbGet('select=key,meta:value->meta&key=like.w*:core'); let snap = 0, purged = 0, pruned = 0, partial = false;
  const live = []; for (const r of list) { const wid = r.key.slice(1, 13); if (r.meta && r.meta.deleted) { if (Date.now() - r.meta.deleted > TRASH_MS) { await sbDel(`key=like.w${wid}:*`); await sbDel(`key=like.bk:*:${wid}:*`); purged++; } } else if (r.meta) live.push(wid); }
  for (let i = 0; i < live.length; i += 4) { if (Date.now() - t0 > 9000) { partial = true; break; } snap += (await Promise.all(live.slice(i, i + 4).map(w => snapshot(w, today).catch(() => false)))).filter(Boolean).length; }
  for (const r of await sbGet('select=key&key=like.bk:*:core')) { const [, label, wid] = r.key.split(':'), age = Date.now() - labelTime(label); if ((/^\d{8}$/.test(label) && age > BK_KEEP_DAYS * 864e5 + 36e5) || (/^pre\d+$/.test(label) && age > 14 * 864e5)) { await sbDel(`key=like.bk:${label}:${wid}:*`); pruned++; } }
  return { ok: true, snapshotted: snap, purged, pruned, partial };
}
const ADMIN_PAGE = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><meta name="color-scheme" content="light dark"><title>Sentinel admin</title><style>
:root{--bg:#f5f5f7;--card:#fff;--ink:#1d1d1f;--mu:#6e6e73;--ac:#0a7aff;--ln:rgba(0,0,0,.1)}@media(prefers-color-scheme:dark){:root{--bg:#1c1c1e;--card:#2a2a2d;--ink:#f5f5f7;--mu:#98989f;--ac:#0a84ff;--ln:rgba(255,255,255,.12)}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 -apple-system,BlinkMacSystemFont,"SF Pro Text",Inter,system-ui,sans-serif;padding:28px 18px}.w{max-width:960px;margin:0 auto}h1{font-size:24px;letter-spacing:-.02em;margin:0 0 4px}p{color:var(--mu);margin:0 0 18px}
.c{background:var(--card);border-radius:12px;box-shadow:0 0 0 .5px var(--ln);padding:16px 18px;margin-bottom:12px}.r{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.sp{flex:1}.mu{color:var(--mu);font-size:13px}
input{height:34px;border:0;border-radius:8px;padding:0 12px;background:rgba(127,127,127,.14);color:inherit;font:inherit;min-width:260px}button{height:30px;padding:0 12px;border:0;border-radius:8px;background:rgba(127,127,127,.18);color:inherit;font:inherit;font-weight:500;cursor:pointer}button.p{background:var(--ac);color:#fff}button.d{background:#ff3b30;color:#fff}
.b{display:inline-block;font-size:12px;border-radius:99px;padding:1px 9px;background:rgba(127,127,127,.18)}.b.x{background:rgba(255,59,48,.16);color:#d70015}code{font-size:12px;background:rgba(127,127,127,.16);padding:1px 6px;border-radius:5px}</style></head><body><div class="w"><h1>Sentinel admin</h1><p>Recover workspaces that were deleted or tampered with.</p>
<div class="c r" id="lg"><input id="t" type="password" placeholder="Admin token" autocomplete="off"><button class="p" id="go">Open</button><span class="mu" id="m"></span></div><div id="fb"></div><div id="o"></div></div>
<script>const $=i=>document.getElementById(i);let T=sessionStorage.getItem('adm')||'';const e=s=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
async function call(b){const r=await fetch('/admin/api',{method:'POST',headers:{'Content-Type':'application/json','x-admin-token':T},body:JSON.stringify(b)});const j=await r.json().catch(()=>({}));if(!r.ok)throw new Error(j.error||'Error '+r.status);return j}
async function loadFb(){const j=await call({op:'feedback'});$('fb').innerHTML=j.items.length?'<h2 style="font-size:17px;margin:18px 0 10px">Feedback and questions</h2>'+j.items.map(f=>'<div class="c"><div class="r"><span class="b">'+e(f.type)+'</span><b>'+e(f.user)+'</b><span class="mu">'+e(f.rank)+' · '+e(f.wsName)+' · '+new Date(f.t).toLocaleString()+'</span></div><p style="color:inherit;margin:8px 0;white-space:pre-wrap">'+e(f.text)+'</p><div class="r"><input data-r="'+f.id+'" placeholder="Write a reply" value="'+e(f.reply||'')+'" style="flex:1"><button class="p" data-o="fr" data-i="'+f.id+'">'+(f.reply?'Update reply':'Reply')+'</button><button class="d" data-o="fd" data-i="'+f.id+'">Delete</button></div></div>').join(''):''}
async function load(){try{const j=await call({op:'list'});loadFb().catch(()=>{});sessionStorage.setItem('adm',T);$('lg').hidden=true;$('o').innerHTML=j.workspaces.map(w=>'<div class="c"><div class="r"><b>'+e(w.name)+'</b> <code>'+w.id+'</code>'+(w.deleted?'<span class="b x">Deleted '+new Date(w.deleted).toLocaleDateString()+'</span>':'')+'<span class="sp"></span><span class="mu">owner '+e(w.owner)+' · '+w.members+' member'+(w.members==1?'':'s')+'</span></div><div class="r" style="margin-top:10px">'+(w.deleted?'<button class="p" data-o="rd" data-w="'+w.id+'">Restore workspace</button>':'')+'<button data-o="sn" data-w="'+w.id+'">Back up now</button><button data-o="ls" data-w="'+w.id+'">Backups…</button><button data-o="dl" data-w="'+w.id+'">Download</button><span class="mu" id="s'+w.id+'"></span></div></div>').join('')||'<div class="c mu">No workspaces yet.</div>'}catch(x){$('m').textContent=x.message}}
$('go').onclick=()=>{T=$('t').value.trim();load()};$('t').onkeydown=k=>{if(k.key==='Enter')$('go').click()};if(T)load();
$('fb').onclick=async ev=>{const b=ev.target.closest('button');if(!b)return;try{if(b.dataset.o==='fr')await call({op:'feedbackReply',id:b.dataset.i,reply:document.querySelector('[data-r="'+b.dataset.i+'"]').value});else if(confirm('Delete this message?'))await call({op:'feedbackDelete',id:b.dataset.i});loadFb()}catch(x){$('m').textContent=x.message}};
$('o').onclick=async ev=>{const b=ev.target.closest('button');if(!b)return;const w=b.dataset.w,s=$('s'+w);try{
if(b.dataset.o==='rd'){if(!confirm('Restore this workspace?'))return;await call({op:'restoreDeleted',wid:w});load()}
else if(b.dataset.o==='sn'){await call({op:'snapshotNow',wid:w});s.textContent='Backed up.'}
else if(b.dataset.o==='ls'){const j=await call({op:'snaps',wid:w});s.innerHTML=j.snaps.length?j.snaps.map(d=>'<button data-o="rs" data-w="'+w+'" data-d="'+d+'">'+(d.startsWith('pre')?'Safety copy '+new Date(+d.slice(3)*1000).toLocaleString():d.slice(0,4)+'-'+d.slice(4,6)+'-'+d.slice(6))+'</button>').join(' '):'No backups yet.'}
else if(b.dataset.o==='rs'){if(!confirm('Replace the workspace with the backup of '+b.dataset.d+'? A safety copy is made first.'))return;await call({op:'restoreSnapshot',wid:w,date:b.dataset.d});s.textContent='Restored.'}
else if(b.dataset.o==='dl'){const j=await call({op:'download',wid:w}),a=document.createElement('a');a.href=URL.createObjectURL(new Blob([JSON.stringify(j,null,1)],{type:'application/json'}));a.download='sentinel-backup-'+w+'.json';a.click()}
}catch(x){(s||$('m')).textContent=x.message}};</script></body></html>`;

// ---- sessions (signed cookies, nothing stored server-side), game keys, helpers ----
const hash = s => crypto.createHash('sha256').update(String(s)).digest();
const same = (a, b) => crypto.timingSafeEqual(hash(a), hash(b));
const SIGN = crypto.createHash('sha256').update('sign:' + APP_SECRET).digest();
const sign = t => crypto.createHmac('sha256', SIGN).update(t).digest('base64url');
const pack = o => { const b = Buffer.from(JSON.stringify(o)).toString('base64url'); return b + '.' + sign(b); };
const unpack = t => { if (!t) return null; const [b, g] = String(t).split('.'); if (!g || !same(g, sign(b))) return null; try { const d = JSON.parse(Buffer.from(b, 'base64url').toString()); return d && d.e > Date.now() ? d : null; } catch { return null; } };
const cookiesOf = req => Object.fromEntries((req.headers.cookie || '').split(';').map(s => s.trim()).filter(Boolean).map(s => { const i = s.indexOf('='); let v = s.slice(i + 1); try { v = decodeURIComponent(v); } catch {} return [s.slice(0, i), v]; }));
const mkCookie = (name, val, { maxAge = 604800, sameSite = 'Strict' } = {}) => `${name}=${encodeURIComponent(val)}; Path=/; HttpOnly; SameSite=${sameSite}; Max-Age=${maxAge}; Secure`;
const clearCookie = name => `${name}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0; Secure`;
const sessionUid = req => { const d = unpack(cookiesOf(req).sid); return d && /^[gr]_\d{1,32}$/.test(d.u || '') ? d.u : null; };
const ALNUM = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
const randSecret = n => { let o = ''; while (o.length < n) for (const b of crypto.randomBytes(n * 2)) if (b < 228 && o.length < n) o += ALNUM[b % ALNUM.length]; return o; };
const codeHash = sec => crypto.createHmac('sha256', SIGN).update('code:' + sec).digest('base64url');
const newCode = wid => { const sec = randSecret(28); return { code: `${wid}-${sec}`, hash: codeHash(sec) }; }; // shown to the owner once; only the hash is stored
const gameKey = (wid, rot) => `${wid}.${rot}.${crypto.createHmac('sha256', SIGN).update(`gamekey:${wid}:${rot}`).digest('base64url').slice(0, 32)}`;
const site = req => (env.SITE_URL || `${req.headers['x-forwarded-proto'] === 'http' ? 'http' : 'https'}://${req.headers['x-forwarded-host'] || req.headers.host}`).replace(/\/$/, '');
const send = (res, code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); };
const body = async req => req._body || {};
const tooMany = (res, s) => { res.setHeader('Retry-After', String(s)); return send(res, 429, { error: `Too many requests. Try again in ${s} seconds.`, retry: s }); };
const page = (res, code, title, text, href = '/', label = 'Back to Sentinel') => { res.writeHead(code, { 'Content-Type': 'text/html; charset=utf-8' }); res.end(`<!DOCTYPE html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title><body style="font:16px -apple-system,Segoe UI,system-ui,sans-serif;background:#f5f5f7;color:#1d1d1f;display:grid;place-items:center;min-height:100vh;margin:0"><div style="background:#fff;border-radius:20px;padding:36px 40px;max-width:380px;text-align:center;box-shadow:0 8px 30px rgba(0,0,0,.08)"><h2 style="margin:0 0 8px">${esc(title)}</h2><p style="color:#6e6e73;margin:0 0 20px">${esc(text)}</p><a href="${esc(href)}" style="display:inline-block;background:#0071e3;color:#fff;text-decoration:none;font-weight:600;padding:10px 20px;border-radius:10px">${esc(label)}</a></div></body>`); };
const cleanName = (s, n = 40) => String(s || '').replace(/[\u0000-\u001f<>]/g, '').replace(/\s+/g, ' ').trim().slice(0, n);
const LEGAL = { privacy: 'Privacy Policy', terms: 'Terms of Service', cookies: 'Cookie Policy', 'acceptable-use': 'Acceptable Use Policy', 'player-notice': 'Player Notice' };
const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
function legalPage(name) {
  const file = path.join(__dirname, '..', 'legal', name + '.html'), frag = fs.readFileSync(file, 'utf8');
  const body = frag.replace(/\{\{(\w+)\}\}/g, (_, k) => cfg[k] ? esc(cfg[k]) : `<mark>[set ${ENVNAME[k] || k} in your Vercel environment variables]</mark>`);
  const mt = fs.statSync(file).mtime, updated = cfg.updated || (mt.getFullYear() > 2020 ? mt.toISOString().slice(0, 10) : '<mark>[set PANEL_LEGAL_UPDATED]</mark>');
  const links = Object.entries(LEGAL).map(([k, t]) => `<a href="/legal/${k}"${k === name ? ' aria-current="page"' : ''}>${t}</a>`).join(' ');
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${LEGAL[name]}</title><style>
body{margin:0;background:#f4f6fb;color:#121528;font:16px/1.65 'Segoe UI',system-ui,sans-serif}main{max-width:780px;margin:0 auto;padding:36px 20px 80px}h1{font-size:36px;line-height:1.15;margin:0 0 4px}h2{font-size:21px;margin:32px 0 8px}
nav{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:28px;font-size:14px}nav a{color:#667085;text-decoration:none;font-weight:600}nav a[aria-current]{color:#2f5bff}a{color:#2f5bff}
table{border-collapse:collapse;width:100%;font-size:15px;margin:10px 0;background:#fff}td,th{border:1px solid #e6e9f2;padding:8px 10px;text-align:left;vertical-align:top}th{background:#eaefff}
mark{background:#fdf2dc;border-radius:4px;padding:0 4px}.draft{background:#fdf2dc;border:1px solid #f0d9a8;border-radius:10px;padding:12px 16px;margin:16px 0;font-size:15px}.muted{color:#667085}code{background:#eaefff;border-radius:4px;padding:1px 5px}
</style></head><body><main><nav>${links}</nav><h1>${LEGAL[name]}</h1><p class="muted">Last updated ${updated}</p>${cfg.legalReviewed ? '' : '<div class="draft"><b>Draft.</b> These documents have not been reviewed by a lawyer. Set LEGAL_REVIEWED to true in your Vercel environment variables once they have, and this notice will disappear.</div>'}${body}</main></body></html>`;
}
async function authRoute(req, res, url, p, ip) {
  const w = limit('auth:' + ip, 20, 60000); if (w) return page(res, 429, 'Too many attempts', `Please wait ${w} seconds and try again.`);
  const m = /^\/auth\/(google|roblox)(\/callback)?$/.exec(p); if (!m || req.method !== 'GET') return page(res, 404, 'Not found', 'That page does not exist.');
  const name = m[1], P = PROV[name]; if (!P.id || !P.secret) return page(res, 404, 'Not available', `Sign in with ${name === 'google' ? 'Google' : 'Roblox'} is not set up here.`);
  const redirect = site(req) + '/auth/' + name + '/callback';
  if (!m[2]) { // step 1: send the person to Google/Roblox
    const state = rnd(18), verifier = rnd(40), invite = url.searchParams.get('invite') || '', cur = sessionUid(req), link = name === 'roblox' && url.searchParams.get('link') === '1' && cur && cur[0] === 'g' ? cur : '';
    const q = new URLSearchParams({ client_id: P.id, redirect_uri: redirect, response_type: 'code', scope: P.scope, state, code_challenge: crypto.createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256', ...(name === 'google' ? { prompt: 'select_account' } : {}) });
    res.setHeader('Set-Cookie', mkCookie('oa', pack({ p: name, s: state, v: verifier, i: /^[a-f0-9]{28}$/.test(invite) ? invite : '', l: link, e: Date.now() + 1800000 }), { maxAge: 1800, sameSite: 'Lax' }));
    res.writeHead(302, { Location: P.auth + '?' + q }); return res.end();
  }
  // step 2: they came back with a code
  const oa = unpack(cookiesOf(req).oa), code = url.searchParams.get('code'), st = url.searchParams.get('state');
  if (url.searchParams.get('error')) return page(res, 400, 'Sign-in cancelled', 'No problem. You can try again whenever you like.');
  if (!oa || oa.p !== name || !code || !st || !same(st, oa.s)) return page(res, 400, 'Sign-in expired', 'That sign-in attempt took too long, was already used, or was started in another tab. Click below to start again.', `/auth/${name}`, 'Try again');
  if (!req._oauth) { // the code works once, so remember the result if this request has to re-run
    const tr = await fetch(P.token, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }, body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: redirect, client_id: P.id, client_secret: P.secret, code_verifier: oa.v }) });
    const tj = await tr.json().catch(() => ({})); if (!tr.ok || !tj.access_token) { req._oauth = { fail: 1 }; }
    else { const info = await (await fetch(P.info, { headers: { Authorization: 'Bearer ' + tj.access_token } })).json().catch(() => ({})); req._oauth = /^\d{1,32}$/.test(String(info.sub || '')) ? { sub: String(info.sub), name: cleanName(info.name || info.nickname || info.preferred_username || 'Member'), uname: cleanName(info.preferred_username || info.nickname || info.name || '') } : { fail: 1 }; }
  }
  if (req._oauth.fail) return page(res, 400, 'Sign-in failed', 'We could not confirm your account with ' + (name === 'google' ? 'Google' : 'Roblox') + '. Please try again.', `/auth/${name}`, 'Try again');
  if (oa.l) { // linking a Roblox account to the signed-in Google account, so in-game activity counts for them
    const cur = sessionUid(req); if (cur !== oa.l) return page(res, 400, 'Sign-in changed', 'Please sign in again and retry linking.');
    setUid(cur); await need('user'); if (!U) return page(res, 400, 'Account not found', 'Please sign in again.');
    U.roblox = { id: req._oauth.sub, name: req._oauth.uname || req._oauth.name };
    res.setHeader('Set-Cookie', clearCookie('oa')); res.writeHead(302, { Location: '/#linked' }); return res.end();
  }
  const uid = name[0] + '_' + req._oauth.sub; setUid(uid); await need('user');
  if (!U) { if (!SIGNUPS_OPEN && !oa.i) return page(res, 403, 'Sign-ups are closed', 'This site is not accepting new accounts right now.'); U = { id: uid, provider: name, workspaces: [], created: Date.now() }; }
  U.name = req._oauth.name;
  res.setHeader('Set-Cookie', [mkCookie('sid', pack({ u: uid, e: Date.now() + 7 * 864e5 })), clearCookie('oa')]);
  res.writeHead(302, { Location: '/' + (oa.i ? '#/join/' + oa.i : '') }); return res.end();
}

const ACT_PERM = { warn: 'mod.warn', kick: 'mod.kick', mute: 'mod.mute', unmute: 'mod.mute', ban: 'mod.ban', unban: 'mod.unban', announce: 'announce', points: 'points.manage' };
const TYPE_GROUP = { Warned: 'warn', Kicked: 'kick', Muted: 'mute', Unmuted: 'mute', Suspended: 'ban', Banned: 'ban', Unbanned: 'ban', Points: 'points', Note: 'note' };
const ok = res => send(res, 200, { ok: true });
const APPEAL_MAX = 2, APPEAL_WINDOW = 5 * 864e5; // each player may appeal twice every 5 days
const APPEAL_PAGE = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><meta name="robots" content="noindex"><title>Ban appeal</title><style>
:root{--bg:#e9eefb;--card:rgba(255,255,255,.82);--ink:#1d1d1f;--mu:#6e6e73;--ac:#0a7aff;--ln:rgba(0,0,0,.14)}@media(prefers-color-scheme:dark){:root{--bg:#0d1020;--card:rgba(44,44,48,.8);--ink:#f5f5f7;--mu:#98989f;--ac:#0a84ff;--ln:rgba(255,255,255,.18)}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:20px;background:radial-gradient(40% 45% at 15% 20%,#8ab8ff55,transparent 70%),radial-gradient(40% 45% at 85% 85%,#ffc2a155,transparent 70%),var(--bg);color:var(--ink);font:15px/1.5 -apple-system,BlinkMacSystemFont,"SF Pro Text",Inter,system-ui,sans-serif}
.c{width:100%;max-width:440px;background:var(--card);-webkit-backdrop-filter:blur(40px) saturate(180%);backdrop-filter:blur(40px) saturate(180%);border-radius:20px;padding:34px 30px;box-shadow:0 0 0 .5px var(--ln),0 24px 64px rgba(20,24,40,.2)}
h1{font-size:23px;letter-spacing:-.02em;margin:0 0 6px}p{color:var(--mu);margin:0 0 20px}label{display:block;font-weight:600;font-size:13px;margin:14px 0 6px}
input,textarea{width:100%;border:0;border-radius:9px;padding:10px 12px;font:inherit;color:inherit;background:rgba(127,127,127,.12);box-shadow:inset 0 0 0 .5px var(--ln);outline:0}input:focus,textarea:focus{box-shadow:0 0 0 3px #0a7aff55}textarea{min-height:120px;resize:vertical}
button{margin-top:20px;width:100%;height:42px;border:0;border-radius:10px;font:600 15px inherit;color:#fff;background:linear-gradient(180deg,#3d9bff,var(--ac));cursor:pointer}button[disabled]{opacity:.5}
.m{margin-top:14px;font-size:14px;padding:10px 12px;border-radius:9px}.e{background:rgba(255,59,48,.14);color:#d70015}.o{background:rgba(48,209,88,.16);color:#1f8a3b}.x{font-size:12px;color:var(--mu);margin-top:18px;text-align:center}
</style></head><body><div class="c" id="c"><h1>Appeal a ban</h1><p id="s">Loading…</p><form id="f" hidden novalidate><label for="u">Your Roblox username</label><input id="u" maxlength="40" autocomplete="off"><label for="t">Why should the ban be lifted?</label><textarea id="t" maxlength="1000" placeholder="Explain what happened and what you will do differently."></textarea><button id="b" disabled>Send appeal</button></form><div id="m"></div><div class="x">Appeals are read by the game's staff. Sending false information may get a denied appeal.</div></div>
<script>const w=location.pathname.split('/')[2]||'',$=i=>document.getElementById(i);
fetch('/api/appeal/info?w='+encodeURIComponent(w)).then(r=>r.json()).then(j=>{if(j.error){$('s').textContent=j.error;return}$('s').textContent='Appeal a ban in '+j.name+'. Staff will review it and you will see the result when you try to join.';$('f').hidden=false}).catch(()=>$('s').textContent='Could not load this page.');
const gate=()=>{$('b').disabled=!($('u').value.trim()&&$('t').value.trim())};$('u').oninput=$('t').oninput=gate;
$('f').onsubmit=async e=>{e.preventDefault();if($('b').disabled)return;$('b').disabled=true;$('m').innerHTML='';try{const r=await fetch('/api/appeal',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({w,username:$('u').value.trim(),text:$('t').value.trim()})}),j=await r.json();if(r.ok){$('f').hidden=true;$('m').innerHTML='<div class="m o">Appeal sent. Staff will review it soon.</div>'}else{$('m').innerHTML='<div class="m e"></div>';$('m').firstChild.textContent=j.error||'Something went wrong.';gate()}}catch{$('m').innerHTML='<div class="m e">No connection. Try again.</div>';gate()}};</script></body></html>`;


async function route(req, res, url, p) {
  try {
    const ip = ipOf(req);
    if (req.method === 'GET' && p === '/') { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); return res.end(fs.readFileSync(path.join(__dirname, '..', 'index.html'))); }
    if (req.method === 'GET' && p.startsWith('/legal/')) { const n = p.slice(7); if (!LEGAL[n]) return send(res, 404, { error: 'not found' }); res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); return res.end(legalPage(n)); }
    if (req.method === 'GET' && /^\/appeal\/[a-f0-9]{12}$/.test(p)) { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }); return res.end(APPEAL_PAGE); }
    if (req.method === 'GET' && p === '/api/appeal/info') {
      const wid = String(url.searchParams.get('w') || ''); if (!/^[a-f0-9]{12}$/.test(wid)) return send(res, 404, { error: 'This appeal link is not valid.' });
      const w0 = limit('appinfo:' + ip, 60, 60000); if (w0) return tooMany(res, w0);
      setWid(wid); await need('core'); if (!D.meta || D.meta.deleted) return send(res, 404, { error: 'This appeal link is not valid.' });
      if (D.settings.appeals === false) return send(res, 403, { error: 'Appeals are closed for this game.' });
      return send(res, 200, { name: D.meta.name });
    }
    if (req.method === 'POST' && p === '/api/appeal') {
      const A = await body(req), wid = String(A.w || ''); if (!/^[a-f0-9]{12}$/.test(wid)) return send(res, 404, { error: 'This appeal link is not valid.' });
      const w0 = limit('appeal:' + ip, 5, 3600000) || limit('appeali:' + ip, 8, APPEAL_WINDOW) || limit('appealw:' + wid, 60, 3600000); if (w0) return tooMany(res, w0);
      const uname = cleanName(A.username, 40), text = cleanName(A.text, 1000); if (!/^\w{3,20}$/.test(uname)) return send(res, 400, { error: 'Enter your exact Roblox username.' });
      if (!text) return send(res, 400, { error: 'Write a short note for staff first.' });
      setWid(wid); await need('core', 'play', 'live'); if (!D.meta || D.meta.deleted || D.settings.appeals === false) return send(res, 403, { error: 'Appeals are closed for this game.' });
      const id = await findId(uname), ban = id && D.bans[id];
      if (!ban || !live(ban)) return send(res, 404, { error: 'We could not find an active ban for that username in this game.' });
      if (D.appeals.some(x => x.uid === id && x.status === 'open')) return send(res, 409, { error: 'You already have an appeal waiting for review.' });
      const recent = D.appeals.filter(x => x.uid === id && Date.now() - x.t < APPEAL_WINDOW).sort((a, b) => b.t - a.t); // anti-spam: 2 appeals per player every 5 days
      if (recent.length >= APPEAL_MAX) { const wait = recent[APPEAL_MAX - 1].t + APPEAL_WINDOW - Date.now(), d = Math.ceil(wait / 864e5), h = Math.ceil(wait / 36e5); return send(res, 429, { error: `You have used both appeals for now. You can send another in ${d > 1 ? d + ' days' : h > 1 ? h + ' hours' : 'about an hour'}.` }); }
      D.appeals.unshift({ id: crypto.randomBytes(4).toString('hex'), uid: id, name: ban.name || uname, text, t: Date.now(), status: 'open', banReason: ban.reason, banBy: ban.by || null }); D.appeals.length = Math.min(D.appeals.length, 200);
      feed(`Ban appeal from ${ban.name || uname}`); notify('appeals', `Ban appeal: ${ban.name || uname}`, text, [['Banned for', ban.reason]], 0x0a7aff);
      return ok(res);
    }
    if (p === '/api/cron' && (req.method === 'GET' || req.method === 'POST')) {
      const w0 = limit('cron:' + ip, 30, 60000); if (w0) return tooMany(res, w0);
      const auth = String(req.headers.authorization || '').replace(/^Bearer /, ''); if (!(CRON_SECRET.length >= 16 && same(auth, CRON_SECRET)) && !(ADMIN_TOKEN.length >= 16 && same(auth, ADMIN_TOKEN))) return send(res, 403, { error: 'Not allowed' });
      return send(res, 200, await cronRun());
    }
    if (req.method === 'GET' && p === '/admin') { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }); return res.end(ADMIN_PAGE); }
    if (req.method === 'POST' && p === '/admin/api') {
      if (ADMIN_TOKEN.length < 16) return send(res, 404, { error: 'The admin console is off. Set ADMIN_TOKEN (16+ characters) in Vercel to turn it on.' });
      const w0 = limit('admtry:' + ip, 40, 900000); if (w0) return tooMany(res, w0);
      if (!same(String(req.headers['x-admin-token'] || ''), ADMIN_TOKEN)) return send(res, 403, { error: 'Wrong token' });
      const A = await body(req), wid = String(A.wid || '');
      if (A.op === 'list') { const rows = await sbGet('select=key,meta:value->meta,members:value->members&key=like.w*:core'); return send(res, 200, { workspaces: rows.filter(r => r.meta).map(r => ({ id: r.key.slice(1, 13), name: r.meta.name, owner: r.meta.owner, created: r.meta.created, deleted: r.meta.deleted || null, members: Object.keys(r.members || {}).length })).sort((a, b) => (a.deleted ? 1 : 0) - (b.deleted ? 1 : 0) || b.created - a.created) }); }
      if (A.op === 'feedback') { await need('fb'); return send(res, 200, { items: FB.slice(0, 200) }); }
      if (A.op === 'feedbackReply' || A.op === 'feedbackDelete') {
        await need('fb'); const i = FB.findIndex(f => f.id === String(A.id || '')); if (i < 0) return send(res, 404, { error: 'Not found' });
        if (A.op === 'feedbackDelete') FB.splice(i, 1); else { FB[i].reply = String(A.reply || '').slice(0, 2000).trim() || null; FB[i].repliedAt = FB[i].reply ? Date.now() : null; }
        return ok(res);
      }
      if (!/^[a-f0-9]{12}$/.test(wid)) return send(res, 400, { error: 'bad workspace' });
      if (A.op === 'snaps') return send(res, 200, { snaps: await listSnapshots(wid) });
      if (A.op === 'snapshotNow') return (await snapshot(wid, bkDay())) ? ok(res) : send(res, 404, { error: 'No such workspace' });
      if (A.op === 'download') { setWid(wid); await need(...BK_ROWS); if (!D.meta) return send(res, 404, { error: 'No such workspace' }); return send(res, 200, backupFile()); }
      if (A.op === 'restoreSnapshot') return (await restoreSnapshot(wid, String(A.date || ''), 'Site admin')) ? ok(res) : send(res, 404, { error: 'That backup does not exist' });
      if (A.op === 'restoreDeleted') {
        setWid(wid); await need('core', 'glob'); if (!D.meta || !D.meta.deleted) return send(res, 400, { error: 'That workspace is not in the recycle bin' });
        delete D.meta.deleted; G.workspaces++; audit('Site admin', 'Restored the deleted workspace'); const owner = D.meta.owner;
        if (/^[gr]_\d{1,32}$/.test(owner)) { setUid(owner); await need('user'); if (U && !U.workspaces.includes(wid)) U.workspaces.push(wid); }
        return ok(res);
      }
      return send(res, 400, { error: 'bad request' });
    }
    if (p.startsWith('/auth/')) return await authRoute(req, res, url, p, ip);

    if (req.method === 'POST' && p === '/game/sync') { // the Roblox script checks in here with its workspace's game key
      const b = await body(req), k = String(b.key || '').replace(/[\[\]\s"'`]/g, ''), isNew = /^[a-f0-9]{12}-[A-Za-z0-9]{28}$/.test(k), [wid, rot, sig] = isNew ? [k.slice(0, 12)] : k.split('.');
      if (!/^[a-f0-9]{12}$/.test(wid || '') || (!isNew && (!/^\d{1,6}$/.test(rot || '') || !sig || !same(k, gameKey(wid, +rot))))) { const w = limit('badkey:' + ip, 30, 60000); return w ? tooMany(res, w) : send(res, 403, { error: 'bad key' }); }
      const job = String(b.jobId || 'studio').slice(0, 64), w1 = limit(`sync:${wid}:${job}`, 40, 60000) || limit('sync:' + wid, 400, 60000); if (w1) return tooMany(res, w1);
      setWid(wid);
      const ev = Array.isArray(b.events) ? b.events : [], chatty = ev.some(e => e && (e.type === 'chat' || e.type === 'modcall'));
      const shards = [...new Set([...(Array.isArray(b.players) ? b.players : []), ...ev].map(x => x && Number.isInteger(x.userId) && x.userId > 0 ? shOf(x.userId) : null).filter(Boolean))];
      await need('core', 'play', 'live', 'cmds', ...shards, ...(chatty ? ['chat'] : []), ...(ev.some(e => e && e.type === 'modcall') ? ['calls'] : []));
      if (!D.meta || D.meta.deleted) return send(res, 403, { error: 'bad key' });
      if (isNew ? !D.meta.codeHash || !same(codeHash(k.slice(13)), D.meta.codeHash) : (D.meta.codeHash || (D.meta.rot || 0) !== +rot)) { const w = limit('badkey:' + ip, 30, 60000); return w ? tooMany(res, w) : send(res, 403, { error: 'bad key' }); }
      const place = Number.isInteger(b.placeId) ? b.placeId : 0;
      if (D.meta.placeLock && D.meta.placeId && place !== D.meta.placeId) return send(res, 403, { error: 'This game key is locked to a different place' });
      if ((D.meta.lastPlace ?? null) !== place) D.meta.lastPlace = place;
      const sv = Number.isInteger(b.scriptV) && b.scriptV > 0 && b.scriptV < 1000 ? b.scriptV : 1; if (sv > (D.meta.scriptV || 0)) D.meta.scriptV = sv; // the highest version seen, so old servers that are still shutting down don't matter
      if (!D.meta.connectedAt) D.meta.connectedAt = Date.now();
      if (chatty && rule('flaggedmute').enabled) await need('logs');
      return send(res, 200, sync(b));
    }

    // ---- the website ----
    if (!p.startsWith('/api/') && p !== '/logout') return send(res, 404, { error: 'not found' });
    const w0 = limit('ip:' + ip, 300, 60000); if (w0) return tooMany(res, w0);
    const ck = cookiesOf(req), uid = sessionUid(req);
    if (req.method === 'POST' && p === '/logout') { res.setHeader('Set-Cookie', [clearCookie('sid'), clearCookie('ws')]); return ok(res); }

    if (p === '/api/me') {
      const base = { providers: providers(), signupsOpen: SIGNUPS_OPEN, user: null, workspaces: [], current: null, maxPerUser: MAX_PER_USER };
      if (!uid) return send(res, 200, base);
      setUid(uid); await need('user'); if (!U) return send(res, 200, base);
      const ids = U.workspaces.filter(w => /^[a-f0-9]{12}$/.test(w)); let list = [], rows0 = [];
      if (ids.length) {
        const r = await sbf(`${SB_URL}/rest/v1/panel_kv?select=key,meta:value->meta,members:value->members,ranks:value->ranks&key=in.(${ids.map(w => `w${w}:core`).join(',')})`, { headers: sbHeaders() });
        if (!r.ok) throw new Error('Supabase read failed: HTTP ' + r.status);
        rows0 = await r.json(); for (const row of rows0) { const mm = row.members && row.members[uid]; if (row.meta && mm && !row.meta.deleted) list.push({ id: row.key.slice(1, 13), name: row.meta.name, rank: (row.ranks && row.ranks[mm.rank] || {}).name || mm.role || 'Member', owner: row.meta.owner === uid }); }
        list.sort((a, b) => ids.indexOf(a.id) - ids.indexOf(b.id));
      }
      const keep = new Set([...list.map(x => x.id), ...rows0.filter(r => r.meta && r.meta.deleted && r.members && r.members[uid]).map(r => r.key.slice(1, 13))]); if (U.workspaces.some(w => !keep.has(w))) U.workspaces = U.workspaces.filter(w => keep.has(w)); // deleted workspaces stay on the list for 30 days so they can be restored
      const cur = list.find(x => x.id === ck.ws) ? ck.ws : (list[0] && list[0].id) || null;
      if (cur && cur !== ck.ws) res.setHeader('Set-Cookie', mkCookie('ws', cur, { maxAge: 31536000 }));
      const roblox = uid[0] === 'r' ? { id: uid.slice(2), name: U.name, viaLogin: true } : U.roblox || null;
      return send(res, 200, { ...base, user: { id: uid, name: U.name, provider: U.provider, roblox }, workspaces: list, current: cur });
    }
    if (p === '/api/invite') {
      const w = limit('invite:' + ip, 20, 60000); if (w) return tooMany(res, w);
      const code = url.searchParams.get('code') || ''; if (!/^[a-f0-9]{28}$/.test(code)) return send(res, 404, { error: 'This invite link is not valid.' });
      setWid(code.slice(0, 12)); await need('core'); const inv = D.meta && !D.meta.deleted && D.invites[code];
      return inv && inv.exp > Date.now() ? send(res, 200, { workspace: D.meta.name, role: (D.ranks[inv.rank] || {}).name || 'Member' }) : send(res, 404, { error: 'This invite has expired or was already used.' });
    }
    if (!uid) return send(res, 401, { error: 'Please sign in', code: 'signin' });
    const w2 = limit('u:' + uid, 180, 60000); if (w2) return tooMany(res, w2);
    setUid(uid);

    if (req.method === 'POST' && p === '/api/me/unlink') { await need('user'); if (U) U.roblox = null; return ok(res); }
    if (req.method === 'POST' && p === '/api/workspaces') {
      const w = limit('create:' + uid, 5, 3600000) || limit('createip:' + ip, 10, 3600000); if (w) return tooMany(res, w);
      const nm = cleanName((await body(req)).name); if (nm.length < 2) return send(res, 400, { error: 'Give your game a name (at least 2 letters).' });
      await need('user', 'glob'); if (!U) return send(res, 401, { error: 'Please sign in', code: 'signin' });
      if (!SIGNUPS_OPEN) return send(res, 403, { error: 'New workspaces are closed right now.' });
      if (U.workspaces.length >= MAX_PER_USER) return send(res, 400, { error: `You can have up to ${MAX_PER_USER} workspaces.` });
      if (G.workspaces >= MAX_WORKSPACES) return send(res, 400, { error: 'This site is full right now. Please try again later.' });
      const wid = crypto.randomBytes(6).toString('hex'); setWid(wid); await need('core');
      const nc = newCode(wid); D.meta = { id: wid, name: nm, owner: uid, created: Date.now(), rot: 0, codeHash: nc.hash }; D.ranks = defaultRanks(); D.webhook = DEFAULT_WEBHOOK();
      D.members[uid] = { name: U.name, rank: 'admin', joined: Date.now() }; audit(U.name, 'Created the workspace');
      G.workspaces++; U.workspaces.push(wid);
      res.setHeader('Set-Cookie', mkCookie('ws', wid, { maxAge: 31536000 })); return send(res, 200, { ok: true, id: wid, code: nc.code });
    }
    if (req.method === 'POST' && p === '/api/join') {
      const w = limit('join:' + uid, 10, 3600000); if (w) return tooMany(res, w);
      const code = String((await body(req)).code || ''); if (!/^[a-f0-9]{28}$/.test(code)) return send(res, 400, { error: 'This invite link is not valid.' });
      setWid(code.slice(0, 12)); await need('user', 'core'); if (!U) return send(res, 401, { error: 'Please sign in', code: 'signin' });
      if (D.meta && D.members[uid]) { res.setHeader('Set-Cookie', mkCookie('ws', CTX.wid, { maxAge: 31536000 })); return send(res, 200, { ok: true, id: CTX.wid }); }
      const inv = D.meta && !D.meta.deleted && D.invites[code]; if (!inv || inv.exp < Date.now()) return send(res, 404, { error: 'This invite has expired or was already used.' });
      if (Object.keys(D.members).length >= 50) return send(res, 400, { error: 'This workspace is full.' });
      const rk = D.ranks[inv.rank] ? inv.rank : Object.entries(D.ranks).sort((a, b) => a[1].pos - b[1].pos)[0][0];
      D.members[uid] = { name: U.name, rank: rk, joined: Date.now() }; delete D.invites[code]; audit(U.name, `Joined as ${D.ranks[rk].name}`);
      if (!U.workspaces.includes(CTX.wid)) U.workspaces.push(CTX.wid);
      res.setHeader('Set-Cookie', mkCookie('ws', CTX.wid, { maxAge: 31536000 })); return send(res, 200, { ok: true, id: CTX.wid });
    }
    if (req.method === 'POST' && p === '/api/switch') {
      const id = String((await body(req)).id || ''); if (!/^[a-f0-9]{12}$/.test(id)) return send(res, 400, { error: 'bad workspace' });
      await need('user'); if (!U || !U.workspaces.includes(id)) return send(res, 403, { error: 'You are not a member of that workspace' });
      res.setHeader('Set-Cookie', mkCookie('ws', id, { maxAge: 31536000 })); return ok(res);
    }

    // ---- workspace pages: you must be a member of the workspace in the "ws" cookie ----
    if (!/^[a-f0-9]{12}$/.test(ck.ws || '')) return send(res, 409, { error: 'Choose a workspace', code: 'no_workspace' });
    setWid(ck.ws); await need('core', 'user', ...(NEEDS[p] || []));
    if (!D.meta || D.meta.deleted) return send(res, 404, { error: 'That workspace no longer exists', code: 'no_workspace' });
    const mem = D.members[uid]; if (!mem) return send(res, 403, { error: 'You are not a member of this workspace', code: 'no_workspace' });
    if (U) { // keep name and linked Roblox account in sync with the person's account
      if (mem.name !== U.name) mem.name = U.name;
      const rid = uid[0] === 'r' ? uid.slice(2) : (U.roblox && U.roblox.id) || null; if ((mem.robloxId || null) !== rid) mem.robloxId = rid;
    }
    const u = who(uid);
    for (const [c, i] of Object.entries(D.invites)) if (i.exp < Date.now()) delete D.invites[c];
    const B = req.method === 'POST' ? await body(req) : {};

    if (p === '/api/state') {
      const now = Date.now(), players = allPlayers(), bans = Object.values(D.bans).filter(live), mutes = Object.values(D.mutes).filter(live), ws = weekStart(now);
      const days = [...Array(14)].map((_, i) => dayKey(now - (13 - i) * 864e5)), ser = f => days.map(d => (D.daily[d] || {})[f] || 0);
      const onLeave = id => D.loa.some(x => x.uid === id && x.status === 'approved' && x.start <= now && x.end >= now);
      const gm = Object.keys(D.members).filter(id => id[0] === 'g'); // Google members may have linked a Roblox account: pick that up for activity tracking
      if (gm.length) { const r = await sbf(`${SB_URL}/rest/v1/panel_kv?select=key,roblox:value->roblox&key=in.(${gm.map(id => 'u:' + id).join(',')})`, { headers: sbHeaders() });
        if (r.ok) for (const row of await r.json()) { const m = D.members[row.key.slice(2)], rid = (row.roblox && row.roblox.id) || null; if (m && (m.robloxId || null) !== rid) m.robloxId = rid; } }
      const team = Object.entries(D.members).map(([id, m]) => { const rid = m.robloxId || (id[0] === 'r' ? id.slice(2) : null), pl = rid ? D.play[rid] : null;
        return { uid: id, name: m.name, rank: m.rank, owner: id === D.meta.owner, via: id[0] === 'g' ? 'Google' : 'Roblox', joined: m.joined, linked: !!rid, robloxId: rid,
          week: pl && pl.weekStart === ws ? Math.round(pl.week) : 0, onLeave: onLeave(id), online: !!rid && players.some(x => String(x.userId) === String(rid)) }; })
        .sort((a, b) => memberPos(b.uid) - memberPos(a.uid) || a.name.localeCompare(b.name));
      return send(res, 200, {
        connected: liveServers() > 0, serverCount: liveServers(), players, bans, mutes, feed: (D.feed || []).slice(0, 20), history: R.history,
        servers: Object.entries(R.servers).filter(([, s]) => now - s.last < LIVE_MS).map(([id, s]) => ({ id: id.slice(0, 8), players: s.players.length, uptime: now - (s.first || now) })),
        me: { uid, name: mem.name, rank: mem.rank, owner: u.isOwner, perms: [...u.perms], linked: !!mem.robloxId, pos: u.pos },
        workspace: { id: CTX.wid, name: D.meta.name, everConnected: !!D.meta.connectedAt, ...(has(u, 'automations.manage') ? { script: scriptInfo() } : {}), ...(u.isOwner ? { placeId: D.meta.placeId || null, placeLock: !!D.meta.placeLock, lastPlace: D.meta.lastPlace ?? null } : {}) },
        ranks: Object.entries(D.ranks).map(([id, r]) => ({ id, ...r, count: Object.values(D.members).filter(m => m.rank === id).length })).sort((a, b) => b.pos - a.pos),
        perms: PERMS.map(([id, label, group, danger]) => ({ id, label, group, danger: !!danger })), team,
        invites: has(u, 'team.manage') ? Object.entries(D.invites).map(([code, i]) => ({ code, rank: i.rank, exp: i.exp, by: i.by })) : [],
        audit: has(u, 'audit.view') ? D.audit.slice(0, 150) : [], rulebook: D.rulebook,
        loa: { mine: D.loa.filter(x => x.uid === uid).slice(0, 20), all: has(u, 'loa.review') ? D.loa.slice(0, 80) : [] },
        webhook: has(u, 'webhooks.manage') ? { set: !!(D.webhook && D.webhook.url), hint: D.webhook && D.webhook.url ? D.webhook.url.slice(-6) : '', events: (D.webhook || DEFAULT_WEBHOOK()).events } : null,
        series: { players: ser('u'), peak: ser('p'), actions: ser('a'), reports: ser('r'), joins: ser('j'), days },
        openCalls: D.calls.filter(c => c.status !== 'resolved').length, calls: D.calls.slice(0, 40),
        session: D.session && { ...D.session, attendees: Object.entries(D.session.attendees).map(([userId, name]) => ({ userId: +userId, name })) }, sessions: D.sessions.slice(0, 15),
        board: Object.entries(D.play).map(([id, x]) => ({ userId: +id, name: x.name, week: x.weekStart === ws ? Math.round(x.week) : 0, total: Math.round(x.total), points: x.points }))
          .sort((a, b) => b.week - a.week || b.points - a.points).slice(0, 50),
        chat: has(u, 'chat.view') ? R.chat.slice(-100).reverse() : [], flagWords: D.flagWords, settings: D.settings, appealsOn: D.settings.appeals !== false, appeals: has(u, 'appeals.review') ? D.appeals.slice(0, 60) : [], watch: D.watch,
        staffWeek: Object.entries(D.audit.filter(a => a.t > now - 7 * 864e5 && a.user && a.user !== 'Automation').reduce((m, a) => (m[a.user] = (m[a.user] || 0) + 1, m), {})).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([user, n]) => ({ user, n })),
        rules: Object.fromEntries(Object.keys(DEFAULT_RULES).map(k => [k, rule(k)])), stats: { ...D.stats, activeBans: bans.length, activeMutes: mutes.length } });
    }
    if (p === '/api/avatars') return send(res, 200, await avatars((url.searchParams.get('ids') || '').split(',').slice(0, 100).map(Number).filter(n => Number.isInteger(n) && n > 0)));
    if (p === '/api/lookup') { const id = await findId(cleanName(url.searchParams.get('name'), 40)); const r = id && await profile(id); return r ? send(res, 200, r) : send(res, 404, { error: 'No player with that username' }); }
    if (p === '/api/player') { const id = +url.searchParams.get('userId'); if (!Number.isInteger(id) || id < 1) return send(res, 400, { error: 'bad userId' }); const r = await profile(id); return r ? send(res, 200, r) : send(res, 404, { error: 'We have no record of that player' }); }
    if (p === '/api/escalation') {
      const id = +url.searchParams.get('userId'), r = D.rulebook.find(x => x.id === url.searchParams.get('rule')); if (!r) return send(res, 404, { error: 'No such rule' });
      const n = (D.logs[id] || []).filter(e => e.ruleId === r.id && e.status !== 'reverted').length;
      return send(res, 200, { offense: n + 1, step: r.steps[Math.min(n, r.steps.length - 1)] });
    }
    if (p === '/api/logbook') {
      const type = url.searchParams.get('type') || '', q = cleanName(url.searchParams.get('q'), 60).toLowerCase();
      let all = []; for (const [id, list] of Object.entries(D.logs)) for (const e of list) all.push({ ...e, userId: +id, name: e.name || (D.play[id] || {}).name || 'User ' + id });
      if (type) all = all.filter(e => TYPE_GROUP[e.type] === type);
      if (q) all = all.filter(e => `${e.name} ${e.reason} ${e.by}`.toLowerCase().includes(q));
      all.sort((a, b) => b.time - a.time); return send(res, 200, { entries: all.slice(0, 200), total: all.length });
    }
    if (req.method === 'POST' && p === '/api/action') {
      const reason0 = cleanName(B.reason, 300); let action = B.action, minutes = clampInt(B.minutes, 0, 525600), ruleId = null, reason = reason0 || 'No reason given';
      if (B.ruleId) {
        const r = D.rulebook.find(x => x.id === B.ruleId); if (!r) return send(res, 404, { error: 'That rule no longer exists' });
        const n = (D.logs[B.userId] || []).filter(e => e.ruleId === r.id && e.status !== 'reverted').length, st = r.steps[Math.min(n, r.steps.length - 1)];
        action = st.type; minutes = st.minutes || 0; ruleId = r.id; reason = `${r.title} (offense ${n + 1})${reason0 ? ': ' + reason0 : ''}`;
      }
      if (!ACT_PERM[action]) return send(res, 400, { error: 'bad action' });
      if (!has(u, action === 'ban' && !(minutes > 0) ? 'mod.permban' : ACT_PERM[action])) return deny(res);
      if (action === 'announce') { cmd({ type: 'announce', text: reason }); feed('Announcement: ' + reason, u.user); return ok(res); }
      if (!Number.isInteger(B.userId) || B.userId < 1) return send(res, 400, { error: 'bad userId' });
      const nm = cleanName(B.name, 40) || String(B.userId);
      if (['warn', 'kick', 'mute', 'ban'].includes(action) && u.limit > 0) { // per-rank anti-abuse limit, counted from the logbook
        const since = Date.now() - 36e5; let c = 0; for (const list of Object.values(D.logs)) for (const e of list) if (e.byUid === uid && e.time > since && MOD_TYPES.includes(e.type)) c++;
        if (c >= u.limit) return send(res, 429, { error: `Your rank allows ${u.limit} moderation actions per hour. Ask a higher rank for help.` });
      }
      if (action === 'points') { const amt = clampInt(B.amount, -100000, 100000); if (!amt) return send(res, 400, { error: 'Enter a points amount' }); addPoints(B.userId, nm, amt, reason, u.user, uid); return ok(res); }
      act({ action, userId: B.userId, name: nm, reason, minutes, by: u.user, byUid: uid, ruleId });
      return send(res, 200, { ok: true, applied: { action, minutes } });
    }
    if (req.method === 'POST' && p === '/api/entry') {
      const id = B.userId; if (!Number.isInteger(id) || id < 1) return send(res, 400, { error: 'bad userId' });
      if (B.op === 'note') { if (!has(u, 'logbook.note')) return deny(res); const t = cleanName(B.text, 500); if (!t) return send(res, 400, { error: 'Write a note first' }); logEntry(id, cleanName(B.name, 40) || 'User ' + id, { type: 'Note', reason: t, by: u.user, byUid: uid }); return ok(res); }
      if (B.op === 'revert') {
        if (!has(u, 'logbook.revert')) return deny(res);
        const e = (D.logs[id] || []).find(x => x.id === B.id); if (!e || e.status === 'reverted') return send(res, 404, { error: 'Entry not found or already reverted' });
        e.status = 'reverted'; e.revertedBy = u.user; e.revertedAt = Date.now();
        if ((e.type === 'Banned' || e.type === 'Suspended') && D.bans[id] && D.bans[id].entry === e.id) { delete D.bans[id]; unbanCmd(id); }
        if (e.type === 'Muted' && D.mutes[id] && D.mutes[id].entry === e.id) delete D.mutes[id];
        if (e.type === 'Points' && e.amount) playOf(id, e.name).points -= e.amount;
        audit(u.user, `Reverted ${e.type.toLowerCase()} for ${e.name}`); return ok(res);
      }
      return send(res, 400, { error: 'bad request' });
    }
    if (req.method === 'POST' && p === '/api/session') {
      if (!has(u, 'sessions.host')) return deny(res);
      const now = Date.now(), s = D.session;
      if (B.op === 'start') {
        if (s) return send(res, 400, { error: 'A session is already running' });
        const type = cleanName(B.type, 40) || 'Session';
        D.session = { id: now, type, notes: cleanName(B.notes, 200), start: now, host: u.user, attendees: {} };
        cmd({ type: 'announce', text: `${type} is starting! Type !attend in chat to be marked present.` }); feed('Session started: ' + type, u.user);
        notify('sessions', `${type} started`, D.session.notes, [['Host', u.user]], 0x12a594);
      } else if (!s) return send(res, 400, { error: 'No session is running' });
      else if (B.op === 'addall') { for (const pl of allPlayers()) s.attendees[pl.userId] = pl.name; }
      else if (B.op === 'end') {
        D.sessions.unshift({ ...s, end: now, attendees: Object.entries(s.attendees).map(([userId, name]) => ({ userId: +userId, name })) }); D.sessions.length = Math.min(D.sessions.length, 50);
        const sp = rule('sessionpoints'); if (sp.enabled) for (const [pid, nm] of Object.entries(s.attendees)) addPoints(+pid, nm, sp.points, 'Attended ' + s.type, 'Automation');
        D.session = null; cmd({ type: 'announce', text: `${s.type} has ended. Thanks for coming!` }); feed(`Session ended: ${s.type} (${Object.keys(s.attendees).length} present)`, u.user);
        notify('sessions', `${s.type} ended`, `${Object.keys(s.attendees).length} attended`, [['Host', s.host]], 0x12a594);
      }
      return ok(res);
    }
    if (req.method === 'POST' && p === '/api/call') {
      if (!has(u, 'reports.handle')) return deny(res);
      const c = D.calls.find(c => c.id === B.id); if (!c) return send(res, 404, { error: 'No such report' });
      if (B.op === 'claim' && c.status === 'open') { c.status = 'claimed'; c.by = u.user; cmd({ type: 'message', kind: 'info', title: 'Report update', body: `A moderator is handling your report #${c.id}.`, userId: c.from.userId, text: `A moderator is handling your report #${c.id}.` }); }
      else if (B.op === 'resolve' && c.status !== 'resolved') {
        c.status = 'resolved'; c.by = c.by || u.user; c.note = cleanName(B.note, 200); c.resolved = Date.now();
        cmd({ type: 'message', kind: 'ok', title: 'Report resolved', body: `Report #${c.id} resolved${c.note ? ': ' + c.note : '.'}`, userId: c.from.userId, text: `Report #${c.id} resolved${c.note ? ': ' + c.note : '.'}` }); feed(`Report #${c.id} resolved`, u.user);
      }
      return ok(res);
    }
    if (req.method === 'POST' && p === '/api/flagwords') {
      if (!has(u, 'automations.manage')) return deny(res);
      D.flagWords = [...new Set((Array.isArray(B.words) ? B.words : []).map(w => String(w).toLowerCase().trim().slice(0, 30)).filter(Boolean))].slice(0, 100);
      audit(u.user, 'Updated flagged words'); return ok(res);
    }
    if (req.method === 'POST' && p === '/api/rules') {
      if (!has(u, 'automations.manage')) return deny(res);
      const base = DEFAULT_RULES[B.id]; if (!base) return send(res, 400, { error: 'bad rule' });
      const next = { enabled: !!B.enabled };
      for (const [k, def] of Object.entries(base)) if (k !== 'enabled') { const v = (B.params || {})[k]; next[k] = typeof def === 'number' ? clampInt(v, 1, 100000) : cleanName(v ?? def, 120); }
      D.rules[B.id] = next; audit(u.user, `Automation "${B.id}" saved (${next.enabled ? 'on' : 'off'})`); return ok(res);
    }
    if (req.method === 'POST' && p === '/api/settings') {
      if (!has(u, 'automations.manage')) return deny(res);
      D.settings.quotaMinutes = clampInt(B.quotaMinutes, 1, 10080); audit(u.user, `Player weekly goal set to ${D.settings.quotaMinutes} minutes`); return ok(res);
    }
    if (req.method === 'POST' && p === '/api/ranks') {
      if (!has(u, 'ranks.manage')) return deny(res);
      const clean = (x, cur) => ({ name: cleanName(x.name, 32) || cur.name || 'New rank', color: /^#[0-9a-f]{6}$/i.test(x.color || '') ? x.color.toLowerCase() : (cur.color || '#64748b'),
        perms: (Array.isArray(x.perms) ? x.perms : cur.perms || []).filter(q => ALLP.includes(q) && (u.isOwner || u.perms.has(q))), // you can't hand out powers you don't have
        quota: clampInt(x.quota ?? cur.quota ?? 0, 0, 10080), limit: clampInt(x.limit ?? cur.limit ?? 0, 0, 1000) });
      if (B.op === 'create') {
        if (Object.keys(D.ranks).length >= 25) return send(res, 400, { error: 'You can have up to 25 ranks.' });
        const id = 'k' + crypto.randomBytes(4).toString('hex'), low = Math.min(...Object.values(D.ranks).map(r => r.pos), u.isOwner ? 1e8 : u.pos);
        D.ranks[id] = { ...clean(B, {}), pos: low - 10 }; audit(u.user, `Created rank ${D.ranks[id].name}`); return send(res, 200, { ok: true, id });
      }
      const r = D.ranks[B.id]; if (!r) return send(res, 404, { error: 'No such rank' });
      if (!above(u, r.pos)) return send(res, 403, { error: 'You can only change ranks below your own.' });
      if (B.op === 'update') { Object.assign(r, clean(B, r)); audit(u.user, `Edited rank ${r.name}`); return ok(res); }
      if (B.op === 'delete') {
        if (Object.keys(D.ranks).length <= 1) return send(res, 400, { error: 'You need at least one rank.' });
        if (Object.values(D.members).some(m => m.rank === B.id)) return send(res, 400, { error: 'Move everyone out of this rank first.' });
        for (const [c, i] of Object.entries(D.invites)) if (i.rank === B.id) delete D.invites[c];
        audit(u.user, `Deleted rank ${r.name}`); delete D.ranks[B.id]; return ok(res);
      }
      if (B.op === 'move') {
        const list = Object.entries(D.ranks).sort((a, b) => b[1].pos - a[1].pos), i = list.findIndex(([id]) => id === B.id), o = list[B.dir === 'up' ? i - 1 : i + 1];
        if (!o) return ok(res); if (!above(u, o[1].pos)) return send(res, 403, { error: 'You can only reorder ranks below your own.' });
        [r.pos, o[1].pos] = [o[1].pos, r.pos]; if (r.pos === o[1].pos) r.pos += B.dir === 'up' ? 1 : -1; audit(u.user, `Moved rank ${r.name} ${B.dir}`); return ok(res);
      }
      return send(res, 400, { error: 'bad request' });
    }
    if (req.method === 'POST' && p === '/api/team') {
      if (B.op === 'leave') { if (u.isOwner) return send(res, 400, { error: 'The owner cannot leave. Delete the workspace instead.' }); delete D.members[uid]; audit(u.user, 'Left the workspace'); res.setHeader('Set-Cookie', clearCookie('ws')); return ok(res); }
      if (!has(u, 'team.manage')) return deny(res);
      if (B.op === 'invite') {
        const r = D.ranks[B.rank]; if (!r) return send(res, 400, { error: 'Pick a rank' });
        if (!above(u, r.pos)) return send(res, 403, { error: 'You can only invite people to ranks below your own.' });
        if (Object.keys(D.invites).length >= 20) return send(res, 400, { error: 'Too many open invites. Revoke some first.' });
        if (Object.keys(D.members).length >= 50) return send(res, 400, { error: 'This workspace is full (50 people).' });
        const code = CTX.wid + crypto.randomBytes(8).toString('hex'); D.invites[code] = { rank: B.rank, exp: Date.now() + 7 * 864e5, by: u.user }; audit(u.user, `Created an invite for ${r.name}`);
        return send(res, 200, { ok: true, code, link: `${site(req)}/#/join/${code}` });
      }
      if (B.op === 'revoke') { delete D.invites[String(B.code || '')]; audit(u.user, 'Revoked an invite'); return ok(res); }
      const t = String(B.uid || ''), m = D.members[t];
      if (!m) return send(res, 404, { error: 'No such member' });
      if (t === D.meta.owner) return send(res, 400, { error: 'The owner cannot be changed.' });
      if (!above(u, memberPos(t))) return send(res, 403, { error: 'You can only manage members below your rank.' });
      if (B.op === 'remove') { audit(u.user, `Removed ${m.name}`); delete D.members[t]; return ok(res); }
      if (B.op === 'setrank') { const r = D.ranks[B.rank]; if (!r || !above(u, r.pos)) return send(res, 403, { error: 'You can only give ranks below your own.' }); m.rank = B.rank; audit(u.user, `Set ${m.name} to ${r.name}`); return ok(res); }
      return send(res, 400, { error: 'bad request' });
    }
    if (req.method === 'POST' && p === '/api/rulebook') {
      if (!has(u, 'rulebook.manage')) return deny(res);
      if (B.op === 'delete') { const r = D.rulebook.find(x => x.id === B.id); D.rulebook = D.rulebook.filter(x => x.id !== B.id); if (r) audit(u.user, `Deleted rule ${r.title}`); return ok(res); }
      if (B.op === 'starter') {
        if (D.rulebook.length) return send(res, 400, { error: 'Your rulebook already has rules.' });
        const W = { type: 'warn' }, K = { type: 'kick' }, M = m => ({ type: 'mute', minutes: m }), Bn = m => ({ type: 'ban', minutes: m });
        const S0 = [['Spamming', 'Repeating messages or flooding chat.', 'low', [W, W, M(30), K]], ['Profanity', 'Swearing or crude language in public chat.', 'medium', [W, M(60), K, Bn(1440)]],
          ['Trolling or disruption', 'Deliberately ruining the game for others.', 'low', [W, K, Bn(1440)]], ['Ignoring staff', 'Refusing reasonable instructions from staff.', 'medium', [W, K, Bn(1440)]],
          ['Harassment or bullying', 'Targeting, threatening or demeaning another player.', 'high', [W, Bn(1440), Bn(10080), Bn(0)]], ['Scamming', 'Tricking players out of items or currency.', 'high', [K, Bn(4320), Bn(0)]],
          ['Inappropriate content', 'Sexual, hateful or otherwise unsuitable content.', 'critical', [Bn(10080), Bn(0)]], ['Exploiting or cheating', 'Using hacks or exploits.', 'critical', [Bn(0)]]];
        for (const [title, desc, severity, steps] of S0) D.rulebook.push({ id: 'r' + crypto.randomBytes(4).toString('hex'), title, desc, severity, steps: steps.map(x => ({ type: x.type, minutes: x.minutes || 0 })), by: u.user, updated: Date.now() });
        audit(u.user, 'Added the starter rules'); return ok(res);
      }
      const steps = (Array.isArray(B.steps) ? B.steps : []).slice(0, 8).filter(s => s && ['warn', 'kick', 'mute', 'ban'].includes(s.type)).map(s => ({ type: s.type, minutes: ['mute', 'ban'].includes(s.type) ? clampInt(s.minutes, 0, 525600) : 0 }));
      const title = cleanName(B.title, 60); if (!title) return send(res, 400, { error: 'Give the rule a title' }); if (!steps.length) return send(res, 400, { error: 'Add at least one punishment step' });
      const r = { title, desc: cleanName(B.desc, 400), severity: ['low', 'medium', 'high', 'critical'].includes(B.severity) ? B.severity : 'medium', steps, by: u.user, updated: Date.now() };
      if (B.id) { const ex = D.rulebook.find(x => x.id === B.id); if (!ex) return send(res, 404, { error: 'No such rule' }); Object.assign(ex, r); }
      else { if (D.rulebook.length >= 100) return send(res, 400, { error: 'You can have up to 100 rules.' }); D.rulebook.push({ id: 'r' + crypto.randomBytes(4).toString('hex'), ...r }); }
      audit(u.user, `Saved rule ${title}`); return ok(res);
    }
    if (req.method === 'POST' && p === '/api/loa') {
      if (B.op === 'request') {
        const s = Date.parse(B.start), e = Date.parse(B.end);
        if (!s || !e || e < s) return send(res, 400, { error: 'Pick a start date and an end date after it.' });
        if (e - s > 120 * 864e5) return send(res, 400, { error: 'Leave can be at most 120 days.' });
        if (D.loa.filter(x => x.uid === uid && x.status === 'pending').length >= 3) return send(res, 400, { error: 'You already have pending requests.' });
        const x = { id: rnd(6), uid, name: u.user, start: s, end: e + 864e5 - 1, reason: cleanName(B.reason, 300), status: 'pending', created: Date.now() };
        D.loa.unshift(x); D.loa = D.loa.slice(0, 300); audit(u.user, 'Requested leave');
        notify('loa', `Leave request from ${u.user}`, x.reason, [['From', dayKey(s)], ['Until', dayKey(e)]], 0x12a594); return ok(res);
      }
      const x = D.loa.find(l => l.id === B.id); if (!x) return send(res, 404, { error: 'No such request' });
      if (B.op === 'cancel') { if (x.uid !== uid) return deny(res); x.status = 'cancelled'; return ok(res); }
      if (B.op === 'decide') {
        if (!has(u, 'loa.review')) return deny(res); if (x.status !== 'pending') return send(res, 400, { error: 'Already decided' });
        if (x.uid === uid && !u.isOwner) return send(res, 403, { error: 'Someone else has to review your own leave.' });
        x.status = B.approve ? 'approved' : 'denied'; x.by = u.user; x.decided = Date.now(); x.note = cleanName(B.note, 200);
        audit(u.user, `${B.approve ? 'Approved' : 'Denied'} leave for ${x.name}`); notify('loa', `Leave ${x.status} for ${x.name}`, x.note, [['By', u.user]], 0x12a594); return ok(res);
      }
      return send(res, 400, { error: 'bad request' });
    }
    if (p === '/api/feedback') {
      if (req.method === 'GET') return send(res, 200, { items: FB.filter(f => f.uid === uid).slice(0, 30).map(f => ({ id: f.id, t: f.t, type: f.type, text: f.text, reply: f.reply || null, repliedAt: f.repliedAt || null })) });
      const w0 = limit('fb:' + uid, 6, 3600000); if (w0) return tooMany(res, w0);
      const type = ['question', 'idea', 'bug', 'praise'].includes(B.type) ? B.type : 'idea', text = String(B.text || '').replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f<>]/g, '').trim().slice(0, 2000);
      if (!text) return send(res, 400, { error: 'Write something first.' });
      FB.unshift({ id: rnd(6), t: Date.now(), type, text, uid, user: mem.name, rank: u.isOwner ? 'Owner' : (D.ranks[mem.rank] || {}).name || 'Member', ws: CTX.wid, wsName: D.meta.name, page: cleanName(B.page, 30) }); FB.length = Math.min(FB.length, 400);
      return ok(res);
    }
    if (p === '/api/backups') {
      if (!u.isOwner) return ownerOnly(res);
      if (req.method === 'GET') return send(res, 200, { snaps: (await listSnapshots(CTX.wid)).map(l => ({ id: l, t: labelTime(l), safety: l.startsWith('pre') })), cron: CRON_SECRET.length >= 16 });
      const w0 = limit('bk:' + CTX.wid, 6, 600000); if (w0) return tooMany(res, w0);
      if (B.op === 'now') { await snapshot(CTX.wid, bkDay()); audit(u.user, 'Made a backup'); return ok(res); }
      if (B.op === 'restore') {
        if (cleanName(B.confirm) !== D.meta.name) return send(res, 400, { error: 'Type the workspace name exactly to confirm' });
        return (await restoreSnapshot(CTX.wid, String(B.id || ''), u.user)) ? ok(res) : send(res, 404, { error: 'That backup does not exist' });
      }
      return send(res, 400, { error: 'bad request' });
    }
    if (req.method === 'GET' && p === '/api/backup/download') {
      if (!u.isOwner) return ownerOnly(res); audit(u.user, 'Downloaded a backup file');
      res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Disposition': `attachment; filename="sentinel-backup-${bkDay()}.json"`, 'Cache-Control': 'no-store' }); return res.end(JSON.stringify(backupFile()));
    }
    if (req.method === 'POST' && p === '/api/backup/import') {
      if (!u.isOwner) return ownerOnly(res); const w0 = limit('bkimp:' + CTX.wid, 4, 600000); if (w0) return tooMany(res, w0);
      if (cleanName(B.confirm) !== D.meta.name) return send(res, 400, { error: 'Type the workspace name exactly to confirm' });
      await snapshot(CTX.wid, 'pre' + Math.floor(Date.now() / 1000)).catch(() => {});
      const err = importBackup(B.data, uid, D.meta.name); if (err) return send(res, 400, { error: err }); audit(u.user, 'Restored the workspace from a backup file'); return ok(res);
    }
    if (req.method === 'POST' && p === '/api/appeals') {
      if (B.op === 'toggle') { if (!has(u, 'automations.manage')) return deny(res); D.settings.appeals = !!B.on; audit(u.user, B.on ? 'Opened ban appeals' : 'Closed ban appeals'); return ok(res); }
      if (!has(u, 'appeals.review')) return deny(res);
      const a = D.appeals.find(x => x.id === B.id && x.status === 'open'); if (!a) return send(res, 404, { error: 'That appeal was already reviewed.' });
      const note = cleanName(B.note, 300);
      if (B.decision === 'accept') { if (!has(u, 'mod.unban')) return deny(res); act({ action: 'unban', userId: a.uid, name: a.name, reason: 'Appeal accepted' + (note ? ': ' + note : ''), by: u.user, byUid: uid }); a.status = 'accepted'; }
      else if (B.decision === 'deny') a.status = 'denied'; else return send(res, 400, { error: 'bad request' });
      a.by = u.user; a.note = note; a.reviewed = Date.now(); audit(u.user, `${a.status === 'accepted' ? 'Accepted' : 'Denied'} the appeal from ${a.name}`); return ok(res);
    }
    if (req.method === 'POST' && p === '/api/watch') {
      if (!has(u, 'logbook.note')) return deny(res); const id = B.userId; if (!Number.isInteger(id) || id < 1) return send(res, 400, { error: 'bad userId' });
      if (B.on) { if (Object.keys(D.watch).length >= 200 && !D.watch[id]) return send(res, 400, { error: 'The watchlist is full (200 players).' }); D.watch[id] = { name: cleanName(B.name, 40) || String(id), by: u.user, t: Date.now(), reason: cleanName(B.reason, 200) }; audit(u.user, `Added ${D.watch[id].name} to the watchlist`); }
      else if (D.watch[id]) { audit(u.user, `Removed ${D.watch[id].name} from the watchlist`); delete D.watch[id]; }
      return ok(res);
    }
    if (req.method === 'POST' && p === '/api/webhook') {
      if (!has(u, 'webhooks.manage')) return deny(res); D.webhook ||= DEFAULT_WEBHOOK();
      if (B.op === 'save') {
        if (B.url !== undefined) { const v = String(B.url || '').trim(); if (v && !HOOK_RE.test(v)) return send(res, 400, { error: 'Paste a Discord webhook URL. It starts with https://discord.com/api/webhooks/' }); D.webhook.url = v; }
        if (B.events) for (const k of Object.keys(D.webhook.events)) if (k in B.events) D.webhook.events[k] = !!B.events[k];
        audit(u.user, 'Updated Discord notifications'); return ok(res);
      }
      if (B.op === 'test') { if (!D.webhook.url) return send(res, 400, { error: 'Add a webhook URL first' }); HOOKS.push({ url: D.webhook.url, body: { username: 'Sentinel', allowed_mentions: { parse: [] }, embeds: [{ title: 'Sentinel is connected', description: `Notifications for ${D.meta.name} will appear in this channel.`, color: 0x635bff }] } }); return ok(res); }
      return send(res, 400, { error: 'bad request' });
    }
    // ---- owner only: the game connection ----
    if (p === '/api/setup') { if (!u.isOwner) return ownerOnly(res); return send(res, 200, { hasCode: !!D.meta.codeHash, origin: site(req), name: D.meta.name, placeId: D.meta.placeId || null, placeLock: !!D.meta.placeLock, lastPlace: D.meta.lastPlace ?? null, connectedAt: D.meta.connectedAt || null, oc: D.meta.oc ? { universe: D.meta.oc.universe || '', last: D.meta.oc.last || null } : null }); }
    if (p === '/api/bridge') {
      if (!u.isOwner) return ownerOnly(res);
      let lua; try { lua = fs.readFileSync(path.join(__dirname, '..', 'SentinelBridge.lua'), 'utf8'); } catch { return send(res, 500, { error: 'SentinelBridge.lua is missing from the deployment' }); }
      lua = lua.replace(/^local URL = ".*"$/m, () => 'local URL = ' + JSON.stringify(site(req))).replace(/^local KEY = ".*"$/m, 'local KEY = "[INPUT CODE HERE]"').replace(/^local INTERVAL = \d+/m, 'local INTERVAL = 10');
      const h = { 'Content-Type': 'text/plain; charset=utf-8' }; if (url.searchParams.get('download')) h['Content-Disposition'] = 'attachment; filename="Sentinel.server.lua"';
      res.writeHead(200, h); return res.end(lua);
    }
    if (req.method === 'POST' && p === '/api/workspace') {
      if (!u.isOwner) return ownerOnly(res);
      if (B.op === 'ocsave') {
        const key = String(B.key || '').replace(/\s+/g, ''), uni = String(B.universe || '').replace(/\s/g, '');
        if (uni && !/^\d{3,20}$/.test(uni)) return send(res, 400, { error: 'The Universe ID is only numbers.' });
        if (!D.meta.oc && key.length < 20) return send(res, 400, { error: 'Paste your Roblox API key.' });
        if (key && (key.length < 20 || key.length > 4000 || !/^[\x21-\x7e]+$/.test(key))) return send(res, 400, { error: key.length < 20 ? 'That key is too short. Copy the whole key from Roblox.' : 'That key has characters a Roblox key never has. Copy it again from Roblox.' });
        D.meta.oc = { ...(D.meta.oc || {}), ...(key ? { key: ocEnc(key) } : {}), universe: uni, last: null }; delete D.meta.oc.uni; audit(u.user, 'Saved the Roblox Open Cloud key'); return ok(res);
      }
      if (B.op === 'occlear') { delete D.meta.oc; audit(u.user, 'Removed the Roblox Open Cloud key'); return ok(res); }
      if (B.op === 'rename') { const nm = cleanName(B.name); if (nm.length < 2) return send(res, 400, { error: 'Name is too short' }); D.meta.name = nm; audit(u.user, 'Renamed the workspace'); return ok(res); }
      if (B.op === 'rotatekey') { D.meta.rot = (D.meta.rot || 0) + 1; const nc = newCode(CTX.wid); D.meta.codeHash = nc.hash; audit(u.user, 'Made a new game code'); return send(res, 200, { ok: true, code: nc.code }); }
      if (B.op === 'place') {
        const pid = B.placeId === '' || B.placeId == null ? null : Number(B.placeId);
        if (pid !== null && (!Number.isInteger(pid) || pid < 1)) return send(res, 400, { error: "The Place ID is the number in your game's link." });
        D.meta.placeId = pid; D.meta.placeLock = !!(pid && B.lock); audit(u.user, pid ? `Set Place ID ${pid}${D.meta.placeLock ? ' (locked)' : ''}` : 'Cleared the Place ID'); return ok(res);
      }
      if (B.op === 'delete') {
        if (cleanName(B.confirm) !== D.meta.name) return send(res, 400, { error: 'Type the workspace name exactly to confirm' });
        await need('glob'); const wid = CTX.wid; G.workspaces = Math.max(0, G.workspaces - 1); if (U) U.workspaces = U.workspaces.filter(w => w !== wid);
        D.meta.deleted = Date.now(); audit(u.user, 'Deleted the workspace'); // kept for 30 days, so the site admin can bring it back if it was a mistake or a hack
        res.setHeader('Set-Cookie', clearCookie('ws'));
        return ok(res);
      }
      return send(res, 400, { error: 'bad request' });
    }
    if (p === '/api/export') {
      if (!has(u, 'privacy.manage')) return deny(res);
      const id = +url.searchParams.get('userId'); if (!Number.isInteger(id) || id < 1) return send(res, 400, { error: 'bad userId' });
      await need(shOf(id)); audit(u.user, `Exported stored data for user ${id}`);
      const data = { exportedAt: new Date().toISOString(), userId: id, activity: D.play[id] || null, playtimeHistory: (D.hist[id % SH] || {})[id] || null, logbook: D.logs[id] || [], ban: D.bans[id] || null, mute: D.mutes[id] || null,
        reportsFiled: D.calls.filter(c => c.from.userId === id), chatInStoredReports: D.calls.flatMap(c => c.chat.filter(m => m.userId === id).map(m => ({ report: c.id, ...m }))), recentChat: R.chat.filter(m => m.userId === id) };
      res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Disposition': `attachment; filename="player-${id}.json"` }); return res.end(JSON.stringify(data, null, 2));
    }
    if (req.method === 'POST' && p === '/api/erase') {
      if (!has(u, 'privacy.manage')) return deny(res);
      const id = B.userId; if (!Number.isInteger(id) || id < 1) return send(res, 400, { error: 'bad userId' });
      const names = new Set([D.play[id]?.name, D.bans[id]?.name, D.mutes[id]?.name, ...D.calls.filter(c => c.from.userId === id).map(c => c.from.name), ...R.chat.filter(m => m.userId === id).map(m => m.name), ...(D.logs[id] || []).map(e => e.name)].filter(Boolean));
      await need(shOf(id)); if (D.hist[id % SH]) delete D.hist[id % SH][id];
      delete D.logs[id]; delete D.play[id]; delete D.mutes[id];
      if (D.bans[id]) D.bans[id] = { userId: id, name: 'User ' + id, reason: 'Retained for community safety', time: D.bans[id].time, expires: D.bans[id].expires };
      D.calls = D.calls.filter(c => c.from.userId !== id); D.calls.forEach(c => c.chat = c.chat.filter(m => m.userId !== id)); R.chat = R.chat.filter(m => m.userId !== id);
      if (D.session) delete D.session.attendees[id]; D.sessions.forEach(s => s.attendees = s.attendees.filter(a => a.userId !== id));
      const scrub = t => [...names].reduce((x, n) => x.split(n).join('[erased user]'), t);
      D.feed.forEach(f => f.text = scrub(f.text)); D.audit.forEach(a => a.text = scrub(a.text));
      audit(u.user, `Erased stored data for user ${id}`); return ok(res);
    }
    send(res, 404, { error: 'not found' });
  } catch (e) { res.failed = true; send(res, 500, { error: String(e) }); }
}

// ---- one request: read body, run, save, replay if another request got there first ----
const makeOut = () => { const o = { code: 200, headers: {}, body: '', failed: false, after: [], setHeader(k, v) { o.headers[k] = v; }, writeHead(c, h) { o.code = c; Object.assign(o.headers, h || {}); }, end(d) { o.body = d === undefined ? '' : d; } }; return o; };
const flush = (o, res) => { res.statusCode = o.code; for (const [k, v] of Object.entries(o.headers)) res.setHeader(k, v); res.end(o.body); };
async function readBody(req) {
  if (req.method === 'GET' || req.method === 'HEAD') return {};
  try { if (req.body !== undefined && req.body !== null) { if (Buffer.isBuffer(req.body)) return JSON.parse(req.body.toString() || '{}'); return typeof req.body === 'string' ? JSON.parse(req.body || '{}') : req.body; } } catch { return {}; }
  return new Promise(r => { let d = ''; req.on('data', c => { d += c; if (d.length > (String(req.url).startsWith('/api/backup/import') ? 4e6 : 1e5)) req.destroy(); }); req.on('end', () => { try { r(JSON.parse(d || '{}')); } catch { r({}); } }); });
}
async function handle(req, res) {
  const url = new URL(req.url, 'http://x'), p = url.pathname;
  if (CONFIG_ERROR.length) { res.statusCode = 500; res.setHeader('Content-Type', 'text/plain'); return res.end('Sentinel is not configured. Missing Vercel environment variables: ' + CONFIG_ERROR.join(', ')); }
  req._body = await readBody(req);
  for (let attempt = 0; attempt < 6; attempt++) {
    resetState();
    const out = makeOut();
    await route(req, out, url, p);
    if (!out.failed) await runOC().catch(() => {});
    if (out.failed || await commit()) { await sendHooks(); for (const f of out.after) await f().catch(() => {}); return flush(out, res); }
    await new Promise(r => setTimeout(r, 25 + Math.random() * 100)); // lost a race with another request: run again on fresh data
  }
  res.statusCode = 503; res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify({ error: 'Busy, please try again' }));
}
let chain = Promise.resolve(); // one request at a time per instance (state is shared in-process while a request runs)
const serial = fn => { const run = chain.then(fn); chain = run.catch(() => {}); return run; };
module.exports = (req, res) => serial(() => handle(req, res)).catch(e => { console.error(e); try { res.statusCode = 500; res.setHeader('Content-Type', 'text/plain'); res.end('Error: ' + e.message); } catch {} });
