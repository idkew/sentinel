// Sentinel: moderation panel for Roblox games. Vercel + Supabase edition (many games, one site).
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

const freshD = () => ({ meta: null, members: {}, invites: {}, bans: {}, mutes: {}, logs: {}, feed: [], stats: { joins: 0, peak: 0, kicks: 0 }, calls: [], callSeq: 0, session: null, sessions: [],
  flagWords: ['scam', 'hack', 'exploit', 'free robux'], play: {}, audit: [], rules: {}, settings: { quotaMinutes: 60 } });
const D = freshD(), R = { servers: {}, cmds: [], history: [], chat: [], flagCount: {}, nextId: 1 };
let U = null, G = { workspaces: 0 }; // U = the signed-in person's account row, G = global counters
const CTX = { uid: null, wid: null };
const setUid = u => { if (!/^[gr]_\d{1,32}$/.test(u)) throw new Error('bad user'); CTX.uid = u; };
const setWid = w => { if (!/^[a-f0-9]{12}$/.test(w)) throw new Error('bad workspace'); CTX.wid = w; };
const save = () => {}; // changes are written once, at the end of each request (see handle)
const pruneCalls = () => { const cut = Date.now() - cfg.callRetentionDays * 864e5; D.calls = D.calls.filter(c => c.t > cut); }; // ModCalls (and their chat snapshots) expire
const liveServers = () => Object.values(R.servers).filter(s => Date.now() - s.last < LIVE_MS).length;

// ---- storage: rows of panel_kv, grouped by how often they change ----
const ROWS = {
  core: { get: () => ({ meta: D.meta, members: D.members, invites: D.invites, bans: D.bans, mutes: D.mutes, feed: D.feed, stats: D.stats, callSeq: D.callSeq, session: D.session, sessions: D.sessions, flagWords: D.flagWords, audit: D.audit, rules: D.rules, settings: D.settings }), set: v => Object.assign(D, v) },
  logs: { get: () => D.logs, set: v => { D.logs = v; } },
  calls: { get: () => D.calls, set: v => { D.calls = v; } },
  play: { get: () => D.play, set: v => { D.play = v; } },
  live: { get: () => ({ servers: R.servers, history: R.history }), set: v => { R.servers = v.servers || {}; R.history = v.history || []; } },
  cmds: { get: () => ({ cmds: R.cmds, nextId: R.nextId }), set: v => { R.cmds = v.cmds || []; R.nextId = v.nextId || 1; } },
  chat: { get: () => ({ chat: R.chat, flagCount: R.flagCount }), set: v => { R.chat = v.chat || []; R.flagCount = v.flagCount || {}; } },
  user: { get: () => U, set: v => { U = v; } },
  glob: { get: () => G, set: v => { G = v; } },
};
const phys = k => k === 'user' ? 'u:' + CTX.uid : k === 'glob' ? 'g:stats' : `w${CTX.wid}:${k}`;
const NEEDS = { '/api/state': ['play', 'live', 'calls', 'chat'], '/api/lookup': ['play', 'live', 'logs'], '/api/action': ['logs', 'play', 'cmds'], '/api/session': ['play', 'logs', 'cmds', 'live'],
  '/api/call': ['calls', 'cmds'], '/api/export': ['logs', 'play', 'calls', 'chat'], '/api/erase': ['logs', 'play', 'calls', 'chat'], '/api/setup': [], '/api/bridge': [], '/api/team': [], '/api/workspace': [] };
const loaded = {};
const sbHeaders = () => ({ apikey: SB_KEY, ...(SB_KEY.startsWith('eyJ') ? { Authorization: 'Bearer ' + SB_KEY } : {}), 'Content-Type': 'application/json' });
function resetState() {
  for (const k of Object.keys(D)) delete D[k]; Object.assign(D, freshD());
  Object.assign(R, { servers: {}, cmds: [], history: [], chat: [], flagCount: {}, nextId: 1 }); U = null; G = { workspaces: 0 }; CTX.uid = CTX.wid = null;
  for (const k of Object.keys(loaded)) delete loaded[k];
}
async function need(...keys) {
  const want = [...new Set(keys)].filter(k => !(k in loaded)); if (!want.length) return;
  const pk = Object.fromEntries(want.map(k => [k, phys(k)]));
  const r = await fetch(`${SB_URL}/rest/v1/panel_kv?select=key,value,version&key=in.(${Object.values(pk).join(',')})`, { headers: sbHeaders() });
  if (!r.ok) throw new Error(`Supabase read failed: HTTP ${r.status} ${(await r.text()).slice(0, 200)}`);
  const rows = Object.fromEntries((await r.json()).map(x => [x.key, x]));
  for (const k of want) {
    const row = rows[pk[k]]; if (row) ROWS[k].set(row.value);
    loaded[k] = { pk: pk[k], ver: row ? row.version : 0, snap: JSON.stringify(ROWS[k].get()) };
    if (k === 'calls') pruneCalls();
    if (k === 'chat') R.chat = R.chat.filter(m => Date.now() - m.t < CHAT_MS);
  }
}
async function commit() { // true = saved (or nothing changed), false = someone else changed a row first
  const changes = [];
  for (const [k, l] of Object.entries(loaded)) { const v = ROWS[k].get(); if (JSON.stringify(v) !== l.snap) changes.push({ key: l.pk, expect: l.ver, value: v }); }
  if (!changes.length) return true;
  const r = await fetch(`${SB_URL}/rest/v1/rpc/panel_commit`, { method: 'POST', headers: sbHeaders(), body: JSON.stringify({ changes }) });
  if (!r.ok) throw new Error(`Supabase save failed: HTTP ${r.status} ${(await r.text()).slice(0, 200)}`);
  return (await r.json()) === true;
}

const live = o => !o.expires || o.expires > Date.now();
const feed = (text, by) => { D.feed.unshift({ t: Date.now(), text }); D.feed.length = Math.min(D.feed.length, 50); if (by) audit(by, text); };
const audit = (user, text) => { D.audit.unshift({ t: Date.now(), user, text }); D.audit.length = Math.min(D.audit.length, 300); };

// ---- roles, automation rules, activity ----
const RANK = { helper: 1, moderator: 2, admin: 3 };
const NEED = { warn: 1, kick: 1, mute: 2, unmute: 2, ban: 2, unban: 3, announce: 2, points: 2, session: 1, call: 1, flagwords: 2, staff: 3, rules: 3, settings: 3 };
const can = (s, n) => RANK[s.role] >= n;
const deny = res => send(res, 403, { error: 'Your role is not allowed to do that' });
const pw = (p, salt) => crypto.scryptSync(String(p), salt, 32).toString('hex');
const DEFAULT_RULES = {
  autosuspend: { enabled: true, warns: 3, minutes: 5 },
  sessionpoints: { enabled: true, points: 5 },
  flaggedmute: { enabled: false, count: 3, minutes: 5 },
  welcome: { enabled: false, text: 'Welcome! Moderators are keeping this game friendly.' },
};
const rule = id => ({ ...DEFAULT_RULES[id], ...(D.rules[id] || {}) });
const weekStart = now => { const d = new Date(now); d.setUTCHours(0, 0, 0, 0); return d.getTime() - ((d.getUTCDay() + 6) % 7) * 864e5; };
const playOf = (userId, name) => (D.play[userId] ||= { name, total: 0, week: 0, weekStart: 0, points: 0 });
function tick(p, dt, now) { const u = playOf(p.userId, p.name), ws = weekStart(now); u.name = p.name; if (u.weekStart !== ws) { u.weekStart = ws; u.week = 0; } u.total += dt; u.week += dt; }
function addPoints(userId, name, amount, reason, by) {
  playOf(userId, name).points += amount;
  (D.logs[userId] ||= []).push({ type: 'Points', reason: `${amount > 0 ? '+' : ''}${amount}: ${reason}`, time: Date.now(), by });
  feed(`Points ${amount > 0 ? '+' : ''}${amount} for ${name} (${reason})`, by);
  cmd({ type: 'message', kind: amount > 0 ? 'ok' : undefined, userId, text: `${amount > 0 ? 'You earned' : 'You lost'} ${Math.abs(amount)} points: ${reason}` });
}
const cmd = c => R.cmds.push({ id: R.nextId++, t: Date.now(), seen: {}, ...c });

function allPlayers() {
  const now = Date.now(), out = [];
  for (const [j, s] of Object.entries(R.servers)) {
    if (now - s.last > LIVE_MS) continue;
    for (const p of s.players) out.push({ ...p, server: j.slice(0, 6) });
  }
  return out;
}

function act({ action, userId, name, reason, minutes, by = 'Panel' }) {
  const expires = minutes > 0 ? Date.now() + minutes * 60000 : null;
  const log = type => { (D.logs[userId] ||= []).push({ type, reason, time: Date.now(), minutes, by }); feed(`${type}: ${name} (${reason})`, by); };
  if (action === 'ban') { D.bans[userId] = { userId, name, reason, time: Date.now(), expires }; log(expires ? 'Suspended' : 'Banned'); cmd({ type: 'ban', userId, reason, seconds: minutes > 0 ? minutes * 60 : -1 }); }
  else if (action === 'unban') { delete D.bans[userId]; log('Unbanned'); cmd({ type: 'unban', userId }); }
  else if (action === 'mute') { D.mutes[userId] = { userId, name, reason, expires }; log('Muted'); }
  else if (action === 'unmute') { delete D.mutes[userId]; log('Unmuted'); }
  else if (action === 'kick') { D.stats.kicks++; log('Kicked'); cmd({ type: 'kick', userId, reason: 'Kicked: ' + reason }); }
  else if (action === 'warn') {
    log('Warned'); cmd({ type: 'message', userId, text: 'Warning: ' + reason });
    let n = 0; // count warnings since the last suspension/ban
    for (const e of [...D.logs[userId]].reverse()) { if (e.type === 'Suspended' || e.type === 'Banned') break; if (e.type === 'Warned') n++; }
    const r = rule('autosuspend');
    if (r.enabled && n >= r.warns) act({ action: 'ban', userId, name, reason: `Automatic: ${r.warns} warnings`, minutes: r.minutes, by: 'Automation' });
  }
  save();
}

function sync(b) {
  const now = Date.now(), id = String(b.jobId || 'studio'), dt = R.servers[id] ? Math.min((now - R.servers[id].last) / 1000, 30) : 0;
  R.servers[id] = { players: b.players || [], last: now };
  for (const [j, sv] of Object.entries(R.servers)) if (now - sv.last > 6e4) delete R.servers[j];
  for (const p of b.players || []) tick(p, dt, now); // playtime tracking
  for (const e of b.events || []) {
    const text = String(e.text || '').slice(0, 200), name = String(e.name || '?').slice(0, 40);
    if (e.type === 'join') { D.stats.joins++; feed(`${name} joined`); const w = rule('welcome'); if (w.enabled) cmd({ type: 'message', kind: 'info', userId: e.userId, text: w.text }); }
    else if (e.type === 'leave') feed(`${name} left`);
    else if (e.type === 'chat') { // live chat monitor (rolling buffer: latest 300 messages, at most 24 hours)
      const flagged = D.flagWords.some(w => text.toLowerCase().includes(w));
      R.chat.push({ t: now, jobId: id, server: id.slice(0, 6), userId: e.userId, name, text, flagged });
      if (R.chat.length > 300) R.chat.shift();
      if (flagged) {
        feed(`Flagged chat from ${name}: ${text}`);
        const r = rule('flaggedmute');
        if (r.enabled && (R.flagCount[e.userId] = (R.flagCount[e.userId] || 0) + 1) >= r.count) { R.flagCount[e.userId] = 0; act({ action: 'mute', userId: e.userId, name, reason: 'Automatic: repeated flagged chat', minutes: r.minutes, by: 'Automation' }); }
      }
    }
    else if (e.type === 'attend' && D.session) {
      D.session.attendees[e.userId] = name;
      cmd({ type: 'message', kind: 'ok', userId: e.userId, text: `You are marked present for ${D.session.type}.` });
    }
    else if (e.type === 'modcall') { // snapshot the last 15 chat lines from that server so moderators have context
      const call = { id: ++D.callSeq, t: now, from: { userId: e.userId, name }, text: text || 'No details given', server: id.slice(0, 6), status: 'open', by: null, note: '',
        chat: R.chat.filter(c => c.jobId === id).slice(-15).map(({ t, userId, name, text, flagged }) => ({ t, userId, name, text, flagged })) };
      D.calls.unshift(call); D.calls.length = Math.min(D.calls.length, 100);
      feed(`ModCall #${call.id} from ${name}: ${call.text}`);
      cmd({ type: 'message', kind: 'ok', userId: e.userId, text: `ModCall #${call.id} sent. A moderator will respond soon.` });
    }
  }
  D.stats.peak = Math.max(D.stats.peak, allPlayers().length);
  for (const p of b.players || []) { // belt and braces: kick anyone with a live ban who is still in-game
    const x = D.bans[p.userId];
    if (x && live(x) && !R.cmds.some(c => c.type === 'kick' && c.userId === p.userId && now - c.t < 10000)) cmd({ type: 'kick', userId: p.userId, reason: 'Banned: ' + x.reason });
  }
  const hist = R.history; if (!hist.length || now - hist[hist.length - 1].t > 6e4) { hist.push({ t: now, n: allPlayers().length }); if (hist.length > 120) hist.shift(); }
  R.cmds = R.cmds.filter(c => now - c.t < 120000);
  const out = R.cmds.filter(c => !c.seen[id]); out.forEach(c => c.seen[id] = 1);
  save();
  return { commands: out.map(({ seen, t, ...c }) => c), muted: Object.values(D.mutes).filter(live).map(m => m.userId) };
}

// ---- Roblox lookups (needs internet) ----
const AV = new Map(), j = (u, o) => fetch(u, o).then(r => r.json());
async function avatars(ids) {
  const need = ids.filter(i => !AV.has(i)).slice(0, 100);
  if (need.length) try { const r = await j(`https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds=${need.join(',')}&size=150x150&format=Png`); for (const d of r.data || []) if (d.imageUrl) AV.set(d.targetId, d.imageUrl); } catch {}
  return Object.fromEntries(ids.filter(i => AV.has(i)).map(i => [i, AV.get(i)]));
}
async function lookup(name) {
  let id, uname = name, display = name, created;
  try {
    const r = await j('https://users.roblox.com/v1/usernames/users', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ usernames: [name], excludeBannedUsers: false }) });
    const u = r.data && r.data[0];
    if (u) { id = u.id; uname = u.name; display = u.displayName; created = (await j('https://users.roblox.com/v1/users/' + id)).created; }
  } catch {}
  if (!id) { const p = allPlayers().find(p => p.name.toLowerCase() === name.toLowerCase()); if (p) { id = p.userId; uname = p.name; display = p.displayName; } }
  if (!id) return null;
  const ban = D.bans[id], mute = D.mutes[id];
  return { userId: id, name: uname, displayName: display, created, avatar: (await avatars([id]))[id], online: allPlayers().some(p => p.userId === id),
           banned: ban && live(ban) ? ban : null, muted: mute && live(mute) ? mute : null, logbook: D.logs[id] || [], play: D.play[id] || null };
}

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
const gameKey = (wid, rot) => `${wid}.${rot}.${crypto.createHmac('sha256', SIGN).update(`gamekey:${wid}:${rot}`).digest('base64url').slice(0, 32)}`;
const site = req => (env.SITE_URL || `${req.headers['x-forwarded-proto'] === 'http' ? 'http' : 'https'}://${req.headers['x-forwarded-host'] || req.headers.host}`).replace(/\/$/, '');
const send = (res, code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); };
const body = async req => req._body || {};
const tooMany = (res, s) => { res.setHeader('Retry-After', String(s)); return send(res, 429, { error: `Too many requests. Try again in ${s} seconds.`, retry: s }); };
const page = (res, code, title, text) => { res.writeHead(code, { 'Content-Type': 'text/html; charset=utf-8' }); res.end(`<!DOCTYPE html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title><body style="font:16px -apple-system,Segoe UI,system-ui,sans-serif;background:#f5f5f7;color:#1d1d1f;display:grid;place-items:center;min-height:100vh;margin:0"><div style="background:#fff;border-radius:20px;padding:36px 40px;max-width:380px;text-align:center;box-shadow:0 8px 30px rgba(0,0,0,.08)"><h2 style="margin:0 0 8px">${esc(title)}</h2><p style="color:#6e6e73;margin:0 0 20px">${esc(text)}</p><a href="/" style="color:#0071e3;text-decoration:none;font-weight:600">Back to Sentinel</a></div></body>`); };
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
const ACTIONS = ['ban', 'unban', 'mute', 'unmute', 'kick', 'warn', 'announce', 'points'];

async function authRoute(req, res, url, p, ip) {
  const w = limit('auth:' + ip, 20, 60000); if (w) return page(res, 429, 'Too many attempts', `Please wait ${w} seconds and try again.`);
  const m = /^\/auth\/(google|roblox)(\/callback)?$/.exec(p); if (!m || req.method !== 'GET') return page(res, 404, 'Not found', 'That page does not exist.');
  const name = m[1], P = PROV[name]; if (!P.id || !P.secret) return page(res, 404, 'Not available', `Sign in with ${name === 'google' ? 'Google' : 'Roblox'} is not set up here.`);
  const redirect = site(req) + '/auth/' + name + '/callback';
  if (!m[2]) { // step 1: send the person to Google/Roblox
    const state = rnd(18), verifier = rnd(40), invite = url.searchParams.get('invite') || '';
    const q = new URLSearchParams({ client_id: P.id, redirect_uri: redirect, response_type: 'code', scope: P.scope, state, code_challenge: crypto.createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256', ...(name === 'google' ? { prompt: 'select_account' } : {}) });
    res.setHeader('Set-Cookie', mkCookie('oa', pack({ p: name, s: state, v: verifier, i: /^[a-f0-9]{28}$/.test(invite) ? invite : '', e: Date.now() + 600000 }), { maxAge: 600, sameSite: 'Lax' }));
    res.writeHead(302, { Location: P.auth + '?' + q }); return res.end();
  }
  // step 2: they came back with a code
  const oa = unpack(cookiesOf(req).oa), code = url.searchParams.get('code'), st = url.searchParams.get('state');
  if (url.searchParams.get('error')) return page(res, 400, 'Sign-in cancelled', 'No problem. You can try again whenever you like.');
  if (!oa || oa.p !== name || !code || !st || !same(st, oa.s)) return page(res, 400, 'Sign-in expired', 'Please go back and try again.');
  if (!req._oauth) { // the code works once, so remember the result if this request has to re-run
    const tr = await fetch(P.token, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }, body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: redirect, client_id: P.id, client_secret: P.secret, code_verifier: oa.v }) });
    const tj = await tr.json().catch(() => ({})); if (!tr.ok || !tj.access_token) { req._oauth = { fail: 1 }; }
    else { const info = await (await fetch(P.info, { headers: { Authorization: 'Bearer ' + tj.access_token } })).json().catch(() => ({})); req._oauth = /^\d{1,32}$/.test(String(info.sub || '')) ? { sub: String(info.sub), name: cleanName(info.name || info.nickname || info.preferred_username || 'Member') } : { fail: 1 }; }
  }
  if (req._oauth.fail) return page(res, 400, 'Sign-in failed', 'We could not confirm your account. Please try again.');
  const uid = name[0] + '_' + req._oauth.sub; setUid(uid); await need('user');
  if (!U) { if (!SIGNUPS_OPEN && !oa.i) return page(res, 403, 'Sign-ups are closed', 'This site is not accepting new accounts right now.'); U = { id: uid, provider: name, workspaces: [], created: Date.now() }; }
  U.name = req._oauth.name;
  res.setHeader('Set-Cookie', [mkCookie('sid', pack({ u: uid, e: Date.now() + 7 * 864e5 })), clearCookie('oa')]);
  res.writeHead(302, { Location: '/' + (oa.i ? '#/join/' + oa.i : '') }); return res.end();
}

async function route(req, res, url, p) {
  try {
    const ip = ipOf(req);
    if (req.method === 'GET' && p === '/') { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); return res.end(fs.readFileSync(path.join(__dirname, '..', 'index.html'))); }
    if (req.method === 'GET' && p.startsWith('/legal/')) { const n = p.slice(7); if (!LEGAL[n]) return send(res, 404, { error: 'not found' }); res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); return res.end(legalPage(n)); }
    if (p.startsWith('/auth/')) return await authRoute(req, res, url, p, ip);

    if (req.method === 'POST' && p === '/game/sync') { // the Roblox script checks in here, using its workspace's game key
      const b = await body(req), k = String(b.key || ''), [wid, rot, sig] = k.split('.');
      if (!/^[a-f0-9]{12}$/.test(wid || '') || !/^\d{1,6}$/.test(rot || '') || !sig || !same(k, gameKey(wid, +rot))) { const w = limit('badkey:' + ip, 30, 60000); return w ? tooMany(res, w) : send(res, 403, { error: 'bad key' }); }
      const job = String(b.jobId || 'studio').slice(0, 64), w1 = limit(`sync:${wid}:${job}`, 40, 60000) || limit('sync:' + wid, 400, 60000); if (w1) return tooMany(res, w1);
      setWid(wid);
      const ev = Array.isArray(b.events) ? b.events : [], chatty = ev.some(e => e.type === 'chat' || e.type === 'modcall');
      await need('core', 'play', 'live', 'cmds', ...(chatty ? ['chat'] : []), ...(ev.some(e => e.type === 'modcall') ? ['calls'] : []));
      if (!D.meta || (D.meta.rot || 0) !== +rot) return send(res, 403, { error: 'bad key' });
      if (chatty && rule('flaggedmute').enabled) await need('logs');
      return send(res, 200, sync(b));
    }

    // ---- everything below is the website talking to us ----
    if (!p.startsWith('/api/')) return send(res, 404, { error: 'not found' });
    const w0 = limit('ip:' + ip, 300, 60000); if (w0) return tooMany(res, w0);
    const ck = cookiesOf(req), uid = sessionUid(req);
    if (req.method === 'POST' && p === '/logout') { res.setHeader('Set-Cookie', [clearCookie('sid'), clearCookie('ws')]); return send(res, 200, { ok: true }); }

    if (p === '/api/me') { // who am I, and which workspaces do I have?
      const base = { providers: providers(), signupsOpen: SIGNUPS_OPEN, user: null, workspaces: [], current: null, maxPerUser: MAX_PER_USER };
      if (!uid) return send(res, 200, base);
      setUid(uid); await need('user'); if (!U) return send(res, 200, base);
      const ids = U.workspaces.filter(w => /^[a-f0-9]{12}$/.test(w)); let list = [];
      if (ids.length) {
        const r = await fetch(`${SB_URL}/rest/v1/panel_kv?select=key,meta:value->meta,members:value->members&key=in.(${ids.map(w => `w${w}:core`).join(',')})`, { headers: sbHeaders() });
        if (!r.ok) throw new Error('Supabase read failed: HTTP ' + r.status);
        for (const row of await r.json()) { const mm = row.members && row.members[uid]; if (row.meta && mm) list.push({ id: row.key.slice(1, 13), name: row.meta.name, role: mm.role, owner: row.meta.owner === uid }); }
        list.sort((a, b) => ids.indexOf(a.id) - ids.indexOf(b.id));
      }
      if (list.length !== U.workspaces.length) U.workspaces = list.map(x => x.id); // forget deleted workspaces and ones you were removed from
      const cur = list.find(x => x.id === ck.ws) ? ck.ws : (list[0] && list[0].id) || null;
      if (cur && cur !== ck.ws) res.setHeader('Set-Cookie', mkCookie('ws', cur, { maxAge: 31536000 }));
      return send(res, 200, { ...base, user: { id: uid, name: U.name, provider: U.provider }, workspaces: list, current: cur });
    }
    if (p === '/api/invite') { // what is this invite for? (works before signing in)
      const w = limit('invite:' + ip, 20, 60000); if (w) return tooMany(res, w);
      const code = url.searchParams.get('code') || ''; if (!/^[a-f0-9]{28}$/.test(code)) return send(res, 404, { error: 'This invite link is not valid.' });
      setWid(code.slice(0, 12)); await need('core'); const inv = D.meta && D.invites[code];
      return inv && inv.exp > Date.now() ? send(res, 200, { workspace: D.meta.name, role: inv.role }) : send(res, 404, { error: 'This invite has expired or was already used.' });
    }
    if (!uid) return send(res, 401, { error: 'Please sign in', code: 'signin' });
    const w2 = limit('u:' + uid, 180, 60000); if (w2) return tooMany(res, w2);
    setUid(uid);

    if (req.method === 'POST' && p === '/api/workspaces') { // create a new game workspace
      const w = limit('create:' + uid, 5, 3600000) || limit('createip:' + ip, 10, 3600000); if (w) return tooMany(res, w);
      const b = await body(req), nm = cleanName(b.name); if (nm.length < 2) return send(res, 400, { error: 'Give your game a name (at least 2 letters).' });
      await need('user', 'glob'); if (!U) return send(res, 401, { error: 'Please sign in', code: 'signin' });
      if (!SIGNUPS_OPEN) return send(res, 403, { error: 'New workspaces are closed right now.' });
      if (U.workspaces.length >= MAX_PER_USER) return send(res, 400, { error: `You can have up to ${MAX_PER_USER} workspaces.` });
      if (G.workspaces >= MAX_WORKSPACES) return send(res, 400, { error: 'This site is full right now. Please try again later.' });
      const wid = crypto.randomBytes(6).toString('hex'); setWid(wid); await need('core');
      D.meta = { id: wid, name: nm, owner: uid, created: Date.now(), rot: 0 }; D.members[uid] = { name: U.name, role: 'admin', joined: Date.now() }; audit(U.name, 'Created the workspace');
      G.workspaces++; U.workspaces.push(wid);
      res.setHeader('Set-Cookie', mkCookie('ws', wid, { maxAge: 31536000 })); return send(res, 200, { ok: true, id: wid });
    }
    if (req.method === 'POST' && p === '/api/join') { // join with an invite link
      const w = limit('join:' + uid, 10, 3600000); if (w) return tooMany(res, w);
      const code = String((await body(req)).code || ''); if (!/^[a-f0-9]{28}$/.test(code)) return send(res, 400, { error: 'This invite link is not valid.' });
      setWid(code.slice(0, 12)); await need('user', 'core');
      if (!U) return send(res, 401, { error: 'Please sign in', code: 'signin' });
      if (D.meta && D.members[uid]) { res.setHeader('Set-Cookie', mkCookie('ws', CTX.wid, { maxAge: 31536000 })); return send(res, 200, { ok: true, id: CTX.wid }); }
      const inv = D.meta && D.invites[code]; if (!inv || inv.exp < Date.now()) return send(res, 404, { error: 'This invite has expired or was already used.' });
      if (Object.keys(D.members).length >= 25) return send(res, 400, { error: 'This workspace is full.' });
      D.members[uid] = { name: U.name, role: inv.role, joined: Date.now() }; delete D.invites[code]; audit(U.name, `Joined as ${inv.role}`);
      if (!U.workspaces.includes(CTX.wid)) U.workspaces.push(CTX.wid);
      res.setHeader('Set-Cookie', mkCookie('ws', CTX.wid, { maxAge: 31536000 })); return send(res, 200, { ok: true, id: CTX.wid });
    }
    if (req.method === 'POST' && p === '/api/switch') {
      const id = String((await body(req)).id || ''); if (!/^[a-f0-9]{12}$/.test(id)) return send(res, 400, { error: 'bad workspace' });
      await need('user'); if (!U || !U.workspaces.includes(id)) return send(res, 403, { error: 'You are not a member of that workspace' });
      res.setHeader('Set-Cookie', mkCookie('ws', id, { maxAge: 31536000 })); return send(res, 200, { ok: true });
    }

    // ---- workspace-scoped: must be a member of the workspace in the "ws" cookie ----
    if (!/^[a-f0-9]{12}$/.test(ck.ws || '')) return send(res, 409, { error: 'Choose a workspace', code: 'no_workspace' });
    setWid(ck.ws); await need('core', ...(NEEDS[p] || []));
    const mem = D.meta && D.members[uid];
    if (!D.meta) return send(res, 404, { error: 'That workspace no longer exists', code: 'no_workspace' });
    if (!mem) return send(res, 403, { error: 'You are not a member of this workspace', code: 'no_workspace' });
    const u = { user: mem.name, uid, role: mem.role, isOwner: D.meta.owner === uid };
    for (const [c, i] of Object.entries(D.invites)) if (i.exp < Date.now()) delete D.invites[c];

    if (p === '/api/state') {
      const players = allPlayers(), bans = Object.values(D.bans).filter(live), mutes = Object.values(D.mutes).filter(live);
      return send(res, 200, { connected: liveServers() > 0, servers: liveServers(), players, bans, mutes, feed: D.feed.slice(0, 15),
        me: { uid, name: mem.name, role: u.role, owner: u.isOwner }, workspace: { id: CTX.wid, name: D.meta.name }, settings: D.settings, rules: Object.fromEntries(Object.keys(DEFAULT_RULES).map(k => [k, rule(k)])),
        board: Object.entries(D.play).map(([id, x]) => ({ userId: +id, name: x.name, week: x.weekStart === weekStart(Date.now()) ? Math.round(x.week) : 0, total: Math.round(x.total), points: x.points }))
          .sort((a, b) => b.week - a.week || b.points - a.points).slice(0, 50),
        team: can(u, 3) ? Object.entries(D.members).map(([id, x]) => ({ uid: id, name: x.name, role: x.role, owner: id === D.meta.owner, via: id[0] === 'g' ? 'Google' : 'Roblox' })) : [],
        invites: can(u, 3) ? Object.entries(D.invites).map(([code, i]) => ({ code, role: i.role, exp: i.exp })) : [], audit: can(u, 2) ? D.audit.slice(0, 40) : [],
        history: R.history, openCalls: D.calls.filter(c => c.status !== 'resolved').length, calls: D.calls.slice(0, 30),
        session: D.session && { ...D.session, attendees: Object.entries(D.session.attendees).map(([userId, name]) => ({ userId: +userId, name })) }, sessions: D.sessions.slice(0, 10),
        chat: R.chat.slice(-80).reverse(), flagWords: D.flagWords, stats: { ...D.stats, activeBans: bans.length, activeMutes: mutes.length } });
    }
    if (p === '/api/avatars') return send(res, 200, await avatars((url.searchParams.get('ids') || '').split(',').map(Number).filter(Number.isInteger)));
    if (p === '/api/lookup') { const r = await lookup((url.searchParams.get('name') || '').trim().slice(0, 40)); return r ? send(res, 200, r) : send(res, 404, { error: 'No player with that username' }); }
    if (req.method === 'POST' && p === '/api/session') {
      if (!can(u, NEED.session)) return deny(res);
      const b = await body(req), now = Date.now(), s = D.session;
      if (b.op === 'start') {
        if (s) return send(res, 400, { error: 'A session is already running' });
        const type = String(b.type || 'Session').slice(0, 40);
        D.session = { id: now, type, notes: String(b.notes || '').slice(0, 200), start: now, attendees: {} };
        cmd({ type: 'announce', text: `${type} is starting! Type !attend in chat to be marked present.` }); feed('Session started: ' + type, u.user);
      } else if (!s) return send(res, 400, { error: 'No session is running' });
      else if (b.op === 'addall') { for (const pl of allPlayers()) s.attendees[pl.userId] = pl.name; }
      else if (b.op === 'end') {
        D.sessions.unshift({ ...s, end: now, attendees: Object.entries(s.attendees).map(([userId, name]) => ({ userId: +userId, name })) }); D.sessions.length = Math.min(D.sessions.length, 50);
        const sp = rule('sessionpoints'); if (sp.enabled) for (const [uid, nm] of Object.entries(s.attendees)) addPoints(+uid, nm, sp.points, 'Attended ' + s.type, 'Automation');
        D.session = null; cmd({ type: 'announce', text: `${s.type} has ended. Thanks for coming!` }); feed(`Session ended: ${s.type} (${Object.keys(s.attendees).length} present)`);
      }
      save(); return send(res, 200, { ok: true });
    }
    if (req.method === 'POST' && p === '/api/call') {
      if (!can(u, NEED.call)) return deny(res);
      const b = await body(req), c = D.calls.find(c => c.id === b.id);
      if (!c) return send(res, 404, { error: 'No such ModCall' });
      if (b.op === 'claim' && c.status === 'open') { c.status = 'claimed'; c.by = u.user; cmd({ type: 'message', kind: 'info', userId: c.from.userId, text: `A moderator is handling your ModCall #${c.id}.` }); }
      else if (b.op === 'resolve' && c.status !== 'resolved') {
        c.status = 'resolved'; c.note = String(b.note || '').slice(0, 200); c.resolved = Date.now();
        cmd({ type: 'message', kind: 'ok', userId: c.from.userId, text: `ModCall #${c.id} resolved${c.note ? ': ' + c.note : '.'}` }); feed(`ModCall #${c.id} resolved`, u.user);
      }
      save(); return send(res, 200, { ok: true });
    }
    if (req.method === 'POST' && p === '/api/flagwords') {
      const b = await body(req);
      if (!can(u, NEED.flagwords)) return deny(res);
      audit(u.user, 'Updated flagged words');
      D.flagWords = [...new Set((b.words || []).map(w => String(w).toLowerCase().trim().slice(0, 30)).filter(Boolean))].slice(0, 100); save();
      return send(res, 200, { ok: true });
    }
    if (p === '/api/setup') { // what the install guide needs
      if (!can(u, 3)) return deny(res);
      return send(res, 200, { gameKey: gameKey(CTX.wid, D.meta.rot || 0), origin: site(req), name: D.meta.name });
    }
    if (p === '/api/bridge') { // the Roblox script with this workspace's address and key already filled in
      if (!can(u, 3)) return deny(res);
      let lua; try { lua = fs.readFileSync(path.join(__dirname, '..', 'SentinelBridge.lua'), 'utf8'); } catch { return send(res, 500, { error: 'SentinelBridge.lua is missing from the deployment' }); }
      lua = lua.replace(/^local URL = ".*"$/m, () => 'local URL = ' + JSON.stringify(site(req))).replace(/^local KEY = ".*"$/m, () => 'local KEY = ' + JSON.stringify(gameKey(CTX.wid, D.meta.rot || 0))).replace(/^local INTERVAL = \d+/m, 'local INTERVAL = 10');
      const h = { 'Content-Type': 'text/plain; charset=utf-8' }; if (url.searchParams.get('download')) h['Content-Disposition'] = 'attachment; filename="Sentinel.server.lua"';
      res.writeHead(200, h); return res.end(lua);
    }
    if (p === '/api/export') { // data access request: everything stored about one player
      if (!can(u, 3)) return deny(res);
      const id = +url.searchParams.get('userId'); if (!Number.isInteger(id) || id < 1) return send(res, 400, { error: 'bad userId' });
      audit(u.user, `Exported stored data for user ${id}`);
      const data = { exportedAt: new Date().toISOString(), userId: id, activity: D.play[id] || null, moderationRecords: D.logs[id] || [], ban: D.bans[id] || null, mute: D.mutes[id] || null,
        modCallsFiled: D.calls.filter(c => c.from.userId === id), chatInStoredReports: D.calls.flatMap(c => c.chat.filter(m => m.userId === id).map(m => ({ modCall: c.id, ...m }))), liveChatBuffer: R.chat.filter(m => m.userId === id) };
      res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Disposition': `attachment; filename="player-${id}.json"` }); return res.end(JSON.stringify(data, null, 2));
    }
    if (req.method === 'POST' && p === '/api/erase') { // deletion request
      if (!can(u, 3)) return deny(res);
      const id = (await body(req)).userId; if (!Number.isInteger(id) || id < 1) return send(res, 400, { error: 'bad userId' });
      const names = new Set([D.play[id]?.name, D.bans[id]?.name, D.mutes[id]?.name, ...D.calls.filter(c => c.from.userId === id).map(c => c.from.name), ...R.chat.filter(m => m.userId === id).map(m => m.name)].filter(Boolean));
      delete D.logs[id]; delete D.play[id]; delete D.mutes[id];
      if (D.bans[id]) D.bans[id] = { userId: id, name: 'User ' + id, reason: 'Retained for community safety', time: D.bans[id].time, expires: D.bans[id].expires };
      D.calls = D.calls.filter(c => c.from.userId !== id); D.calls.forEach(c => c.chat = c.chat.filter(m => m.userId !== id)); R.chat = R.chat.filter(m => m.userId !== id);
      if (D.session) delete D.session.attendees[id]; D.sessions.forEach(s => s.attendees = s.attendees.filter(a => a.userId !== id));
      const scrub = t => [...names].reduce((x, n) => x.split(n).join('[erased user]'), t);
      D.feed.forEach(f => f.text = scrub(f.text)); D.audit.forEach(a => a.text = scrub(a.text));
      audit(u.user, `Erased stored data for user ${id}`); save(); return send(res, 200, { ok: true });
    }
    if (req.method === 'POST' && p === '/api/rules') {
      if (!can(u, NEED.rules)) return deny(res);
      const b = await body(req), base = DEFAULT_RULES[b.id];
      if (!base) return send(res, 400, { error: 'bad rule' });
      const next = { enabled: !!b.enabled };
      for (const [k, def] of Object.entries(base)) if (k !== 'enabled') { const v = (b.params || {})[k]; next[k] = typeof def === 'number' ? Math.min(Math.max(Math.floor(+v) || 1, 1), 100000) : String(v ?? def).slice(0, 120); }
      D.rules[b.id] = next; audit(u.user, `Automation "${b.id}" saved (${next.enabled ? 'on' : 'off'})`); save();
      return send(res, 200, { ok: true });
    }
    if (req.method === 'POST' && p === '/api/settings') {
      if (!can(u, NEED.settings)) return deny(res);
      const b = await body(req); D.settings.quotaMinutes = Math.min(Math.max(Math.floor(+b.quotaMinutes) || 1, 1), 10080);
      audit(u.user, `Weekly quota set to ${D.settings.quotaMinutes} minutes`); save();
      return send(res, 200, { ok: true });
    }
    if (req.method === 'POST' && p === '/api/team') {
      const b = await body(req);
      if (b.op === 'leave') { if (u.isOwner) return send(res, 400, { error: 'The owner cannot leave. Delete the workspace instead.' }); delete D.members[uid]; audit(u.user, 'Left the workspace'); res.setHeader('Set-Cookie', clearCookie('ws')); return send(res, 200, { ok: true }); }
      if (!can(u, 3)) return deny(res);
      const target = String(b.uid || '');
      if (b.op === 'invite') {
        if (!RANK[b.role]) return send(res, 400, { error: 'Pick a role' });
        if (Object.keys(D.invites).length >= 20) return send(res, 400, { error: 'Too many open invites. Revoke some first.' });
        if (Object.keys(D.members).length >= 25) return send(res, 400, { error: 'This workspace is full (25 people).' });
        const code = CTX.wid + crypto.randomBytes(8).toString('hex'); D.invites[code] = { role: b.role, exp: Date.now() + 7 * 864e5, by: u.user }; audit(u.user, `Created a ${b.role} invite`);
        return send(res, 200, { ok: true, code, link: `${site(req)}/#/join/${code}` });
      }
      if (b.op === 'revoke') { delete D.invites[String(b.code || '')]; audit(u.user, 'Revoked an invite'); }
      else if (!D.members[target]) return send(res, 404, { error: 'No such member' });
      else if (target === D.meta.owner) return send(res, 400, { error: 'The owner cannot be changed' });
      else if (b.op === 'remove') { audit(u.user, `Removed ${D.members[target].name}`); delete D.members[target]; }
      else if (b.op === 'setrole' && RANK[b.role]) { D.members[target].role = b.role; audit(u.user, `Set ${D.members[target].name} to ${b.role}`); }
      else return send(res, 400, { error: 'bad request' });
      return send(res, 200, { ok: true });
    }
    if (req.method === 'POST' && p === '/api/workspace') {
      const b = await body(req);
      if (b.op === 'rename') { if (!can(u, 3)) return deny(res); const nm = cleanName(b.name); if (nm.length < 2) return send(res, 400, { error: 'Name is too short' }); D.meta.name = nm; audit(u.user, 'Renamed the workspace'); return send(res, 200, { ok: true }); }
      if (b.op === 'rotatekey') { if (!can(u, 3)) return deny(res); D.meta.rot = (D.meta.rot || 0) + 1; audit(u.user, 'Made a new game key'); return send(res, 200, { ok: true }); }
      if (b.op === 'delete') {
        if (!u.isOwner) return send(res, 403, { error: 'Only the owner can delete the workspace' });
        if (cleanName(b.confirm) !== D.meta.name) return send(res, 400, { error: 'Type the workspace name exactly to confirm' });
        await need('user', 'glob'); const wid = CTX.wid; G.workspaces = Math.max(0, G.workspaces - 1); U.workspaces = U.workspaces.filter(w => w !== wid);
        res.setHeader('Set-Cookie', clearCookie('ws'));
        res.after.push(() => fetch(`${SB_URL}/rest/v1/panel_kv?key=like.w${wid}:*`, { method: 'DELETE', headers: { ...sbHeaders(), Prefer: 'return=minimal' } })); // wipe every row of this workspace once the counters are saved
        return send(res, 200, { ok: true });
      }
      return send(res, 400, { error: 'bad request' });
    }
    if (req.method === 'POST' && p === '/api/action') {
      const b = await body(req), reason = String(b.reason || 'No reason given').slice(0, 200);
      if (!ACTIONS.includes(b.action)) return send(res, 400, { error: 'bad action' });
      if (!can(u, b.action === 'ban' && !(+b.minutes > 0) ? 3 : NEED[b.action])) return deny(res);
      if (b.action === 'announce') { cmd({ type: 'announce', text: reason }); feed('Announcement: ' + reason, u.user); save(); return send(res, 200, { ok: true }); }
      if (!Number.isInteger(b.userId) || b.userId < 1) return send(res, 400, { error: 'bad userId' });
      const nm = String(b.name || b.userId).slice(0, 40);
      if (b.action === 'points') {
        const amt = Math.max(-100000, Math.min(100000, Math.trunc(+b.amount) || 0));
        if (!amt) return send(res, 400, { error: 'Enter a points amount' });
        addPoints(b.userId, nm, amt, reason, u.user); save(); return send(res, 200, { ok: true });
      }
      act({ action: b.action, userId: b.userId, name: nm, reason, minutes: Math.min(Math.max(+b.minutes || 0, 0), 525600), by: u.user });
      return send(res, 200, { ok: true });
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
  return new Promise(r => { let d = ''; req.on('data', c => { d += c; if (d.length > 1e5) req.destroy(); }); req.on('end', () => { try { r(JSON.parse(d || '{}')); } catch { r({}); } }); });
}
async function handle(req, res) {
  const url = new URL(req.url, 'http://x'), p = url.pathname;
  if (CONFIG_ERROR.length) { res.statusCode = 500; res.setHeader('Content-Type', 'text/plain'); return res.end('Sentinel is not configured. Missing Vercel environment variables: ' + CONFIG_ERROR.join(', ')); }
  req._body = await readBody(req);
  for (let attempt = 0; attempt < 6; attempt++) {
    resetState();
    const out = makeOut();
    await route(req, out, url, p);
    if (out.failed || await commit()) { for (const f of out.after) await f().catch(() => {}); return flush(out, res); }
    await new Promise(r => setTimeout(r, 25 + Math.random() * 100)); // lost a race with another request: run again on fresh data
  }
  res.statusCode = 503; res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify({ error: 'Busy, please try again' }));
}
let chain = Promise.resolve(); // one request at a time per instance (state is shared in-process while a request runs)
const serial = fn => { const run = chain.then(fn); chain = run.catch(() => {}); return run; };
module.exports = (req, res) => serial(() => handle(req, res)).catch(e => { console.error(e); try { res.statusCode = 500; res.setHeader('Content-Type', 'text/plain'); res.end('Error: ' + e.message); } catch {} });
