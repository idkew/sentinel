// Moderation panel for Vercel + Supabase.
// Vercel runs this file as ONE serverless function. Functions forget everything between requests,
// so all state lives in Supabase (table panel_kv). Each request loads the rows it needs, runs, and
// saves only what changed in a single all-or-nothing transaction (panel_commit). If two requests
// collide, the loser is re-run automatically.
const fs = require('fs'), path = require('path'), crypto = require('crypto');
const env = process.env, rnd = n => crypto.randomBytes(n).toString('base64url');

const cfg = { service: env.PANEL_SERVICE || 'Sentinel', company: env.PANEL_COMPANY || '', email: env.PANEL_EMAIL || '', country: env.PANEL_COUNTRY || '',
  legalReviewed: /^(1|true|yes)$/i.test(env.LEGAL_REVIEWED || ''), callRetentionDays: +env.CALL_RETENTION_DAYS || 90, updated: env.PANEL_LEGAL_UPDATED || '' };
const ENVNAME = { service: 'PANEL_SERVICE', company: 'PANEL_COMPANY', email: 'PANEL_EMAIL', country: 'PANEL_COUNTRY', callRetentionDays: 'CALL_RETENTION_DAYS' };
const GAME_KEY = env.GAME_KEY || '', PASSWORD = env.ADMIN_PASSWORD || '';
const SB_URL = (env.SUPABASE_URL || '').replace(/\/$/, ''), SB_KEY = env.SUPABASE_SERVICE_KEY || '';
const CONFIG_ERROR = [!SB_URL && 'SUPABASE_URL', !SB_KEY && 'SUPABASE_SERVICE_KEY', PASSWORD.length < 8 && 'ADMIN_PASSWORD (at least 8 characters)', GAME_KEY.length < 16 && 'GAME_KEY (at least 16 characters)'].filter(Boolean);
const LIVE_MS = 35000, CHAT_MS = 24 * 36e5; // a game server counts as online for 35 s after its last check-in; chat is kept at most 24 h

const freshD = () => ({ bans: {}, mutes: {}, logs: {}, feed: [], stats: { joins: 0, peak: 0, kicks: 0 }, calls: [], callSeq: 0, session: null, sessions: [],
  flagWords: ['scam', 'hack', 'exploit', 'free robux'], play: {}, audit: [], staff: {}, rules: {}, settings: { quotaMinutes: 60 } });
const D = freshD(), R = { servers: {}, cmds: [], history: [], chat: [], flagCount: {}, nextId: 1 };
let RL = {}; // failed-login counters per IP
const save = () => {}; // changes are written once, at the end of each request (see handle)
const pruneCalls = () => { const cut = Date.now() - cfg.callRetentionDays * 864e5; D.calls = D.calls.filter(c => c.t > cut); }; // ModCalls (and their chat snapshots) expire
const liveServers = () => Object.values(R.servers).filter(s => Date.now() - s.last < LIVE_MS).length;

// ---- storage: rows of panel_kv, grouped by how often they change ----
const ROWS = {
  core: { get: () => ({ bans: D.bans, mutes: D.mutes, feed: D.feed, stats: D.stats, callSeq: D.callSeq, session: D.session, sessions: D.sessions, flagWords: D.flagWords, audit: D.audit, staff: D.staff, rules: D.rules, settings: D.settings }), set: v => Object.assign(D, v) },
  logs: { get: () => D.logs, set: v => { D.logs = v; } },
  calls: { get: () => D.calls, set: v => { D.calls = v; } },
  play: { get: () => D.play, set: v => { D.play = v; } },
  live: { get: () => ({ servers: R.servers, history: R.history }), set: v => { R.servers = v.servers || {}; R.history = v.history || []; } },
  cmds: { get: () => ({ cmds: R.cmds, nextId: R.nextId }), set: v => { R.cmds = v.cmds || []; R.nextId = v.nextId || 1; } },
  chat: { get: () => ({ chat: R.chat, flagCount: R.flagCount }), set: v => { R.chat = v.chat || []; R.flagCount = v.flagCount || {}; } },
  rl: { get: () => RL, set: v => { RL = v; } },
};
const NEEDS = { '/api/state': ['play', 'live', 'calls', 'chat'], '/api/lookup': ['play', 'live', 'logs'], '/api/action': ['logs', 'play', 'cmds'], '/api/session': ['play', 'logs', 'cmds', 'live'],
  '/api/call': ['calls', 'cmds'], '/api/export': ['logs', 'play', 'calls', 'chat'], '/api/erase': ['logs', 'play', 'calls', 'chat'] };
const loaded = {};
const sbHeaders = () => ({ apikey: SB_KEY, ...(SB_KEY.startsWith('eyJ') ? { Authorization: 'Bearer ' + SB_KEY } : {}), 'Content-Type': 'application/json' });
function resetState() {
  for (const k of Object.keys(D)) delete D[k]; Object.assign(D, freshD());
  Object.assign(R, { servers: {}, cmds: [], history: [], chat: [], flagCount: {}, nextId: 1 }); RL = {};
  for (const k of Object.keys(loaded)) delete loaded[k];
}
async function need(...keys) {
  const want = [...new Set(keys)].filter(k => !(k in loaded)); if (!want.length) return;
  const r = await fetch(`${SB_URL}/rest/v1/panel_kv?select=key,value,version&key=in.(${want.join(',')})`, { headers: sbHeaders() });
  if (!r.ok) throw new Error(`Supabase read failed: HTTP ${r.status} ${(await r.text()).slice(0, 200)}`);
  const rows = Object.fromEntries((await r.json()).map(x => [x.key, x]));
  for (const k of want) {
    const row = rows[k]; if (row) ROWS[k].set(row.value);
    loaded[k] = { ver: row ? row.version : 0, snap: JSON.stringify(ROWS[k].get()) };
    if (k === 'calls') pruneCalls();
    if (k === 'chat') R.chat = R.chat.filter(m => Date.now() - m.t < CHAT_MS);
  }
}
async function commit() { // true = saved (or nothing changed), false = someone else changed a row first
  const changes = [];
  for (const [k, l] of Object.entries(loaded)) { const v = ROWS[k].get(); if (JSON.stringify(v) !== l.snap) changes.push({ key: k, expect: l.ver, value: v }); }
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

// ---- auth + http ----
const SECRET = crypto.createHash('sha256').update('session:' + PASSWORD + ':' + GAME_KEY).digest();
const sign = t => crypto.createHmac('sha256', SECRET).update(t).digest('base64url');
const mkToken = user => { const b = Buffer.from(JSON.stringify({ u: user, e: Date.now() + 7 * 864e5 })).toString('base64url'); return b + '.' + sign(b); };
const hash = s => crypto.createHash('sha256').update(String(s)).digest();
const same = (a, b) => crypto.timingSafeEqual(hash(a), hash(b));
const sid = req => (req.headers.cookie || '').split(';').map(s => s.trim()).find(s => s.startsWith('sid='))?.slice(4);
const me = req => { // signed cookie, nothing stored server-side; the role is looked up fresh on every request
  const t = sid(req); if (!t) return null; const [b, g] = t.split('.'); if (!g || !same(g, sign(b))) return null;
  let d; try { d = JSON.parse(Buffer.from(b, 'base64url').toString()); } catch { return null; } if (!d || d.e < Date.now()) return null;
  if (d.u === 'owner') return { user: 'owner', role: 'admin' }; const st = D.staff[d.u]; return st ? { user: d.u, role: st.role } : null; };
const send = (res, code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); };
const body = async req => req._body || {};
const LEGAL = { privacy: 'Privacy Policy', terms: 'Terms of Service', cookies: 'Cookie Policy', 'acceptable-use': 'Acceptable Use Policy', 'player-notice': 'Player Notice' };
const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const origin = req => (req.headers['x-forwarded-proto'] === 'https' ? 'https' : 'http') + '://' + req.headers.host;
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

async function route(req, res, url, p) {
  try {
    if (req.method === 'GET' && p === '/') { res.writeHead(200, { 'Content-Type': 'text/html' }); return res.end(fs.readFileSync(path.join(__dirname, '..', 'index.html'))); }
    if (req.method === 'POST' && p === '/game/sync') {
      const b = await body(req); if (!(b.key && same(b.key, GAME_KEY))) return send(res, 403, { error: 'bad key' });
      const ev = Array.isArray(b.events) ? b.events : [], chatty = ev.some(e => e.type === 'chat' || e.type === 'modcall');
      await need('core', 'play', 'live', 'cmds', ...(chatty ? ['chat'] : []), ...(ev.some(e => e.type === 'modcall') ? ['calls'] : []));
      if (chatty && rule('flaggedmute').enabled) await need('logs');
      return send(res, 200, sync(b));
    }
    if (req.method === 'POST' && p === '/login') {
      await need('core', 'rl'); const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
      for (const k of Object.keys(RL)) if (Date.now() - (RL[k].t || 0) > 36e5) delete RL[k];
      const f = RL[ip] || { n: 0, until: 0 };
      if (f.until > Date.now()) return send(res, 429, { error: 'Too many attempts. Wait 30 seconds.' });
      const b = await body(req);
      const uname = String(b.username || 'owner').toLowerCase().trim(), st = D.staff[uname];
      const good = uname === 'owner' ? same(b.password || '', PASSWORD) : st && crypto.timingSafeEqual(Buffer.from(pw(b.password || '', st.salt), 'hex'), Buffer.from(st.hash, 'hex'));
      if (good) {
        delete RL[ip]; const t = mkToken(uname);
        res.setHeader('Set-Cookie', `sid=${t}; HttpOnly; SameSite=Strict; Path=/; Max-Age=604800${req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : ''}`);
        return send(res, 200, { ok: true });
      }
      if (++f.n >= 5) { f.until = Date.now() + 30000; f.n = 0; } f.t = Date.now(); RL[ip] = f;
      return send(res, 401, { error: 'Wrong password' });
    }
    if (req.method === 'POST' && p === '/logout') { res.setHeader('Set-Cookie', 'sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'); return send(res, 200, { ok: true }); }
    if (req.method === 'GET' && p.startsWith('/legal/')) { const n = p.slice(7); if (!LEGAL[n]) return send(res, 404, { error: 'not found' }); res.writeHead(200, { 'Content-Type': 'text/html' }); return res.end(legalPage(n)); }
    if (!p.startsWith('/api/')) return send(res, 404, { error: 'not found' });
    await need('core', ...(NEEDS[p] || []));
    const u = me(req);
    if (!u) return send(res, 401, { error: 'login required' });

    if (p === '/api/state') {
      const players = allPlayers(), bans = Object.values(D.bans).filter(live), mutes = Object.values(D.mutes).filter(live);
      return send(res, 200, { connected: liveServers() > 0, servers: liveServers(), players, bans, mutes, feed: D.feed.slice(0, 15), me: { user: u.user, role: u.role }, settings: D.settings, rules: Object.fromEntries(Object.keys(DEFAULT_RULES).map(k => [k, rule(k)])),
        board: Object.entries(D.play).map(([id, x]) => ({ userId: +id, name: x.name, week: x.weekStart === weekStart(Date.now()) ? Math.round(x.week) : 0, total: Math.round(x.total), points: x.points }))
          .sort((a, b) => b.week - a.week || b.points - a.points).slice(0, 50),
        staff: can(u, 3) ? Object.entries(D.staff).map(([username, s]) => ({ username, role: s.role })) : [], audit: can(u, 2) ? D.audit.slice(0, 40) : [],
        history: R.history, openCalls: D.calls.filter(c => c.status !== 'resolved').length, calls: D.calls.slice(0, 30),
        session: D.session && { ...D.session, attendees: Object.entries(D.session.attendees).map(([userId, name]) => ({ userId: +userId, name })) }, sessions: D.sessions.slice(0, 10),
        chat: R.chat.slice(-80).reverse(), flagWords: D.flagWords,
        stats: { ...D.stats, activeBans: bans.length, activeMutes: mutes.length } });
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
      if (b.op === 'claim' && c.status === 'open') { c.status = 'claimed'; c.by = 'Moderator'; cmd({ type: 'message', kind: 'info', userId: c.from.userId, text: `A moderator is handling your ModCall #${c.id}.` }); }
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
    if (p === '/api/setup') { if (!can(u, 3)) return deny(res); return send(res, 200, { gameKey: GAME_KEY, origin: origin(req), legal: { company: !!cfg.company, email: !!cfg.email, country: !!cfg.country, reviewed: !!cfg.legalReviewed } }); }
    if (p === '/api/bridge') { // the Roblox script with this panel's address and game key already filled in
      if (!can(u, 3)) return deny(res);
      let lua; try { lua = fs.readFileSync(path.join(__dirname, '..', 'SentinelBridge.lua'), 'utf8'); } catch { return send(res, 500, { error: 'SentinelBridge.lua must be in the same folder as server.js' }); }
      lua = lua.replace(/^local URL = ".*"$/m, () => 'local URL = ' + JSON.stringify(origin(req))).replace(/^local KEY = ".*"$/m, () => 'local KEY = ' + JSON.stringify(GAME_KEY)).replace(/^local INTERVAL = \d+/m, 'local INTERVAL = 10');
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
    if (req.method === 'POST' && p === '/api/staff') {
      if (!can(u, NEED.staff)) return deny(res);
      const b = await body(req), name = String(b.username || '').toLowerCase().trim();
      if (b.op === 'add') {
        if (!/^[a-z0-9_]{3,20}$/.test(name) || name === 'owner' || D.staff[name]) return send(res, 400, { error: 'Pick another username (3-20 letters, numbers or _)' });
        if (String(b.password || '').length < 8) return send(res, 400, { error: 'Password must be at least 8 characters' });
        if (!RANK[b.role]) return send(res, 400, { error: 'Pick a role' });
        const salt = rnd(12); D.staff[name] = { salt, hash: pw(b.password, salt), role: b.role }; audit(u.user, `Added staff ${name} as ${b.role}`);
      } else if (!D.staff[name]) return send(res, 404, { error: 'No such staff member' });
      else if (b.op === 'remove') { delete D.staff[name]; audit(u.user, `Removed staff ${name}`); }
      else if (b.op === 'setrole' && RANK[b.role]) { D.staff[name].role = b.role; audit(u.user, `Set ${name} to ${b.role}`); }
      save(); return send(res, 200, { ok: true });
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
const makeOut = () => { const o = { code: 200, headers: {}, body: '', failed: false, setHeader(k, v) { o.headers[k] = v; }, writeHead(c, h) { o.code = c; Object.assign(o.headers, h || {}); }, end(d) { o.body = d === undefined ? '' : d; } }; return o; };
const flush = (o, res) => { res.statusCode = o.code; for (const [k, v] of Object.entries(o.headers)) res.setHeader(k, v); res.end(o.body); };
async function readBody(req) {
  if (req.method === 'GET' || req.method === 'HEAD') return {};
  try { if (req.body !== undefined && req.body !== null) { if (Buffer.isBuffer(req.body)) return JSON.parse(req.body.toString() || '{}'); return typeof req.body === 'string' ? JSON.parse(req.body || '{}') : req.body; } } catch { return {}; }
  return new Promise(r => { let d = ''; req.on('data', c => { d += c; if (d.length > 1e5) req.destroy(); }); req.on('end', () => { try { r(JSON.parse(d || '{}')); } catch { r({}); } }); });
}
async function handle(req, res) {
  const url = new URL(req.url, 'http://x'), p = url.pathname;
  if (CONFIG_ERROR.length) { res.statusCode = 500; res.setHeader('Content-Type', 'text/plain'); return res.end('Panel is not configured. Missing Vercel environment variables: ' + CONFIG_ERROR.join(', ')); }
  req._body = await readBody(req);
  for (let attempt = 0; attempt < 6; attempt++) {
    resetState();
    const out = makeOut();
    await route(req, out, url, p);
    if (out.failed || await commit()) return flush(out, res);
    await new Promise(r => setTimeout(r, 25 + Math.random() * 100)); // lost a race with another request: run again on fresh data
  }
  res.statusCode = 503; res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify({ error: 'Busy, please try again' }));
}
let chain = Promise.resolve(); // one request at a time per instance (state is shared in-process while a request runs)
const serial = fn => { const run = chain.then(fn); chain = run.catch(() => {}); return run; };
module.exports = (req, res) => serial(() => handle(req, res)).catch(e => { console.error(e); try { res.statusCode = 500; res.setHeader('Content-Type', 'text/plain'); res.end('Error: ' + e.message); } catch {} });
