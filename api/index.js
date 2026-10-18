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
async function slimit(key, max, windowMs) { // a limit that holds across every Vercel server (kept in the database); seconds to wait, or 0
  const win = Math.floor(Date.now() / windowMs), exp = (win + 1) * windowMs, k = `rl:${Math.floor(exp / 60000)}:${crypto.createHash('sha256').update(key).digest('base64url').slice(0, 22)}`;
  for (let i = 0; i < 3; i++) {
    let rows; try { rows = await sbGet(`select=value,version&key=in.(${k})`); } catch { return 0; } // never lock people out because of a database hiccup
    const cur = rows[0], n = (cur && cur.value ? cur.value.n || 0 : 0) + 1;
    if (n > max) return Math.max(1, Math.ceil((exp - Date.now()) / 1000));
    try { const r = await sbf(`${SB_URL}/rest/v1/rpc/panel_commit`, { method: 'POST', headers: sbHeaders(), body: JSON.stringify({ changes: [{ key: k, expect: cur ? cur.version : 0, value: { n } }] }) }); if (r.ok && (await r.json()) === true) return 0; } catch { return 0; }
  }
  return 0;
}
const ALERTED = new Map();
async function opsAlert(title, detail) { // tell the site admin in Discord when something breaks (ALERT_WEBHOOK), at most once per 10 minutes per problem
  const url = env.OPS_TEST_URL || env.ALERT_WEBHOOK || ''; if (!env.OPS_TEST_URL && !/^https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d{5,30}\/[\w-]{20,120}$/.test(url)) return;
  const sig = title + String(detail).slice(0, 80), last = ALERTED.get(sig) || 0; if (Date.now() - last < 6e5) return; ALERTED.set(sig, Date.now());
  await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'Sentinel alerts', allowed_mentions: { parse: [] }, embeds: [{ title: String(title).slice(0, 200), description: String(detail).slice(0, 1500), color: 0xe5484d, timestamp: new Date().toISOString() }] }), signal: AbortSignal.timeout(2500) }).catch(() => {});
}
const ipOf = req => String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '?').split(',')[0].trim();

// ---- permissions: every rank gets a set of these. The workspace owner always has all of them ----
const PERMS = [
  ['mod.warn', 'Warn players', 'Moderation'], ['mod.kick', 'Kick players', 'Moderation'], ['mod.mute', 'Mute and unmute players', 'Moderation'],
  ['mod.ban', 'Suspend players (timed bans)', 'Moderation', 1], ['mod.permban', 'Ban players permanently', 'Moderation', 1], ['mod.unban', 'Unban players', 'Moderation', 1],
  ['logbook.note', 'Add private notes to players', 'Moderation'], ['logbook.revert', 'Revert logbook entries', 'Moderation', 1],
  ['reports.handle', 'Claim and resolve reports', 'Reports'], ['appeals.review', 'Review ban appeals', 'Reports'], ['chat.view', 'Read live chat', 'Reports'], ['chatlogs.view', 'Read and search chat logs', 'Reports', 1], ['training.use', 'Use the training page', 'Team'],
  ['announce', 'Announce to every server', 'Game'], ['sessions.host', 'Host sessions', 'Activity'], ['shifts.manage', 'Create shifts and see attendance', 'Activity'], ['points.manage', 'Give and remove points', 'Activity'],
  ['loa.review', 'Approve or deny leave requests', 'Team'], ['team.manage', 'Invite, remove and re-rank members below them', 'Team', 1], ['ranks.manage', 'Create and edit ranks below their own', 'Team', 1],
  ['rulebook.manage', 'Edit the rulebook', 'Settings'], ['automations.manage', 'Change automations, flagged words and quotas', 'Settings'], ['audit.view', 'See the audit log', 'Settings'],
  ['webhooks.manage', 'Manage Discord notifications', 'Settings', 1], ['privacy.manage', 'Export and erase player data', 'Settings', 1],
  ['forms.review', 'Review form responses and applications', 'Team'], ['forms.manage', 'Create and edit forms', 'Settings'],
  ['servers.manage', 'Close live servers', 'Game', 1], ['staff.review', 'See staff performance and give staff strikes', 'Team', 1],
];
const ALLP = PERMS.map(p => p[0]);
const defaultRanks = () => ({
  admin: { name: 'Administrator', color: '#635bff', pos: 30, perms: ALLP.slice(), quota: 0, limit: 0 },
  mod: { name: 'Moderator', color: '#0ea5e9', pos: 20, perms: ['mod.warn', 'mod.kick', 'mod.mute', 'mod.ban', 'mod.unban', 'logbook.note', 'reports.handle', 'chat.view', 'chatlogs.view', 'training.use', 'announce', 'sessions.host', 'points.manage'], quota: 120, limit: 30 },
  helper: { name: 'Trial Moderator', color: '#10b981', pos: 10, perms: ['mod.warn', 'mod.kick', 'logbook.note', 'reports.handle', 'chat.view', 'training.use', 'sessions.host'], quota: 60, limit: 15 },
});
const DEFAULT_WEBHOOK = () => ({ url: '', events: { approvals: true, forms: true, shifts: true, signals: true, reports: true, bans: true, kicks: false, warns: false, loa: true, sessions: false, appeals: true, watch: true, alerts: false, digest: false, health: false } }); // alerts, digest and health start off; only the owner turns them on
const OWNER_EVENTS = ['alerts', 'digest', 'health']; // webhook events only the owner can switch
const HOOK_RE = /^https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d{5,30}\/[\w-]{20,120}$/;

// ---- storage ----
const freshD = () => ({ meta: null, members: {}, invites: {}, ranks: {}, rulebook: [], loa: [], webhook: null, daily: {},
  bans: {}, mutes: {}, logs: {}, feed: [], stats: { joins: 0, peak: 0, kicks: 0 }, calls: [], callSeq: 0, session: null, sessions: [],
  flagWords: ['scam', 'hack', 'exploit', 'free robux'], play: {}, audit: [], rules: {}, settings: { quotaMinutes: 60 }, appeals: [], watch: {}, hist: {}, forms: [], formsNew: 0, shifts: [], signals: {}, kicks: [], cussWords: null, abuse: {}, notices: [], escal: [], onboard: { lists: {}, done: {}, skip: {} }, training: { cases: [], results: {} }, alertWords: [], alerts: [], discord: null, discordCodes: {}, pending: [], syncSeen: {}, strikes: [] });
const D = freshD(), R = { servers: {}, cmds: [], history: [], chat: [], flagCount: {}, am: {}, nextId: 1 };
let VT = { items: [] }; // the evidence vault: its own row, loaded only by the routes that need it
let CBO = {}, CBQ = [], OCQ = [], FB = [], FR = [], DG = {}, BOTQ = [], U = null, G = { workspaces: 0 }, HOOKS = []; // U = the signed-in person's account, G = global counters, HOOKS = Discord messages to send after saving
const CTX = { uid: null, wid: null, guild: null };
const setUid = u => { if (!/^[gr]_\d{1,32}$/.test(u)) throw new Error('bad user'); CTX.uid = u; };
const setWid = w => { if (!/^[a-f0-9]{12}$/.test(w)) throw new Error('bad workspace'); CTX.wid = w; };
const save = () => {};
// a report from a game server still running gets a link that joins that exact server (Roblox's start link with gameInstanceId)
const callOut = c => { const { jobId, placeId, ...rest } = c, up = !!(jobId && R.servers[jobId] && Date.now() - R.servers[jobId].last < 6e4 && !R.servers[jobId].closed); return jobId ? { ...rest, live: up, join: up ? `https://www.roblox.com/games/start?placeId=${placeId}&gameInstanceId=${encodeURIComponent(jobId)}` : '' } : rest; };
const callsOut = () => { // the newest 40, plus the first report of any group they belong to, with a suggested playbook for open ones
  const top = D.calls.slice(0, 40), ids = new Set(top.map(c => c.id));
  for (const c of top.slice()) if (c.grp && !ids.has(c.grp)) { const l = D.calls.find(x => x.id === c.grp); if (l) { top.push(l); ids.add(l.id); } }
  return top.map(c => ({ ...callOut(c), ...(c.status !== 'resolved' ? { pb: pbSuggest(c) } : {}) }));
};
const pruneCalls = () => { const cut = Date.now() - cfg.callRetentionDays * 864e5; D.calls = D.calls.filter(c => c.t > cut); };
const MUTE_SCRIPT = 6, MUTE_HIDE_SCRIPT = 9; // MUTE_HIDE_SCRIPT: the first script version that can let a muted player keep typing // the first script version that really stops muted players chatting
function unbanWarn() { // Roblox only lifts a ban from a running game server (or the Open Cloud key), and a banned player cannot join to start one
  if (D.meta && D.meta.oc) return null; if (Object.values(R.servers).some(s => Date.now() - s.last < LIVE_MS)) return null;
  return 'Lifted in Sentinel, but nobody is in your game, so Roblox keeps the ban until a game server runs. Ask someone else to join, add a Roblox API key in Settings, Game (best), or lift it in Creator Hub under Moderation.';
}
function muteWarn(hide = true) { // why a mute might not stop chat right now (checked at the moment a mute is made), or null
  const live = Object.values(R.servers).filter(s => Date.now() - s.last < LIVE_MS); if (!live.length) return null; // nobody in game: it applies when a server connects
  if (hide === false) { const o9 = live.find(s => s.sv < MUTE_HIDE_SCRIPT); if (o9) return `Muted, but your game script is out of date (version ${o9.sv}), so it will still take their chat box away instead of letting them type. Update the script in Settings, Game.`; }
  const old = live.find(s => s.sv < MUTE_SCRIPT); if (old) return `Muted, but your game script is out of date (version ${old.sv}), so it will not stop the player chatting. Update the script in Settings, Game.`;
  if (live.some(s => s.chat === 'legacy')) return 'Muted, but your game uses the old Roblox chat, which mutes cannot control. In Studio, set TextChatService, ChatVersion to TextChatService.';
  if (live.some(s => s.chat === 'nochannel')) return 'Muted, but the game has no RBXGeneral chat channel, so mutes cannot be applied. Check TextChatService has CreateDefaultTextChannels on.';
  const e = live.find(s => s.muteErr); if (e) return `Muted, but the game reported a problem applying it: ${e.muteErr}`;
  return null;
}
let SITE_NOW = ''; // this request's site address, so in-game messages can include the appeal link
function appealWait(id) { // why this player can't appeal right now, or ''
  if (D.appeals.some(x => x.uid === id && x.status === 'open')) return 'You already have an appeal waiting for review.';
  const recent = D.appeals.filter(x => x.uid === id && Date.now() - x.t < APPEAL_WINDOW).sort((a, b) => b.t - a.t); // anti-spam: 2 appeals per player every 5 days
  if (recent.length < APPEAL_MAX) return '';
  const wait = recent[APPEAL_MAX - 1].t + APPEAL_WINDOW - Date.now(), d = Math.ceil(wait / 864e5), h = Math.ceil(wait / 36e5); return `You have used both appeals for now. You can send another in ${d > 1 ? d + ' days' : h > 1 ? h + ' hours' : 'about an hour'}.`;
}
function appealMake(id, uname, text, via) { // a new ban appeal from the web page or the appeal game; returns [status, body]
  const ban = id && D.bans[id];
  if (!ban || !live(ban)) return [404, { error: 'We could not find an active ban for that username in this game.' }];
  const why = appealWait(id); if (why) return [why.startsWith('You already') ? 409 : 429, { error: why }];
  const aid = crypto.randomBytes(4).toString('hex'), tok = rnd(9), nm = ban.name || uname;
  abuseTick('pub'); D.appeals.unshift({ id: aid, tok, uid: id, name: nm, text, t: Date.now(), status: 'open', banReason: ban.reason, banBy: ban.by || null, entry: ban.entry || null, ...(via ? { via: 'hub', hub: via } : {}) }); D.appeals.length = Math.min(D.appeals.length, 200);
  feed(`Ban appeal from ${nm}${via ? ' (appeal game)' : ''}`);
  const fl = [['Banned for', ban.reason], ['Banned by', ban.by], ...(via ? [['Sent from', via]] : [])];
  if (!botPost({ embeds: [dEmbed(`Ban appeal: ${nm}`, text, fl, 0x0a7aff)], components: [{ type: 1, components: [dBtn('Accept and unban', `ap:${aid}:a`, 3), dBtn('Deny', `ap:${aid}:d`, 4)] }] })) notify('appeals', `Ban appeal: ${nm}`, text, fl.filter(x => x[0] !== 'Banned by'), 0x0a7aff);
  return [200, { ok: true, aid, tok }];
}
function banText(x, plain) { // what the banned player reads: Roblox's ban screen (about 400 characters) or the kick message. Roblox runs the ban screen text through its filter and shows ##### for anything it dislikes, links included, so that one (plain) carries no link
  const len = x.expires ? `This suspension ends ${new Date(x.expires).toUTCString().slice(0, 16)} (UTC).` : 'This ban does not expire.';
  const ap = !plain && D.meta && D.settings.appeals !== false && SITE_NOW ? ` Appeal at ${SITE_NOW}/appeal/${D.meta.id}` : '';
  const h = hubOn() ? hubMain() : null, hb = h ? (plain ? ` Appeal in the "${h.name}" game on Roblox.` : ` Or appeal in game: ${hubLink(h)}`) : ''; // the ban screen can't show links, so it names the game
  return `You are banned from ${D.meta ? D.meta.name : 'this game'}. Reason: ${String(x.reason || 'No reason given').slice(0, 160)}. ${len}${ap}${hb}`.slice(0, 395);
}
const liveServers = () => Object.values(R.servers).filter(s => Date.now() - s.last < LIVE_MS).length;
const CORE_KEYS = ['meta', 'members', 'invites', 'ranks', 'rulebook', 'loa', 'webhook', 'daily', 'bans', 'mutes', 'feed', 'kicks', 'cussWords', 'abuse', 'notices', 'escal', 'onboard', 'training', 'alertWords', 'alerts', 'stats', 'callSeq', 'session', 'sessions', 'flagWords', 'audit', 'rules', 'settings', 'appeals', 'watch', 'forms', 'formsNew', 'shifts', 'signals', 'discord', 'discordCodes', 'pending', 'syncSeen', 'strikes'];
const ROWS = {
  core: { get: () => Object.fromEntries(CORE_KEYS.map(k => [k, D[k]])), set: v => Object.assign(D, v) },
  logs: { get: () => D.logs, set: v => { D.logs = v; } },
  calls: { get: () => D.calls, set: v => { D.calls = v; } },
  play: { get: () => D.play, set: v => { D.play = v; } },
  live: { get: () => ({ servers: R.servers, history: R.history }), set: v => { R.servers = v.servers || {}; R.history = v.history || []; } },
  cmds: { get: () => ({ cmds: R.cmds, nextId: R.nextId }), set: v => { R.cmds = v.cmds || []; R.nextId = v.nextId || 1; } },
  vault: { get: () => VT, set: v => { VT = v && Array.isArray(v.items) ? v : { items: [] }; } }, // evidence staff keep: links, notes and copied chat boxes
  cbo: { get: () => CBO, set: v => { CBO = v && typeof v === 'object' && !Array.isArray(v) ? v : {}; } }, // chat log boxes still filling, per game server
  chat: { get: () => ({ chat: R.chat, flagCount: R.flagCount, am: R.am }), set: v => { R.chat = v.chat || []; R.flagCount = v.flagCount || {}; R.am = v.am || {}; } },
  user: { get: () => U, set: v => { U = v; } },
  ...Object.fromEntries([...Array(16).keys()].map(i => ['h' + i, { get: () => (D.hist[i] ||= {}), set: v => { D.hist[i] = v || {}; } }])), // per-player playtime history, split in 16 rows so each save stays small
  glob: { get: () => G, set: v => { G = v; } },
  fb: { get: () => FB, set: v => { FB = Array.isArray(v) ? v : []; } },
  dguild: { get: () => DG, set: v => { DG = v && typeof v === 'object' ? v : {}; } }, // which workspace a Discord server is linked to
  forms: { get: () => ({ responses: FR }), set: v => { FR = (v && Array.isArray(v.responses)) ? v.responses : []; } }, // form responses (applications, reports), newest first // feedback and questions from every workspace, answered from the admin page
};
const phys = k => k === 'dguild' ? (/^\d{5,25}$/.test(CTX.guild || '') ? 'dg:' + CTX.guild : (() => { throw new Error('bad guild'); })()) : k === 'user' ? 'u:' + CTX.uid : k === 'glob' ? 'g:stats' : k === 'fb' ? 'g:feedback' : `w${CTX.wid}:${k}`;
const NEEDS = { '/api/state': ['play', 'live', 'calls', 'chat'], '/api/lookup': ['play', 'live', 'logs', 'chat', 'calls'], '/api/player': ['play', 'live', 'logs', 'chat', 'calls'],
  '/api/action': ['logs', 'play', 'cmds', 'live', 'chat'], '/api/escalation': ['logs'], '/api/analytics': ['logs'], '/api/appeals': ['logs', 'cmds', 'play'], '/api/approvals': ['logs', 'cmds', 'play', 'live'], '/api/backups': ['logs', 'play', 'calls', 'forms'], '/api/feedback': ['fb'], '/api/backup/download': ['logs', 'play', 'calls', 'forms'], '/api/backup/import': ['logs', 'play', 'calls', 'forms'], '/api/forms': ['forms'], '/api/logbook': ['logs', 'play'], '/api/entry': ['logs', 'play', 'cmds'],
  '/api/session': ['play', 'logs', 'cmds', 'live'], '/api/call': ['calls', 'cmds', 'live', 'cbo'], '/api/chatlogs': ['cbo', 'live'], '/api/escalate': ['calls', 'logs'], '/api/training': ['logs', 'play'], '/api/chatlogs/box': ['cbo', 'live'], '/api/export': ['logs', 'play', 'calls', 'chat', 'vault'], '/api/erase': ['logs', 'play', 'calls', 'chat', 'cbo', 'vault'], '/api/vault': ['vault', 'cbo', 'calls', 'logs'], '/api/vault/item': ['vault'], '/api/reputation': ['logs', 'play', 'calls', 'vault'], '/api/server': ['live', 'cmds'], '/api/staffperf': ['logs', 'play', 'calls'] };
const loaded = {};
const sbf = (u, o) => fetch(u, { ...o, signal: AbortSignal.timeout(8000) }); // never hang forever on the database
const sbHeaders = () => ({ apikey: SB_KEY, ...(SB_KEY.startsWith('eyJ') ? { Authorization: 'Bearer ' + SB_KEY } : {}), 'Content-Type': 'application/json' });
function resetState() {
  for (const k of Object.keys(D)) delete D[k]; Object.assign(D, freshD());
  Object.assign(R, { servers: {}, cmds: [], history: [], chat: [], flagCount: {}, nextId: 1 }); CTX.ro = false; EVQ = []; U = null; FB = []; FR = []; DG = {}; BOTQ = []; CTX.guild = null; OCQ = []; CBO = {}; CBQ = []; VT = { items: [] }; G = { workspaces: 0 }; HOOKS = []; CTX.uid = CTX.wid = null;
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
  await Promise.all(HOOKS.splice(0).map(h => fetch(h.url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(h.body), signal: AbortSignal.timeout(3000) }).then(r => { if (!r.ok) logEvent('webhook_fail', 'Discord webhook said ' + r.status); }, e => logEvent('webhook_fail', 'Discord webhook could not be reached: ' + String((e && e.message) || e).slice(0, 80)))));
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
  D.discordCodes ||= {}; D.pending ||= []; D.syncSeen ||= {}; if (D.webhook && D.webhook.events && !('approvals' in D.webhook.events)) D.webhook.events.approvals = true;
  D.signals ||= {}; if (!D.meta.v8) { D.meta.v8 = 1; D.kicks ||= []; } D.kicks ||= []; if (D.webhook && D.webhook.events && !('signals' in D.webhook.events)) D.webhook.events.signals = true;
  D.shifts ||= []; if (D.webhook && D.webhook.events && !('shifts' in D.webhook.events)) D.webhook.events.shifts = true;
  if (!D.meta.v6) { D.meta.v6 = 1; for (const r of Object.values(D.ranks)) if (r.perms.includes('team.manage') && !r.perms.includes('shifts.manage')) r.perms.push('shifts.manage'); }
  D.forms ||= []; D.formsNew ||= 0; if (D.webhook && D.webhook.events && !('forms' in D.webhook.events)) D.webhook.events.forms = true;
  if (!D.meta.v5) { D.meta.v5 = 1; for (const r of Object.values(D.ranks)) if (r.perms.includes('team.manage')) for (const x of ['forms.manage', 'forms.review']) if (!r.perms.includes(x)) r.perms.push(x); }
  D.strikes ||= [];
  D.escal ||= []; D.onboard ||= { lists: {}, done: {}, skip: {} }; D.training ||= { cases: [], results: {} };
  D.alertWords ||= []; D.alerts ||= [];
  if (!D.meta.v16) { D.meta.v16 = 1; if (typeof D.settings.warnAck !== 'boolean') D.settings.warnAck = false; } // warning acknowledgement starts off
  if (!D.meta.v15) { D.meta.v15 = 1; if (!VAULT_DAYS.includes(D.settings.vaultDays)) D.settings.vaultDays = 180; } // evidence vault items are kept 180 days unless the owner picks another length
  if (!D.meta.v14) { D.meta.v14 = 1; if (!MERGE_MIN.includes(D.settings.mergeMin)) D.settings.mergeMin = 10; } // reports about the same player within 10 minutes are grouped
  if (!D.meta.v13) { D.meta.v13 = 1; if (D.webhook && D.webhook.events) for (const k of ['digest', 'health']) if (!(k in D.webhook.events)) D.webhook.events[k] = false; } // the daily summary and game health reach Discord only once the owner turns them on
  if (!D.meta.v12) { D.meta.v12 = 1; if (D.webhook && D.webhook.events && !('alerts' in D.webhook.events)) D.webhook.events.alerts = false; } // chat alerts reach Discord only once the owner turns them on
  if (!D.meta.v11) { D.meta.v11 = 1; for (const id of Object.keys(D.members)) if (id !== D.meta.owner) D.onboard.skip[id] = true; for (const k of ['helper', 'mod']) { const r = D.ranks[k]; if (r && !r.perms.includes('training.use')) r.perms.push('training.use'); } } // staff from before checklists skip them; trainees get the training page
  if (!D.meta.v10) { D.meta.v10 = 1; D.abuse ||= {}; D.notices ||= []; } // abuse counters and notices from the Sentinel team
  D.abuse ||= {}; D.notices ||= [];
  if (!D.meta.v9) { D.meta.v9 = 1; const elev = new Set(PERMS.filter(p => p[3]).map(p => p[0])); for (const r of Object.values(D.ranks)) if (r.perms.includes('reports.handle') && r.perms.some(x => elev.has(x)) && !r.perms.includes('chatlogs.view')) r.perms.push('chatlogs.view'); } // chat logs: Moderator and up
  if (!D.meta.v7) { D.meta.v7 = 1; for (const r of Object.values(D.ranks)) if (r.perms.includes('team.manage')) for (const x of ['staff.review', 'servers.manage']) if (!r.perms.includes(x)) r.perms.push(x); }
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
// Where one logbook entry stands right now, so the website can say so plainly.
// active: still in force. fulfilled: a timed mute or suspension that ran its course, or a kick that was carried out.
// lifted: ended early by an unmute or unban. reverted: undone by staff. none: notes, points and lifts have nothing to track.
const ACK_MS = 120000; // after 2 minutes without "I understand" a warning shows as not acknowledged, and nothing else happens
function entryState(e, id) {
  if (!e) return {};
  if (e.status === 'reverted') return { state: 'reverted' };
  if (e.type === 'Kicked') return { state: 'fulfilled', ends: e.time };
  if (e.type === 'Warned') return { state: 'active', ...(e.ack ? { ack: 'yes', ackAt: e.ack } : e.ackWant ? { ack: Date.now() - e.ackWant < ACK_MS ? 'waiting' : 'no' } : {}) };
  if (!['Muted', 'Suspended', 'Banned'].includes(e.type)) return { state: 'none' };
  const now = Date.now(), ends = e.minutes > 0 ? e.time + e.minutes * 60000 : null, lift = e.type === 'Muted' ? 'Unmuted' : 'Unbanned';
  const lifted = (D.logs[id] || []).find(x => x.type === lift && x.status !== 'reverted' && x.time > e.time && (!ends || x.time < ends));
  if (lifted) return { state: 'lifted', ends: lifted.time };
  if (ends && ends <= now) return { state: 'fulfilled', ends };
  const cur = e.type === 'Muted' ? D.mutes[id] : D.bans[id];
  return cur && cur.entry === e.id ? { state: 'active', ends } : { state: 'lifted' };
}
const feed = (text, by) => { D.feed.unshift({ t: Date.now(), text }); D.feed.length = Math.min(D.feed.length, 50); if (by) audit(by, text); };
const audit = (user, text) => { D.audit.unshift({ t: Date.now(), user, text }); D.audit.length = Math.min(D.audit.length, 300); };
const DEFAULT_RULES = {
  autosuspend: { enabled: true, warns: 3, minutes: 5 }, sessionpoints: { enabled: true, points: 5 },
  flaggedmute: { enabled: false, count: 3, minutes: 5 }, welcome: { enabled: false, text: 'Welcome! Moderators are keeping this game friendly.' },
  spam: { enabled: false, messages: 6, seconds: 8, action: 'mute', minutes: 10 }, repeat: { enabled: false, times: 3, action: 'warn', minutes: 10 },
  links: { enabled: false, action: 'warn', minutes: 10 }, caps: { enabled: false, percent: 80, action: 'warn', minutes: 10 },
  rapidjoin: { enabled: false, joins: 5, seconds: 60, action: 'kick', minutes: 10 },
};
const AM_RULES = ['spam', 'repeat', 'links', 'caps']; // rules that read chat; rapidjoin reads joins
const DEFAULT_PRESETS = [
  { id: 'spam', name: 'Spamming', action: 'mute', minutes: 30, reason: 'Spamming chat' },
  { id: 'lang', name: 'Bad language', action: 'warn', minutes: 0, reason: 'Inappropriate language' },
  { id: 'harass', name: 'Harassment', action: 'ban', minutes: 1440, reason: 'Harassing other players' },
  { id: 'exploit', name: 'Exploiting', action: 'ban', minutes: 0, reason: 'Using exploits or cheats' },
];
const presets = () => Array.isArray(D.settings.presets) ? D.settings.presets : DEFAULT_PRESETS;
// ---- playbooks: written steps for common cases. They only fill in the Moderate window; staff still decide and apply
const DEFAULT_PLAYBOOKS = [
  { id: 'scam', name: 'Scamming', when: 'Someone offers free Robux, trades or a link to get items or account details.', steps: ['Read the chat and look for links or Discord invites.', 'Check whether other players reported the same person.', 'Ban if they posted a scam link. Warn for a first offer without a link.', 'Add the link or a screenshot as evidence.'], preset: '', match: { flags: ['link', 'invite'], words: ['free robux', 'robux', 'giveaway', 'scam', 'trade'] } },
  { id: 'exploit', name: 'Exploiting', when: 'Flying, speed, teleporting or other cheats.', steps: ['Join their server or ask the reporter for a clip.', 'Check their logbook and any alt-account hint.', 'Ban with the Exploiting preset.', 'Add the clip as evidence.'], preset: 'exploit', match: { flags: [], words: ['exploit', 'hack', 'cheat', 'fly', 'flying', 'speed', 'teleport', 'aimbot'] } },
  { id: 'harass', name: 'Harassment', when: 'Insults, threats or slurs aimed at another player.', steps: ['Read the chat around the report.', 'Mute first if it is still going on.', 'Suspend for repeat or serious cases.', 'Resolve the report with a short note.'], preset: 'harass', match: { flags: ['strong'], words: ['harass', 'bully', 'insult', 'threat', 'racist'] } },
  { id: 'spam', name: 'Spam', when: 'Flooding chat with repeated or shouted messages.', steps: ['Open the chat box and check for repeats.', 'Mute with the Spamming preset.', 'Send it up if it continues after the mute.'], preset: 'spam', match: { flags: ['spam', 'repeat', 'caps'], words: ['spam', 'flood'] } },
];
const playbooks = () => Array.isArray(D.settings.playbooks) ? D.settings.playbooks : DEFAULT_PLAYBOOKS;
function pbSuggest(c) { // the playbook that fits a report best, shown to staff as a suggestion and never applied
  const own = c.target ? (c.chat || []).filter(m => m.userId === c.target.userId) : (c.chat || []), fl = new Set(chatFlags(own).flatMap(m => m.flags || []));
  const txt = ' ' + [c.text, ...own.map(m => m.text)].join(' ').toLowerCase().replace(/[^a-z0-9 ]+/g, ' ') + ' ';
  let best = '', top = 0;
  for (const p of playbooks()) {
    const m = p.match || {}, n = (m.flags || []).filter(f => fl.has(f)).length * 2 + (m.words || []).filter(w => w && txt.includes(' ' + String(w).toLowerCase())).length;
    if (n > top) { top = n; best = p.id; }
  }
  return best;
}
// ---- merged reports: reports about the same player close together become one item. Every original report is kept
const MERGE_MIN = [5, 10, 30], PB_FLAGS = ['strong', 'mild', 'invite', 'link', 'pii', 'caps', 'repeat', 'spam', 'long', 'garble'];
const grpOf = c => c.grp || c.id;
const grpMembers = g => D.calls.filter(c => grpOf(c) === g);
const repKey = c => c.from.userId > 0 ? 'u' + c.from.userId : c.staff ? 's' + c.from.name : 'anon'; // anonymous web reports count as one reporter
const grpReporters = g => new Set(grpMembers(g).map(repKey)).size;
function callMerge(call) { // before the new report is added: join an open report about the same player within the window
  if (!call.target) return null;
  const win = (MERGE_MIN.includes(D.settings.mergeMin) ? D.settings.mergeMin : 10) * 60000;
  const lead = D.calls.find(c => !c.grp && c.status !== 'resolved' && c.target && c.target.userId === call.target.userId && call.t - Math.max(...grpMembers(c.id).map(x => x.t)) <= win);
  if (!lead) return null;
  call.grp = lead.id; if (lead.status === 'claimed') { call.status = 'claimed'; call.by = lead.by; }
  return lead;
}
function callTell(list, kind, title, line) { // one in-game message per reporter, naming their own report numbers
  const by = {}; for (const c of list) if (c.from.userId > 0) (by[c.from.userId] ||= []).push(c.id);
  for (const [id, ns] of Object.entries(by)) { const t = `Report #${ns.sort((a, b) => a - b).join(', #')} ${line}`; cmd({ type: 'message', kind, title, body: t, userId: +id, text: t }); }
}
const CLOSED_MSG = 'This server was closed by a moderator. Rejoin to play in a new one.';
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
let CLI_V = null; // same idea for the optional player script: its CLIENT_VERSION in SentinelClient.lua is the newest
const latestClient = () => { if (CLI_V === null) { try { CLI_V = +((fs.readFileSync(path.join(__dirname, '..', 'SentinelClient.lua'), 'utf8').match(/^local CLIENT_VERSION = (\d+)/m) || [])[1]) || 0; } catch { CLI_V = 0; } } return CLI_V; };
const clientInfo = () => { const v = D.meta.clientV || 0, latest = latestClient(); return { v, latest, outdated: v > 0 && latest > 0 && v < latest, bridgeNew: (D.meta.scriptV || 0) >= 15 }; };
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
// ---- two-step verification (authenticator app, RFC 6238) ----
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const b32 = buf => { let bits = 0, v = 0, o = ''; for (const b of buf) { v = (v << 8) | b; bits += 8; while (bits >= 5) { o += B32[(v >>> (bits - 5)) & 31]; bits -= 5; } } if (bits > 0) o += B32[(v << (5 - bits)) & 31]; return o; };
const hotp = (key, counter) => { const c = Buffer.alloc(8); c.writeBigUInt64BE(BigInt(counter)); const h = crypto.createHmac('sha1', key).update(c).digest(), o = h[19] & 15; return String((h.readUInt32BE(o) & 0x7fffffff) % 1e6).padStart(6, '0'); };
const totpCounter = () => Math.floor(Date.now() / 30000);
const totpCheck = (key, code, last = 0) => { code = String(code || '').replace(/\s/g, ''); if (!/^\d{6}$/.test(code)) return 0; const now = totpCounter(); for (const d of [0, -1, 1]) { const c = now + d; if (c > last && same(code, hotp(key, c))) return c; } return 0; }; // a code can only be used once
const newRecovery = () => { const raw = [...Array(8)].map(() => crypto.randomBytes(6).toString('hex')); return { codes: raw.map(c => c.slice(0, 6) + '-' + c.slice(6)), hashes: raw.map(c => codeHash('rec:' + c)) }; };
const useRecovery = (m, input) => { const c = String(input || '').toLowerCase().replace(/[^a-f0-9]/g, ''); if (c.length !== 12) return false; const i = (m.rec || []).indexOf(codeHash('rec:' + c)); if (i < 0) return false; m.rec.splice(i, 1); return true; };
function mfaTry(m, code) { // checks an authenticator code or a recovery code; five wrong tries lock it for 15 minutes (saved, so it holds across servers)
  const now = Date.now(); if (m.lock && m.lock > now) return { code: 429, err: `Too many wrong codes. Try again in ${Math.max(1, Math.ceil((m.lock - now) / 60000))} minutes.` };
  const c = totpCheck(Buffer.from(ocDec(m.s), 'hex'), code, m.last || 0);
  if (c) { m.last = c; m.fails = 0; m.lock = 0; return { ok: true }; }
  if (useRecovery(m, code)) { m.fails = 0; m.lock = 0; return { ok: true, recovery: true }; }
  m.fails = (m.fails || 0) + 1; if (m.fails >= 5) { m.fails = 0; m.lock = now + 900000; }
  return { code: 400, err: 'That code is not right. Check the 6 digits in your authenticator app, or use a recovery code.' };
}
const ADMINP = ['team.manage', 'ranks.manage', 'webhooks.manage', 'privacy.manage', 'automations.manage']; // powers that make a rank "administrator level"
const isAdminLevel = u => !!u && (u.isOwner || ADMINP.some(x => u.perms.has(x)));
const RBX_USERS = env.RBXUSERS_TEST_BASE || 'https://users.roblox.com'; // the override is for tests only
// ---- Roblox group rank sync (one way: the group decides Sentinel ranks; Sentinel never changes the group) ----
const RBX_GROUPS = env.RBXGROUPS_TEST_BASE || 'https://groups.roblox.com'; // the override is for tests only
const RBX_FRIENDS = env.RBXFRIENDS_TEST_BASE || 'https://friends.roblox.com'; // the override is for tests only
const gget = async u => { const r = await fetch(RBX_GROUPS + u, { signal: AbortSignal.timeout(5000) }); if (!r.ok) throw new Error(`Roblox groups said ${r.status}`); return r.json(); };
async function groupInfo(id) { const [g, r] = await Promise.all([gget(`/v1/groups/${id}`), gget(`/v1/groups/${id}/roles`)]); return { id: String(id), name: cleanName(g.name, 60), roles: (r.roles || []).filter(x => x.rank > 0).map(x => ({ id: String(x.id), name: cleanName(x.name, 40), rank: x.rank })).sort((a, b) => b.rank - a.rank) }; }
async function groupRoleOf(gid, robloxId) { const j = await gget(`/v2/users/${robloxId}/groups/roles`); const e = (j.data || []).find(x => x.group && String(x.group.id) === String(gid)); return e ? String(e.role.id) : null; }
async function groupSync(req, by = 'Group sync') { // returns a short summary; never throws
  const G0 = D.meta.group; if (!G0 || !G0.id) return null;
  const roleIds = Object.entries(G0.map || {}).filter(([, rk]) => rk && D.ranks[rk]).map(([rid]) => rid);
  try {
    if (!req._grp) { const who = {}; for (const rid of roleIds) { let cur = '', n = 0; do { const j = await gget(`/v1/groups/${G0.id}/roles/${rid}/users?limit=100&sortOrder=Asc${cur ? '&cursor=' + encodeURIComponent(cur) : ''}`); for (const u of j.data || []) who[String(u.userId)] = rid; cur = j.nextPageCursor || ''; } while (cur && ++n < 10); } req._grp = who; }
    const who = req._grp, changes = [], removals = [], unlinked = [];
    for (const [mid, m] of Object.entries(D.members)) {
      if (mid === D.meta.owner) continue;
      const rid = m.robloxId || (mid[0] === 'r' ? mid.slice(2) : null); if (!rid) { unlinked.push(m.name); continue; }
      const role = who[String(rid)], rk = role && G0.map[role];
      if (rk && D.ranks[rk]) { if (m.rank !== rk) changes.push([mid, rk]); else if (!m.group) m.group = role; }
      else if (m.group && G0.removeLeft) removals.push(mid);
      else if (m.group) delete m.group;
    }
    const managed = Object.values(D.members).filter(m => m.group).length;
    const brake = removals.length > 2 && removals.length > managed / 2; // Roblox returning an empty list should never wipe a team
    for (const [mid, rk] of changes) { const m = D.members[mid], role = who[String(m.robloxId || mid.slice(2))]; audit(by, `${m.name} is now ${D.ranks[rk].name} (Roblox group role)`); m.rank = rk; m.group = role; }
    if (!brake) for (const mid of removals) { audit(by, `Removed ${D.members[mid].name} (no longer holds a mapped role in the Roblox group)`); delete D.members[mid]; }
    G0.last = { t: Date.now(), ok: true, changed: changes.length, removed: brake ? 0 : removals.length, unlinked: unlinked.slice(0, 20), brake: brake ? removals.length : 0, staff: Object.keys(who).length };
    if (brake) audit(by, `Did not remove ${removals.length} members: that is more than half the group-managed team at once, so Sentinel waited. Check the group, then press Sync now.`);
    return G0.last;
  } catch (e) { G0.last = { t: Date.now(), ok: false, error: String(e.message || e).slice(0, 160) }; return G0.last; }
}
async function rbxUser(name) { // the real Roblox account behind a username, or null
  try { const r = await j(RBX_USERS + '/v1/usernames/users', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ usernames: [name], excludeBannedUsers: false }) }); const u = r.data && r.data[0]; if (u && u.id) return { id: String(u.id), name: cleanName(u.name || name, 40) }; } catch {}
  return null;
}
const unbanCmd = userId => { cmd({ type: 'unban', userId }); if (D.meta && D.meta.oc) OCQ.push({ id: +userId, active: false }); };
const machineOn = () => !!(D.meta && D.meta.oc && D.meta.oc.key && D.meta.oc.machine && feat('machineBans')); // machine bans: Roblox also bans the accounts it links to this player (Roblox does the matching, Sentinel stores no device data)
async function ocUniverse() {
  const o = D.meta.oc; if (o.universe) return o.universe;
  const place = D.meta.placeId || D.meta.lastPlace; if (!place) throw new Error('Sentinel does not know your game yet. Enter your Universe ID, or start the game once.');
  const r = await sbf(`${RBX_API}/universes/v1/places/${encodeURIComponent(place)}/universe`); const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.universeId) throw new Error('Could not find the universe for place ' + place); o.uni = String(j.universeId); return o.uni;
}
async function ocPatch(uni, op, key, mask) {
  const g = op.active ? { active: true, ...(op.seconds > 0 ? { duration: op.seconds + 's' } : {}), privateReason: String(op.private || '').slice(0, 1000), displayReason: String(op.display || '').slice(0, 400), excludeAltAccounts: !op.alts } : { active: false };
  const r = await sbf(`${RBX_API}/cloud/v2/universes/${uni}/user-restrictions/${op.id}${mask ? '?updateMask=gameJoinRestriction' : ''}`, { method: 'PATCH', headers: { 'x-api-key': key, 'Content-Type': 'application/json' }, body: JSON.stringify({ gameJoinRestriction: g }) });
  return { r, text: (await r.text().catch(() => '')).slice(0, 300) };
}
async function runOC() {
  if (D.meta && D.meta.oc && D.meta.oc.retry) { const now = Date.now(), r = D.meta.oc.retry; D.meta.oc.retry = r.filter(x => x.at > now); r.filter(x => x.at <= now).forEach(x => OCQ.push({ id: x.id, active: false, tries: x.tries })); if (!D.meta.oc.retry.length) delete D.meta.oc.retry; } // unbans Roblox refused with 429: at most 3 tries in all
  if (!OCQ.length || !D.meta || !D.meta.oc) { OCQ = []; return; }
  const last = new Map(); for (const op of OCQ) last.set(op.id, op); // the newest decision for a player wins
  const ops = [...last.values()].slice(0, 5); OCQ = []; const o = D.meta.oc, key = ocDec(o.key);
  for (const op of ops) {
    const id = op.id, what = op.active ? 'apply the Roblox alt ban to' : 'lift the Roblox ban on'; let ok = false, msg = '';
    try {
      if (!key) throw new Error('The saved Roblox key could not be read. Save it again.');
      const uni = o.universe || o.uni || await ocUniverse(); let x = await ocPatch(uni, op, key, true);
      if (x.r.status === 400) x = await ocPatch(uni, op, key, false);
      ok = x.r.ok; msg = ok ? (op.active ? 'Machine ban applied' : 'Lifted') : `Roblox said ${x.r.status}${x.r.status === 401 || x.r.status === 403 ? ' (check the key, that it has the User Restrictions write permission, and that it covers this experience)' : x.r.status === 404 ? ' (that player has no Roblox ban here, or the Universe ID is wrong)' : ''}: ${x.text.replace(/\s+/g, ' ').slice(0, 140)}`;
      if (x.r.status === 429) {
        const tries = (op.tries || 1) + 1, again = !op.active && tries <= 3; // bans are never retried; an unban gets at most 3 tries, 2 minutes apart
        if (again) o.retry = (o.retry || []).filter(r => r.id !== id).concat({ id, at: Date.now() + 120000, tries }).slice(-50); else if (!op.active) o.retry = (o.retry || []).filter(r => r.id !== id);
        msg = 'Roblox asked Sentinel to slow down for this player (they were banned or unbanned moments ago).' + (again ? ' Sentinel will try again in a couple of minutes, and a running game server can also lift it.' : op.active ? ' The normal ban still applies.' : ' A running game server can still lift it, or lift it again later.');
      } else if (ok && o.retry) o.retry = o.retry.filter(r => r.id !== id);
      if (!op.active && x.r.status === 404 && /not.?found/i.test(x.text)) { ok = true; msg = 'No ban found on Roblox, so nothing to lift'; }
    } catch (e) { msg = String(e.message || e).slice(0, 200); }
    o.last = { t: Date.now(), userId: id, ok, msg, ...(op.active ? { machine: true } : {}) };
    if (!ok) { audit('Sentinel', `Could not ${what} ${id}: ${msg}`); logEvent('oc_fail', `Could not ${what} ${id}: ${msg}`); }
    if (op.active && op.entry) { const e = (D.logs[id] || []).find(x => x.id === op.entry); if (e) { if (ok) delete e.machineErr; else e.machineErr = msg.slice(0, 200); } }
  }
}
const MOD_TYPES = ['Warned', 'Kicked', 'Muted', 'Suspended', 'Banned'];
// ---- Discord bot (HTTP interactions: no always-on bot process) ----
const DISCORD = { app: env.DISCORD_APP_ID || '', pub: (env.DISCORD_PUBLIC_KEY || '').trim(), token: env.DISCORD_BOT_TOKEN || '', api: env.DISCORD_TEST_BASE || 'https://discord.com/api/v10' };
const discordOn = () => !!(DISCORD.app && DISCORD.pub && DISCORD.token);
let DPUB = null;
const dKey = () => DPUB ||= crypto.createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(DISCORD.pub, 'hex')]), format: 'der', type: 'spki' });
function dVerify(req) {
  try {
    const sig = String(req.headers['x-signature-ed25519'] || ''), ts = String(req.headers['x-signature-timestamp'] || '');
    if (!/^[a-f0-9]{128}$/.test(sig) || !/^\d{8,12}$/.test(ts) || req._raw == null || !/^[a-f0-9]{64}$/.test(DISCORD.pub)) return false;
    if (Math.abs(Date.now() / 1000 - +ts) > 300) return false; // stale: could be a replay
    return crypto.verify(null, Buffer.from(ts + req._raw), dKey(), Buffer.from(sig, 'hex'));
  } catch { return false; }
}
const dEmbed = (title, desc, fields = [], color = 0x5e5ce6) => ({ title: String(title).slice(0, 250), description: String(desc || '').slice(0, 3000), color, fields: fields.filter(f => f[1]).map(([n, v]) => ({ name: n, value: String(v).slice(0, 1000), inline: true })), footer: { text: D.meta ? D.meta.name + ' · Sentinel' : 'Sentinel' }, timestamp: new Date().toISOString() });
const dBtn = (label, id, style = 2) => ({ type: 2, style, label, custom_id: id });
function botPost(body) { if (!discordOn() || !D.discord || !D.discord.channel) return false; BOTQ.push({ ch: D.discord.channel, body }); return true; }
async function sendBot() { await Promise.all(BOTQ.splice(0).map(m => fetch(`${DISCORD.api}/channels/${m.ch}/messages`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bot ' + DISCORD.token }, body: JSON.stringify({ allowed_mentions: { parse: [] }, ...m.body }), signal: AbortSignal.timeout(3000) }).catch(() => {}))); }
async function findPlayer(name) { // quick lookup for the bot: people Sentinel has seen first, then Roblox (Discord wants an answer within 3 seconds)
  const n = name.toLowerCase(), on = allPlayers().find(p => p.name.toLowerCase() === n); if (on) return { id: on.userId, name: on.name };
  const k = Object.entries(D.play).find(([, x]) => (x.name || '').toLowerCase() === n); if (k) return { id: +k[0], name: k[1].name };
  try { const r = await fetch(RBX_USERS + '/v1/usernames/users', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ usernames: [name], excludeBannedUsers: false }), signal: AbortSignal.timeout(1800) }); const j2 = await r.json(); const x = j2.data && j2.data[0]; if (x) return { id: x.id, name: x.name }; } catch {}
  return null;
}
const DISCORD_COMMANDS = (() => { const pl = { type: 3, name: 'player', description: 'Their Roblox username', required: true }, rs = req => ({ type: 3, name: 'reason', description: 'What happened', required: req, max_length: 300 });
  return [
    { name: 'sentinel', description: 'Set up Sentinel in this server', dm_permission: false, options: [
      { type: 1, name: 'link', description: 'Link this server to your Sentinel workspace', options: [{ type: 3, name: 'code', description: 'The code from Sentinel, Settings, Discord', required: true }] },
      { type: 1, name: 'me', description: 'Link your Discord account to your Sentinel account', options: [{ type: 3, name: 'code', description: 'Your code from Sentinel, Settings, Discord', required: true }] },
      { type: 1, name: 'channel', description: 'Post appeals, applications and unban approvals here, with buttons' },
      { type: 1, name: 'unlink', description: 'Disconnect this server from Sentinel' }] },
    { name: 'warn', description: 'Warn a player in game', dm_permission: false, options: [pl, rs(true)] },
    { name: 'kick', description: 'Kick a player from the game', dm_permission: false, options: [pl, rs(true)] },
    { name: 'mute', description: 'Mute a player in game chat', dm_permission: false, options: [pl, { type: 4, name: 'minutes', description: 'How long', required: true, min_value: 1, max_value: 525600 }, rs(true)] },
    { name: 'ban', description: 'Ban a player (leave days empty for permanent)', dm_permission: false, options: [pl, rs(true), { type: 4, name: 'days', description: 'Leave empty for a permanent ban', min_value: 1, max_value: 3650 }] },
    { name: 'unban', description: 'Lift a ban', dm_permission: false, options: [pl, rs(false)] },
    { name: 'lookup', description: "See a player's status and recent records", dm_permission: false, options: [pl] },
  ]; })();
function lookupEmbed(t, base) {
  const on = allPlayers().find(p => p.userId === t.id), ban = D.bans[t.id], mute = D.mutes[t.id], pl = D.play[t.id], recs = (D.logs[t.id] || []).filter(e => MOD_TYPES.includes(e.type) && e.status !== 'reverted').slice(-5).reverse();
  return dEmbed(t.name, `[Open in Sentinel](${base}/#/player/${t.id})`, [['Status', on ? `In game (server ${on.server})` : 'Not in game'], ['Ban', ban && live(ban) ? `${ban.expires ? 'Suspended until <t:' + Math.floor(ban.expires / 1000) + ':f>' : 'Permanent'}: ${ban.reason}` : 'None'], ['Mute', mute && live(mute) ? `Until <t:${Math.floor(mute.expires / 1000)}:t>` : 'None'],
    ['Time played', pl ? fmtMin(Math.round((pl.total || 0) / 60)) : '0 min'], ['Recent records', recs.length ? recs.map(e => `${e.type}: ${e.reason}`).join('\n') : 'Nothing on record']], ban && live(ban) ? 0xe5484d : 0x5e5ce6);
}
// ---- "worth a look" signals: hints that a new player might be a banned player's alt. Never acted on automatically. ----
const nrm = s => String(s || '').toLowerCase().replace(/[^a-z0-9]/g, '');
function lev(a, b) { if (Math.abs(a.length - b.length) > 2) return 9; let prev = [...Array(b.length + 1).keys()]; for (let i = 1; i <= a.length; i++) { const cur = [i]; for (let k = 1; k <= b.length; k++) cur[k] = Math.min(prev[k] + 1, cur[k - 1] + 1, prev[k - 1] + (a[i - 1] === b[k - 1] ? 0 : 1)); prev = cur; } return prev[b.length]; }
function nameLike(a, b) {
  a = nrm(a); b = nrm(b); if (a.length < 5 || b.length < 5) return false; if (a === b) return true;
  const sa = a.replace(/\d+$/, ''), sb = b.replace(/\d+$/, ''); if (sa.length >= 5 && sa === sb) return true;
  return lev(a, b) <= (Math.min(a.length, b.length) >= 8 ? 2 : 1);
}
async function banSyncPull() { // copy new bans from the owner's other games (never from anyone else's), at most once a minute
  const sy = D.settings.sync, now = Date.now(); if (!sy || !sy.from || !sy.from.length || now - (sy.at || 0) < 60000) return;
  sy.at = now; let rows; try { rows = await sbGet('select=key,meta:value->meta,bans:value->bans&key=in.(' + sy.from.map(f => 'w' + f.id + ':core').join(',') + ')'); } catch { return; }
  D.syncSeen ||= {}; const staff = new Set(Object.entries(D.members).map(([mid, m]) => String(m.robloxId || (mid[0] === 'r' ? mid.slice(2) : '')))); let n = 0;
  for (const r of rows) {
    const m = r.meta; if (!m || m.deleted || m.suspended || m.owner !== D.meta.owner) continue;
    for (const b of Object.values(r.bans || {})) {
      if (n >= 25) break;
      if (!b || !Number.isInteger(b.userId) || b.userId < 1 || !live(b) || staff.has(String(b.userId)) || (D.bans[b.userId] && live(D.bans[b.userId])) || (D.syncSeen[b.userId] || 0) >= (b.time || 1)) continue;
      await need('logs'); D.syncSeen[b.userId] = b.time || 1; n++;
      act({ action: 'ban', userId: b.userId, name: cleanName(b.name, 40) || String(b.userId), reason: cleanName(`Copied from ${m.name}: ${b.reason}`, 300), minutes: b.expires ? Math.max(1, Math.ceil((b.expires - now) / 60000)) : 0, by: 'Ban sync' });
    }
  }
  if (n) feed(`Ban sync added ${n} ban${n > 1 ? 's' : ''}`, 'Ban sync');
  const ks = Object.keys(D.syncSeen); if (ks.length > 3000) for (const k of ks.sort((a, b) => D.syncSeen[a] - D.syncSeen[b]).slice(0, ks.length - 3000)) delete D.syncSeen[k];
}
async function signalCheck(req, fresh, joined) { // alt-account hints for staff. Only public Roblox data; never an automatic action
  if (D.settings.signals === false || !joined.length) return;
  const now = Date.now(), staff = new Set(Object.entries(D.members).map(([mid, m]) => String(m.robloxId || (mid[0] === 'r' ? mid.slice(2) : '')))), bans = Object.values(D.bans).filter(live);
  const cand = [...new Set(joined)].filter(id => !staff.has(String(id)) && !(D.bans[id] && live(D.bans[id])) && !(D.signals[id] && now - D.signals[id].t < 864e5)).slice(0, 20);
  req._ages ||= {}; req._grp ||= {}; let fetched = 0, calls = 0; const budget = () => calls < 8 && ++calls;
  const groupsOf = async uid => { if (uid in req._grp) return req._grp[uid]; if (!budget()) return null; let g = null; try { const x = await j(RBX_GROUPS + '/v2/users/' + uid + '/groups/roles'); g = (x && Array.isArray(x.data) ? x.data : []).map(d => d.group || {}).filter(g => g.id && Number.isInteger(g.memberCount) && g.memberCount > 0 && g.memberCount < 500).map(g => ({ id: g.id, name: String(g.name || g.id).slice(0, 60) })); } catch { g = null; } return (req._grp[uid] = g); };
  const recentBans = bans.slice().sort((a, b) => (b.time || 0) - (a.time || 0)).slice(0, 10);
  for (const id of cand) {
    const name = (D.play[id] || {}).name || String(id), reasons = []; let of = null;
    const add = (k, w, text, who) => { reasons.push({ k, w, text }); if (who) of ||= { userId: who.userId, name: who.name }; };
    const sim = bans.find(bn => bn.userId !== id && nameLike(name, bn.name)); if (sim) add('name', 4, `Name looks like ${sim.name}, who is banned`, sim);
    if (fresh.has(id)) {
      const rb = bans.filter(bn => bn.time && now - bn.time < 36e5 && bn.userId !== id).sort((a, b) => b.time - a.time)[0], rk = (D.kicks || []).filter(k => now - k.t < 36e5 && k.userId !== id).sort((a, b) => b.t - a.t)[0];
      const last = rb && (!rk || rb.time >= rk.t) ? { who: rb, t: rb.time, what: 'banned' } : rk ? { who: rk, t: rk.t, what: 'kicked' } : null;
      if (last) add('ban', 2, `First joined ${Math.max(1, Math.round((now - last.t) / 60000))} min after ${last.who.name} was ${last.what}`, last.who);
      if (id in req._ages || fetched < 3) {
        if (!(id in req._ages)) { fetched++; try { const x = await j(RBX_USERS + '/v1/users/' + id); req._ages[id] = x && x.created ? Date.parse(x.created) : null; } catch { req._ages[id] = null; } }
        const c = req._ages[id]; if (c && D.play[id] && !D.play[id].created) D.play[id].created = c; if (c) { const d = Math.floor((now - c) / 864e5); if (d < 7) add('age', 1, `Roblox account is ${d < 1 ? 'less than a day' : d + (d === 1 ? ' day' : ' days')} old`); }
      }
      if (bans.length && budget()) { // friends with a banned player (public friends list)
        try { const x = await j(RBX_FRIENDS + '/v1/users/' + id + '/friends'); const ids = new Set((x && Array.isArray(x.data) ? x.data : []).map(f => Number(f.id)));
          const fb = bans.find(bn => bn.userId !== id && ids.has(Number(bn.userId))); if (fb) add('friend', 3, `Is friends with ${fb.name}, who is banned`, fb); } catch {}
      }
      if (recentBans.length) { // a small group (under 500 members) shared with a recently banned player
        const mine = await groupsOf(id);
        if (mine && mine.length) for (const bn of recentBans) { if (bn.userId === id) continue; const theirs = await groupsOf(bn.userId); if (!theirs) break; const g = mine.find(x => theirs.some(y => y.id === x.id)); if (g) { add('group', 2, `In the small group ${g.name} with ${bn.name}, who is banned`, bn); break; } }
      }
    }
    const score = reasons.reduce((n, r) => n + r.w, 0), strength = score >= 6 ? 'strong' : score >= 4 ? 'likely' : score >= 3 ? 'weak' : null; // weights: name 4, friend 3, small group 2, joined after a ban or kick 2, new account 1. One weak sign alone is never a hint
    if (strength) { D.signals[id] = { t: now, name, reasons, score, status: 'open', strength, ...(of ? { of } : {}) }; feed(`Worth a look: ${name}`); notify('signals', `Worth a look (${strength}): ${name}`, reasons.map(r => '• ' + r.text).join('\n') + '\nThese are hints, not proof. Check before acting.', [], 0xf5a524); }
  }
  const keys = Object.keys(D.signals).sort((a, b) => D.signals[b].t - D.signals[a].t); for (const [i, k] of keys.entries()) if (i >= 100 || now - D.signals[k].t > 14 * 864e5) delete D.signals[k];
}
// ---- shifts ----
const shEnd = x => x.start + x.mins * 60000;
function inGameSecs(rid, a, b) { // seconds a Roblox user spent in game between a and b, from their saved sessions
  const h = (D.hist[rid % SH] || {})[rid]; if (!h) return 0; let t = 0;
  const add = (s, e) => { const o = Math.min(e, b) - Math.max(s, a); if (o > 0) t += o; };
  for (const [st, secs] of h.j || []) add(st, st + secs * 1000);
  if (h.cur) add(h.cur.t, h.cur.t + h.cur.s * 1000);
  return Math.round(t / 1000);
}
const ridOf = mid => { const m = D.members[mid]; return m ? m.robloxId || (mid[0] === 'r' ? mid.slice(2) : null) : null; };
function shiftView(x, uid) {
  const now = Date.now(), end = shEnd(x), state = now < x.start ? 'upcoming' : now < end ? 'now' : 'done';
  const people = x.signups.map(s => { const rid = ridOf(s.uid); let att = null;
    if (state !== 'upcoming') { if (x.att && s.uid in x.att) att = x.att[s.uid]; else if (rid) att = Math.round(inGameSecs(+rid, x.start, Math.min(end, now)) / 60); }
    return { uid: s.uid, name: (D.members[s.uid] || {}).name || s.name, linked: !!rid, robloxId: rid, mins: att }; });
  return { ...x, att: undefined, end, state, people, mine: x.signups.some(s => s.uid === uid), full: x.signups.length >= x.slots };
}
// ---- forms ----
const FTYPES = ['short', 'long', 'choice', 'number', 'roblox', 'yesno'];
function cleanForm(f, u) { // returns the cleaned form, or an error string
  f = f && typeof f === 'object' ? f : {};
  const title = cleanName(f.title, 80); if (!title) return 'Give the form a title.';
  const fields = (Array.isArray(f.fields) ? f.fields : []).slice(0, 25).map(x => {
    const type = FTYPES.includes(x && x.type) ? x.type : 'short';
    return { id: /^[a-f0-9]{6}$/.test(x && x.id) ? x.id : crypto.randomBytes(3).toString('hex'), label: cleanName(x && x.label, 120), type, required: !!(x && x.required),
      ...(type === 'choice' ? { options: [...new Set((Array.isArray(x.options) ? x.options : String(x.options || '').split(',')).map(o => cleanName(o, 60)).filter(Boolean))].slice(0, 15) } : {}) };
  }).filter(x => x.label);
  if (!fields.length) return 'Add at least one question.';
  if (fields.some(x => x.type === 'choice' && x.options.length < 2)) return 'Choice questions need at least two options, separated by commas.';
  const kind = ['application', 'report', 'custom'].includes(f.kind) ? f.kind : 'custom', audience = f.audience === 'staff' ? 'staff' : 'public';
  let rank = null;
  if (kind === 'application' && f.rank) {
    const r = D.ranks[f.rank]; if (!r) return 'That rank no longer exists.'; if (!above(u, r.pos)) return 'You can only offer ranks below your own.';
    if (!fields.some(x => x.type === 'roblox')) return 'Add a "Roblox username" question, so the invite can be locked to the applicant.';
    rank = f.rank;
  }
  return { title, desc: String(f.desc || '').replace(/[\u0000-\u0009\u000b-\u001f<>]/g, '').slice(0, 600).trim(), kind, audience, open: f.open !== false, rank, fields };
}
async function readAnswers(form, ans) {
  const out = []; let whoR = null; ans = ans && typeof ans === 'object' ? ans : {};
  for (const f of form.fields) {
    let v = ans[f.id] == null ? '' : String(ans[f.id]);
    v = f.type === 'long' ? v.replace(/\r/g, '').replace(/[\u0000-\u0009\u000b-\u001f<>]/g, '').slice(0, 2000).trim() : cleanName(v, f.type === 'short' ? 300 : 100);
    if (f.required && !v) return { err: `Please answer: ${f.label}` };
    if (v && f.type === 'number' && !/^-?\d{1,9}(\.\d{1,3})?$/.test(v)) return { err: `${f.label}: please enter a number.` };
    if (v && f.type === 'choice' && !f.options.includes(v)) return { err: `${f.label}: please pick one of the options.` };
    if (v && f.type === 'yesno' && v !== 'Yes' && v !== 'No') return { err: `${f.label}: please answer Yes or No.` };
    if (v && f.type === 'roblox') {
      const nm = v.replace(/^@/, ''); if (!/^\w{3,20}$/.test(nm)) return { err: `${f.label}: that is not a Roblox username.` };
      const ru = await rbxUser(nm); if (!ru) return { err: `${f.label}: we could not find a Roblox account called ${nm}.` }; v = ru.name; if (!whoR) whoR = ru;
    }
    out.push({ id: f.id, label: f.label, type: f.type, value: v });
  }
  return { answers: out, who: whoR };
}
const needSecond = (u, ban) => !!(D.settings.twoPerson && ban && !ban.expires && !u.isOwner); // lifting a permanent ban takes two staff (the owner can always do it alone)
const APPR_KINDS = { permBan: 'Permanent bans', rank: 'Rank changes', wsDelete: 'Deleting the workspace' }, APPR_MS = 72 * 36e5, PEND_MSG = 'Sent for approval. A second staff member has to approve it before it happens.';
const approvalOn = k => !!(D.settings.approvals && D.settings.approvals[k]);
function canApprove(it, a, auid) { // who may sign off a waiting request: never the person who asked
  if (!a || !it || it.byUid === auid) return false;
  if (it.kind === 'permBan') return has(a, 'mod.permban');
  if (it.kind === 'rank') { const m = D.members[it.payload.uid], r = D.ranks[it.payload.rank]; return !!(m && r && it.payload.uid !== D.meta.owner && above(a, memberPos(it.payload.uid)) && above(a, r.pos)); }
  if (it.kind === 'wsDelete') return isAdminLevel(a);
  return false;
}
const approverExists = (kind, uid, payload) => Object.keys(D.members).some(id => id !== uid && canApprove({ kind, payload, byUid: uid }, who(id), id)); // with nobody else able to approve, the action just goes ahead
function propose(kind, u, uid, payload, text, reason) {
  const now = Date.now(); D.pending = (D.pending || []).filter(x => now - x.t < APPR_MS);
  const key = JSON.stringify(payload), dup = D.pending.find(x => x.kind === kind && x.byUid === uid && JSON.stringify(x.payload) === key); if (dup) return dup;
  if (D.pending.length >= 30) return null;
  const it = { id: crypto.randomBytes(5).toString('hex'), kind, payload, by: u.user, byUid: uid, t: now, text, reason: reason || '' };
  D.pending.push(it); audit(u.user, `Asked for approval to ${text}`); feed(`Needs approval: ${text}`, u.user);
  notify('approvals', `Needs a second approval: ${text}`, reason, [['Asked by', u.user]], 0xf5a524); return it;
}
const DEFAULT_REPLIES = ['Thanks for being honest. We have lifted your ban. Please follow the rules from now on.', 'We reviewed what happened and the ban stays. You can appeal again later.', 'Bans for exploiting are not lifted on appeal.', 'Please tell us more about what happened next time you appeal.'];
const cleanLinks = (arr, max) => (Array.isArray(arr) ? arr : []).map(x => String(x || '').trim()).filter(x => /^https?:\/\/[^\s<>"'`]{3,300}$/i.test(x)).slice(0, max);
// ---- staff workflow: escalation (send a report, appeal or logbook entry up to a senior)
const ESC_KINDS = { report: 'report', appeal: 'appeal', entry: 'logbook entry' };
const escCan = (m, kind) => !!m && (kind === 'appeal' ? has(m, 'appeals.review') : has(m, 'reports.handle'));
function escSenior(uid, x) { // may this member take, return or resolve escalation x? The owner always may
  const m = who(uid); if (!m) return false; if (m.isOwner) return true;
  return uid !== x.byUid && m.pos > x.byPos && has(m, 'staff.review') && escCan(m, x.kind) && (x.to === 'any' || m.rank === x.to);
}
function escRef(x) { // what was sent up, with its evidence
  if (x.kind === 'report') { const c = D.calls.find(c => c.id === x.ref); return c ? { title: `Report #${c.id}`, text: c.text, who: c.target ? c.target.name : c.from.name, userId: c.target ? c.target.userId : c.from.userId, chat: c.chat || [], box: c.box || null, status: c.status } : null; }
  if (x.kind === 'appeal') { const a = D.appeals.find(a => a.id === x.ref); return a ? { title: `Appeal from ${a.name}`, text: a.text, who: a.name, userId: a.uid, banReason: a.banReason || '', status: a.status, reply: a.reply || null } : null; }
  const e = (D.logs[x.ref.userId] || []).find(e => e.id === x.ref.entryId);
  return e ? { title: `${e.type}: ${e.name}`, text: e.reason, who: e.name, userId: +x.ref.userId, type: e.type, minutes: e.minutes || 0, by: e.by, ev: e.ev || [], ctx: e.ctx || [], boxes: e.boxes || [], status: e.status } : null;
}
const escOut = (x, uid) => ({ id: x.id, kind: x.kind, title: x.title, to: x.to, toName: x.to === 'any' ? 'Any senior' : (D.ranks[x.to] || {}).name || 'Removed rank', note: x.note, by: x.by, t: x.t, status: x.status, takenBy: x.takenBy || null, log: x.log, mine: x.byUid === uid, canAct: escSenior(uid, x) });
const escSame = (a, b) => a.kind === b.kind && JSON.stringify(a.ref) === JSON.stringify(b.ref);
// ---- onboarding checklist per rank. Items tick themselves when the action happens, or by hand
const OB_DEF = [{ id: 'rulebook', label: 'Read the rulebook', auto: 'rulebook' }, { id: 'practice', label: 'Finish a practice case', auto: 'practice' }, { id: 'report', label: 'Handle a first report', auto: 'report' }, { id: 'shift', label: 'Complete a first shift', auto: 'shift' }];
const OB_AUTO = { rulebook: 'Opens the Rulebook', practice: 'Answers a training case', report: 'Claims or resolves a report', appeal: 'Answers an appeal', shift: 'Works a shift they signed up for' };
const obList = rank => { const l = D.onboard.lists[rank]; return Array.isArray(l) ? l : OB_DEF; };
const obTick = (uid, ev) => { if (!uid || !D.members[uid] || !OB_AUTO[ev]) return; const d = (D.onboard.done[uid] ||= {}); if (!d['auto:' + ev]) d['auto:' + ev] = Date.now(); };
function obState(uid) { // a new member's checklist, or null when there is none (owner, staff from before checklists, empty list)
  const m = D.members[uid]; if (!m || uid === D.meta.owner || D.onboard.skip[uid]) return null;
  const d = D.onboard.done[uid] || {}, shift = D.shifts.some(x => x.att && x.att[uid] > 0);
  const items = obList(m.rank).map(i => ({ id: i.id, label: i.label, auto: i.auto || '', done: !!(d[i.id] || (i.auto && (d['auto:' + i.auto] || (i.auto === 'shift' && shift)))) }));
  return items.length ? { items, n: items.filter(i => i.done).length } : null;
}
// ---- training: anonymised practice cases. Answers are recorded per trainee and never touch real players
const TR_TYPES = { Warned: 'warn', Muted: 'mute', Kicked: 'kick', Suspended: 'ban', Banned: 'ban' };
const trId = (userId, entryId) => 'e' + crypto.createHmac('sha256', SIGN).update('tr:' + userId + ':' + entryId).digest('base64url').slice(0, 14); // no user id inside
function anonymiser(seed) { // every name the workspace knows becomes Player A, B, ... (staff: Staff A, B, ...); links, emails, phone and long numbers are removed
  const staff = new Set(Object.values(D.members).map(m => String(m.name || '').toLowerCase())), names = new Set(), map = new Map(), cnt = { p: 0, s: 0 };
  for (const p of Object.values(D.play)) { if (p && p.name) names.add(String(p.name)); if (p && p.displayName) names.add(String(p.displayName)); }
  for (const b of [...Object.values(D.bans), ...Object.values(D.mutes)]) if (b && b.name) names.add(String(b.name));
  for (const m of Object.values(D.members)) if (m.name) names.add(String(m.name));
  for (const n of seed) if (n) names.add(String(n));
  const letter = n => (n < 26 ? '' : String.fromCharCode(64 + Math.floor(n / 26))) + String.fromCharCode(65 + n % 26);
  const label = n => { const k = n.toLowerCase(); if (!map.has(k)) map.set(k, staff.has(k) ? 'Staff ' + letter(cnt.s++) : 'Player ' + letter(cnt.p++)); return map.get(k); };
  for (const n of seed) if (n) label(String(n)); // the case's own player is Player A
  const list = [...names].filter(n => n.length >= 3).sort((a, b) => b.length - a.length).slice(0, 5000).map(n => n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  const re = list.length ? new RegExp('@?(?<![A-Za-z0-9_])(' + list.join('|') + ')(?![A-Za-z0-9_])', 'gi') : null;
  const ids = new Set([...Object.keys(D.play), ...Object.keys(D.logs), ...Object.keys(D.bans), ...Object.keys(D.mutes), ...Object.values(D.members).map(m => String(m.robloxId || ''))].filter(Boolean)); // user ids the workspace knows
  return t => {
    let s = String(t || ''); if (re) s = s.replace(re, (m0, n) => label(n));
    s = s.replace(/\d{2,}/g, m => (ids.has(m) ? '[id removed]' : m));
    s = s.replace(/\b(Mr|Mrs|Ms|Miss|Mx|Dr)\.?\s+[A-Z][\w'-]+/g, '[name removed]'); // a real-world name after a title
    return s.replace(new RegExp(EMAIL_RE.source, 'gi'), '[email removed]').replace(/https?:\/\/\S+|www\.\S+/gi, '[link removed]').replace(new RegExp(LINK_RE.source, 'gi'), '[link removed]').replace(new RegExp(PHONE_RE.source, 'g'), '[number removed]').replace(/\d{5,}/g, '[number removed]');
  };
}
function trCases() { // newest 200 real cases plus every entry marked for training, then the owner's own cases
  const all = [];
  for (const [pid, list] of Object.entries(D.logs)) for (const e of list) if (TR_TYPES[e.type] && e.status !== 'reverted' && e.reason) all.push([pid, e]);
  all.sort((a, b) => b[1].time - a[1].time);
  const pick = [...all.filter(x => x[1].train), ...all.filter(x => !x[1].train).slice(0, 200)], out = [];
  for (const [pid, e] of pick) {
    const anon = anonymiser([e.name]), rule = e.ruleId && (D.rulebook.find(r => r.id === e.ruleId) || {}).title, act0 = TR_TYPES[e.type];
    out.push({ id: trId(pid, e.id), text: anon(e.reason), rule: rule ? anon(rule) : null, chat: e.train ? (e.ctx || []).map(m => anon(m.text)) : [], answer: { action: act0, minutes: act0 === 'mute' || act0 === 'ban' ? e.minutes || 0 : 0 }, note: e.train && e.note ? anon(e.note) : null, real: true, t: e.time });
  }
  for (const c of D.training.cases) { const anon = anonymiser([]); out.push({ id: c.id, text: anon(c.text), rule: null, chat: (c.chat || []).map(anon), answer: { action: c.action, minutes: c.minutes || 0 }, note: c.note ? anon(c.note) : null, real: false, t: c.t }); }
  return out;
}
const trMatch = (p, a) => p.action === a.action && (!['mute', 'ban'].includes(a.action) || (a.minutes === 0 ? p.minutes === 0 : p.minutes > 0 && p.minutes >= a.minutes / 2 && p.minutes <= a.minutes * 2)); // same action, and a length within half to double
// ---- chat alert words: staff are told fast when a watched word appears. An alert never takes action
const seqIn = (toks, want) => { for (let i = 0; i + want.length <= toks.length; i++) if (want.every((w, j) => toks[i + j] === w)) return true; return false; };
function alertHit(text, a) { // same normalising as the chat flags: leetspeak, spaced-out letters, stretched letters
  const want = cussTokens(a.w); if (!want.length) return false;
  const toks = cussTokens(text), t1 = toks.map(once), w1 = want.map(once);
  if (a.whole) return seqIn(toks, want) || seqIn(t1, w1);
  return toks.join(' ').includes(want.join(' ')) || t1.join(' ').includes(w1.join(' ')) || t1.join('').includes(w1.join(''));
}
function alertCheck(job, uid, name, text, now) {
  const words = D.alertWords; if (!uid || !words || !words.length) return;
  for (const a of words) {
    if (!alertHit(text, a)) continue;
    const k = 'aw:' + uid + ':' + a.id; if ((R.am[k] || 0) > now - 5 * 60000) continue; R.am[k] = now; // one alert per player per word per 5 minutes
    const box = CBO[job] ? CBO[job].id : null, x = { id: rnd(6), t: now, word: a.w, userId: uid, name, text: String(text).slice(0, 200), server: String(job).slice(0, 8), box };
    D.alerts = [x, ...(D.alerts || [])].slice(0, 100); feed(`Chat alert "${a.w}": ${name}`);
    if ((D.settings.alertDest || 'inbox') !== 'inbox') notify('alerts', `Chat alert: "${a.w}"`, `${name}: ${x.text}`, [['Player', name], ['Server', x.server], ['Chat box', box || '']], 0xf5a524);
  }
}
// ---- player risk score: advice for staff only, never shown to players, never acted on automatically
const RISK_W = { Warned: 6, Muted: 10, Kicked: 12, Suspended: 18, Banned: 25, box: 4, boxStrong: 8, report: 8, hint: { weak: 10, likely: 15, strong: 20 }, newAccount: 10, halfLifeDays: 30, maxAgeDays: 90 };
const RISK_LABEL = { Warned: ['warning', 'warnings'], Muted: ['mute', 'mutes'], Kicked: ['kick', 'kicks'], Suspended: ['suspension', 'suspensions'], Banned: ['ban', 'bans'], box: ['flagged chat box', 'flagged chat boxes'], boxStrong: ['chat box with strong language or slurs', 'chat boxes with strong language or slurs'] };
function rkAdd(id, name, kind, eid) { // a compact history in the play row, read by riskOf
  if (!('play' in loaded) || !RISK_W[kind]) return; const p = playOf(id, name); (p.rk ||= []).push([kind, Date.now(), eid || 0]); if (p.rk.length > 50) p.rk.splice(0, p.rk.length - 50);
}
function riskOf(id, now = Date.now()) { // 0 to 100, with the parts it is made of. Older activity counts less: halves every 30 days, ignored after 90
  const p = D.play[id] || {}, parts = {}, add = (key, label, pts) => { const x = (parts[key] ||= { label, points: 0, n: 0 }); x.points += pts; x.n++; };
  for (const [k, t] of p.rk || []) { const age = (now - t) / 864e5; if (age > RISK_W.maxAgeDays || !RISK_W[k] || !RISK_LABEL[k]) continue; add(k, RISK_LABEL[k], RISK_W[k] * Math.pow(0.5, age / RISK_W.halfLifeDays)); }
  const groups = new Set(D.calls.filter(c => c.target && c.target.userId === +id && c.status !== 'resolved').map(grpOf)); // a merged report counts by its distinct reporters, at most 3
  for (const g of groups) add('report', ['open report against them', 'open reports against them'], RISK_W.report * Math.min(3, grpReporters(g)));
  const sg = D.signals[id]; if (sg && sg.status === 'open') add('hint', [`${sg.strength || 'likely'} alt-account hint`, 'alt-account hints'], RISK_W.hint[sg.strength] || RISK_W.hint.likely);
  if (p.created && now - p.created < 7 * 864e5) add('age', ['Roblox account under 7 days old', ''], RISK_W.newAccount);
  for (const a of p.adj || []) { const age = (now - a.t) / 864e5; if (a.reverted || age > RISK_W.maxAgeDays) continue; add('trust:' + a.id, [`Trust restored by ${a.by}`, ''], -a.pts * Math.pow(0.5, age / RISK_W.halfLifeDays)); } // staff lowered it; fades like everything else
  const list = Object.values(parts).map(x => ({ label: x.n > 1 ? `${x.n} ${x.label[1]}` : x.label[0], points: Math.round(x.points) })).filter(x => x.points !== 0).sort((a, b) => b.points - a.points);
  const up = Math.min(100, list.filter(x => x.points > 0).reduce((a, x) => a + x.points, 0)), down = list.filter(x => x.points < 0).reduce((a, x) => a + x.points, 0);
  return { score: Math.max(0, up + down), parts: list };
}
// ---- evidence vault: links, notes and copied chat boxes, each with an expiry and a log of who opened it
const VAULT_CAP = 512 * 1024, VAULT_DAYS = [30, 90, 180, 365], CASE_RE = /^(call:\d{1,9}|appeal:[\w-]{1,24}|escal:[\w-]{1,24})$/;
const vaultDays = () => VAULT_DAYS.includes(D.settings.vaultDays) ? D.settings.vaultDays : 180;
const vaultItems = () => { const now = Date.now(); if (VT.items.some(x => x.exp <= now)) VT.items = VT.items.filter(x => x.exp > now); return VT.items; }; // expired items are deleted the next time the vault is read
const vaultSize = () => JSON.stringify(VT).length;
const vaultMeta = x => ({ id: x.id, uid: x.uid || null, name: x.name || '', cases: x.cases || [], kind: x.kind, title: x.title, by: x.by, byUid: x.byUid, t: x.t, exp: x.exp, n: x.msgs ? x.msgs.length : 0, opened: (x.log || []).length });
function caseInfo(cs) { // what a case points at, or null when it is gone
  const [k, v] = cs.split(':');
  if (k === 'call') { const c = D.calls.find(c => c.id === +v); return c ? { uid: c.target ? c.target.userId : c.from.userId, name: c.target ? c.target.name : c.from.name } : null; }
  if (k === 'appeal') { const a = D.appeals.find(a => a.id === v); return a ? { uid: a.uid, name: a.name } : null; }
  const x = D.escal.find(x => x.id === v); if (!x) return null; const r = escRef(x); return { uid: r ? r.userId : null, name: r ? r.who : '' };
}
async function boxGet(id) { // a chat box from the closed table, or one still filling up
  let bx = null; try { const r = await cbFetch(`chat_boxes?select=id,closed_at,server,msgs&wid=eq.${CTX.wid}&id=eq.${id}`, { ms: 4000 }); if (r.ok) bx = (await r.json())[0] || null; } catch {}
  if (!bx) { const oj = Object.keys(CBO).find(j => CBO[j].id === id); if (oj) bx = { id, closed_at: new Date(CBO[oj].last).toISOString(), server: String(oj).slice(0, 8), msgs: chatFlags(CBO[oj].msgs) }; }
  return bx;
}
// ---- owner visibility: game connection health and the daily summary (sent by /api/cron/tick) ----
const DOWN_MS = 10 * 60000;
function healthNote(kind, title, text, now) { D.notices = [...(D.notices || []).filter(n => n && n.kind !== 'health' && n.exp > now), { id: rnd(6), kind: 'health', state: kind, t: now, exp: now + (kind === 'down' ? 7 : 1) * 864e5, title, text }]; }
function healthSync(now) { // every game check-in. Writes the core row at most once a minute, or when the game empties or fills
  const m = D.meta, pl = allPlayers().length > 0;
  if (now - (m.lastSyncAt || 0) >= 6e4 || !!m.livePl !== pl) { m.lastSyncAt = now; m.livePl = pl; }
  if (pl && now - (m.activeAt || 0) >= 6e4) m.activeAt = now;
  const h = m.health; if (!h || !h.down) return;
  const mins = Math.max(1, Math.round((now - h.since) / 6e4)); m.health = { down: 0, log: [...(h.log || []), { since: h.since, up: now }].slice(-10) };
  healthNote('back', 'Your game is connected again', `Sentinel heard from your game again after ${plural(mins, 'minute')} without contact.`, now);
  notify('health', 'Game connected again', `Sentinel heard from your game again after ${plural(mins, 'minute')} without contact.`, [], 0x30a46c);
}
// went quiet with people still in game, more than 10 minutes ago, and was played in the last 24 hours. Empty and unused games never alert
const healthDue = (m, now) => !!(m && !m.deleted && !m.suspended && m.lastSyncAt && m.livePl && now - m.lastSyncAt > DOWN_MS && now - (m.activeAt || 0) < 864e5 && !(m.health && m.health.down));
function localDay(tz, t) { try { const p = Object.fromEntries(new Intl.DateTimeFormat('en-CA', { timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', hourCycle: 'h23' }).formatToParts(t).map(x => [x.type, x.value])); return { day: `${p.year}-${p.month}-${p.day}`, hour: +p.hour % 24 }; } catch { return null; } }
const digestSlot = (dg, now) => { const l = localDay(dg.tz || 'UTC', now); return !l ? null : l.hour >= dg.hour ? l.day : localDay(dg.tz || 'UTC', now - 864e5).day; }; // the latest local day whose chosen hour has passed
const digestDue = (m, dg, now) => { if (!m || m.deleted || m.suspended || !dg || !dg.on) return null; const s = digestSlot(dg, now); return s && m.digestDay !== s ? s : null; };
async function digestBuild(now) { // needs core, logs and calls loaded
  const since = now - 864e5, iso = new Date(since).toISOString(), n = (k, w) => plural(k, w);
  const acts = Object.values(D.logs).flat().filter(e => e.time >= since && MOD_TYPES.includes(e.type) && e.status !== 'reverted').length;
  const reps = D.calls.filter(c => c.t >= since).length, open = D.calls.filter(c => c.status === 'open').length, apps = D.appeals.filter(a => a.status === 'open').length, alerts = (D.alerts || []).filter(a => a.t >= since).length;
  let boxes = null; if (feat('chatLogs')) try { const r = await cbFetch(`chat_boxes?select=id&wid=eq.${CTX.wid}&flagged=is.true&closed_at=gt.${iso}&limit=1000`, { ms: 3000 }); if (r.ok) boxes = (await r.json()).length; } catch {}
  const probs = {}; try { const r = await cbFetch(`panel_events?select=kind&wid=eq.${CTX.wid}&at=gt.${iso}&limit=500`, { ms: 3000 }); if (r.ok) for (const e of await r.json()) probs[e.kind] = (probs[e.kind] || 0) + 1; } catch {}
  const outages = ((D.meta.health || {}).log || []).filter(x => x.up >= since).length + (D.meta.health && D.meta.health.down ? 1 : 0);
  const PK = { oc_fail: 'failed Roblox API call', webhook_fail: 'failed Discord message', sync_error: 'game check-in error', rate_limit: 'slowed-down game check-in' };
  const pl = [...(outages ? [`the game lost contact ${outages === 1 ? 'once' : outages + ' times'}`] : []), ...Object.entries(PK).filter(([k]) => probs[k]).map(([k, w]) => n(probs[k], w))];
  const text = `Last 24 hours: ${n(acts, 'moderation action')}, ${n(reps, 'report')}, ${n(alerts, 'chat alert')}${boxes === null ? '' : `, ${n(boxes, 'flagged chat log')}`}. Waiting: ${n(open, 'open report')}, ${n(apps, 'ban appeal')}. Problems: ${pl.length ? pl.join(', ') : 'none'}.`;
  return { text, fields: [['Actions', String(acts)], ['Reports', String(reps)], ['Open reports', String(open)], ['Appeals waiting', String(apps)], ['Chat alerts', String(alerts)], ['Flagged chat logs', boxes === null ? 'n/a' : String(boxes)], ['Problems', pl.length ? pl.join(', ') : 'None']] };
}
async function tickRun() { // every 5 minutes from an outside pinger, and once a day from the Vercel cron. Loads only the workspaces that need something
  const t0 = Date.now(), rows = await sbGet('select=key,meta:value->meta,dg:value->settings->digest&key=like.w*:core'), out = { digests: 0, down: 0, partial: false };
  for (const r of rows) {
    const now = Date.now(); if (!digestDue(r.meta, r.dg, now) && !healthDue(r.meta, now)) continue;
    if (now - t0 > 11000) { out.partial = true; break; }
    for (let i = 0; i < 4; i++) { // the claim is saved before anything is sent, so a tick running at the same moment skips it
      resetState(); setWid(r.key.slice(1, 13)); await need('core');
      const t = Date.now(), dd = digestDue(D.meta, D.settings.digest, t), hd = healthDue(D.meta, t); if (!dd && !hd) break;
      if (dd) { await need('logs', 'calls'); const d = await digestBuild(t); D.meta.digestDay = dd; D.notices = [...(D.notices || []).filter(x => x && x.kind !== 'digest' && x.exp > t), { id: rnd(6), kind: 'digest', t, exp: t + 2 * 864e5, title: 'Daily summary', text: d.text }]; notify('digest', `Daily summary: ${D.meta.name}`, d.text, d.fields); }
      if (hd) { const since = D.meta.lastSyncAt, mins = Math.round((t - since) / 6e4); D.meta.health = { ...(D.meta.health || {}), down: t, since }; healthNote('down', 'Your game lost contact with Sentinel', `No game server has checked in for ${plural(mins, 'minute')}, while players were in game. Check that the game is running, HTTP requests are allowed and the script is in place.`, t); notify('health', 'Game lost contact', `No game server has checked in for ${plural(mins, 'minute')}, while players were in game.`, [], 0xe5484d); }
      if (await commit()) { await sendHooks(); await sendEvents(); if (dd) out.digests++; if (hd) out.down++; break; }
      HOOKS = []; await new Promise(z => setTimeout(z, 25 + Math.random() * 100));
    }
  }
  resetState(); const bx = { closed: 0, partial: false }; try { await boxIdleRun(t0, 12500, bx); } catch (e) { console.warn('[Sentinel] chat box save: ' + String((e && e.message) || e).slice(0, 200)); } resetState(); out.chatClosed = bx.closed; return out;
}

async function erasePlayer(id) { // everything this workspace stores about one player. A running ban is kept, without the name, for community safety. Needs core, logs, play, calls, chat and cbo loaded
  const names = new Set([D.play[id]?.name, D.bans[id]?.name, D.mutes[id]?.name, ...D.calls.filter(c => c.from.userId === id).map(c => c.from.name), ...R.chat.filter(m => m.userId === id).map(m => m.name), ...(D.logs[id] || []).map(e => e.name)].filter(x => x && String(x).length >= 3));
  await need(shOf(id)); if (D.hist[id % SH]) delete D.hist[id % SH][id];
  delete D.logs[id]; delete D.play[id]; delete D.mutes[id]; delete D.signals[id]; delete D.watch[id];
  if (D.bans[id]) D.bans[id] = { userId: id, name: 'User ' + id, reason: 'Retained for community safety', time: D.bans[id].time, expires: D.bans[id].expires };
  D.calls = D.calls.filter(c => c.from.userId !== id); D.calls.forEach(c => c.chat = (c.chat || []).filter(m => m.userId !== id)); R.chat = R.chat.filter(m => m.userId !== id);
  D.appeals = D.appeals.filter(a => a.uid !== id); D.kicks = (D.kicks || []).filter(k => k.userId !== id);
  await forgetInBoxes(CTX.wid, id); for (const o of Object.values(CBO)) o.msgs = o.msgs.filter(m => m.userId !== id);
  await need('vault'); VT.items = VT.items.filter(x => x.uid !== id); for (const x of VT.items) if (x.msgs) x.msgs = x.msgs.filter(m => m.userId !== id);
  if (D.session) delete D.session.attendees[id]; D.sessions.forEach(s => s.attendees = s.attendees.filter(a => a.userId !== id));
  const scrub = t => [...names].reduce((x, n) => x.split(n).join('[erased user]'), t);
  D.feed.forEach(f => f.text = scrub(f.text)); D.audit.forEach(a => a.text = scrub(a.text));
}
// per-workspace limits the site admin can change (D.meta.caps), so one workspace can't fill the database
const CAP_DEF = { members: 100, logbook: 50000 };
const capOf = k => { const v = D.meta && D.meta.caps && D.meta.caps[k]; return Number.isInteger(v) && v > 0 ? v : CAP_DEF[k]; };
const logCount = () => Object.values(D.logs).reduce((n, l) => n + l.length, 0);
function trimLogs(max, protect) { // over the logbook limit: oldest points and notes go first, then the oldest finished records. Running bans and mutes are never removed
  let over = logCount() - max; if (over <= 0) return 0;
  const keep = new Set([...Object.values(D.bans), ...Object.values(D.mutes)].map(x => x && x.entry).filter(Boolean).concat(protect || [])), all = [];
  for (const [id, l] of Object.entries(D.logs)) for (const e of l) if (!keep.has(e.id) && !(e.type === 'Note' && e.pin)) all.push([id, e]);
  const rank = e => (e.type === 'Points' || e.type === 'Note' ? 0 : 1);
  all.sort((a, b) => rank(a[1]) - rank(b[1]) || a[1].time - b[1].time);
  const drop = new Set(all.slice(0, over).map(x => x[1].id)); let n = 0;
  for (const [id, l] of Object.entries(D.logs)) { const k = l.filter(e => !drop.has(e.id)); n += l.length - k.length; if (k.length) D.logs[id] = k; else delete D.logs[id]; }
  return n;
}
function logEntry(userId, name, e) {
  const list = (D.logs[userId] ||= []), x = { id: rnd(6), name, status: 'active', time: Date.now(), ...e };
  list.push(x); if (list.length > 500) list.splice(0, list.length - 500);
  if (MOD_TYPES.includes(x.type)) { daily().a++; rkAdd(userId, name, x.type, x.id); }
  if (D.meta) { const cap = capOf('logbook'); let n = logCount(); if (n > cap) { const t = trimLogs(cap, x.id); n -= t; feed(`Logbook limit reached: removed ${t} old ${t === 1 ? 'entry' : 'entries'}`, 'Sentinel'); } D.meta.logN = n; }
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
function act({ action, userId, name, reason, minutes, by = 'Automation', byUid = null, ruleId = null, extra = null, hide = true, alts = true }) {
  const expires = minutes > 0 ? Date.now() + minutes * 60000 : null;
  const log = type => { const e = logEntry(userId, name, { type, reason, minutes, by, byUid, ruleId, ...(extra || {}) }); feed(`${type}: ${name} (${reason})`, by); return e; };
  if (action === 'ban') {
    abuseTick('ban'); const mb = machineOn() && alts !== false, e = log(expires ? 'Suspended' : 'Banned'); if (mb) e.machine = true; D.bans[userId] = { userId, name, reason, time: Date.now(), expires, entry: e.id, by };
    { const sg = D.signals[userId]; if (sg && sg.status === 'open') { sg.status = 'confirmed'; sg.by = by; sg.done = Date.now(); } } // an alt-account hint that ended in a ban
    cmd({ type: 'ban', userId, reason, display: banText(D.bans[userId], true), seconds: minutes > 0 ? minutes * 60 : -1, alts: mb });
    if (mb) OCQ.push({ id: +userId, active: true, seconds: minutes > 0 ? minutes * 60 : 0, display: banText(D.bans[userId], true), private: `${reason} (by ${by})`, alts: true, entry: e.id }); notify('bans', `${expires ? 'Suspended' : 'Banned'} ${name}`, reason, [['Length', fmtMin(minutes)], ['By', by]], 0xe5484d);
  } else if (action === 'unban') { delete D.bans[userId]; log('Unbanned'); unbanCmd(userId); notify('bans', `Unbanned ${name}`, reason, [['By', by]], 0x30a46c); }
  else if (action === 'mute') { const e = log('Muted'); D.mutes[userId] = { userId, name, reason, expires, entry: e.id, hide: hide !== false }; const len = expires ? 'for ' + fmtMin(minutes) : 'until a moderator lifts it'; const mt = hide !== false ? `You can't chat ${len}. Reason: ${reason}` : `You are muted ${len}. You can still type, but nobody can see your messages. Reason: ${reason}`; cmd({ type: 'message', kind: 'warn', title: 'You were muted', body: mt, userId, text: mt }); }
  else if (action === 'unmute') { delete D.mutes[userId]; log('Unmuted'); }
  else if (action === 'kick') { D.stats.kicks++; log('Kicked'); D.kicks = (D.kicks || []).filter(k => Date.now() - k.t < 36e5).concat({ userId: +userId, name, t: Date.now() }).slice(-50); cmd({ type: 'kick', userId, reason: 'Kicked: ' + reason }); notify('kicks', `Kicked ${name}`, reason, [['By', by]], 0xf76b15); }
  else if (action === 'warn') {
    const we = log('Warned'), ak = !!D.settings.warnAck && !(D.mutes[userId] && live(D.mutes[userId])) && !(D.bans[userId] && live(D.bans[userId])); if (ak) we.ackWant = Date.now(); // the player script shows "I understand"; nothing is blocked
    cmd({ type: 'message', kind: 'warn', title: 'Warning', body: reason, userId, text: 'Warning: ' + reason, ...(ak ? { ack: we.id } : {}) }); notify('warns', `Warned ${name}`, reason, [['By', by]], 0xffc53d);
    let n = 0; // active warnings since the last suspension or ban
    for (const e of [...D.logs[userId]].reverse()) { if (e.status === 'reverted') continue; if (e.type === 'Suspended' || e.type === 'Banned') break; if (e.type === 'Warned') n++; }
    const r = rule('autosuspend');
    if (r.enabled && n >= r.warns && we.ackWant) { delete we.ackWant; for (const c of R.cmds) if (c.ack === we.id) delete c.ack; } // the suspension comes first, so no "I understand" card
    if (r.enabled && n >= r.warns) act({ action: 'ban', userId, name, reason: `Automatic: ${r.warns} warnings`, minutes: r.minutes, by: 'Automation' });
  }
}
const isStaffId = uid => !!D.members['r_' + uid] || Object.values(D.members).some(m => m.robloxId && String(m.robloxId) === String(uid));
function amPrune(now) { for (const [k, v] of Object.entries(R.am)) { if (Array.isArray(v)) { const f = v.filter(t => t > now - 36e5); if (f.length) R.am[k] = f; else delete R.am[k]; } else if (!(v > now - 6e5)) delete R.am[k]; } }
function amHit(id, uid, name, why, now) { // apply an automatic rule's action once per player per 30 seconds
  const r = rule(id), k = `c:${id}:${uid}`; if ((R.am[k] || 0) > now - 30000) return false; R.am[k] = now;
  act({ action: r.action, userId: uid, name, reason: 'Automatic: ' + why, minutes: r.action === 'mute' ? r.minutes : 0, by: 'Automation' }); return true;
}
// one definition of "a link", "shouting", "the same message" and "spam", shared by the auto-moderation rules and the chat log flags
const LINK_RE = /(https?:\/\/|www\.|\b[a-z0-9-]{2,}\.(com|net|org|gg|io|co|xyz|ru|tk|ly|me)\b)/i;
const isLink = t => LINK_RE.test(String(t));
const isShout = (t, pct) => { const l = String(t).replace(/[^a-z]/gi, ''); return l.length >= 12 && l.replace(/[^A-Z]/g, '').length * 100 / l.length >= pct; };
const nz = x => String(x).toLowerCase().replace(/\s+/g, ' ').trim();
const burst = (list, uid, now, seconds) => list.filter(m => m.userId === uid && m.t > now - seconds * 1000 && m.t <= now).length; // messages from one player in the last few seconds
function autoMod(uid, name, text, now) { // spam, repeats, links and shouting; staff and already-muted players are left alone
  if (!uid || isStaffId(uid) || (D.mutes[uid] && live(D.mutes[uid]))) return;
  amPrune(now);
  const sp = rule('spam'); if (sp.enabled && burst(R.chat, uid, now, sp.seconds) >= sp.messages && amHit('spam', uid, name, `spam (${sp.messages} messages in ${sp.seconds} seconds)`, now)) return;
  const rp = rule('repeat'); if (rp.enabled) { const mine = R.chat.filter(m => m.userId === uid && m.t > now - 6e4).slice(-rp.times); if (mine.length >= rp.times && mine.every(m => nz(m.text) === nz(text)) && amHit('repeat', uid, name, `repeated the same message ${rp.times} times`, now)) return; }
  const lk = rule('links'); if (lk.enabled && isLink(text) && amHit('links', uid, name, 'posted a link', now)) return;
  const cp = rule('caps'); if (cp.enabled && isShout(text, cp.percent) && amHit('caps', uid, name, 'shouting in capital letters', now)) return;
}

// ---- chat logs: chat grouped into boxes of up to 10 messages from one game server, kept in the chat_boxes table (see supabase.sql)
const BOX_N = 10, BOX_IDLE = 5 * 60000, CB_MAX_N = +env.CHATLOG_MAX_BOXES || 25000, CB_MAX_BYTES = (+env.CHATLOG_MAX_MB || 40) * 1e6, CB_PAGE = 20, CB_OPEN_MAX = 200;
const BOX_ID_RE = /^[A-Z0-9]{9}-[A-Z0-9]{8}$/;
const boxId = () => { const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', r = n => Array.from({ length: n }, () => A[crypto.randomInt(36)]).join(''); return r(9) + '-' + r(8); };
const CHAT_FLAGS = { strong: 'Strong language or slur', mild: 'Mild language', link: 'Link', invite: 'Discord invite', pii: 'Possible personal info', caps: 'Shouting', repeat: 'Same message repeated', spam: 'Rapid-fire spam', long: 'Very long message', garble: 'Strange characters' };
const chatDays = () => [7, 14, 30].includes(D.settings.chatDays) ? D.settings.chatDays : 14;
// swearing and slurs. Owners can replace the list in Settings, Automations. Only used to help staff look: nothing is punished from it
const DEFAULT_CUSS = {
  mild: ['damn', 'dammit', 'hell', 'crap', 'piss', 'pissed', 'ass', 'arse', 'dick', 'prick', 'wanker', 'bollocks', 'bastard', 'douche', 'jackass', 'dumbass', 'bloody'],
  strong: ['fuck', 'fck', 'fuk', 'shit', 'cunt', 'bitch', 'asshole', 'motherfuck', 'whore', 'slut', 'twat', 'cock', 'pussy', 'nigger', 'nigga', 'faggot', 'fag', 'retard', 'tranny', 'kike', 'spic', 'chink'],
};
const CUSS_OK = new Set(['shitake', 'shiitake', 'cocktail', 'cocktails', 'cockpit', 'cockpits', 'cockroach', 'cockroaches', 'cockatoo', 'cockatiel', 'cockney', 'cockerel', 'cockle', 'cockles', 'spice', 'spices', 'spiced', 'spicy', 'spicey', 'spicier', 'spiciest', 'niggard', 'niggardly', 'retardant', 'retardants', 'pussycat', 'pussywillow', 'chinking', 'chinked', 'scunthorpe', 'fagin']);
const cussList = () => { const c = D.cussWords; return c && Array.isArray(c.mild) && Array.isArray(c.strong) ? c : DEFAULT_CUSS; };
const LEET = { 0: 'o', 1: 'i', 3: 'e', 4: 'a', 5: 's', 7: 't', 8: 'b', 9: 'g', '@': 'a', $: 's', '!': 'i', '+': 't', '|': 'i', '€': 'e' };
const once = s => s.replace(/([a-z])\1+/g, '$1'); // "fuuuck" -> "fuck"
function cussTokens(text) { // lower case, leetspeak undone, spaced-out or dotted letters joined ("f u c k", "f.u.c.k")
  const s = String(text).toLowerCase().normalize('NFKD').replace(/[̀-ͯ]/g, ''), out = [];
  let run = [];
  const flush = () => { if (run.length >= 3) out.push(run.join('')); else out.push(...run); run = []; };
  for (const w0 of s.split(/\s+/)) {
    const w = w0.replace(/[!?.,]+$/, '').replace(/[0134578@$!+|€9]/g, c => LEET[c] || c), seg = w.split(/[^a-z*]+/).filter(Boolean); // "hell!" stays "hell", "sh!t" becomes "shit"
    if (seg.length >= 3 && seg.every(x => x.length === 1)) { flush(); out.push(seg.join('')); continue; }
    if (seg.length === 1 && seg[0].length === 1) { run.push(seg[0]); continue; }
    flush(); out.push(...seg);
  }
  flush(); return out;
}
function cussHit(text, list = cussList()) { // the worst word found, or null
  let best = null;
  for (const t of cussTokens(text)) {
    if (CUSS_OK.has(t) || CUSS_OK.has(once(t))) continue;
    const vs = new Set([t, t.replace(/v/g, 'u'), t.replace(/ph/g, 'f')]);
    for (const sev of ['strong', 'mild']) {
      for (const w0 of list[sev]) {
        const w = String(w0).toLowerCase().trim(); if (!w) continue;
        const hit = [...vs].some(v => {
          if (v.includes('*')) return v.length === w.length && v.replace(/\*/g, '').length >= 2 && new RegExp('^' + v.replace(/\*/g, '[a-z]') + '$').test(w);
          if (v === w || (v !== once(v) && once(v) === once(w) && once(w).length >= 3)) return true; // exact, or stretched out ("shiiiit")
          return sev === 'strong' && w.length >= 4 && (v.startsWith(w) || once(v).startsWith(once(w))); // "fucking", "shitty"
        });
        if (hit) { if (sev === 'strong') return { sev, word: w }; best ||= { sev, word: w }; }
      }
    }
  }
  return best;
}
const INVITE_RE = /(discord(?:app)?\.(?:gg|com\/invite)|dsc\.gg)\/[\w-]+/i, EMAIL_RE = /[a-z0-9._%+-]+@[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}/i, PHONE_RE = /(?<![\w+])\+?\d(?:[\s().-]?\d){8,13}(?!\w)/;
const GARBLE_RE = /[^\p{L}\p{N}\p{Extended_Pictographic}\s.,!?'"()\-:;‍️]{8,}/u, ZALGO_RE = /[̀-ͯ҉]{3,}/;
function chatFlags(msgs) { // why each message is worth a look. Stored with the box; staff decide what to do
  const cw = cussList(), sp = rule('spam'), cp = rule('caps');
  return msgs.map((m, i) => {
    const t = String(m.text || ''), f = [], c = cussHit(t, cw);
    if (c) f.push(c.sev);
    if (INVITE_RE.test(t)) f.push('invite'); else if (isLink(t.replace(new RegExp(EMAIL_RE.source, 'gi'), ' '))) f.push('link'); // an email address is personal info, not a link
    if (EMAIL_RE.test(t) || PHONE_RE.test(t)) f.push('pii');
    if (isShout(t, cp.percent)) f.push('caps');
    if (msgs.slice(0, i + 1).filter(x => x.userId === m.userId && nz(x.text) === nz(t)).length >= 3) f.push('repeat');
    if (burst(msgs, m.userId, m.t, sp.seconds) >= Math.min(sp.messages, BOX_N)) f.push('spam');
    if (t.length >= 150) f.push('long');
    if (GARBLE_RE.test(t) || ZALGO_RE.test(t)) f.push('garble');
    const { flags, ...rest } = m; return f.length ? { ...rest, flags: f } : rest;
  });
}
function boxClose(j, at) {
  const o = CBO[j]; delete CBO[j]; if (!o || !o.msgs.length) return;
  const msgs = chatFlags(o.msgs), types = [...new Set(msgs.flatMap(m => m.flags || []))];
  const row = { id: o.id, wid: CTX.wid, opened_at: new Date(o.opened).toISOString(), closed_at: new Date(at).toISOString(), server: String(j).slice(0, 8), user_ids: [...new Set(msgs.map(m => m.userId).filter(x => x > 0))],
    names: ' ' + [...new Set(msgs.map(m => String(m.name).toLowerCase()))].join(' ') + ' ', body: msgs.map(m => String(m.text).toLowerCase()).join('\n'), flagged: types.length > 0, flag_types: types, msgs };
  row.bytes = Buffer.byteLength(JSON.stringify(msgs)); CBQ.push(row);
  for (const id of row.user_ids) { const mine = msgs.filter(m => m.userId === id && m.flags && m.flags.length); if (mine.length) rkAdd(id, mine[0].name, mine.some(m => m.flags.includes('strong')) ? 'boxStrong' : 'box', row.id); } // feeds the risk score
}
function boxAdd(j, m) { // one chat message from game server j
  let o = CBO[j]; // a box stays open until it holds 10 messages (or its server shuts down)
  if (!o) { const open = Object.entries(CBO); if (open.length >= CB_OPEN_MAX) { const [oj, oo] = open.sort((a, b) => a[1].last - b[1].last)[0]; boxClose(oj, oo.last); } o = CBO[j] = { id: boxId(), opened: m.t, last: m.t, msgs: [] }; }
  o.msgs.push(m); o.last = m.t; if (o.msgs.length >= BOX_N) boxClose(j, m.t);
}
const SV_GONE = 120000; // a game server that has not checked in for 2 minutes has shut down
const boxSweep = (now, sv = R.servers) => { for (const [j, o] of Object.entries(CBO)) { const s = sv && sv[j]; if ((!s || now - s.last > SV_GONE) && now - o.last > 60000) boxClose(j, o.last); } }; // the last, part-full box of a server that shut down
async function cbFetch(path, o = {}) { const { ms, headers, ...rest } = o; return fetch(`${SB_URL}/rest/v1/${path}`, { ...rest, headers: { ...sbHeaders(), ...(headers || {}) }, signal: AbortSignal.timeout(ms || 4000) }); }
async function ownBoxes(ids) { // the chat box IDs that exist in this workspace
  const ok = [...new Set(ids.map(x => String(x).toUpperCase()).filter(x => BOX_ID_RE.test(x)))].slice(0, 5); if (!ok.length) return [];
  try { const r = await cbFetch(`chat_boxes?select=id&wid=eq.${CTX.wid}&id=in.(${ok.join(',')})`, { ms: 3000 }); if (!r.ok) return []; const have = new Set((await r.json()).map(x => x.id)); return ok.filter(x => have.has(x)); } catch { return []; }
}
const boxOut = b => ({ id: b.id, t: Date.parse(b.closed_at), opened: Date.parse(b.opened_at), server: b.server, users: b.user_ids || [], flagged: !!b.flagged, types: b.flag_types || [], msgs: b.msgs || [] });
const cbClean = (s, n) => String(s || '').replace(/[%*,()\\:."'{}\[\]]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, n); // nothing that means something to the database query
async function chatLogs(url, p, res) { // GET /api/chatlogs (search, newest first) and /api/chatlogs/box?id=
  const sp = url.searchParams, days = chatDays(), page = clampInt(sp.get('page'), 0, 500) || 0, terms = [];
  boxSweep(Date.now()); await sendBoxes(); // close quiet servers' boxes now, so they show up
  const f = [`wid=eq.${CTX.wid}`, `closed_at=gte.${new Date(Date.now() - days * 864e5).toISOString()}`];
  const open = Object.entries(CBO).map(([j, o]) => { const msgs = chatFlags(o.msgs), types = [...new Set(msgs.flatMap(m => m.flags || []))]; return { id: o.id, t: o.last, opened: o.opened, server: String(j).slice(0, 8), users: [...new Set(msgs.map(m => m.userId).filter(x => x > 0))], flagged: types.length > 0, types, msgs, open: true, max: BOX_N }; }).sort((a, b) => b.t - a.t); // boxes still filling up, live
  if (p === '/api/chatlogs/box') { const id = String(sp.get('id') || '').toUpperCase().trim(); if (!BOX_ID_RE.test(id)) return send(res, 400, { error: 'That is not a chat box ID.' }); const ob = open.find(b => b.id === id); if (ob) return send(res, 200, { box: ob, days }); f.push(`id=eq.${id}`); }
  else {
    const q = String(sp.get('q') || '').toUpperCase().replace(/[^A-Z0-9-]/g, '').slice(0, 18); if (q) { f.push(BOX_ID_RE.test(q) ? `id=eq.${q}` : `id=ilike.*${q}*`); terms.push(q); }
    const us = cbClean(sp.get('user'), 40).toLowerCase(); if (us) { if (/^\d{1,19}$/.test(us)) f.push(`user_ids=cs.%7B${us}%7D`); else { f.push(`names=ilike.*${encodeURIComponent(us)}*`); terms.push(us); } }
    const kws = cbClean(sp.get('kw'), 60).toLowerCase().split(' ').filter(Boolean).slice(0, 3);
    if (kws.length) { f.push(kws.length === 1 ? `body=ilike.*${encodeURIComponent(kws[0])}*` : `and=(${kws.map(k => `body.ilike.*${encodeURIComponent(k)}*`).join(',')})`); terms.push(...kws); }
    const day = k => { const v = String(sp.get(k) || ''); return /^\d{4}-\d{2}-\d{2}$/.test(v) && !isNaN(Date.parse(v + 'T00:00:00Z')) ? Date.parse(v + 'T00:00:00Z') : null; };
    const from = day('from'), to = day('to'); if (from !== null) f.push(`closed_at=gte.${new Date(from).toISOString()}`); if (to !== null) f.push(`closed_at=lt.${new Date(to + 864e5).toISOString()}`);
    const sv = String(sp.get('server') || '').toLowerCase().replace(/[^a-z0-9-]/g, '').slice(0, 8); if (sv) f.push(`server=ilike.${sv}*`);
    const ty = String(sp.get('type') || ''); if (ty && CHAT_FLAGS[ty]) f.push(`flag_types=cs.%7B${ty}%7D`); else if (sp.get('flagged') === '1') f.push('flagged=is.true');
    const fl = sp.get('flagged') === '1'; // the same filters, for the open boxes
    for (let i = open.length - 1; i >= 0; i--) { const b = open[i], body = b.msgs.map(m => String(m.text).toLowerCase()).join(String.fromCharCode(10)), names = b.msgs.map(m => String(m.name).toLowerCase()).join(' ');
      if ((q && !b.id.includes(q)) || (us && (/^\d{1,19}$/.test(us) ? !b.users.includes(+us) : !names.includes(us))) || kws.some(k => !body.includes(k)) || (from !== null && b.t < from) || (to !== null && b.t >= to + 864e5) || (sv && !b.server.toLowerCase().startsWith(sv)) || (ty && CHAT_FLAGS[ty] ? !b.types.includes(ty) : fl && !b.flagged)) open.splice(i, 1); }
  }
  let r = null, txt = '';
  try { r = await cbFetch(`chat_boxes?select=id,opened_at,closed_at,server,user_ids,flagged,flag_types,msgs&${f.join('&')}&order=closed_at.desc&limit=${CB_PAGE}&offset=${page * CB_PAGE}`, { headers: { Prefer: 'count=exact' }, ms: 6000 }); if (!r.ok) txt = await r.text(); } catch (e) { txt = String(e.message || e); }
  if (!r || !r.ok) { if ((r && r.status === 404) || /chat_boxes|42P01|PGRST20/.test(txt)) return send(res, 200, { setup: false, boxes: [], total: 0, page: 0, pages: 1, terms, days }); console.warn('[Sentinel] chat log search failed: ' + txt.slice(0, 200)); return send(res, 502, { error: 'Could not load chat logs right now. Try again in a moment.' }); }
  const boxes = (await r.json()).map(boxOut), total = +((r.headers.get('content-range') || '').split('/')[1]) || boxes.length;
  if (p === '/api/chatlogs/box') return boxes.length ? send(res, 200, { box: boxes[0], days }) : send(res, 404, { error: `No chat box with that ID in this workspace. Boxes are kept for ${days} days.` });
  return send(res, 200, { setup: true, boxes: page ? boxes : [...open, ...boxes], total: total + open.length, page, pages: Math.max(1, Math.ceil(total / CB_PAGE)), terms, days });
}
async function boxesOf(id) { // a player's own messages in this workspace's chat logs (for a data export)
  try { const r = await cbFetch(`chat_boxes?select=id,closed_at,msgs&wid=eq.${CTX.wid}&user_ids=cs.%7B${id}%7D&order=closed_at.desc&limit=2000`, { ms: 6000 }); if (!r.ok) return []; return (await r.json()).flatMap(b => (b.msgs || []).filter(m => m.userId === id).map(m => ({ box: b.id, t: m.t, text: m.text }))); } catch { return []; }
}
async function forgetInBoxes(wid, id) { // removes one player's messages from a workspace's chat logs
  try { const r = await cbFetch('rpc/chat_box_forget', { method: 'POST', body: JSON.stringify({ w: wid, uid: id }), ms: 6000 }); return r.ok ? +(await r.json()) || 0 : 0; } catch { return 0; }
}
// ---- feature flags (row g:flags): a feature can be on for chosen workspaces first, then for everyone
const FLAG_DEF = { machineBans: { all: true, wids: [] }, chatLogs: { all: false, wids: [] } }; // machine bans shipped in 5.4, so it stays on for everyone
const FLAG_NAMES = { machineBans: 'Machine bans', chatLogs: 'Chat logs' };
let FC = { t: 0, v: null, ver: 0 };
// ---- appeal games: Roblox games run by Sentinel where a banned player can appeal to any workspace that banned them. Registered in the admin console, each with its own key
let HC = { t: 0, ver: 0, v: [] };
async function hubsLoad(force) { // cached for a minute; the first one in the list is the one named on ban screens
  if (!force && HC.t && Date.now() - HC.t < 60000) return HC.v;
  try { const r = (await sbGet('select=value,version&key=eq.g:hubs'))[0]; HC = { t: Date.now(), ver: r ? r.version : 0, v: r && r.value && Array.isArray(r.value.list) ? r.value.list : [] }; } catch { HC.t = Date.now(); }
  return HC.v;
}
async function hubsSave(list) {
  const r = await sbf(`${SB_URL}/rest/v1/rpc/panel_commit`, { method: 'POST', headers: sbHeaders(), body: JSON.stringify({ changes: [{ key: 'g:hubs', expect: HC.ver, value: { list } }] }) });
  if (!r.ok || (await r.json()) !== true) { HC.t = 0; return false; }
  HC = { t: Date.now(), ver: HC.ver + 1, v: list }; return true;
}
const HUB_KEY_RE = /^hub_[a-f0-9]{8}_[\w-]{32}$/;
const hubMain = () => (HC.v || [])[0] || null;
const hubOn = () => !!(hubMain() && D.meta && D.settings.appeals !== false && D.settings.hubAppeals !== false); // this workspace takes appeals from the appeal game
const hubLink = h => `https://www.roblox.com/games/${h.placeId}`;
async function hubAuth(key) { const k = String(key || ''); if (!HUB_KEY_RE.test(k)) return null; const kh = hash('hub:' + k).toString('hex'); return (await hubsLoad()).find(h => h.kh && same(h.kh, kh)) || null; }
async function flagsLoad(force) { // cached for 30 seconds; a missing or unreadable row means the defaults
  if (!force && FC.v && Date.now() - FC.t < 30000) return FC.v;
  try { const r = (await sbGet('select=value,version&key=eq.g:flags'))[0]; const v = r && r.value && typeof r.value === 'object' ? r.value : {}; FC = { t: Date.now(), ver: r ? r.version : 0, v: Object.fromEntries(Object.keys(FLAG_DEF).map(k => [k, { all: v[k] ? !!v[k].all : FLAG_DEF[k].all, wids: v[k] && Array.isArray(v[k].wids) ? v[k].wids.filter(w => /^[a-f0-9]{12}$/.test(w)) : [] }])) }; }
  catch { FC = { t: Date.now(), ver: FC.ver, v: FC.v || FLAG_DEF }; }
  return FC.v;
}
const feat = (name, wid = CTX.wid) => { const f = (FC.v || FLAG_DEF)[name] || FLAG_DEF[name]; return !!(f && (f.all || (wid && f.wids.includes(wid)))); };
// ---- problems for the admin console (table panel_events). Never allowed to break the request that hit them
let EVQ = [];
const logEvent = (kind, msg, wid = CTX.wid) => { if (EVQ.length < 20) EVQ.push({ wid: wid || '', kind, msg: String(msg || '').replace(/\s+/g, ' ').slice(0, 300) }); };
async function sendEvents() { if (!EVQ.length) return; const rows = EVQ.splice(0); try { const r = await cbFetch('panel_events', { method: 'POST', headers: { Prefer: 'return=minimal' }, body: JSON.stringify(rows), ms: 2500 }); if (!r.ok) throw new Error('HTTP ' + r.status); } catch (e) { console.warn('[Sentinel] panel_events insert failed: ' + String((e && e.message) || e).slice(0, 120)); } }
// ---- abuse signals: bans and public form submissions per hour (last 48 hours)
function abuseTick(k) { const a = (D.abuse ||= {}), h = String(Math.floor(Date.now() / 36e5)), m = (a[k] ||= {}); m[h] = (m[h] || 0) + 1; for (const x of Object.keys(m)) if (+x < +h - 48) delete m[x]; }
async function sendBoxes() { // after the save: closed boxes go to the chat_boxes table. A missing table (SQL not run yet) must never break game sync
  if (!CBQ.length) return; const rows = CBQ.splice(0);
  try {
    const ins = async list => { const r = await cbFetch('chat_boxes?on_conflict=id&select=id', { method: 'POST', headers: { Prefer: 'resolution=ignore-duplicates,return=representation' }, body: JSON.stringify(list), ms: 3000 }); if (!r.ok) throw new Error('HTTP ' + r.status + ' ' + (await r.text()).slice(0, 160)); return new Set((await r.json()).map(x => x.id)); };
    const got = await ins(rows), miss = rows.filter(x => !got.has(x.id));
    if (miss.length) { // an id already taken: the same box saved before (skip), or another box by pure chance (new id, once)
      const r = await cbFetch(`chat_boxes?id=in.(${miss.map(x => x.id).join(',')})&select=id,wid,opened_at`, { ms: 3000 }), have = r.ok ? await r.json() : [];
      const again = miss.filter(x => !have.some(h => h.id === x.id && h.wid === x.wid && Date.parse(h.opened_at) === Date.parse(x.opened_at))).map(x => ({ ...x, id: boxId() }));
      if (again.length) await ins(again);
    }
    await cbFetch('rpc/chat_box_trim', { method: 'POST', body: JSON.stringify({ w: rows[0].wid, max_n: CB_MAX_N, max_bytes: CB_MAX_BYTES }), ms: 3000 }).catch(() => {});
  } catch (e) { console.warn('[Sentinel] chat_boxes insert failed: ' + String((e && e.message) || e).slice(0, 200)); }
}
function autoJoin(uid, name, now) { // someone joining again and again in a short time
  const rj = rule('rapidjoin'); if (!rj.enabled || !uid || isStaffId(uid)) return;
  amPrune(now); const k = 'j:' + uid, arr = (R.am[k] = (R.am[k] || []).filter(t => t > now - rj.seconds * 1000)); arr.push(now);
  if (arr.length >= rj.joins) { R.am[k] = []; amHit('rapidjoin', uid, name, `joined ${rj.joins} times in ${rj.seconds} seconds`, now); }
}
function sync(b) {
  const now = Date.now(), id = String(b.jobId || 'studio').slice(0, 64), prev = R.servers[id], dt = prev ? Math.min((now - prev.last) / 1000, 30) : 0;
  const players = (Array.isArray(b.players) ? b.players : []).slice(0, 200).filter(p => p && Number.isInteger(p.userId) && p.userId > 0)
    .map(p => ({ userId: p.userId, name: String(p.name || p.userId).slice(0, 40), displayName: String(p.displayName || p.name || '').slice(0, 40) }));
  R.servers[id] = { players, last: now, first: prev ? prev.first || now : now, sv: Number.isInteger(b.scriptV) && b.scriptV > 0 && b.scriptV < 1000 ? b.scriptV : 1, chat: ['text', 'legacy', 'nochannel'].includes(b.chat) ? b.chat : '', muteErr: String(b.muteErr || '').replace(/[\u0000-\u001f<>]/g, '').slice(0, 160), closed: (prev && prev.closed) || 0, closeMsg: (prev && prev.closeMsg) || '' };
  for (const [j, sv] of Object.entries(R.servers)) if (now - sv.last > 6e4) delete R.servers[j];
  for (const p of players) tick({ ...p, sv: id.slice(0, 8) }, dt, now);
  for (const e of (Array.isArray(b.events) ? b.events : []).slice(0, 300)) {
    if (!e) continue;
    const text = String(e.text || '').slice(0, 200), name = String(e.name || '?').slice(0, 40), uid = Number.isInteger(e.userId) ? e.userId : 0;
    if (e.type === 'join') autoJoin(uid, name, now);
    if (e.type === 'join' && D.meta && scriptInfo().outdated && Date.now() - (D.meta.scriptAlertAt || 0) > 6 * 36e5) { // tell the owner and anyone who can change settings, in game
      const dev = Object.entries(D.members).some(([mid, m]) => m.robloxId && String(m.robloxId) === String(uid) && (mid === D.meta.owner || has(who(mid), 'automations.manage')));
      if (dev) { D.meta.scriptAlertAt = Date.now(); const msg = 'Your Sentinel game script is out of date. Open Settings, then Game on the website, download the new script and paste it into your game.'; cmd({ type: 'message', kind: 'warn', title: 'Sentinel update available', body: msg, text: 'Sentinel update: ' + msg, userId: uid }); }
    }
    if (e.type === 'join' && D.meta && !scriptInfo().outdated && clientInfo().outdated && Date.now() - (D.meta.clientAlertAt || 0) > 6 * 36e5) { // the player script is out of date: same heads-up, once every 6 hours
      const dev = Object.entries(D.members).some(([mid, m]) => m.robloxId && String(m.robloxId) === String(uid) && (mid === D.meta.owner || has(who(mid), 'automations.manage')));
      if (dev) { D.meta.clientAlertAt = Date.now(); const msg = 'Your Sentinel player script is out of date. Open Settings, then Game on the website, copy the new player script and paste it over the old one in StarterPlayerScripts.'; cmd({ type: 'message', kind: 'warn', title: 'Sentinel update available', body: msg, text: 'Sentinel update: ' + msg, userId: uid }); }
    }
    if (e.type === 'join') { D.stats.joins++; daily().j++; feed(`${name} joined`); if (D.watch[uid]) { feed(`Watchlist: ${name} joined (${D.watch[uid].reason || 'no reason'})`); notify('watch', `Watched player joined: ${name}`, D.watch[uid].reason || '', [['Server', String(b.jobId || '').slice(0, 8)]], 0xffc53d); } const w = rule('welcome'); if (w.enabled) cmd({ type: 'message', kind: 'info', userId: uid, text: w.text }); if (uid) { const h = phist(uid); if (h.cur && h.cur.s >= 5) { closeSession(h); h.cur = { t: now, s: 0, sv: id.slice(0, 8), last: now }; } } }
    else if (e.type === 'leave') { feed(`${name} left`); if (uid) closeSession(phist(uid)); }
    else if (e.type === 'chat') { // rolling buffer: latest 300 messages, at most 24 hours
      const flagged = D.flagWords.some(w => text.toLowerCase().includes(w));
      const cw = text ? cussHit(text, cussList()) : null; // swearing is only marked for staff here; automations still use the flagged words
      R.chat.push({ t: now, jobId: id, server: id.slice(0, 8), userId: uid, name, text, flagged, ...(cw ? { cuss: cw.sev } : {}) }); if (R.chat.length > 300) R.chat.shift(); autoMod(uid, name, text, now);
      if (text && feat('chatLogs')) boxAdd(id, { t: now, userId: uid, name, text });
      if (text) alertCheck(id, uid, name, text, now); // watched words: an alert for staff, never an action // the same message also goes into this server's chat log box
      if (flagged) {
        feed(`Flagged chat from ${name}: ${text}`);
        const r = rule('flaggedmute');
        if (r.enabled && (R.flagCount[uid] = (R.flagCount[uid] || 0) + 1) >= r.count) { R.flagCount[uid] = 0; act({ action: 'mute', userId: uid, name, reason: 'Automatic: repeated flagged chat', minutes: r.minutes, by: 'Automation' }); }
      }
    } else if (e.type === 'attend' && D.session) {
      D.session.attendees[uid] = name; cmd({ type: 'message', kind: 'ok', title: 'Session', body: `You are marked present for ${D.session.type}.`, userId: uid, text: `You are marked present for ${D.session.type}.` });
    } else if (e.type === 'ack') { // the player pressed "I understand" on a warning
      const x = uid && (D.logs[uid] || []).find(z => z.id === String(e.entry || '')); if (x && x.type === 'Warned' && x.ackWant && !x.ack && x.status !== 'reverted') x.ack = now;
    } else if (e.type === 'modcall') {
      const tg = e.target && Number.isInteger(e.target.userId) && e.target.userId > 0 && e.target.userId !== uid ? { userId: e.target.userId, name: String(e.target.name || e.target.userId).slice(0, 40) } : null;
      const near = R.chat.filter(c => c.jobId === id), pick = new Set([...near.slice(-15), ...(tg ? near.filter(c => c.userId === tg.userId).slice(-10) : [])]);
      const call = { id: ++D.callSeq, t: now, from: { userId: uid, name }, text: text || (tg ? 'Reported ' + tg.name : 'No details given'), server: id.slice(0, 8), status: 'open', by: null, note: '', ...(tg ? { target: tg } : {}), ...(id !== 'studio' && Number.isInteger(b.placeId) && b.placeId > 0 ? { jobId: id, placeId: b.placeId } : {}),
        chat: near.filter(c => pick.has(c)).map(({ t, userId, name, text, flagged }) => ({ t, userId, name, text, flagged })) };
      const lead = callMerge(call); D.calls.unshift(call); D.calls.length = Math.min(D.calls.length, 100); daily().r++;
      feed(`Report #${call.id} from ${name}: ${call.text}${lead ? ` (grouped with #${lead.id})` : ''}`);
      notify('reports', `Report #${call.id} from ${name}`, call.text, [['Server', id.slice(0, 8)], ...(tg ? [['Reported player', tg.name]] : []), ...(lead ? [['Grouped with', `#${lead.id}, ${grpReporters(lead.id)} reporters`]] : [])], 0x635bff);
      cmd({ type: 'message', kind: 'ok', title: 'Report sent', body: `Report #${call.id} sent. A moderator will respond soon.`, userId: uid, text: `Report #${call.id} sent. A moderator will respond soon.` });
    }
  }
  boxSweep(now);
  const total = allPlayers().length;
  if (total > D.stats.peak) D.stats.peak = total;
  if (total > ((D.daily[dayKey(now)] || {}).p || 0)) daily().p = total;
  const hist = R.history; if (!hist.length || now - hist[hist.length - 1].t > 6e4) { hist.push({ t: now, n: total }); if (hist.length > 120) hist.shift(); }
  for (const p of players) { const x = D.bans[p.userId]; if (x && live(x) && !R.cmds.some(c => c.type === 'kick' && c.userId === p.userId && now - c.t < 10000)) cmd({ type: 'kick', userId: p.userId, reason: 'Banned: ' + x.reason, display: banText(x) }); }
  R.cmds = R.cmds.filter(c => now - c.t < (c.keep ? KEEP_MS : 120000) && !(c.type === 'ban' && c.seconds > 0 && now - c.t >= c.seconds * 1000)); if (R.cmds.length > 300) R.cmds = R.cmds.slice(-300);
  if (!prev || now - prev.last > 90000) for (const c of R.cmds) if (c.keep) delete c.seen[id]; // a server that went quiet and came back (or a new Studio test, which always reports the same id) gets bans and unbans again
  if (R.servers[id].closed && now - R.servers[id].closed < 180000) for (const p of players) if (!R.cmds.some(c => c.type === 'kick' && c.userId === p.userId && c.target === id && now - c.t < 10000)) cmd({ type: 'kick', userId: p.userId, target: id, reason: 'Server closed', display: R.servers[id].closeMsg || CLOSED_MSG });
  const out = R.cmds.filter(c => !c.seen[id] && (!c.target || c.target === id)); out.forEach(c => c.seen[id] = 1);
  return { commands: out.map(({ seen, t, keep, target, ...c }) => c.type === 'ban' && c.seconds > 0 ? { ...c, seconds: Math.max(1, Math.round(c.seconds - (now - t) / 1000)) } : c), muted: Object.values(D.mutes).filter(live).map(m => m.userId), muteHide: Object.values(D.mutes).filter(m => live(m) && m.hide !== false).map(m => m.userId) };
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
  if (rb && rb.created && local && !local.created && Date.parse(rb.created)) local.created = Date.parse(rb.created);
  return { risk: riskOf(id), userId: id, name: rb ? rb.name : online ? online.name : local ? local.name : 'User ' + id, displayName: rb ? rb.displayName : online ? online.displayName : '', created: rb ? rb.created : null,
    avatar: (await avatars([id]))[id] || null, online: !!online, server: online ? online.server : null,
    banned: ban && live(ban) ? ban : null, muted: mute && live(mute) ? mute : null, signal: D.signals[id] || null, logbook: (D.logs[id] || []).slice().reverse().map(e => ({ ...e, ...entryState(e, id) })),
    play: local ? { total: Math.round(local.total), week: local.weekStart === ws ? Math.round(local.week) : 0, points: local.points } : null,
    reports: D.calls.filter(c => c.from.userId === id).slice(0, 20).map(c => ({ id: c.id, t: c.t, text: c.text, status: c.status })),
    against: D.calls.filter(c => c.target && c.target.userId === id && c.status !== 'resolved').length,
    chat: R.chat.filter(m => m.userId === id).slice(-60).reverse(), ...auditExtras(id, online), sessions: D.sessions.filter(s => s.attendees.some(a => a.userId === id)).length };
}

// ---- backups: daily snapshots, owner downloads, a 30-day recycle bin and a site-admin console ----
const BK_ROWS = ['core', 'logs', 'play', 'calls', 'forms'], BK_KEEP_DAYS = 7, TRASH_MS = 30 * 864e5, ADMIN_TOKEN = env.ADMIN_TOKEN || '', CRON_SECRET = env.CRON_SECRET || '', TICK_SECRET = env.TICK_SECRET || '';
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
  Object.assign(D, CORE_FRESH()); ROWS.core.set(snap.core); if (snap.logs) ROWS.logs.set(snap.logs); if (snap.play) ROWS.play.set(snap.play); if (snap.calls) ROWS.calls.set(snap.calls); if (snap.forms) ROWS.forms.set(snap.forms);
  migrate(); if (D.meta) { delete D.meta.deleted; if (keepHash) D.meta.codeHash = keepHash; if (keepOc) D.meta.oc = keepOc; else delete D.meta.oc; } audit(by, `Restored the workspace from the backup of ${label.startsWith('pre') ? 'a safety copy' : label}`); return true;
}
function backupFile() {
  const core = ROWS.core.get(); if (core.meta) { core.meta = { ...core.meta }; delete core.meta.codeHash; delete core.meta.oc; delete core.meta.deleted; }
  return { format: 'sentinel-backup', v: 1, exportedAt: new Date().toISOString(), workspace: { id: CTX.wid, name: D.meta.name }, rows: { core, logs: D.logs, play: D.play, calls: D.calls, forms: { responses: FR.map(({ tok, ...x }) => x) } } };
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
  D.logs = l && typeof l === 'object' && !Array.isArray(l) ? l : {}; D.play = pl && typeof pl === 'object' && !Array.isArray(pl) ? pl : {}; D.calls = Array.isArray(ca) ? ca : []; const fr = data.rows.forms; FR = fr && Array.isArray(fr.responses) ? fr.responses.slice(0, 500) : [];
  migrate(); return '';
}
async function cronRun() {
  const t0 = Date.now(), today = bkDay(), list = await sbGet('select=key,meta:value->meta&key=like.w*:core'); let snap = 0, purged = 0, pruned = 0, partial = false;
  const live = []; for (const r of list) { const wid = r.key.slice(1, 13); if (r.meta && r.meta.deleted) { if (Date.now() - r.meta.deleted > TRASH_MS) { await sbDel(`key=like.w${wid}:*`); await sbDel(`key=like.bk:*:${wid}:*`); await cbFetch(`chat_boxes?wid=eq.${wid}`, { method: 'DELETE', headers: { Prefer: 'return=minimal' } }).catch(() => {}); purged++; } } else if (r.meta) live.push(wid); }
  for (let i = 0; i < live.length; i += 4) { if (Date.now() - t0 > 9000) { partial = true; break; } snap += (await Promise.all(live.slice(i, i + 4).map(w => snapshot(w, today).catch(() => false)))).filter(Boolean).length; }
  for (const r of await sbGet('select=key&key=like.bk:*:core')) { const [, label, wid] = r.key.split(':'), age = Date.now() - labelTime(label); if ((/^\d{8}$/.test(label) && age > BK_KEEP_DAYS * 864e5 + 36e5) || (/^pre\d+$/.test(label) && age > 14 * 864e5)) { await sbDel(`key=like.bk:${label}:${wid}:*`); pruned++; } }
  const cc = await chatCron(t0);
  return { ok: true, snapshotted: snap, purged, pruned, partial: partial || cc.partial, chatClosed: cc.closed, chatRemoved: cc.removed };
}
async function boxIdleRun(t0, until, out) { // save the chat boxes of servers that went quiet (closed servers never check in again)
  for (const row of await sbGet('select=key,value,version&key=like.w*:cbo')) {
    if (!Object.values(row.value || {}).some(o => o && Date.now() - o.last > 60000)) continue;
    if (Date.now() - t0 > until) { out.partial = true; break; }
    const wid = row.key.slice(1, 13), core = (await sbGet(`select=rules:value->rules,cuss:value->cussWords&key=eq.w${wid}:core`))[0] || {}, lv = (await sbGet(`select=sv:value->servers&key=eq.w${wid}:live`))[0] || {};
    CTX.wid = wid; D.rules = core.rules || {}; D.cussWords = core.cuss || null; CBO = row.value; CBQ = []; boxSweep(Date.now(), lv.sv || {}); if (!CBQ.length) continue;
    const r = await sbf(`${SB_URL}/rest/v1/rpc/panel_commit`, { method: 'POST', headers: sbHeaders(), body: JSON.stringify({ changes: [{ key: row.key, expect: row.version, value: CBO }] }) });
    if (r.ok && (await r.json()) === true) { out.closed += CBQ.length; await sendBoxes(); } else CBQ = [];
  }
  CBO = {}; CBQ = []; D.rules = {}; D.cussWords = null; CTX.wid = null;
}
async function chatCron(t0) { // nightly: close the boxes of servers that went quiet, then delete boxes older than each workspace keeps them
  const out = { closed: 0, removed: 0, partial: false };
  try {
    await boxIdleRun(t0, 11000, out);
    const cfgs = await sbGet('select=key,days:value->settings->chatDays,meta:value->meta&key=like.w*:core'), by = { 7: [], 14: [], 30: [] };
    for (const c of cfgs) if (c.meta) by[[7, 14, 30].includes(c.days) ? c.days : 14].push(c.key.slice(1, 13));
    for (const [d, ws] of Object.entries(by)) for (let i = 0; i < ws.length; i += 80) {
      if (Date.now() - t0 > 13000) { out.partial = true; break; }
      const r = await cbFetch(`chat_boxes?wid=in.(${ws.slice(i, i + 80).join(',')})&closed_at=lt.${new Date(Date.now() - d * 864e5).toISOString()}&select=id`, { method: 'DELETE', headers: { Prefer: 'return=representation' }, ms: 5000 });
      if (r.ok) out.removed += (await r.json()).length;
    }
  } catch (e) { console.warn('[Sentinel] chat log clean-up: ' + String((e && e.message) || e).slice(0, 200)); }
  try { await cbFetch(`panel_events?at=lt.${new Date(Date.now() - 14 * 864e5).toISOString()}`, { method: 'DELETE', headers: { Prefer: 'return=minimal' }, ms: 4000 }); } catch {} // the admin error log keeps 14 days
  CBO = {}; CBQ = []; D.rules = {}; D.cussWords = null; CTX.wid = null;
  return out;
}
// ---- admin console: abuse, growth, errors, versions, lookup, announcements, flags, storage, data requests
const ABUSE = { ban: 25, pub: 30 }, WS_MAX_BYTES = 25e6;
const coreRows = async () => (await sbGet('select=key,meta:value->meta,daily:value->daily,abuse:value->abuse,settings:value->settings,hook:value->webhook->url,discord:value->discord,forms:value->forms,notices:value->notices,members:value->members&key=like.w*:core')).filter(r => r.meta).map(r => ({ ...r, wid: r.key.slice(1, 13) }));
const weekOf = t => { const d = new Date(t), day = (d.getUTCDay() + 6) % 7; return dayKey(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()) - day * 864e5); };
const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;
async function personScan(rid, withData, from) { // every workspace that stores something about one Roblox player
  const t0 = Date.now(), ws = (await sbGet('select=key,meta:value->meta&key=like.w*:core')).filter(r => r.meta && !r.meta.deleted).map(r => ({ wid: r.key.slice(1, 13), name: r.meta.name })).sort((a, b) => (a.wid < b.wid ? -1 : 1)), found = [];
  for (let i = from; i < ws.length; i++) {
    if (Date.now() - t0 > 11000) return { found, next: i };
    const w = ws[i].wid, keys = ['core', 'logs', 'play', 'calls', 'chat', 'vault', shOf(rid)].map(k => `w${w}:${k}`), v = Object.fromEntries((await sbGet(`select=key,value&key=in.(${keys.join(',')})`)).map(r => [r.key.split(':')[1], r.value]));
    const core = v.core || {}, logs = (v.logs || {})[rid] || [], play = (v.play || {})[rid] || null, calls = (v.calls || []).filter(c => c.from && c.from.userId === rid), chat = ((v.chat || {}).chat || []).filter(m => m.userId === rid), hist = (v[shOf(rid)] || {})[rid] || null, vault = ((v.vault || {}).items || []).filter(x => x.uid === rid || (x.msgs || []).some(m => m.userId === rid));
    let boxes = []; try { const r = await cbFetch(`chat_boxes?select=id,closed_at,msgs&wid=eq.${w}&user_ids=cs.%7B${rid}%7D&limit=2000`, { ms: 4000 }); if (r.ok) boxes = await r.json(); } catch {}
    const ban = (core.bans || {})[rid] || null, mute = (core.mutes || {})[rid] || null, signal = (core.signals || {})[rid] || null, appeals = (core.appeals || []).filter(a => a.uid === rid), inReports = (v.calls || []).filter(c => (c.chat || []).some(m => m.userId === rid)).length;
    const rows = logs.length + (play ? 1 : 0) + calls.length + chat.length + boxes.length + (ban ? 1 : 0) + (mute ? 1 : 0) + (signal ? 1 : 0) + appeals.length + (hist ? 1 : 0) + inReports + vault.length;
    if (!rows) continue;
    const x = { wid: w, name: ws[i].name, rows, logbook: logs.length, chatLogs: boxes.length, reports: calls.length + inReports, appeals: appeals.length, ban: !!ban, mute: !!mute };
    if (withData) x.data = { logbook: logs, activity: play, playtime: hist, ban, mute, hint: signal, appeals, reportsFiled: calls, recentChat: chat, evidenceVault: vault.map(({ log, msgs, ...x }) => ({ ...x, ...(x.uid === rid ? { msgs } : { msgs: (msgs || []).filter(m => m.userId === rid) }) })), chatLogs: boxes.flatMap(b => (b.msgs || []).filter(m => m.userId === rid).map(m => ({ box: b.id, t: m.t, text: m.text }))) };
    found.push(x);
  }
  return { found, next: null };
}
async function adminMore(A, res, alog) { // the newer console tools. Returns true when it handled the request
  const op = A.op, now = Date.now(), S = (c, o) => (send(res, c, o), true);
  if (op === 'abuse') {
    const items = [], seen = G.abuseSeen || {};
    for (const r of await coreRows()) {
      if (r.meta.deleted) continue;
      const add = (key, kind, n, at, text) => { if (!seen[key]) items.push({ key, wid: r.wid, name: r.meta.name, kind, n, at, text, suspended: !!r.meta.suspended }); };
      for (const k of ['ban', 'pub']) for (const [h, n] of Object.entries((r.abuse || {})[k] || {})) if (n >= ABUSE[k] && now - h * 36e5 < 48 * 36e5) add(`${r.wid}:${k}:${h}`, k, n, h * 36e5, k === 'ban' ? `${n} bans in one hour` : `${n} public reports or appeals in one hour`);
      const d = r.daily || {}, today = dayKey(now), t = (d[today] || {}).r || 0, prev = Object.keys(d).filter(k => k < today).sort().slice(-14).map(k => d[k].r || 0), avg = prev.length ? prev.reduce((a, b) => a + b, 0) / prev.length : 0;
      if (t >= 20 && t >= 5 * Math.max(avg, 1)) add(`${r.wid}:rep:${today}`, 'reports', t, now, `${t} reports today, against about ${avg.toFixed(1)} a day before`);
    }
    return S(200, { items: items.sort((a, b) => b.at - a.at), limits: ABUSE });
  }
  if (op === 'abuseDismiss') {
    const k = String(A.key || ''); if (!/^[a-f0-9]{12}:(ban|pub|rep):[\d-]+$/.test(k)) return S(400, { error: 'bad key' });
    G.abuseSeen ||= {}; G.abuseSeen[k] = now; for (const [x, t] of Object.entries(G.abuseSeen)) if (now - t > 7 * 864e5) delete G.abuseSeen[x];
    alog('Dismissed an abuse flag for workspace ' + k.slice(0, 12)); return S(200, { ok: true });
  }
  if (op === 'growth') {
    const rows = (await coreRows()).filter(r => !r.meta.deleted), weeks = {}, days = {};
    for (let i = 11; i >= 0; i--) weeks[weekOf(now - i * 7 * 864e5)] = 0;
    for (let i = 29; i >= 0; i--) days[dayKey(now - i * 864e5)] = { active: 0, actions: 0, reports: 0, joins: 0 };
    const fu = { connected: 0, openCloud: 0, machineBans: 0, chatLogs: 0, group: 0, discord: 0, webhook: 0, forms: 0, appeals: 0, signals: 0 };
    for (const r of rows) {
      const wk = weekOf(r.meta.created || 0); if (wk in weeks) weeks[wk]++;
      for (const [k, v] of Object.entries(r.daily || {})) if (days[k]) { if ((v.u || 0) > 0 || (v.j || 0) > 0) days[k].active++; days[k].actions += v.a || 0; days[k].reports += v.r || 0; days[k].joins += v.j || 0; }
      const m = r.meta, s = r.settings || {};
      if (m.connectedAt) fu.connected++; if (m.oc && m.oc.key) fu.openCloud++; if (m.oc && m.oc.machine && feat('machineBans', r.wid)) fu.machineBans++; if (feat('chatLogs', r.wid)) fu.chatLogs++;
      if (m.group && m.group.id) fu.group++; if (r.discord) fu.discord++; if (r.hook) fu.webhook++; if (Array.isArray(r.forms) && r.forms.length) fu.forms++; if (s.appeals !== false) fu.appeals++; if (s.signals !== false) fu.signals++;
    }
    return S(200, { total: rows.length, weeks: Object.entries(weeks).map(([k, n]) => ({ k, n })), days: Object.entries(days).map(([k, v]) => ({ k, ...v })), features: fu });
  }
  if (op === 'events') {
    let r = null; try { r = await cbFetch(`panel_events?select=at,wid,kind,msg&at=gte.${new Date(now - 7 * 864e5).toISOString()}&order=at.desc&limit=2000`, { ms: 6000 }); } catch {}
    if (!r || !r.ok) return S(200, { setup: false, groups: [] });
    const names = Object.fromEntries((await coreRows()).map(x => [x.wid, x.meta.name])), g = {};
    for (const e of await r.json()) {
      const w = e.wid || '', x = (g[w] ||= { wid: w, name: w ? names[w] || '(deleted workspace)' : 'No workspace', total: 0, kinds: {} }); x.total++;
      const k = (x.kinds[e.kind] ||= { n: 0, last: 0, msg: '' }); k.n++; const t = Date.parse(e.at); if (t > k.last) { k.last = t; k.msg = e.msg; }
    }
    return S(200, { setup: true, groups: Object.values(g).sort((a, b) => b.total - a.total) });
  }
  if (op === 'hubList') { const l = await hubsLoad(true); return S(200, { hubs: l.map(({ kh, ...h }) => ({ ...h, link: hubLink(h) })) }); }
  if (op === 'hubAdd' || op === 'hubKey' || op === 'hubDel' || op === 'hubTop') {
    const l = (await hubsLoad(true)).slice(), i = l.findIndex(h => h.id === A.id), key = () => `hub_${crypto.randomBytes(4).toString('hex').slice(0, 8)}_${rnd(24)}`;
    let shown = null;
    if (op === 'hubAdd') {
      const name = cleanName(A.name, 40), pl = Number(A.placeId); if (!name) return S(400, { error: 'Give the appeal game a name, as players see it on Roblox.' });
      if (!Number.isSafeInteger(pl) || pl < 1) return S(400, { error: 'Enter the place ID (numbers only, from the game link).' }); if (l.length >= 10) return S(400, { error: 'Up to 10 appeal games.' });
      shown = key(); l.push({ id: crypto.randomBytes(4).toString('hex'), name, placeId: pl, kh: hash('hub:' + shown).toString('hex'), t: now });
    } else {
      if (i < 0) return S(404, { error: 'That appeal game is not registered.' });
      if (op === 'hubKey') { shown = key(); l[i] = { ...l[i], kh: hash('hub:' + shown).toString('hex') }; }
      if (op === 'hubDel') l.splice(i, 1);
      if (op === 'hubTop') l.unshift(l.splice(i, 1)[0]);
    }
    if (!await hubsSave(l)) return S(409, { error: 'The list changed at the same moment. Reload and try again.' });
    const nm = op === 'hubAdd' ? A.name : (HC.v.find(h => h.id === A.id) || {}).name || 'an appeal game';
    alog({ hubAdd: `Registered the appeal game "${cleanName(A.name, 40)}"`, hubKey: `Made a new key for the appeal game "${nm}"`, hubDel: 'Removed an appeal game', hubTop: `Made "${nm}" the appeal game named on ban screens` }[op]);
    return S(200, { ok: true, ...(shown ? { key: shown } : {}) });
  }
  if (op === 'versions') {
    const ls = latestScript(), lc = latestClient();
    const items = (await coreRows()).filter(r => !r.meta.deleted).map(r => { const sv = r.meta.scriptV || (r.meta.connectedAt ? 1 : 0), cv = r.meta.clientV || 0, rem = (r.notices || []).filter(n => n && n.kind === 'update').map(n => n.t).sort().pop() || null; return { wid: r.wid, name: r.meta.name, owner: r.meta.owner, scriptV: sv, clientV: cv, oldScript: sv > 0 && sv < ls, oldClient: cv > 0 && cv < lc, connected: !!r.meta.connectedAt, reminded: rem }; });
    return S(200, { latestScript: ls, latestClient: lc, items });
  }
  if (op === 'personLookup') {
    const t = String(A.uid || '').trim(); if (!/^[gr]_\d{1,32}$/.test(t)) return S(400, { error: 'An account id looks like r_123456 or g_123456.' });
    setUid(t); await need('user'); if (!U) return S(404, { error: 'No such account' });
    const ids = (U.workspaces || []).filter(w => /^[a-f0-9]{12}$/.test(w)); let ws = [];
    if (ids.length) {
      const rows = await sbGet(`select=key,meta:value->meta,members:value->members,ranks:value->ranks,audit:value->audit&key=in.(${ids.map(w => `w${w}:core`).join(',')})`);
      ws = rows.filter(r => r.meta).map(r => { const mem = (r.members || {})[t] || null, nm = mem ? mem.name : U.name; return { wid: r.key.slice(1, 13), name: r.meta.name, owner: r.meta.owner === t, deleted: !!r.meta.deleted, rank: mem ? ((r.ranks || {})[mem.rank] || {}).name || mem.rank : null, members: Object.keys(r.members || {}).length, recent: (r.audit || []).filter(a => a && a.user === nm).slice(0, 20) }; });
    }
    alog(`Looked up account ${t}`);
    return S(200, { id: t, name: U.name, provider: U.provider, roblox: t[0] === 'r' ? { id: t.slice(2), name: U.name } : U.roblox || null, created: U.created || null, workspaces: ws });
  }
  if (op === 'announcements') return S(200, { items: (G.announcements || []).filter(a => a.exp > now) });
  if (op === 'annAdd') {
    const text = String(A.text || '').replace(/[\u0000-\u001f<>]/g, ' ').trim().slice(0, 240); if (!text) return S(400, { error: 'Write the message first.' });
    const hours = clampInt(A.hours, 1, 720) || 24, kind = A.kind === 'warn' ? 'warn' : 'info'; let target = A.target;
    if (target === 'ws') { const w = String(A.wid || '').trim(); if (!/^[a-f0-9]{12}$/.test(w)) return S(400, { error: 'Enter the workspace id (12 characters).' }); target = 'ws:' + w; } else if (target !== 'oldScript') target = 'all';
    G.announcements = [...(G.announcements || []).filter(a => a.exp > now), { id: rnd(6), text, kind, target, exp: now + hours * 36e5, t: now }].slice(-20);
    alog(`Posted an announcement for ${target === 'all' ? 'every workspace' : target === 'oldScript' ? 'owners on an old script' : 'workspace ' + target.slice(3)} (${plural(hours, 'hour')})`); return S(200, { ok: true });
  }
  if (op === 'annDel') { G.announcements = (G.announcements || []).filter(a => a.id !== A.id); alog('Removed an announcement'); return S(200, { ok: true }); }
  if (op === 'flags') { const v = await flagsLoad(true); return S(200, { flags: Object.entries(v).map(([k, f]) => ({ name: k, label: FLAG_NAMES[k], all: f.all, wids: f.wids })) }); }
  if (op === 'flagSet') {
    if (!FLAG_DEF[A.name]) return S(400, { error: 'Unknown feature' });
    const cur = await flagsLoad(true), wids = [...new Set((Array.isArray(A.wids) ? A.wids : []).map(x => String(x).trim()).filter(w => /^[a-f0-9]{12}$/.test(w)))].slice(0, 500), val = { ...cur, [A.name]: { all: !!A.all, wids } };
    const r = await sbf(`${SB_URL}/rest/v1/rpc/panel_commit`, { method: 'POST', headers: sbHeaders(), body: JSON.stringify({ changes: [{ key: 'g:flags', expect: FC.ver, value: val }] }) });
    if (!r.ok || (await r.json()) !== true) return S(409, { error: 'The flags changed at the same moment. Reload and try again.' });
    FC = { t: Date.now(), v: val, ver: FC.ver + 1 };
    alog(`Feature ${FLAG_NAMES[A.name]}: ${A.all ? 'on for everyone' : wids.length ? 'on for ' + plural(wids.length, 'chosen workspace') : 'off'}`); return S(200, { ok: true });
  }
  if (op === 'storage') {
    const rows = (await coreRows()).filter(r => !r.meta.deleted); let pu = null, cu = null;
    try { const r = await cbFetch('rpc/panel_usage', { method: 'POST', body: '{}', ms: 6000 }); if (r.ok) pu = Object.fromEntries((await r.json()).map(x => [x.wid, x])); } catch {}
    try { const r = await cbFetch('rpc/chat_box_usage_all', { method: 'POST', body: '{}', ms: 6000 }); if (r.ok) cu = Object.fromEntries((await r.json()).map(x => [x.wid, x])); } catch {}
    const items = rows.map(r => {
      const m = r.meta, caps = m.caps || {}, p = pu && pu[r.wid], c = cu && cu[r.wid];
      const mem = { n: Object.keys(r.members || {}).length, max: caps.members || CAP_DEF.members }, lb = { n: m.logN || 0, max: caps.logbook || CAP_DEF.logbook }, st = pu ? { n: p ? +p.n : 0, bytes: p ? +p.bytes : 0, max: WS_MAX_BYTES } : null, ch = cu ? { n: c ? +c.n : 0, bytes: c ? +c.bytes : 0, maxN: CB_MAX_N, maxBytes: CB_MAX_BYTES } : null, warn = [];
      if (mem.n >= mem.max * .8) warn.push('members'); if (lb.n >= lb.max * .8) warn.push('logbook'); if (st && st.bytes >= st.max * .8) warn.push('storage'); if (ch && (ch.n >= ch.maxN * .8 || ch.bytes >= ch.maxBytes * .8)) warn.push('chat logs');
      return { wid: r.wid, name: m.name, members: mem, logbook: lb, storage: st, chat: ch, warn };
    }).sort((a, b) => b.warn.length - a.warn.length || ((b.storage || {}).bytes || 0) - ((a.storage || {}).bytes || 0));
    return S(200, { setup: !!pu, chatSetup: !!cu, items });
  }
  if (op === 'dataReqs') return S(200, { items: G.dataReqs || [] });
  if (['personExport', 'personDeleteCheck', 'personDelete'].includes(op)) {
    const rid = +String(A.rid || '').trim(), who = String(A.who || '').replace(/[\u0000-\u001f<>]/g, ' ').trim().slice(0, 120);
    if (!Number.isInteger(rid) || rid < 1) return S(400, { error: 'Enter the Roblox user id (numbers only).' });
    if (!who) return S(400, { error: 'Write who asked for this, for example their email or a ticket number.' });
    const logReq = (kind, result) => { G.dataReqs = [{ t: Date.now(), kind, target: rid, who, result }, ...(G.dataReqs || [])].slice(0, 300); alog(`Data request (${kind}) for Roblox user ${rid}, asked by ${who}: ${result}`); };
    if (op === 'personDelete') {
      const tk = unpack(String(A.token || ''));
      if (String(A.confirm || '').trim() !== String(rid)) return S(400, { error: 'Type the Roblox user id exactly to confirm.' });
      if (!tk || tk.pd !== rid || !Array.isArray(tk.w)) return S(400, { error: 'Run the check first. A check is valid for 10 minutes.' });
      const done = [];
      for (const w of tk.w) for (let i = 0; i < 4; i++) {
        resetState(); setWid(w); await need('core', 'logs', 'play', 'calls', 'chat', 'cbo', 'vault'); if (!D.meta) break;
        await erasePlayer(rid); audit('Site admin', `Erased stored data for Roblox user ${rid} (data request)`);
        if (await commit()) { done.push(w); break; }
      }
      resetState(); await need('glob'); G.adminLog ||= []; logReq('delete', `erased in ${done.length} of ${plural(tk.w.length, 'workspace')}`);
      return S(200, { ok: true, done: done.length, of: tk.w.length });
    }
    const out = await personScan(rid, op === 'personExport', clampInt(A.from, 0, 100000) || 0);
    if (op === 'personExport') { logReq('export', `${plural(out.found.length, 'workspace')} with data${out.next !== null ? ' (first part, continue for the rest)' : ''}`); return S(200, { rid, exportedAt: new Date().toISOString(), workspaces: out.found, next: out.next }); }
    if (out.next !== null) return S(200, { partial: true, error: 'Too many workspaces to check in one go. Try again in a quiet moment.' });
    const rows = out.found.reduce((a, x) => a + x.rows, 0); logReq('check', `found ${plural(rows, 'record')} in ${plural(out.found.length, 'workspace')}`);
    return S(200, { rows, workspaces: out.found.length, breakdown: out.found, token: out.found.length ? pack({ pd: rid, w: out.found.map(x => x.wid), e: Date.now() + 10 * 60000 }) : null });
  }
  return false;
}
const ADMIN_PAGE = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><meta name="color-scheme" content="dark"><title>Sentinel Admin</title><link rel="icon" href="/favicon.svg" type="image/svg+xml"><link rel="icon" href="/favicon-32.png" sizes="32x32" type="image/png"><link rel="apple-touch-icon" href="/apple-touch-icon.png"><style>
:root{--bg:#07080c;--bg2:#0b0d13;--card:#10131b;--card2:#151927;--ln:#222637;--ink:#e9ebf3;--mu:#8a8fa6;--ac:#4f8bff;--ac2:#7aa7ff;--red:#ff4d5e;--amb:#f5b942;--grn:#3ddc97}
*{box-sizing:border-box}[hidden]{display:none!important}html{color-scheme:dark}
body{margin:0;min-height:100vh;color:var(--ink);font:14px/1.5 Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;background:radial-gradient(900px 500px at 85% -10%,rgba(79,139,255,.14),transparent 60%),radial-gradient(700px 420px at -10% 110%,rgba(255,77,94,.09),transparent 60%),var(--bg);background-attachment:fixed}
body:before{content:"";position:fixed;inset:0;pointer-events:none;background-image:linear-gradient(rgba(255,255,255,.025) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.025) 1px,transparent 1px);background-size:44px 44px;mask-image:radial-gradient(ellipse at 50% 0,#000 20%,transparent 75%);-webkit-mask-image:radial-gradient(ellipse at 50% 0,#000 20%,transparent 75%)}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
button,input{font:inherit;color:inherit}
.btn{height:34px;padding:0 14px;border:1px solid var(--ln);border-radius:9px;background:var(--card2);color:var(--ink);font-weight:550;cursor:pointer;transition:.15s;display:inline-flex;align-items:center;gap:7px}
.btn:hover{border-color:#34395a;background:#1b2033}.btn:active{transform:translateY(1px)}.btn:disabled{opacity:.5;cursor:default}
.btn.p{background:linear-gradient(180deg,#5d97ff,#3f78ec);border-color:#4f8bff;color:#fff;box-shadow:0 6px 20px -8px rgba(79,139,255,.8)}.btn.p:hover{filter:brightness(1.08)}
.btn.d{background:rgba(255,77,94,.12);border-color:rgba(255,77,94,.4);color:#ff8f9a}.btn.d:hover{background:rgba(255,77,94,.2)}
.btn.s{height:28px;padding:0 10px;font-size:13px;border-radius:8px}
input.in{height:38px;border:1px solid var(--ln);border-radius:10px;padding:0 13px;background:#0a0c12;width:100%;outline:none;transition:.15s}
input.in:focus{border-color:var(--ac);box-shadow:0 0 0 3px rgba(79,139,255,.18)}
.pill{display:inline-flex;align-items:center;gap:6px;font-size:11.5px;font-weight:650;letter-spacing:.06em;text-transform:uppercase;border-radius:99px;padding:3px 10px;border:1px solid var(--ln);color:var(--mu);background:rgba(255,255,255,.03)}
.pill.red{color:#ff8f9a;border-color:rgba(255,77,94,.4);background:rgba(255,77,94,.08)}.pill.grn{color:var(--grn);border-color:rgba(61,220,151,.35);background:rgba(61,220,151,.07)}.pill.amb{color:var(--amb);border-color:rgba(245,185,66,.4);background:rgba(245,185,66,.08)}
.dot{width:7px;height:7px;border-radius:50%;background:currentColor;box-shadow:0 0 10px currentColor}

.top{position:sticky;top:0;z-index:20;display:flex;align-items:center;gap:14px;padding:12px 24px;background:rgba(7,8,12,.78);backdrop-filter:blur(14px);border-bottom:1px solid var(--ln)}
.top:after{content:"";position:absolute;left:0;right:0;bottom:-1px;height:1px;background:linear-gradient(90deg,transparent,var(--red) 20%,var(--amb) 50%,var(--ac) 80%,transparent);opacity:.7}
.br{display:flex;align-items:center;gap:11px}.br img{width:30px;height:30px}.br b{font-size:16px;letter-spacing:-.01em}.br small{display:block;color:var(--mu);font-size:11.5px;margin-top:-2px}
.sp{flex:1}
.w{max-width:1120px;margin:0 auto;padding:26px 24px 70px}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:22px}
.st{background:linear-gradient(180deg,var(--card2),var(--card));border:1px solid var(--ln);border-radius:14px;padding:16px 18px;position:relative;overflow:hidden}
.st:before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--c,var(--ac))}
.st small{color:var(--mu);font-size:11.5px;font-weight:650;letter-spacing:.06em;text-transform:uppercase}.st b{display:block;font-size:30px;letter-spacing:-.03em;margin-top:2px;font-variant-numeric:tabular-nums}
.tabs{display:flex;gap:4px;border-bottom:1px solid var(--ln);margin-bottom:18px;overflow-x:auto;scrollbar-width:none}.tabs::-webkit-scrollbar{display:none}
.tab{white-space:nowrap;background:none;border:0;border-bottom:2px solid transparent;margin-bottom:-1px;padding:10px 14px;color:var(--mu);font-weight:600;cursor:pointer;display:flex;gap:8px;align-items:center}
.tab:hover{color:var(--ink)}.tab.on{color:var(--ink);border-color:var(--ac)}.tab i{font-style:normal;font-size:11px;background:rgba(79,139,255,.18);color:var(--ac2);border-radius:99px;padding:1px 8px}
.bar{display:flex;gap:10px;align-items:center;margin-bottom:14px;flex-wrap:wrap}.bar .in{max-width:340px}
.chips{display:flex;gap:6px}.chip{height:30px;padding:0 12px;border-radius:99px;border:1px solid var(--ln);background:none;color:var(--mu);cursor:pointer;font-weight:600;font-size:13px}.chip.on{background:rgba(79,139,255,.15);border-color:rgba(79,139,255,.5);color:var(--ac2)}
.card{background:linear-gradient(180deg,var(--card2),var(--card));border:1px solid var(--ln);border-radius:14px;padding:16px 18px;margin-bottom:10px}
.ws{display:flex;gap:14px;align-items:center;flex-wrap:wrap}
.av{width:42px;height:42px;border-radius:12px;display:grid;place-items:center;font-weight:750;font-size:17px;background:linear-gradient(135deg,#243a7a,#4f8bff);color:#fff;flex:none}
.card.del .av{background:linear-gradient(135deg,#5a1d27,#c8374a)}
.nm{min-width:0}.nm b{font-size:15.5px}.nm .m{color:var(--mu);font-size:12.5px;margin-top:1px;display:flex;gap:10px;flex-wrap:wrap}
code{font-size:12px;background:#0a0c12;border:1px solid var(--ln);padding:1px 7px;border-radius:6px;color:var(--ac2)}
.acts{display:flex;gap:8px;flex-wrap:wrap;margin-top:14px;padding-top:14px;border-top:1px solid var(--ln);align-items:center}
.snaps{display:flex;gap:6px;flex-wrap:wrap;margin-top:10px}
.note{color:var(--mu);font-size:13px}
.empty{text-align:center;color:var(--mu);padding:46px 10px;border:1px dashed var(--ln);border-radius:14px}
.tg{display:grid;grid-template-columns:repeat(auto-fit,minmax(310px,1fr));gap:12px}.tg .card{margin:0;display:flex;flex-direction:column;gap:12px}
.tg h3{margin:0;font-size:15.5px;display:flex;gap:9px;align-items:center}.tg p{margin:0;color:var(--mu);font-size:13px}
.ic{width:30px;height:30px;border-radius:9px;display:grid;place-items:center;background:rgba(79,139,255,.14);color:var(--ac2)}.ic svg{width:17px;height:17px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.fb p{white-space:pre-wrap;margin:10px 0}.fb .r{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.bd{font-size:11px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;border-radius:6px;padding:2px 8px;background:rgba(79,139,255,.16);color:var(--ac2)}
.toast{position:fixed;left:50%;bottom:26px;transform:translate(-50%,20px);background:#1b2033;border:1px solid #34395a;border-radius:11px;padding:11px 18px;opacity:0;pointer-events:none;transition:.25s;z-index:60;box-shadow:0 20px 50px -20px #000}.toast.on{opacity:1;transform:translate(-50%,0)}.toast.err{border-color:rgba(255,77,94,.6);color:#ff9ba5}
.scrim{position:fixed;inset:0;background:rgba(3,4,8,.7);backdrop-filter:blur(5px);display:grid;place-items:center;z-index:50;padding:20px;animation:fi .15s}@keyframes fi{from{opacity:0}}
.md{width:100%;max-width:420px;background:var(--card2);border:1px solid var(--ln);border-radius:16px;padding:22px;box-shadow:0 40px 90px -30px #000}.md h2{margin:0 0 6px;font-size:18px}.md p{margin:0 0 18px;color:var(--mu)}.md .r{display:flex;gap:8px;justify-content:flex-end}
.skel{height:92px;border-radius:14px;border:1px solid var(--ln);background:linear-gradient(90deg,var(--card),var(--card2),var(--card));background-size:200% 100%;animation:sk 1.2s infinite;margin-bottom:10px}@keyframes sk{to{background-position:-200% 0}}
.dp{margin-top:14px;padding-top:14px;border-top:1px solid var(--ln);display:grid;gap:16px}
.kv{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:10px}.kv div{background:#0a0c12;border:1px solid var(--ln);border-radius:10px;padding:9px 12px}.kv small{display:block;color:var(--mu);font-size:11px;font-weight:650;letter-spacing:.05em;text-transform:uppercase}.kv b{font-size:14px;word-break:break-word}
.sec{font-size:12px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--mu);margin:0 0 8px}
.tb{width:100%;border-collapse:collapse;font-size:13px}.tb th{text-align:left;color:var(--mu);font-weight:650;font-size:11.5px;letter-spacing:.05em;text-transform:uppercase;padding:6px 8px;border-bottom:1px solid var(--ln)}.tb td{padding:7px 8px;border-bottom:1px solid rgba(255,255,255,.04)}
.zone{border:1px solid rgba(255,77,94,.35);background:rgba(255,77,94,.05);border-radius:12px;padding:12px 14px}.zone .sec{color:#ff8f9a}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.lg{font-size:13px}.lg .e{display:flex;gap:12px;padding:8px 2px;border-bottom:1px solid rgba(255,255,255,.05)}.lg time{color:var(--mu);white-space:nowrap;width:150px;flex:none}.lg .e.bad span{color:#ff8f9a}
.hc{display:flex;gap:12px;align-items:center;padding:10px 0;border-bottom:1px solid rgba(255,255,255,.05)}.hc:last-child{border:0}.hc b{flex:1}.hc span.note{max-width:55%;text-align:right}
textarea.in{height:auto;padding:10px 13px;resize:vertical;min-height:64px;font:inherit;line-height:1.45}
select.in{height:38px}
.big{height:42px;font-size:15px}
.mt{margin-top:12px}
select.in,textarea.in{border:1px solid var(--ln);border-radius:10px;background:#0a0c12;color:var(--ink);outline:none}select.in{height:38px;padding:0 10px}textarea.in{width:100%;padding:10px 13px;resize:vertical;font:inherit}
.tw2{overflow-x:auto}.tw2 .tb td,.tw2 .tb th{padding:8px 10px;text-align:left;border-bottom:1px solid var(--ln);vertical-align:middle}
.mtr{height:6px;border-radius:3px;background:var(--card2);overflow:hidden}.mtr>i{display:block;height:6px;border-radius:3px;background:var(--ac)}.mtr.hi>i{background:var(--amb)}
@media(max-width:760px){.stats{grid-template-columns:repeat(2,1fr)}.top{padding:10px 14px}.w{padding:18px 14px 60px}}
</style></head><body>
<header class="top"><div class="br"><img src="/favicon.svg" alt=""><div><b>Sentinel Admin</b><small>Site console</small></div></div><span class="pill red"><span class="dot"></span>Restricted</span><span class="sp"></span><span class="pill red" id="pill-m" hidden>Maintenance on</span><span class="pill amb" id="pill-a" hidden>Announcement live</span><span class="pill grn" id="ss"><span class="dot"></span>Session active</span><button class="btn s" id="out">Sign out</button></header>
<main class="w">
<section class="stats"><div class="st"><small>Workspaces</small><b id="s1">-</b></div><div class="st" style="--c:var(--red)"><small>In recycle bin</small><b id="s2">-</b></div><div class="st" style="--c:var(--grn)"><small>Total members</small><b id="s3">-</b></div><div class="st" style="--c:var(--amb)"><small>Feedback</small><b id="s4">-</b></div></section>
<nav class="tabs" role="tablist"><button class="tab on" data-t="ws" role="tab">Workspaces</button><button class="tab" data-t="lv" role="tab">Live <i id="lvn" hidden>0</i></button><button class="tab" data-t="ac" role="tab">Accounts</button><button class="tab" data-t="fb" role="tab">Feedback <i id="fbn" hidden>0</i></button><button class="tab" data-t="st" role="tab">Site</button><button class="tab" data-t="lg" role="tab">Audit log</button><button class="tab" data-t="tl" role="tab">Tools</button><button class="tab" data-t="ab" role="tab">Abuse <i id="abn" hidden>0</i></button><button class="tab" data-t="gr" role="tab">Growth</button><button class="tab" data-t="er" role="tab">Errors</button><button class="tab" data-t="vr" role="tab">Versions</button><button class="tab" data-t="sg" role="tab">Storage</button><button class="tab" data-t="ff" role="tab">Flags</button><button class="tab" data-t="dq" role="tab">Data requests</button><button class="tab" data-t="hb" role="tab">Appeal games</button></nav>
<section id="p-ws"><div class="bar"><input class="in" id="q" placeholder="Search by name, id or owner" aria-label="Search workspaces"><div class="chips"><button class="chip on" data-f="all">All</button><button class="chip" data-f="live">Active</button><button class="chip" data-f="del">Deleted</button></div><span class="sp"></span><button class="btn s" id="rf">Refresh</button></div><div id="o"><div class="skel"></div><div class="skel"></div></div></section>
<section id="p-lv" hidden><div class="bar"><span class="note" id="lvs">Loading</span><span class="sp"></span><button class="btn s" id="lvr">Refresh</button></div><div id="lvo"></div></section>
<section id="p-ac" hidden><div class="bar"><input class="in" id="uq" placeholder="Search accounts by name, Roblox name or id" aria-label="Search accounts"><button class="btn p" id="ub">Search</button></div><div id="uo"><div class="empty">Search for an account to see their workspaces and manage them.</div></div></section>
<section id="p-fb" hidden><div id="fb"></div></section>
<section id="p-st" hidden><div class="tg">
<div class="card"><h3><span class="ic"><svg viewBox="0 0 24 24"><path d="M3 11v2a1 1 0 001 1h3l5 4V6L7 10H4a1 1 0 00-1 1zM16 8a5 5 0 010 8"/></svg></span>Announcement banner <span class="pill" id="anp">Off</span></h3><p>Shows a message at the top of Sentinel for everyone, like planned downtime. People can close it.</p><textarea class="in" id="ant" maxlength="240" placeholder="Sentinel will be briefly down tonight at 9pm Central."></textarea><div class="row"><select class="in" id="ank" style="width:auto"><option value="info">Info (blue)</option><option value="warn">Warning (amber)</option></select><button class="btn p" id="anb">Post</button><button class="btn" id="anr">Remove</button></div></div>
<div class="card"><h3><span class="ic"><svg viewBox="0 0 24 24"><path d="M14.7 6.3a4 4 0 00-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 005.4-5.4l-2.4 2.4-2.6-.6-.6-2.6z"/></svg></span>Maintenance mode <span class="pill" id="mtp">Off</span></h3><p>Shows a "Back soon" page while you fix something. This console and the status page always work.</p><select class="in" id="mts"><option value="panel">Panel only (games keep syncing, in-game moderation continues)</option><option value="full">Entire website (panel, public pages, appeals, forms and games all pause)</option></select><input class="in" id="mtm" maxlength="240" placeholder="We are updating Sentinel. Back in a few minutes."><div class="row"><button class="btn d" id="mtb">Turn on</button></div></div>
<div class="card" style="grid-column:1/-1"><h3><span class="ic"><svg viewBox="0 0 24 24"><path d="M4 6h16M4 12h10M4 18h6"/></svg></span>Targeted announcements <span class="pill" id="tap">0</span></h3><p>Shown inside the panel until it expires: to every workspace, to one workspace, or only to owners whose Sentinel scripts are out of date.</p><textarea class="in" id="tat" rows="2" placeholder="Message (up to 240 characters)" maxlength="240"></textarea><div class="row mt" style="flex-wrap:wrap;gap:8px"><select class="in" id="tag" style="width:auto"><option value="all">Every workspace</option><option value="ws">One workspace</option><option value="oldScript">Owners on an old script</option></select><input class="in" id="taw" placeholder="Workspace id" style="width:170px" hidden><select class="in" id="tak" style="width:auto"><option value="info">Info</option><option value="warn">Warning</option></select><select class="in" id="tah" style="width:auto"><option value="24">For 1 day</option><option value="72">For 3 days</option><option value="168">For 7 days</option><option value="720">For 30 days</option></select><button class="btn p" id="tapost">Post</button></div><div id="tao" class="mt"></div></div>
<div class="card" style="grid-column:1/-1"><h3><span class="ic"><svg viewBox="0 0 24 24"><path d="M3 12h4l3-8 4 16 3-8h4"/></svg></span>Health <span class="sp" style="flex:1"></span><button class="btn s" id="hb">Run checks</button></h3><div id="ho" class="note">Running checks...</div></div>
</div></section>
<section id="p-lg" hidden><div class="bar"><span class="note">Everything done in this console, newest first.</span><span class="sp"></span><button class="btn s" id="lgr">Refresh</button></div><div class="card lg" id="lgo"></div></section>
<section id="p-tl" hidden><div class="tg">
<div class="card"><h3><span class="ic"><svg viewBox="0 0 24 24"><path d="M12 3v12m0 0l-4-4m4 4l4-4M4 17v2a2 2 0 002 2h12a2 2 0 002-2v-2"/></svg></span>Off-site copy</h3><p>Download every workspace and account in one file. Keep it somewhere outside Supabase, like your own computer.</p><div><button class="btn p" id="eb">Download everything</button> <span class="note" id="em"></span></div></div>
<div class="card"><h3><span class="ic"><svg viewBox="0 0 24 24"><path d="M5 8h14M5 12h10M5 16h6M3 4h18v16H3z"/></svg></span>Discord bot</h3><p>Register the slash commands after setting the Discord variables. Run it again whenever Sentinel adds commands.</p><div><button class="btn p" id="dr">Register commands</button> <span class="note" id="dm"></span></div></div>
<div class="card"><h3><span class="ic"><svg viewBox="0 0 24 24"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 018 0v3"/></svg></span>Reset two-step</h3><p>Removes two-step verification from a locked-out account so the person can set it up again.</p><div style="display:flex;gap:8px"><input class="in" id="mu" placeholder="User id, like r_123456" autocomplete="off"><button class="btn d" id="mr">Reset</button></div><span class="note" id="mm"></span></div>
</div></section>
<section id="p-ab" hidden><div class="bar"><span class="note">Workspaces that may be misusing Sentinel in the last 48 hours: 25 or more bans in an hour, 30 or more public reports or appeals in an hour, or a sudden spike in reports.</span><span class="sp"></span><button class="btn s" id="abr">Refresh</button></div><div id="abo"></div></section>
<section id="p-gr" hidden><div class="bar"><span class="note" id="grs">Loading</span><span class="sp"></span><button class="btn s" id="grr">Refresh</button></div><div class="tg" id="gro"></div></section>
<section id="p-er" hidden><div class="bar"><span class="note">Failed Roblox calls, Discord webhook failures, game sync errors and rate limits from the last 7 days, by workspace.</span><span class="sp"></span><button class="btn s" id="err">Refresh</button></div><div id="ero"></div></section>
<section id="p-vr" hidden><div class="bar"><span class="note" id="vrs">Loading</span><span class="sp"></span><label class="note" style="display:flex;gap:6px;align-items:center"><input type="checkbox" id="vro" checked> Out of date only</label><button class="btn s" id="vrr">Refresh</button></div><div class="card tw2" id="vrt"></div></section>
<section id="p-sg" hidden><div class="bar"><span class="note" id="sgs">Loading</span><span class="sp"></span><button class="btn s" id="sgr">Refresh</button></div><div class="card tw2" id="sgt"></div></section>
<section id="p-ff" hidden><div class="bar"><span class="note">Turn a feature on for chosen workspaces first, then for everyone. Every server picks up a change within 30 seconds.</span></div><div class="tg" id="ffo"></div></section>
<section id="p-dq" hidden><div class="tg">
<div class="card"><h3>Person data request</h3><p>Export or delete what every workspace stores about one Roblox player. Every request is logged with who asked.</p><input class="in" id="dqr" placeholder="Roblox user id" inputmode="numeric" autocomplete="off"><input class="in mt" id="dqw" placeholder="Who asked (their email or a ticket number)" autocomplete="off"><div class="row mt" style="gap:8px;flex-wrap:wrap"><button class="btn" id="dqe">Export</button><button class="btn d" id="dqc">Check before deleting</button></div><div id="dqo" class="mt note"></div></div>
<div class="card"><h3>Workspace data</h3><p>To export a whole workspace, open it under Workspaces and choose Download. To delete it, move it to the recycle bin there; it is erased for good after 30 days.</p></div>
<div class="card" style="grid-column:1/-1"><h3>Request log <span class="sp" style="flex:1"></span><button class="btn s" id="dql">Refresh</button></h3><div id="dqlo" class="note tw2"></div></div>
</div></section>
<section id="p-hb" hidden><div class="card"><h3>Appeal games</h3><p>Roblox games you run where banned players appeal to any workspace that banned them. Put SentinelHub.lua (Script, ServerScriptService) and SentinelHubClient.lua (LocalScript, StarterPlayerScripts) in the game and paste its key into SentinelHub.lua. The first game in the list is the one named on ban screens.</p><input class="in" id="hbn" placeholder="Game name, as players see it on Roblox" maxlength="40" autocomplete="off"><input class="in mt" id="hbp" placeholder="Place ID (the number in the game link)" inputmode="numeric" autocomplete="off"><div class="row mt"><button class="btn" id="hba">Register game</button></div><div id="hbk" class="mt"></div><div id="hbt" class="mt tw2 note">Loading</div></div></section>
</main><div class="toast" id="tt" role="status"></div><div id="md"></div>
<script>var $=function(i){return document.getElementById(i)},WS=[],FB=[],FL='all';
function e(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
var tt=null;function toast(m,bad){var t=$('tt');t.textContent=m;t.className='toast on'+(bad?' err':'');clearTimeout(tt);tt=setTimeout(function(){t.className='toast'},3200)}
function back(){location.reload()}
function call(b){return fetch('/admin/api',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)}).then(function(r){return r.json().catch(function(){return{}}).then(function(j){if(r.status===401||r.status===403){back();throw new Error('Session ended')}if(!r.ok)throw new Error(j.error||'Error '+r.status);return j})})}
function ask(title,text,ok,danger){return new Promise(function(res){var m=$('md');m.innerHTML='<div class="scrim"><div class="md" role="dialog" aria-modal="true"><h2>'+e(title)+'</h2><p>'+e(text)+'</p><div class="r"><button class="btn" id="mn">Cancel</button><button class="btn '+(danger?'d':'p')+'" id="my">'+e(ok)+'</button></div></div></div>';var c=function(v){m.innerHTML='';document.removeEventListener('keydown',k);res(v)},k=function(x){if(x.key==='Escape')c(false)};document.addEventListener('keydown',k);$('mn').onclick=function(){c(false)};$('my').onclick=function(){c(true)};m.firstChild.onclick=function(x){if(x.target===m.firstChild)c(false)};$('my').focus()})}
function stats(){$('s1').textContent=WS.filter(function(w){return!w.deleted}).length;$('s2').textContent=WS.filter(function(w){return w.deleted}).length;$('s3').textContent=WS.reduce(function(a,w){return a+(w.members||0)},0);$('s4').textContent=FB.length;var n=$('fbn');n.hidden=!FB.length;n.textContent=FB.length}
var OPEN={},DET={};
function ago(t){if(!t)return'never';var s=Math.round((Date.now()-t)/1000);if(s<60)return s+'s ago';if(s<3600)return Math.round(s/60)+' min ago';if(s<86400)return Math.round(s/3600)+' h ago';return Math.round(s/86400)+' d ago'}
function dt(t){return t?new Date(t).toLocaleString():'-'}
function detHtml(w){var d=DET[w.id];if(!d)return'<div class="dp"><div class="note">Loading details...</div></div>';var m=d.meta,c=d.counts;
var kv=function(k,v){return'<div><small>'+k+'</small><b>'+v+'</b></div>'};
var sv=m.scriptV?('v'+m.scriptV+(m.latestScript&&m.scriptV<m.latestScript?' <span class="pill amb">outdated, latest v'+m.latestScript+'</span>':'')):'Never connected';
var html='<div class="dp"><div><div class="sec">Overview</div><div class="kv">'+kv('Owner',e(m.owner))+kv('Created',dt(m.created))+kv('Connected',m.connectedAt?dt(m.connectedAt):'Never')+kv('Game script',sv)+kv('Place ID',m.placeId?e(m.placeId)+(m.placeLock?' (locked)':''):'Not set')+kv('Last place seen',m.lastPlace==null?'-':e(m.lastPlace))+kv('Game code changes',m.rot)+kv('Open Cloud key',m.openCloud?'Set':'Not set')+kv('Roblox group',m.group?e(m.group):'Not linked')+kv('Discord',m.discord?'Linked':'Not linked')+kv('Two-step required',m.require2fa?'Yes':'No')+kv('Status',m.deleted?'In recycle bin':m.suspended?'Suspended':'Active')+'</div></div>';
html+='<div><div class="sec">Numbers</div><div class="kv">'+kv('Active bans',c.bans)+kv('Active mutes',c.mutes)+kv('Appeals',c.appeals+' ('+c.openAppeals+' open)')+kv('Forms',c.forms)+kv('Ranks',c.ranks)+kv('Rules',c.rules)+kv('Shifts',c.shifts)+'</div></div>';
html+='<div><div class="sec">Live servers ('+d.servers.length+')</div>'+(d.servers.length?'<table class="tb"><tr><th>Players</th><th>Script</th><th>Chat</th><th>Up for</th></tr>'+d.servers.map(function(s){return'<tr><td>'+s.players+'</td><td>v'+s.sv+'</td><td>'+e(s.chat||'-')+'</td><td>'+ago(s.since).replace(' ago','')+'</td></tr>'}).join('')+'</table>':'<div class="note">Nobody is connected right now.</div>')+'</div>';
html+='<div><div class="sec">Team ('+d.members.length+')</div><table class="tb"><tr><th>Name</th><th>Rank</th><th>Id</th><th>Joined</th></tr>'+d.members.map(function(x){return'<tr><td>'+e(x.name)+(x.owner?' <span class="pill amb">Owner</span>':'')+'</td><td>'+e(x.rank)+'</td><td class="mono">'+e(x.id)+'</td><td>'+new Date(x.joined).toLocaleDateString()+'</td></tr>'}).join('')+'</table></div>';
html+='<div><div class="sec">Recent activity</div>'+(d.audit.length?'<table class="tb">'+d.audit.map(function(a){return'<tr><td style="white-space:nowrap;color:var(--mu)">'+dt(a.t)+'</td><td>'+e(a.user)+'</td><td>'+e(a.text)+'</td></tr>'}).join('')+'</table>':'<div class="note">Nothing yet.</div>')+'</div>';
html+='<div class="zone"><div class="sec">Manage</div><div class="row"><button class="btn s" data-o="rn" data-w="'+e(w.id)+'">Rename</button>'+(m.deleted?'':'<button class="btn s" data-o="va" data-w="'+e(w.id)+'">View as owner (read-only)</button><button class="btn s" data-o="cp" data-w="'+e(w.id)+'">Limits</button>')+''+(m.suspended?'<button class="btn s" data-o="us" data-w="'+e(w.id)+'">Lift suspension</button>':(m.deleted?'':'<button class="btn s" data-o="su" data-w="'+e(w.id)+'">Suspend</button>'))+'<button class="btn s" data-o="rk" data-w="'+e(w.id)+'">Make a new game code</button>'+(m.deleted?'':'<button class="btn d s" data-o="bn" data-w="'+e(w.id)+'">Move to recycle bin</button>')+'<button class="btn d s" data-o="pg" data-w="'+e(w.id)+'">Delete forever</button></div><div class="note mt" id="k'+e(w.id)+'"></div></div></div>';
return html}
function drawWs(){var q=$('q').value.trim().toLowerCase(),l=WS.filter(function(w){return(FL==='all'||(FL==='del')===!!w.deleted)&&(!q||(w.name+' '+w.id+' '+w.owner).toLowerCase().indexOf(q)>=0)});
$('o').innerHTML=l.length?l.map(function(w){return'<div class="card '+(w.deleted?'del':'')+'"><div class="ws"><div class="av">'+e((w.name||'?').charAt(0).toUpperCase())+'</div><div class="nm"><b>'+e(w.name)+'</b> <code>'+e(w.id)+'</code><div class="m"><span>Owner '+e(w.owner)+'</span><span>'+w.members+' member'+(w.members==1?'':'s')+'</span>'+(w.created?'<span>Created '+new Date(w.created).toLocaleDateString()+'</span>':'')+'</div></div><span class="sp" style="flex:1"></span>'+(w.deleted?'<span class="pill red">Deleted '+new Date(w.deleted).toLocaleDateString()+'</span>':w.suspended?'<span class="pill amb">Suspended</span>':'<span class="pill grn"><span class="dot"></span>Active</span>')+'</div><div class="acts">'+(w.deleted?'<button class="btn p s" data-o="rd" data-w="'+e(w.id)+'">Restore workspace</button>':'')+'<button class="btn s" data-o="dtl" data-w="'+e(w.id)+'">'+(OPEN[w.id]?'Hide details':'Details')+'</button><button class="btn s" data-o="sn" data-w="'+e(w.id)+'">Back up now</button><button class="btn s" data-o="ls" data-w="'+e(w.id)+'">Backups</button><button class="btn s" data-o="dl" data-w="'+e(w.id)+'">Download</button><span class="note" id="s'+e(w.id)+'"></span></div>'+(OPEN[w.id]?detHtml(w):'')+'</div>'}).join(''):'<div class="empty">'+(WS.length?'No workspaces match.':'No workspaces yet.')+'</div>'}
function ask2(title,text,ok,o){o=o||{};return new Promise(function(res){var m=$('md');m.innerHTML='<div class="scrim"><form class="md" role="dialog" aria-modal="true"><h2>'+e(title)+'</h2><p>'+e(text)+'</p><input class="in" id="mi" autocomplete="off" placeholder="'+e(o.ph||'')+'" value="'+e(o.val||'')+'" style="margin-bottom:18px"><div class="r"><button type="button" class="btn" id="mn">Cancel</button><button class="btn '+(o.danger?'d':'p')+'" id="my">'+e(ok)+'</button></div></form></div>';var c=function(v){m.innerHTML='';document.removeEventListener('keydown',k);res(v)},k=function(x){if(x.key==='Escape')c(null)};document.addEventListener('keydown',k);$('mn').onclick=function(){c(null)};m.querySelector('form').onsubmit=function(x){x.preventDefault();var v=$('mi').value.trim();if(o.must&&v!==o.must){toast('That does not match.',true);return}if(!o.opt&&!v){return}c(v)};m.firstChild.onclick=function(x){if(x.target===m.firstChild)c(null)};$('mi').focus()})}
function drawFb(){$('fb').innerHTML=FB.length?FB.map(function(f){return'<div class="card fb"><div class="r"><span class="bd">'+e(f.type)+'</span><b>'+e(f.user)+'</b><span class="note">'+e(f.rank)+' - '+e(f.wsName)+' - '+new Date(f.t).toLocaleString()+'</span></div><p>'+e(f.text)+'</p><div class="r"><input class="in" style="flex:1;min-width:220px;width:auto" data-r="'+e(f.id)+'" placeholder="Write a reply" value="'+e(f.reply||'')+'"><button class="btn p s" data-o="fr" data-i="'+e(f.id)+'">'+(f.reply?'Update reply':'Reply')+'</button><button class="btn d s" data-o="fd" data-i="'+e(f.id)+'">Delete</button></div></div>'}).join(''):'<div class="empty">No feedback yet.</div>'}
function load(){return call({op:'list'}).then(function(j){WS=j.workspaces;stats();drawWs();return call({op:'feedback'}).then(function(f){FB=f.items;stats();drawFb()},function(){})}).catch(function(x){$('o').innerHTML='<div class="empty">'+e(x.message)+'</div>'})}
document.querySelector('.tabs').onclick=function(ev){var b=ev.target.closest('.tab');if(!b)return;document.querySelectorAll('.tab').forEach(function(t){t.classList.toggle('on',t===b)});var t=b.dataset.t;['ws','lv','ac','fb','st','lg','tl'].forEach(function(k){$('p-'+k).hidden=k!==t});clearInterval(lvT);if(t==='lv'){loadLive();lvT=setInterval(loadLive,10000)}if(t==='st'){loadSite();runHealth()}if(t==='lg')loadLog()};
document.querySelector('.chips').onclick=function(ev){var b=ev.target.closest('.chip');if(!b)return;FL=b.dataset.f;document.querySelectorAll('.chip').forEach(function(c){c.classList.toggle('on',c===b)});drawWs()};
$('q').oninput=drawWs;$('rf').onclick=function(){load().then(function(){toast('Refreshed')})};
$('out').onclick=function(){fetch('/admin/logout',{method:'POST'}).then(back)};
$('eb').onclick=function(){call({op:'exportAll'}).then(function(j){var a=document.createElement('a');a.href=URL.createObjectURL(new Blob([JSON.stringify(j)],{type:'application/json'}));a.download='sentinel-site-'+new Date().toISOString().slice(0,10)+'.json';a.click();$('em').textContent=j.rows.length+' rows saved.'}).catch(function(x){$('em').textContent=x.message})};
$('dr').onclick=function(){call({op:'discordRegister'}).then(function(j){$('dm').textContent='Registered '+j.count+' commands. They can take a minute to appear.'}).catch(function(x){$('dm').textContent=x.message})};
$('mr').onclick=function(){var u=$('mu').value.trim();if(!u)return;call({op:'mfaReset',uid:u}).then(function(j){$('mm').textContent=j.had?'Two-step removed. They can sign in and set it up again.':'That user did not have two-step on.'}).catch(function(x){$('mm').textContent=x.message})};
$('fb').onclick=function(ev){var b=ev.target.closest('button');if(!b)return;var go=function(){return b.dataset.o==='fr'?call({op:'feedbackReply',id:b.dataset.i,reply:document.querySelector('[data-r="'+b.dataset.i+'"]').value}).then(function(){toast('Reply saved')}):ask('Delete this message?','It will be removed for good.','Delete',true).then(function(y){if(y)return call({op:'feedbackDelete',id:b.dataset.i}).then(function(){toast('Deleted')})})};go().then(load).catch(function(x){toast(x.message,true)})};
$('o').onclick=function(ev){var b=ev.target.closest('button');if(!b)return;var w=b.dataset.w,s=$('s'+w),o=b.dataset.o,wsr=WS.filter(function(x){return x.id===w})[0]||{},nm=wsr.name||w;
var fail=function(x){var t=$('k'+w)||s;if(t)t.textContent=x.message;toast(x.message,true)};
var reloadDet=function(){return call({op:'wsDetail',wid:w}).then(function(d){DET[w]=d;drawWs()})};
if(o==='dtl'){if(OPEN[w]){delete OPEN[w];drawWs()}else{OPEN[w]=1;drawWs();reloadDet().catch(fail)}}
else if(o==='rd')ask('Restore this workspace?','It comes back with its team, logs and settings.','Restore').then(function(y){if(y)return call({op:'restoreDeleted',wid:w}).then(function(){toast('Workspace restored');return load()})}).catch(fail);
else if(o==='sn')call({op:'snapshotNow',wid:w}).then(function(){s.textContent='Backed up.';toast('Backup saved')}).catch(fail);
else if(o==='ls')call({op:'snaps',wid:w}).then(function(j){s.innerHTML='';var d=s.parentNode,old=d.parentNode.querySelector('.snaps');if(old)old.remove();var x=document.createElement('div');x.className='snaps';x.innerHTML=j.snaps.length?j.snaps.map(function(k){return'<button class="btn s" data-o="rs" data-w="'+e(w)+'" data-d="'+e(k)+'">'+(k.indexOf('pre')===0?'Safety copy '+new Date(+k.slice(3)*1000).toLocaleString():k.slice(0,4)+'-'+k.slice(4,6)+'-'+k.slice(6))+'</button>'}).join(''):'<span class="note">No backups yet.</span>';d.parentNode.insertBefore(x,d.nextSibling)}).catch(fail);
else if(o==='rs')ask('Restore this backup?','The workspace is replaced with the backup of '+b.dataset.d+'. A safety copy is made first.','Restore',true).then(function(y){if(y)return call({op:'restoreSnapshot',wid:w,date:b.dataset.d}).then(function(){toast('Backup restored')})}).catch(fail);
else if(o==='dl')call({op:'download',wid:w}).then(function(j){var a=document.createElement('a');a.href=URL.createObjectURL(new Blob([JSON.stringify(j,null,1)],{type:'application/json'}));a.download='sentinel-backup-'+w+'.json';a.click()}).catch(fail);
else if(o==='rn')ask2('Rename workspace','Pick the new name (2 to 40 characters).','Rename',{val:nm,ph:'Workspace name'}).then(function(v){if(v)return call({op:'wsRename',wid:w,name:v}).then(function(){toast('Renamed');return load().then(reloadDet)})}).catch(fail);
else if(o==='su')ask2('Suspend '+nm,'Its team is locked out of the panel and the game stops syncing, but nothing is deleted. Write the reason they will see.','Suspend',{ph:'Reason',danger:1,opt:1}).then(function(v){if(v!==null)return call({op:'wsSuspend',wid:w,on:true,reason:v}).then(function(){toast('Suspended');return load().then(reloadDet)})}).catch(fail);
else if(o==='us')call({op:'wsSuspend',wid:w,on:false}).then(function(){toast('Suspension lifted');return load().then(reloadDet)}).catch(fail);
else if(o==='rk')ask('Make a new game code?','The old code stops working at once. The game will go offline until the owner puts the new code in their script.','Make new code',true).then(function(y){if(y)return call({op:'wsRotate',wid:w}).then(function(j){var t=$('k'+w);t.innerHTML='New code (shown once): <code class="mono" style="user-select:all">'+e(j.code)+'</code> <button class="btn s" id="cc">Copy</button>';$('cc').onclick=function(){navigator.clipboard.writeText(j.code).then(function(){toast('Copied')})};toast('New game code made')})}).catch(fail);
else if(o==='bn')ask('Move '+nm+' to the recycle bin?','Its team loses access now. You can restore it for 30 days, then it is deleted for good.','Move to bin',true).then(function(y){if(y)return call({op:'wsBin',wid:w}).then(function(){toast('Moved to the recycle bin');return load().then(reloadDet)})}).catch(fail);
else if(o==='pg')ask2('Delete '+nm+' forever','This erases the workspace, its backups and every record. It cannot be undone. Type the workspace name to confirm.','Delete forever',{ph:nm,must:nm,danger:1}).then(function(v){if(v)return call({op:'wsPurge',wid:w,confirm:v}).then(function(){delete OPEN[w];toast('Deleted forever');return load()})}).catch(fail)};
/* ---- live servers ---- */
var lvT=null;function loadLive(){return call({op:'live'}).then(function(j){var items=j.items,p=items.reduce(function(a,x){return a+x.players},0),sv=items.reduce(function(a,x){return a+x.servers},0);$('lvs').textContent=p+' player'+(p==1?'':'s')+' in '+sv+' server'+(sv==1?'':'s')+' across '+items.length+' workspace'+(items.length==1?'':'s')+'. Updates every 10 seconds.';var n=$('lvn');n.hidden=!items.length;n.textContent=p;$('lvo').innerHTML=items.length?'<div class="card"><table class="tb"><tr><th>Workspace</th><th>Servers</th><th>Players</th><th>Script</th><th>Chat</th><th>Last check-in</th></tr>'+items.map(function(x){return'<tr><td><b>'+e(x.name)+'</b> <code>'+e(x.id)+'</code></td><td>'+x.servers+'</td><td>'+x.players+'</td><td>v'+x.sv+(x.sv<j.latest?' <span class="pill amb">outdated</span>':'')+'</td><td>'+e(x.chat.join(', ')||'-')+'</td><td>'+ago(x.seen)+'</td></tr>'}).join('')+'</table></div>':'<div class="empty">No game servers are connected right now.</div>'}).catch(function(x){$('lvs').textContent=x.message})}
$('lvr').onclick=loadLive;
/* ---- accounts ---- */
function userCard(u){return'<div class="card"><div class="ws"><div class="av">'+e((u.name||'?').charAt(0).toUpperCase())+'</div><div class="nm"><b>'+e(u.name||'(no name)')+'</b> <code>'+e(u.id)+'</code><div class="m"><span>'+e(u.provider||'')+' sign-in</span>'+(u.roblox?'<span>Roblox @'+e(u.roblox)+'</span>':'')+(u.created?'<span>Joined '+new Date(u.created).toLocaleDateString()+'</span>':'')+(u.revoked?'<span>Signed out everywhere '+ago(u.revoked)+'</span>':'')+'</div></div><span class="sp" style="flex:1"></span>'+(u.mfa?'<span class="pill grn">Two-step on</span>':'<span class="pill">No two-step</span>')+'</div>'+(u.workspaces.length?'<div class="snaps">'+u.workspaces.map(function(w){return'<span class="pill'+(w.deleted?' red':w.owner?' amb':'')+'">'+e(w.name)+(w.owner?' - owner':'')+(w.deleted?' - deleted':'')+'</span>'}).join('')+'</div>':'<div class="note mt">Not in any workspace.</div>')+'<div class="acts"><button class="btn s" data-u="so" data-i="'+e(u.id)+'">Sign out everywhere</button><button class="btn s" data-u="lk" data-i="'+e(u.id)+'">Details</button><button class="btn s" data-u="ex" data-i="'+e(u.id)+'">Export data</button>'+(u.mfa?'<button class="btn s" data-u="mf" data-i="'+e(u.id)+'">Reset two-step</button>':'')+'<button class="btn d s" data-u="dl" data-i="'+e(u.id)+'" data-n="'+e(u.name||'')+'">Delete account</button><span class="note" id="u'+e(u.id)+'"></span></div></div>'}
function searchUsers(){var q=$('uq').value.trim();if(q.length<2){toast('Type at least 2 characters',true);return}call({op:'userSearch',q:q}).then(function(j){$('uo').innerHTML=j.items.length?j.items.map(userCard).join(''):'<div class="empty">No accounts match.</div>'}).catch(function(x){toast(x.message,true)})}
$('ub').onclick=searchUsers;$('uq').onkeydown=function(k){if(k.key==='Enter')searchUsers()};
function saveJson(name,j){var a=document.createElement('a');a.href=URL.createObjectURL(new Blob([JSON.stringify(j,null,1)],{type:'application/json'}));a.download=name;a.click()}
$('uo').onclick=function(ev){var b=ev.target.closest('button');if(!b)return;var id=b.dataset.i,t=b.dataset.u,s=$('u'+id),fail=function(x){if(s)s.textContent=x.message;toast(x.message,true)};
if(t==='so')ask('Sign '+id+' out everywhere?','Every browser they are signed in on is signed out. They can sign in again.','Sign out',true).then(function(y){if(y)return call({op:'userSignOut',uid:id}).then(function(){toast('Signed out everywhere');searchUsers()})}).catch(fail);
else if(t==='ex')call({op:'userExport',uid:id}).then(function(j){saveJson('sentinel-account-'+id+'.json',j);toast('Export downloaded')}).catch(fail);
else if(t==='mf')ask('Reset two-step for '+id+'?','Removes two-step so they can sign in and set it up again.','Reset',true).then(function(y){if(y)return call({op:'mfaReset',uid:id}).then(function(){toast('Two-step removed');searchUsers()})}).catch(fail);
else if(t==='dl')ask2('Delete account '+id,'Removes the account and takes them off every team. Workspaces they own must be deleted or handed over first. Type the user id to confirm.','Delete account',{ph:id,must:id,danger:1}).then(function(v){if(v)return call({op:'userDelete',uid:id,confirm:v}).then(function(){toast('Account deleted');searchUsers()})}).catch(fail)};
/* ---- site ---- */
function drawSite(j){var a=j.announce,m=j.maint;$('anp').textContent=a?'On':'Off';$('anp').className='pill'+(a?' grn':'');if(a){$('ant').value=a.text;$('ank').value=a.kind}$('mtp').textContent=m&&m.on?(m.full?'ON - whole site':'ON - panel'):'Off';$('mts').value=m&&m.full?'full':'panel';$('mtp').className='pill'+(m&&m.on?' red':'');$('mtb').textContent=m&&m.on?'Turn off':'Turn on';$('mtb').className='btn '+(m&&m.on?'p':'d');if(m&&m.on)$('mtm').value=m.message||'';$('pill-m').hidden=!(m&&m.on);$('pill-m').textContent=m&&m.full?'Maintenance: whole site':'Maintenance: panel';$('pill-a').hidden=!a}
function loadSite(){return call({op:'site'}).then(drawSite).catch(function(){})}
$('anb').onclick=function(){call({op:'announce',on:true,text:$('ant').value,kind:$('ank').value}).then(function(){toast('Announcement posted');loadSite()}).catch(function(x){toast(x.message,true)})};
$('anr').onclick=function(){call({op:'announce',on:false}).then(function(){$('ant').value='';toast('Announcement removed');loadSite()}).catch(function(x){toast(x.message,true)})};
$('mtb').onclick=function(){var on=$('mtp').textContent==='Off',full=$('mts').value==='full';(on?ask('Turn on maintenance mode?',full?'The ENTIRE website pauses: panel, appeal and form pages, sign-in and game syncing. Moderation actions will not reach games until you turn it off.':'Nobody can use the panel until you turn it off. Games keep syncing.','Turn on',true):Promise.resolve(true)).then(function(y){if(y)return call({op:'maintenance',on:on,full:full,message:$('mtm').value}).then(function(){toast(on?'Maintenance mode is ON':'Maintenance mode is off');loadSite()})}).catch(function(x){toast(x.message,true)})};
function hrow(n,st,t){return'<div class="hc"><b>'+n+'</b><span class="note">'+e(t||'')+'</span><span class="pill '+(st==='ok'?'grn':st==='warn'?'amb':'red')+'">'+(st==='ok'?'OK':st==='warn'?'Check':'Problem')+'</span></div>'}
function runHealth(){$('ho').innerHTML='Running checks...';call({op:'health'}).then(function(j){var c=j.config,b=j.backups,h='';
h+=hrow('Database',j.db.ok?(j.db.ms>1500?'warn':'ok'):'bad',j.db.ok?j.db.ms+' ms':'Cannot reach Supabase');
h+=hrow('Workspaces',j.workspaces.live>=j.workspaces.max*.9?'warn':'ok',j.workspaces.live+' of '+j.workspaces.max+' allowed ('+j.workspaces.rows+' stored)');
h+=hrow('Nightly backups',b?(b.ok&&Date.now()-b.t<36*36e5?'ok':'bad'):'warn',b?'Last run '+ago(b.t)+(b.ok?'':', with errors'):'Has never run. Check CRON_SECRET and the cron job.');
h+=hrow('Cron secret',c.cronSecret?'ok':'warn',c.cronSecret?'Set':'Missing or under 16 characters');
h+=hrow('Roblox',j.roblox==='ok'?'ok':'bad',j.roblox==='ok'?'Reachable':j.roblox);
h+=hrow('Discord bot',!j.discord.configured?'warn':j.discord.status==='ok'?'ok':'bad',!j.discord.configured?'Not set up':j.discord.status);
h+=hrow('Sign-in methods',j.signIn.length?'ok':'bad',j.signIn.join(', ')||'None configured');
h+=hrow('Sign-ups',c.signupsOpen?'ok':'warn',c.signupsOpen?'Open (up to '+c.maxPerUser+' workspaces per person)':'Closed');
h+=hrow('Legal pages',c.legalReviewed?'ok':'warn',c.legalReviewed?'Marked as reviewed':'Still marked as a draft (LEGAL_REVIEWED)');
h+=hrow('Alert webhook',c.alertWebhook?'ok':'warn',c.alertWebhook?'Set':'Not set (ALERT_WEBHOOK)');
h+=hrow('Report retention',  'ok',c.callRetentionDays+' days');
$('ho').innerHTML=h}).catch(function(x){$('ho').textContent=x.message})}
$('hb').onclick=runHealth;
/* ---- audit log ---- */
function loadLog(){call({op:'adminLog'}).then(function(j){$('lgo').innerHTML=j.items.length?j.items.map(function(l){return'<div class="e'+(l.bad?' bad':'')+'"><time>'+dt(l.t)+'</time><span>'+e(l.text)+(l.who?' <span class="note">('+e(l.who)+')</span>':'')+'</span></div>'}).join(''):'<div class="note">Nothing yet.</div>'}).catch(function(x){$('lgo').textContent=x.message})}
$('lgr').onclick=loadLog;
load();loadSite();loadLive();</script>
<script>(function(){
function fail(x){toast(x.message,true)}
function mb(b){return (b/1e6).toFixed(b<1e7?2:1)+' MB'}
function meter(n,max,txt){var p=max?Math.min(100,Math.round(n/max*100)):0;return '<div style="min-width:130px"><div class="mtr'+(p>=80?' hi':'')+'"><i style="width:'+p+'%"></i></div><div class="note">'+txt+'</div></div>'}
function bars(list,key){var max=Math.max.apply(null,list.map(function(x){return x[key]}).concat([1])),w=100/list.length;return '<svg viewBox="0 0 100 40" preserveAspectRatio="none" style="width:100%;height:90px;display:block">'+list.map(function(x,i){var h=x[key]/max*38;return '<rect x="'+(i*w+w*0.12).toFixed(2)+'" y="'+(40-Math.max(h,0.5)).toFixed(2)+'" width="'+(w*0.76).toFixed(2)+'" height="'+Math.max(h,0.5).toFixed(2)+'" fill="#4f8bff" opacity="'+(x[key]?1:0.25)+'"><title>'+e(x.k)+': '+x[key]+'</title></rect>'}).join('')+'</svg><div class="note" style="display:flex;justify-content:space-between"><span>'+e(list[0].k)+'</span><span>'+e(list[list.length-1].k)+'</span></div>'}
function modal(title,html){var m=$('md');m.innerHTML='<div class="scrim"><div class="md" role="dialog" aria-modal="true" style="max-width:760px;width:100%;max-height:82vh;overflow:auto"><h2>'+e(title)+'</h2>'+html+'<div class="r"><button class="btn" id="mn">Close</button></div></div></div>';$('mn').onclick=function(){m.innerHTML=''}}
function openWs(w){document.querySelector('.tab[data-t="ws"]').click();$('q').value=w;OPEN[w]=1;drawWs();call({op:'wsDetail',wid:w}).then(function(d){DET[w]=d;drawWs()}).catch(fail)}
/* abuse */
function loadAbuse(){$('abo').innerHTML='<div class="note">Loading...</div>';call({op:'abuse'}).then(function(j){var n=$('abn');n.hidden=!j.items.length;n.textContent=j.items.length;
$('abo').innerHTML=j.items.length?j.items.map(function(x){return '<div class="card"><div class="ws"><div class="nm"><b>'+e(x.name)+'</b> <code>'+e(x.wid)+'</code>'+(x.suspended?' <span class="pill red">Suspended</span>':'')+'<div class="m"><span style="color:var(--amb);font-weight:600">'+e(x.text)+'</span><span>'+dt(x.at)+'</span></div></div><div style="display:flex;gap:6px;flex-wrap:wrap;margin-left:auto"><button class="btn s" data-x="rv" data-w="'+e(x.wid)+'">Review</button>'+(x.suspended?'':'<button class="btn s d" data-x="su" data-w="'+e(x.wid)+'" data-n="'+e(x.name)+'">Suspend</button>')+'<button class="btn s" data-x="ok" data-k="'+e(x.key)+'">Dismiss</button></div></div></div>'}).join(''):'<div class="empty">Nothing looks wrong right now.</div>'}).catch(function(x){$('abo').innerHTML='<div class="empty">'+e(x.message)+'</div>'})}
$('abr').onclick=loadAbuse;
$('abo').onclick=function(ev){var b=ev.target.closest('button');if(!b)return;var x=b.dataset.x,w=b.dataset.w;
if(x==='ok')call({op:'abuseDismiss',key:b.dataset.k}).then(function(){toast('Dismissed');loadAbuse()}).catch(fail);
else if(x==='su')ask2('Suspend '+b.dataset.n,'Its team is locked out of the panel and the game stops syncing, but nothing is deleted. Write the reason they will see.','Suspend',{ph:'Reason',danger:1,opt:1}).then(function(v){if(v!==null)return call({op:'wsSuspend',wid:w,on:true,reason:v}).then(function(){toast('Suspended');load();loadAbuse()})}).catch(fail);
else if(x==='rv')openWs(w)};
/* growth */
function loadGrowth(){$('grs').textContent='Loading';call({op:'growth'}).then(function(j){var f=j.features,lab={connected:'Connected a game',openCloud:'Roblox API key saved',machineBans:'Machine bans on',chatLogs:'Chat logs on',group:'Roblox group linked',discord:'Discord bot',webhook:'Discord webhook',forms:'Forms',appeals:'Appeals on',signals:'Alt-account hints on'};
$('grs').textContent=j.total+' live workspace'+(j.total==1?'':'s');
$('gro').innerHTML='<div class="card"><h3>New workspaces per week</h3>'+bars(j.weeks,'n')+'</div><div class="card"><h3>Active games per day</h3>'+bars(j.days,'active')+'</div><div class="card"><h3>Moderation actions per day</h3>'+bars(j.days,'actions')+'</div><div class="card"><h3>Feature use</h3><table class="tb">'+Object.keys(lab).map(function(k){var n=f[k]||0,p=j.total?Math.round(n/j.total*100):0;return '<tr><td>'+lab[k]+'</td><td style="width:40%"><div class="mtr"><i style="width:'+p+'%"></i></div></td><td style="text-align:right;white-space:nowrap">'+n+' <span class="note">'+p+'%</span></td></tr>'}).join('')+'</table></div>'}).catch(fail)}
$('grr').onclick=loadGrowth;
/* errors */
var KL={oc_fail:'Roblox Open Cloud',webhook_fail:'Discord webhook',sync_error:'Game sync error',rate_limit:'Rate limit'};
function loadEvents(){$('ero').innerHTML='<div class="note">Loading...</div>';call({op:'events'}).then(function(j){if(!j.setup){$('ero').innerHTML='<div class="empty">The error log is not set up yet. Run the new SQL in supabase.sql once in Supabase.</div>';return}
$('ero').innerHTML=j.groups.length?j.groups.map(function(g){return '<div class="card"><div class="ws"><div class="nm"><b>'+e(g.name)+'</b>'+(g.wid?' <code>'+e(g.wid)+'</code>':'')+'<div class="m"><span>'+g.total+' problem'+(g.total==1?'':'s')+'</span></div></div></div><div class="tw2"><table class="tb mt">'+Object.keys(g.kinds).map(function(k){var x=g.kinds[k];return '<tr><td style="white-space:nowrap"><span class="pill '+(k==='rate_limit'?'amb':'red')+'">'+e(KL[k]||k)+'</span></td><td style="white-space:nowrap">'+(x.n==1?'once':x.n+' times')+'</td><td>'+e(x.msg)+'</td><td class="note" style="white-space:nowrap">'+ago(x.last)+'</td></tr>'}).join('')+'</table></div></div>'}).join(''):'<div class="empty">No problems in the last 7 days.</div>'}).catch(fail)}
$('err').onclick=loadEvents;
/* versions */
var VR=null;function drawVersions(){var j=VR,only=$('vro').checked,old=j.items.filter(function(x){return x.oldScript||x.oldClient}),l=only?old:j.items;
$('vrs').textContent='Latest game script v'+j.latestScript+', player script v'+j.latestClient+'. '+old.length+' workspace'+(old.length==1?'':'s')+' out of date.';
$('vrt').innerHTML=l.length?'<table class="tb"><tr><th>Workspace</th><th>Game script</th><th>Player script</th><th>Reminded</th><th></th></tr>'+l.map(function(x){return '<tr><td><b>'+e(x.name)+'</b> <code>'+e(x.wid)+'</code></td><td>'+(x.scriptV?'v'+x.scriptV:'<span class="note">never connected</span>')+(x.oldScript?' <span class="pill amb">old</span>':'')+'</td><td>'+(x.clientV?'v'+x.clientV:'<span class="note">not seen</span>')+(x.oldClient?' <span class="pill amb">old</span>':'')+'</td><td class="note">'+(x.reminded?ago(x.reminded):'never')+'</td><td>'+(x.oldScript||x.oldClient?'<button class="btn s" data-w="'+e(x.wid)+'">Remind owner</button>':'')+'</td></tr>'}).join('')+'</table>':'<div class="empty">'+(only?'Every connected workspace is up to date.':'No workspaces yet.')+'</div>'}
function loadVersions(){call({op:'versions'}).then(function(j){VR=j;drawVersions()}).catch(fail)}
$('vro').onchange=function(){if(VR)drawVersions()};$('vrr').onclick=loadVersions;
$('vrt').onclick=function(ev){var b=ev.target.closest('button');if(!b)return;b.disabled=true;call({op:'wsRemind',wid:b.dataset.w}).then(function(){toast('Reminder sent. The owner sees it in their Inbox and on Home.');loadVersions()}).catch(function(x){b.disabled=false;fail(x)})};
/* storage and limits */
function setCaps(w,m,l){return ask2('Member limit','How many people can be on this team (1 to 5000).','Next',{val:String(m),ph:'100'}).then(function(a){if(!a)return;return ask2('Logbook limit','How many logbook entries to keep (1000 to 1000000). Above it, the oldest points and notes go first. Running bans and mutes are never removed.','Save',{val:String(l),ph:'50000'}).then(function(b){if(!b)return;return call({op:'wsCaps',wid:w,members:+a,logbook:+b}).then(function(){toast('Limits saved')})})})}
function loadStorage(){$('sgs').textContent='Loading';call({op:'storage'}).then(function(j){var w=j.items.filter(function(x){return x.warn.length}).length;
$('sgs').textContent=(j.setup?'':'Stored sizes need the new SQL in supabase.sql. ')+w+' workspace'+(w==1?'':'s')+' at 80% or more of a limit.';
$('sgt').innerHTML=j.items.length?'<table class="tb"><tr><th>Workspace</th><th>Stored data</th><th>Chat logs</th><th>Members</th><th>Logbook</th><th></th></tr>'+j.items.map(function(x){return '<tr><td><b>'+e(x.name)+'</b> <code>'+e(x.wid)+'</code>'+(x.warn.length?'<div><span class="pill amb">Near the limit: '+e(x.warn.join(', '))+'</span></div>':'')+'</td><td>'+(x.storage?meter(x.storage.bytes,x.storage.max,x.storage.n+' rows, '+mb(x.storage.bytes)):'<span class="note">-</span>')+'</td><td>'+(x.chat?meter(Math.max(x.chat.n/x.chat.maxN,x.chat.bytes/x.chat.maxBytes)*1000,1000,x.chat.n+' boxes, '+mb(x.chat.bytes)):'<span class="note">-</span>')+'</td><td>'+meter(x.members.n,x.members.max,x.members.n+' of '+x.members.max)+'</td><td>'+meter(x.logbook.n,x.logbook.max,x.logbook.n+' of '+x.logbook.max)+'</td><td><button class="btn s" data-w="'+e(x.wid)+'" data-m="'+x.members.max+'" data-l="'+x.logbook.max+'">Limits</button></td></tr>'}).join('')+'</table>':'<div class="empty">No workspaces yet.</div>'}).catch(fail)}
$('sgr').onclick=loadStorage;
$('sgt').onclick=function(ev){var b=ev.target.closest('button');if(!b)return;setCaps(b.dataset.w,b.dataset.m,b.dataset.l).then(loadStorage).catch(fail)};
/* feature flags */
function loadFlags(){call({op:'flags'}).then(function(j){$('ffo').innerHTML=j.flags.map(function(f){return '<div class="card"><h3>'+e(f.label)+' <span class="pill '+(f.all?'grn':f.wids.length?'amb':'')+'">'+(f.all?'Everyone':f.wids.length?f.wids.length+' chosen':'Off')+'</span></h3><label class="note" style="display:flex;gap:8px;align-items:center;margin-bottom:10px"><input type="checkbox" data-all="'+e(f.name)+'"'+(f.all?' checked':'')+'> On for every workspace</label><p>Chosen workspaces, one id per line. They get it while it is not on for everyone.</p><textarea class="in" rows="3" data-ws="'+e(f.name)+'">'+e(f.wids.join(String.fromCharCode(10)))+'</textarea><div class="mt"><button class="btn p s" data-save="'+e(f.name)+'">Save</button></div></div>'}).join('')}).catch(fail)}
$('ffo').onclick=function(ev){var b=ev.target.closest('[data-save]');if(!b)return;var n=b.dataset.save,all=document.querySelector('[data-all="'+n+'"]').checked,ws=document.querySelector('[data-ws="'+n+'"]').value.split(/[^a-f0-9]+/).filter(function(x){return x.length===12});call({op:'flagSet',name:n,all:all,wids:ws}).then(function(){toast('Saved');loadFlags()}).catch(fail)};
/* data requests */
function rqv(){return {rid:$('dqr').value.trim(),who:$('dqw').value.trim()}}
function hubKey(k){$('hbk').innerHTML=k?'<div class="card" style="margin:0"><b>Hub key, shown once</b><p class="note">Paste it over PASTE HUB KEY HERE in SentinelHub.lua, then publish the game. If you lose it, make a new key.</p><code style="word-break:break-all">'+e(k)+'</code></div>':''}
function loadHubs(){call({op:'hubList'}).then(function(j){$('hbt').innerHTML=j.hubs.length?'<table class="tb"><tr><th>Game</th><th>Place</th><th>Last check-in</th><th></th></tr>'+j.hubs.map(function(h,i){return '<tr><td><b>'+e(h.name)+'</b>'+(i===0?' <span class="pill">named on ban screens</span>':'')+'</td><td><a href="'+e(h.link)+'" target="_blank" rel="noopener">'+e(h.placeId)+'</a></td><td class="note">'+(h.last?ago(h.last):'never')+'</td><td style="white-space:nowrap">'+(i>0?'<button class="btn s" data-h="'+e(h.id)+'" data-o="hubTop">Name on ban screens</button> ':'')+'<button class="btn s" data-h="'+e(h.id)+'" data-o="hubKey">New key</button> <button class="btn s d" data-h="'+e(h.id)+'" data-o="hubDel">Remove</button></td></tr>'}).join('')+'</table>':'No appeal games yet. Banned players can only use the web appeal page.'}).catch(fail)}
$('hba').onclick=function(){call({op:'hubAdd',name:$('hbn').value.trim(),placeId:$('hbp').value.trim()}).then(function(j){hubKey(j.key);$('hbn').value=$('hbp').value='';toast('Registered');loadHubs()}).catch(fail)};
$('hbt').onclick=function(ev){var b=ev.target.closest('button');if(!b)return;if(b.dataset.o!=='hubTop'&&!confirm(b.dataset.o==='hubDel'?'Remove this appeal game? It stops working at once.':'Make a new key? The old key stops working at once.'))return;call({op:b.dataset.o,id:b.dataset.h}).then(function(j){hubKey(j.key);toast('Done');loadHubs()}).catch(fail)};
function loadReqs(){call({op:'dataReqs'}).then(function(j){$('dqlo').innerHTML=j.items.length?'<table class="tb">'+j.items.map(function(x){return '<tr><td style="white-space:nowrap">'+dt(x.t)+'</td><td><span class="pill">'+e(x.kind)+'</span></td><td class="mono">'+e(x.target)+'</td><td>'+e(x.who)+'</td><td>'+e(x.result)+'</td></tr>'}).join('')+'</table>':'No requests yet.'}).catch(fail)}
$('dql').onclick=loadReqs;
$('dqe').onclick=function(){var v=rqv(),all=[];$('dqo').textContent='Collecting...';var step=function(from){return call({op:'personExport',rid:v.rid,who:v.who,from:from}).then(function(j){all=all.concat(j.workspaces);if(j.next!==null&&j.next!==undefined)return step(j.next);saveJson('sentinel-player-'+v.rid+'.json',{robloxUserId:v.rid,exportedAt:j.exportedAt,workspaces:all});$('dqo').textContent='Export downloaded: '+all.length+' workspace'+(all.length==1?'':'s')+' with data.';loadReqs()})};step(0).catch(function(x){$('dqo').textContent=x.message})};
$('dqc').onclick=function(){var v=rqv();$('dqo').textContent='Checking every workspace...';call({op:'personDeleteCheck',rid:v.rid,who:v.who}).then(function(j){loadReqs();if(j.partial){$('dqo').textContent=j.error;return}if(!j.rows){$('dqo').textContent='Nothing is stored about this player in any workspace.';return}
$('dqo').innerHTML='<b>Found '+j.rows+' record'+(j.rows==1?'':'s')+' in '+j.workspaces+' workspace'+(j.workspaces==1?'':'s')+'.</b> Nothing has been deleted yet.<div class="tw2"><table class="tb mt"><tr><th>Workspace</th><th>Logbook</th><th>Chat logs</th><th>Reports</th><th>Appeals</th><th>Ban</th></tr>'+j.breakdown.map(function(x){return '<tr><td>'+e(x.name)+'</td><td>'+x.logbook+'</td><td>'+x.chatLogs+'</td><td>'+x.reports+'</td><td>'+x.appeals+'</td><td>'+(x.ban?'kept, without the name':'-')+'</td></tr>'}).join('')+'</table></div><div class="row mt" style="gap:8px;flex-wrap:wrap"><input class="in" id="dqx" placeholder="Type '+e(v.rid)+' to confirm" style="max-width:240px" autocomplete="off"><button class="btn d" id="dqd" disabled>Delete this data</button></div>';
$('dqx').oninput=function(){$('dqd').disabled=$('dqx').value.trim()!==v.rid};
$('dqd').onclick=function(){$('dqd').disabled=true;call({op:'personDelete',rid:v.rid,who:v.who,confirm:$('dqx').value.trim(),token:j.token}).then(function(r){$('dqo').textContent='Deleted in '+r.done+' of '+r.of+' workspace'+(r.of==1?'':'s')+'.';toast('Data deleted');loadReqs()}).catch(fail)}}).catch(function(x){$('dqo').textContent=x.message})};
/* targeted announcements (Site tab) */
function loadAnn(){call({op:'announcements'}).then(function(j){$('tap').textContent=j.items.length;$('tao').innerHTML=j.items.map(function(a){return '<div class="hc"><b>'+e(a.target==='all'?'Every workspace':a.target==='oldScript'?'Owners on an old script':'Workspace '+a.target.slice(3))+'</b><span class="note">'+e(a.text)+' (until '+dt(a.exp)+')</span><button class="btn s" data-a="'+e(a.id)+'">Remove</button></div>'}).join('')}).catch(fail)}
$('tag').onchange=function(){$('taw').hidden=$('tag').value!=='ws'};
$('tapost').onclick=function(){call({op:'annAdd',text:$('tat').value,target:$('tag').value,wid:$('taw').value,kind:$('tak').value,hours:+$('tah').value}).then(function(){$('tat').value='';toast('Announcement posted');loadAnn()}).catch(fail)};
$('tao').onclick=function(ev){var b=ev.target.closest('button');if(!b)return;call({op:'annDel',id:b.dataset.a}).then(function(){toast('Removed');loadAnn()}).catch(fail)};
/* account details */
$('uo').addEventListener('click',function(ev){var b=ev.target.closest('[data-u="lk"]');if(!b)return;var id=b.dataset.i;call({op:'personLookup',uid:id}).then(function(j){modal((j.name||id)+' ('+id+')','<p class="note">'+e(j.provider||'')+' sign-in'+(j.roblox?', Roblox @'+e(j.roblox.name||j.roblox.id):'')+'</p>'+(j.workspaces.length?j.workspaces.map(function(w){return '<div class="card" style="margin-top:10px"><b>'+e(w.name)+'</b> <code>'+e(w.wid)+'</code> '+(w.owner?'<span class="pill amb">Owner</span>':'<span class="pill">'+e(w.rank||'Member')+'</span>')+(w.deleted?' <span class="pill red">Deleted</span>':'')+'<div class="note">'+w.members+' member'+(w.members==1?'':'s')+'</div>'+(w.recent.length?'<div class="tw2"><table class="tb mt">'+w.recent.map(function(a){return '<tr><td class="note" style="white-space:nowrap">'+dt(a.t)+'</td><td>'+e(a.text)+'</td></tr>'}).join('')+'</table></div>':'<div class="note">No recent actions.</div>')+'</div>'}).join(''):'<p class="note">Not on any workspace.</p>'))}).catch(fail)});
/* workspace panel: read-only view and limits */
$('o').addEventListener('click',function(ev){var b=ev.target.closest('button');if(!b)return;var o=b.dataset.o,w=b.dataset.w;
if(o==='va')ask('View as the owner?','Opens this workspace read-only, as its owner sees it, for 15 minutes. Nothing can be changed. The visit is written to the workspace audit log, which the owner can see.','Open').then(function(y){if(y)return call({op:'wsViewAs',wid:w}).then(function(){window.open('/','_blank')})}).catch(fail);
else if(o==='cp'){var d=DET[w]||{},c=d.caps||{members:100,logbook:50000};setCaps(w,c.members,c.logbook).then(function(){return call({op:'wsDetail',wid:w}).then(function(x){DET[w]=x;drawWs()})}).catch(fail)}});
var T={ab:loadAbuse,gr:loadGrowth,er:loadEvents,vr:loadVersions,sg:loadStorage,ff:loadFlags,dq:loadReqs,hb:loadHubs};
document.querySelector('.tabs').addEventListener('click',function(ev){var b=ev.target.closest('.tab');if(!b)return;var t=b.dataset.t;Object.keys(T).forEach(function(k){$('p-'+k).hidden=k!==t});if(T[t])T[t]();if(t==='st')loadAnn()});
loadAbuse();
})();</script></body></html>
`;
const ADMIN_GATE = () => `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><meta name="color-scheme" content="dark"><title>Sentinel Admin</title><link rel="icon" href="/favicon.svg" type="image/svg+xml"><link rel="icon" href="/favicon-32.png" sizes="32x32" type="image/png"><link rel="apple-touch-icon" href="/apple-touch-icon.png"><style>
:root{--bg:#07080c;--bg2:#0b0d13;--card:#10131b;--card2:#151927;--ln:#222637;--ink:#e9ebf3;--mu:#8a8fa6;--ac:#4f8bff;--ac2:#7aa7ff;--red:#ff4d5e;--amb:#f5b942;--grn:#3ddc97}
*{box-sizing:border-box}[hidden]{display:none!important}html{color-scheme:dark}
body{margin:0;min-height:100vh;color:var(--ink);font:14px/1.5 Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;background:radial-gradient(900px 500px at 85% -10%,rgba(79,139,255,.14),transparent 60%),radial-gradient(700px 420px at -10% 110%,rgba(255,77,94,.09),transparent 60%),var(--bg);background-attachment:fixed}
body:before{content:"";position:fixed;inset:0;pointer-events:none;background-image:linear-gradient(rgba(255,255,255,.025) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.025) 1px,transparent 1px);background-size:44px 44px;mask-image:radial-gradient(ellipse at 50% 0,#000 20%,transparent 75%);-webkit-mask-image:radial-gradient(ellipse at 50% 0,#000 20%,transparent 75%)}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
button,input{font:inherit;color:inherit}
.btn{height:34px;padding:0 14px;border:1px solid var(--ln);border-radius:9px;background:var(--card2);color:var(--ink);font-weight:550;cursor:pointer;transition:.15s;display:inline-flex;align-items:center;gap:7px}
.btn:hover{border-color:#34395a;background:#1b2033}.btn:active{transform:translateY(1px)}.btn:disabled{opacity:.5;cursor:default}
.btn.p{background:linear-gradient(180deg,#5d97ff,#3f78ec);border-color:#4f8bff;color:#fff;box-shadow:0 6px 20px -8px rgba(79,139,255,.8)}.btn.p:hover{filter:brightness(1.08)}
.btn.d{background:rgba(255,77,94,.12);border-color:rgba(255,77,94,.4);color:#ff8f9a}.btn.d:hover{background:rgba(255,77,94,.2)}
.btn.s{height:28px;padding:0 10px;font-size:13px;border-radius:8px}
input.in{height:38px;border:1px solid var(--ln);border-radius:10px;padding:0 13px;background:#0a0c12;width:100%;outline:none;transition:.15s}
input.in:focus{border-color:var(--ac);box-shadow:0 0 0 3px rgba(79,139,255,.18)}
.pill{display:inline-flex;align-items:center;gap:6px;font-size:11.5px;font-weight:650;letter-spacing:.06em;text-transform:uppercase;border-radius:99px;padding:3px 10px;border:1px solid var(--ln);color:var(--mu);background:rgba(255,255,255,.03)}
.pill.red{color:#ff8f9a;border-color:rgba(255,77,94,.4);background:rgba(255,77,94,.08)}.pill.grn{color:var(--grn);border-color:rgba(61,220,151,.35);background:rgba(61,220,151,.07)}.pill.amb{color:var(--amb);border-color:rgba(245,185,66,.4);background:rgba(245,185,66,.08)}
.dot{width:7px;height:7px;border-radius:50%;background:currentColor;box-shadow:0 0 10px currentColor}

body{display:grid;place-items:center;padding:24px}
.g{position:relative;width:100%;max-width:400px;background:linear-gradient(180deg,rgba(21,25,39,.92),rgba(14,17,26,.92));border:1px solid var(--ln);border-radius:20px;padding:34px 30px 28px;box-shadow:0 30px 80px -30px #000,0 0 0 1px rgba(255,255,255,.02) inset;backdrop-filter:blur(8px);animation:up .5s cubic-bezier(.2,.8,.2,1)}
.g:before{content:"";position:absolute;left:24px;right:24px;top:-1px;height:2px;border-radius:2px;background:linear-gradient(90deg,transparent,var(--red),var(--amb),transparent)}
@keyframes up{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:none}}
.lg{width:62px;height:62px;border-radius:16px;margin:0 auto 18px;display:grid;place-items:center;background:#0a0c12;border:1px solid var(--ln);box-shadow:0 0 40px -6px rgba(79,139,255,.55)}.lg img{width:38px;height:38px}
h1{margin:0;text-align:center;font-size:22px;letter-spacing:-.02em}.sub{text-align:center;color:var(--mu);margin:6px 0 22px}
.row{display:flex;justify-content:center;margin-bottom:18px}
label{display:block;font-size:12px;color:var(--mu);margin:0 0 7px;font-weight:600;letter-spacing:.04em;text-transform:uppercase}
.pw{position:relative}.pw button{position:absolute;right:6px;top:5px;height:28px;border:0;background:none;color:var(--mu);cursor:pointer;font-size:12px;font-weight:600}
.go{width:100%;height:42px;margin-top:16px;justify-content:center;font-size:15px}
.err{min-height:20px;margin-top:12px;color:#ff8f9a;font-size:13px;text-align:center}
.foot{margin-top:18px;text-align:center;color:var(--mu);font-size:12px}
.shake{animation:sh .35s}@keyframes sh{20%,60%{transform:translateX(-6px)}40%,80%{transform:translateX(6px)}}
</style></head><body><form class="g" id="f" autocomplete="off" novalidate>
<div class="lg"><img src="/favicon.svg" alt="Sentinel"></div>
<div class="row"><span class="pill red"><span class="dot"></span>Restricted area</span></div>
<h1>Sentinel Admin</h1><p class="sub" id="sb">Enter the admin password to continue.</p>
<label for="t">Admin password</label><div class="pw"><input class="in" id="t" type="password" placeholder="Admin password" autocomplete="current-password" autofocus><button type="button" id="sh">Show</button></div>
<button class="btn p go" id="go">Unlock</button><div class="err" id="m" role="alert"></div>
<div class="foot">Sessions end after 8 hours. Attempts are rate limited.</div></form>
<script>var $=function(i){return document.getElementById(i)};
if(${ADMIN_TOKEN.length < 16}){$('sb').textContent='The admin console is switched off. Set ADMIN_TOKEN (16+ characters) in Vercel, then redeploy.';$('t').disabled=true;$('go').disabled=true}
$('sh').onclick=function(){var t=$('t');t.type=t.type==='password'?'text':'password';this.textContent=t.type==='password'?'Show':'Hide'};
$('f').onsubmit=function(e){e.preventDefault();var b=$('go');if(!$('t').value.trim())return;b.disabled=true;b.textContent='Checking...';$('m').textContent='';
fetch('/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:$('t').value.trim()})}).then(function(r){return r.json().catch(function(){return{}}).then(function(j){return[r,j]})}).then(function(a){if(a[0].ok){b.textContent='Welcome';location.reload()}else{b.disabled=false;b.textContent='Unlock';$('m').textContent=a[1].error||'That did not work.';var g=$('f');g.classList.remove('shake');void g.offsetWidth;g.classList.add('shake');$('t').select()}}).catch(function(){b.disabled=false;b.textContent='Unlock';$('m').textContent='Could not reach the server.'})};</script></body></html>
`;

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
const sessIssued = req => { const d = unpack(cookiesOf(req).sid); return (d && d.i) || 0; }; // when this sign-in began (0 for older cookies)
const revoked = (U0, req) => !!(U0 && U0.revoked && U0.revoked > sessIssued(req));
const annFor = u => (G.announcements || []).filter(a => a && a.exp > Date.now() && (a.target === 'all' || a.target === 'ws:' + CTX.wid || (a.target === 'oldScript' && u.isOwner && (scriptInfo().outdated || clientInfo().outdated)))).map(({ id, text, kind, exp }) => ({ id, text, kind, exp })); // admin announcements meant for this workspace
const viewAsOf = req => { const c = cookiesOf(req), d = unpack(c.va), a = unpack(c.adm); return d && d.va === 1 && /^[a-f0-9]{12}$/.test(d.w || '') && /^[gr]_\d{1,32}$/.test(d.u || '') && a && a.a === 1 ? d : null; }; // needs the admin session too
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
const page = (res, code, title, text, href = '/', label = 'Back to Sentinel') => { res.writeHead(code, { 'Content-Type': 'text/html; charset=utf-8' }); res.end(`<!DOCTYPE html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title><link rel="icon" href="/favicon.svg" type="image/svg+xml"><link rel="icon" href="/favicon-32.png" sizes="32x32" type="image/png"><link rel="apple-touch-icon" href="/apple-touch-icon.png"><body style="font:16px -apple-system,Segoe UI,system-ui,sans-serif;background:#f5f5f7;color:#1d1d1f;display:grid;place-items:center;min-height:100vh;margin:0"><div style="background:#fff;border-radius:20px;padding:36px 40px;max-width:380px;text-align:center;box-shadow:0 8px 30px rgba(0,0,0,.08)"><h2 style="margin:0 0 8px">${esc(title)}</h2><p style="color:#6e6e73;margin:0 0 20px">${esc(text)}</p><a href="${esc(href)}" style="display:inline-block;background:#0071e3;color:#fff;text-decoration:none;font-weight:600;padding:10px 20px;border-radius:10px">${esc(label)}</a></div></body>`); };
const cleanName = (s, n = 40) => String(s || '').replace(/[\u0000-\u001f<>]/g, '').replace(/\s+/g, ' ').trim().slice(0, n);
const LEGAL = { privacy: 'Privacy Policy', terms: 'Terms of Service', cookies: 'Cookie Policy', 'acceptable-use': 'Acceptable Use Policy', 'player-notice': 'Player Notice' };
const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
function legalPage(name) {
  const file = path.join(__dirname, '..', 'legal', name + '.html'), frag = fs.readFileSync(file, 'utf8');
  const body = frag.replace(/\{\{(\w+)\}\}/g, (_, k) => cfg[k] ? esc(cfg[k]) : `<mark>[set ${ENVNAME[k] || k} in your Vercel environment variables]</mark>`);
  const mt = fs.statSync(file).mtime, updated = cfg.updated || (mt.getFullYear() > 2020 ? mt.toISOString().slice(0, 10) : '<mark>[set PANEL_LEGAL_UPDATED]</mark>');
  const links = Object.entries(LEGAL).map(([k, t]) => `<a href="/legal/${k}"${k === name ? ' aria-current="page"' : ''}>${t}</a>`).join(' ');
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${LEGAL[name]}</title><link rel="icon" href="/favicon.svg" type="image/svg+xml"><link rel="icon" href="/favicon-32.png" sizes="32x32" type="image/png"><link rel="apple-touch-icon" href="/apple-touch-icon.png"><style>
body{margin:0;background:#f4f6fb;color:#121528;font:16px/1.65 'Segoe UI',system-ui,sans-serif}main{max-width:780px;margin:0 auto;padding:36px 20px 80px}h1{font-size:36px;line-height:1.15;margin:0 0 4px}h2{font-size:21px;margin:32px 0 8px}
nav{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:28px;font-size:14px}nav a{color:#667085;text-decoration:none;font-weight:600}nav a[aria-current]{color:#2f5bff}a{color:#2f5bff}
table{border-collapse:collapse;width:100%;font-size:15px;margin:10px 0;background:#fff}td,th{border:1px solid #e6e9f2;padding:8px 10px;text-align:left;vertical-align:top}th{background:#eaefff}
mark{background:#fdf2dc;border-radius:4px;padding:0 4px}.draft{background:#fdf2dc;border:1px solid #f0d9a8;border-radius:10px;padding:12px 16px;margin:16px 0;font-size:15px}.muted{color:#667085}code{background:#eaefff;border-radius:4px;padding:1px 5px}
</style></head><body><main><nav>${links}</nav><h1>${LEGAL[name]}</h1><p class="muted">Last updated ${updated}</p>${cfg.legalReviewed ? '' : '<div class="draft"><b>Draft.</b> These documents have not been reviewed by a lawyer. Set LEGAL_REVIEWED to true in your Vercel environment variables once they have, and this notice will disappear.</div>'}${body}</main></body></html>`;
}
async function authRoute(req, res, url, p, ip) {
  const w = limit('auth:' + ip, 20, 60000) || (/\/callback$/.test(p) ? 0 : await slimit('auth:' + ip, 40, 600000)); if (w) return page(res, 429, 'Too many attempts', `Please wait ${w} seconds and try again.`);
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
    res.setHeader('Set-Cookie', clearCookie('oa')); res.writeHead(302, { Location: oa.i ? '/#/join/' + oa.i : '/#linked' }); return res.end();
  }
  const uid = name[0] + '_' + req._oauth.sub; setUid(uid); await need('user');
  if (!U) { if (!SIGNUPS_OPEN && !oa.i) return page(res, 403, 'Sign-ups are closed', 'This site is not accepting new accounts right now.'); U = { id: uid, provider: name, workspaces: [], created: Date.now() }; }
  U.name = req._oauth.name;
  if (U.mfa && U.mfa.on) { // they have two-step on: the session only starts after the code is checked
    res.setHeader('Set-Cookie', [mkCookie('mp', pack({ u: uid, e: Date.now() + 600000 }), { maxAge: 600 }), clearCookie('sid'), clearCookie('oa')]);
    res.writeHead(302, { Location: '/' + (oa.i ? '#/join/' + oa.i : '') }); return res.end();
  }
  res.setHeader('Set-Cookie', [mkCookie('sid', pack({ u: uid, i: Date.now(), e: Date.now() + 7 * 864e5 })), clearCookie('oa')]);
  res.writeHead(302, { Location: '/' + (oa.i ? '#/join/' + oa.i : '') }); return res.end();
}

function reviewForm(u, uid, B, base) { // accept, decline or mark a form response reviewed (website and Discord); returns [status, body]
if (!has(u, 'forms.review')) return [403, { error: 'Your rank does not allow that.' }];
  const x = FR.find(y => y.id === B.rid); if (!x) return [404, { error: 'That response no longer exists.' }];
  if (x.status !== 'new') return [409, { error: 'That response was already reviewed.' }];
  const dec = ['accept', 'decline', 'reviewed'].includes(B.decision) ? B.decision : null; if (!dec) return [400, { error: 'bad request' }];
  let link = null;
  if (dec === 'accept') {
    const F = D.forms.find(f => f.id === x.form), rk = F && F.kind === 'application' && F.rank && D.ranks[F.rank];
    if (rk) {
      if (!x.who) return [400, { error: 'This response has no Roblox username, so an invite cannot be locked to the applicant.' }];
      if (!above(u, rk.pos)) return [403, { error: `You can only accept applicants into ranks below your own. Ask someone above ${rk.name}.` }];
      if (Object.keys(D.invites).length >= 20) return [400, { error: 'Too many open invites. Revoke some first.' }];
      const code = CTX.wid + crypto.randomBytes(8).toString('hex'); D.invites[code] = { rank: F.rank, exp: Date.now() + 7 * 864e5, by: u.user, lock: { id: String(x.who.id), name: x.who.name } }; x.invite = code; link = `${base}/#/join/${code}`;
    }
  }
  x.status = { accept: 'accepted', decline: 'declined', reviewed: 'reviewed' }[dec]; x.reviewer = u.user; x.reviewed = Date.now(); x.note = cleanName(B.note, 300) || null; x.reply = cleanName(B.reply, 600) || null;
  D.formsNew = Math.max(0, (D.formsNew || 0) - 1); audit(u.user, `${x.status[0].toUpperCase() + x.status.slice(1)} a ${x.formTitle} response${x.who ? ' from ' + x.who.name : ''}${link ? ' and created a locked invite' : ''}`);
  return [200, { ok: true, link }];
      }
function reviewAppeal(u, uid, B) { // accept or deny a ban appeal (website and Discord); returns [status, body]
if (!has(u, 'appeals.review')) return [403, { error: 'Your rank does not allow that.' }];
  const a = D.appeals.find(x => x.id === B.id && x.status === 'open'); if (!a) return [404, { error: 'That appeal was already reviewed.' }];
  const note = cleanName(B.note, 300), reply = cleanName(B.reply, 600);
  if (B.decision === 'accept') {
    if (!has(u, 'mod.unban')) return [403, { error: 'Your rank does not allow that.' }];
    const ban = D.bans[a.uid];
    if (needSecond(u, ban)) {
      a.approvals ||= [];
      if (a.approvals.some(x => x.uid === uid)) return [409, { error: 'You already approved this appeal. A different staff member needs to approve it too.' }];
      if (!a.approvals.length) { a.approvals.push({ uid, by: u.user, t: Date.now(), note, reply }); audit(u.user, `Approved the appeal from ${a.name} (waiting for a second approval)`); if (!botPost({ embeds: [dEmbed(`Appeal needs a second approval: ${a.name}`, a.text, [['First approval', u.user], ['Banned for', a.banReason]], 0xf5a524)], components: [{ type: 1, components: [dBtn('Give final approval', `ap:${a.id}:a`, 3), dBtn('Deny', `ap:${a.id}:d`, 4)] }] })) notify('appeals', `Appeal needs a second approval: ${a.name}`, a.text, [['First approval', u.user]], 0xf5a524); return [200, { ok: true, pending: true, msg: 'Approved. This is a permanent ban, so one more staff member must approve before they are unbanned.' }]; }
    }
    const first = (a.approvals || [])[0];
    act({ action: 'unban', userId: a.uid, name: a.name, reason: 'Appeal accepted' + (first ? ` (approved by ${first.by} and ${u.user})` : '') + (note ? ': ' + note : ''), by: u.user, byUid: uid }); a.status = 'accepted';
    a.reply = reply || (first && first.reply) || null;
  }
  else if (B.decision === 'deny') { a.status = 'denied'; a.reply = reply || null; delete a.approvals; } else return [400, { error: 'bad request' }];
  a.by = u.user; a.note = note; a.reviewed = Date.now(); obTick(uid, 'appeal'); audit(u.user, `${a.status === 'accepted' ? 'Accepted' : 'Denied'} the appeal from ${a.name}`); return [200, { ok: true }];
    }
function doAction(u, uid, B) { // one moderation action, shared by the website and the Discord bot; returns [status, body]
      const reason0 = cleanName(B.reason, 300); let action = B.action, minutes = clampInt(B.minutes, 0, 525600), ruleId = null, reason = reason0 || 'No reason given';
  if (B.ruleId) {
    const r = D.rulebook.find(x => x.id === B.ruleId); if (!r) return [404, { error: 'That rule no longer exists' }];
    const n = (D.logs[B.userId] || []).filter(e => e.ruleId === r.id && e.status !== 'reverted').length, st = r.steps[Math.min(n, r.steps.length - 1)];
    action = st.type; minutes = st.minutes || 0; ruleId = r.id; reason = `${r.title} (offense ${n + 1})${reason0 ? ': ' + reason0 : ''}`;
  }
  if (!ACT_PERM[action]) return [400, { error: 'bad action' }];
  if (!has(u, action === 'ban' && !(minutes > 0) ? 'mod.permban' : ACT_PERM[action])) return [403, { error: 'Your rank does not allow that.' }];
  if (action === 'announce') {
    let target = null; if (B.server) { target = Object.keys(R.servers).find(k => k.slice(0, 8) === String(B.server) && Date.now() - R.servers[k].last < LIVE_MS); if (!target) return [404, { error: 'That server has already closed.' }]; }
    cmd({ type: 'announce', text: reason, ...(target ? { target } : {}) }); feed((target ? `Announcement to server ${target.slice(0, 8)}: ` : 'Announcement: ') + reason, u.user); return [200, { ok: true }];
  }
  if (!Number.isInteger(B.userId) || B.userId < 1) return [400, { error: 'bad userId' }];
  const nm = cleanName(B.name, 40) || String(B.userId);
  if (['warn', 'kick', 'mute', 'ban'].includes(action) && u.limit > 0) { // per-rank anti-abuse limit, counted from the logbook
    const since = Date.now() - 36e5; let c = 0; for (const list of Object.values(D.logs)) for (const e of list) if (e.byUid === uid && e.time > since && MOD_TYPES.includes(e.type)) c++;
    if (c >= u.limit) return [429, { error: `Your rank allows ${u.limit} moderation actions per hour. Ask a higher rank for help.` }];
  }
  if (action === 'points') { const amt = clampInt(B.amount, -100000, 100000); if (!amt) return [400, { error: 'Enter a points amount' }]; addPoints(B.userId, nm, amt, reason, u.user, uid); return [200, { ok: true }]; }
  if (action === 'ban' && !(minutes > 0) && !u.isOwner && approvalOn('permBan')) { // permanent bans can need a second person
    const pl = { userId: B.userId, name: nm, reason, ruleId, ev: cleanLinks(B.evidence, 5), note: cleanName(B.note, 500), ...(B.alts === false ? { alts: false } : {}) };
    if (approverExists('permBan', uid, pl)) { const it = propose('permBan', u, uid, pl, `permanently ban ${nm}`, reason); if (!it) return [429, { error: 'Too many requests are waiting for approval. Ask someone to clear them first.' }]; return [200, { ok: true, pending: true, msg: PEND_MSG }]; }
  }
  if (action === 'unban' && needSecond(u, D.bans[B.userId])) {
    const ban = D.bans[B.userId], rq = ban.unreq;
    if (!rq || Date.now() - rq.t > 7 * 864e5) { ban.unreq = { uid, by: u.user, t: Date.now(), reason }; audit(u.user, `Asked to unban ${nm} (a second staff member must approve)`); if (!botPost({ embeds: [dEmbed(`Unban needs a second approval: ${nm}`, reason, [['Asked by', u.user], ['Banned for', ban.reason]], 0xf5a524)], components: [{ type: 1, components: [dBtn('Approve unban', `ub:${B.userId}`, 3)] }] })) notify('bans', `Unban needs a second approval: ${nm}`, reason, [['Asked by', u.user]], 0xf5a524); return [200, { ok: true, pending: true, msg: 'Saved. This is a permanent ban, so a second staff member must also approve the unban.' }]; }
    if (rq.uid === uid) return [409, { error: 'You already asked to lift this ban. A different staff member needs to approve it.' }];
    reason = `${rq.reason} (approved by ${rq.by} and ${u.user})`;
  }
  const ev = cleanLinks(B.evidence, 5), pnote = cleanName(B.note, 500);
  const ctx = B.ctx === false || !['warn', 'kick', 'mute', 'ban'].includes(action) ? [] : R.chat.filter(m => m.userId === B.userId && Date.now() - m.t < 36e5).slice(-15).map(m => ({ t: m.t, text: m.text }));
  act({ action, userId: B.userId, name: nm, reason, minutes, by: u.user, byUid: uid, ruleId, hide: B.hideChat !== false, alts: B.alts !== false, extra: { ...(ev.length ? { ev } : {}), ...(pnote ? { note: pnote } : {}), ...(ctx.length ? { ctx } : {}), ...(Array.isArray(B.boxes) && B.boxes.length ? { boxes: B.boxes.slice(0, 5) } : {}) } });
  const mw = action === 'mute' ? muteWarn(B.hideChat !== false) : action === 'unban' ? unbanWarn() : null;
  return [200, { ok: true, applied: { action, minutes }, ...(mw ? { warn: mw } : {}) }];
    }
const ACT_PERM = { warn: 'mod.warn', kick: 'mod.kick', mute: 'mod.mute', unmute: 'mod.mute', ban: 'mod.ban', unban: 'mod.unban', announce: 'announce', points: 'points.manage' };
const TYPE_GROUP = { Warned: 'warn', Kicked: 'kick', Muted: 'mute', Unmuted: 'mute', Suspended: 'ban', Banned: 'ban', Unbanned: 'ban', Points: 'points', Note: 'note' };
const ok = res => send(res, 200, { ok: true });
const APPEAL_MAX = 2, APPEAL_WINDOW = 5 * 864e5; // each player may appeal twice every 5 days
const APPEAL_PAGE = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><meta name="robots" content="noindex"><title>Ban appeal</title><link rel="icon" href="/favicon.svg" type="image/svg+xml"><link rel="icon" href="/favicon-32.png" sizes="32x32" type="image/png"><link rel="apple-touch-icon" href="/apple-touch-icon.png"><style>
:root{--bg:#e9eefb;--card:rgba(255,255,255,.82);--ink:#1d1d1f;--mu:#6e6e73;--ac:#0a7aff;--ln:rgba(0,0,0,.14)}@media(prefers-color-scheme:dark){:root{--bg:#0d1020;--card:rgba(44,44,48,.8);--ink:#f5f5f7;--mu:#98989f;--ac:#0a84ff;--ln:rgba(255,255,255,.18)}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:20px;background:radial-gradient(40% 45% at 15% 20%,#8ab8ff55,transparent 70%),radial-gradient(40% 45% at 85% 85%,#ffc2a155,transparent 70%),var(--bg);color:var(--ink);font:15px/1.5 -apple-system,BlinkMacSystemFont,"SF Pro Text",Inter,system-ui,sans-serif}
.c{width:100%;max-width:440px;background:var(--card);-webkit-backdrop-filter:blur(40px) saturate(180%);backdrop-filter:blur(40px) saturate(180%);border-radius:20px;padding:34px 30px;box-shadow:0 0 0 .5px var(--ln),0 24px 64px rgba(20,24,40,.2)}
h1{font-size:23px;letter-spacing:-.02em;margin:0 0 6px}p{color:var(--mu);margin:0 0 20px}label{display:block;font-weight:600;font-size:13px;margin:14px 0 6px}
input,textarea{width:100%;border:0;border-radius:9px;padding:10px 12px;font:inherit;color:inherit;background:rgba(127,127,127,.12);box-shadow:inset 0 0 0 .5px var(--ln);outline:0}input:focus,textarea:focus{box-shadow:0 0 0 3px #0a7aff55}textarea{min-height:120px;resize:vertical}
button{margin-top:20px;width:100%;height:42px;border:0;border-radius:10px;font:600 15px inherit;color:#fff;background:linear-gradient(180deg,#3d9bff,var(--ac));cursor:pointer}button[disabled]{opacity:.5}
.m{margin-top:14px;font-size:14px;padding:10px 12px;border-radius:9px}.e{background:rgba(255,59,48,.14);color:#d70015}.o{background:rgba(48,209,88,.16);color:#1f8a3b}.x{font-size:12px;color:var(--mu);margin-top:18px;text-align:center}.n{background:rgba(10,122,255,.12);color:var(--ac)}.rp{margin-top:12px;padding:12px 14px;border-radius:10px;background:rgba(127,127,127,.12);font-size:14px;white-space:pre-wrap}.rp b{display:block;font-size:12px;color:var(--mu);margin-bottom:4px}.lk{display:block;margin-top:8px;padding:10px 12px;border-radius:9px;background:rgba(127,127,127,.12);font:13px/1.4 ui-monospace,Menlo,monospace;word-break:break-all;color:var(--ink);text-decoration:none}
</style></head><body><div class="c" id="c"><h1 id="h">Appeal a ban</h1><p id="s">Loading…</p><form id="f" hidden novalidate><label for="u">Your Roblox username</label><input id="u" maxlength="40" autocomplete="off"><label for="t">Why should the ban be lifted?</label><textarea id="t" maxlength="1000" placeholder="Explain what happened and what you will do differently."></textarea><button id="b" disabled>Send appeal</button></form><div id="m"></div><div id="hub" class="rp" hidden></div><div class="x">Appeals are read by the game's staff. Sending false information may get a denied appeal.</div></div>
<script>const w=location.pathname.split('/')[2]||'',rq=new URLSearchParams(location.search).get('r')||'',$=i=>document.getElementById(i);
const el=(t,c,x)=>{const e=document.createElement(t);if(c)e.className=c;if(x!=null)e.textContent=x;return e};
function showStatus(j){$('f').hidden=true;$('h').textContent='Your appeal';$('s').textContent='Appeal in '+j.game+', sent '+new Date(j.t).toLocaleDateString()+'.';$('m').innerHTML='';
 const st={open:j.waiting2?'Waiting for a final review':'Waiting for review',accepted:'Accepted. You have been unbanned.',denied:'Denied'}[j.status]||j.status;
 $('m').appendChild(el('div','m '+(j.status==='accepted'?'o':j.status==='denied'?'e':'n'),st));
 if(j.reply){const r=el('div','rp');r.appendChild(el('b','','Message from staff'));r.appendChild(el('div','',j.reply));$('m').appendChild(r)}}
if(rq){fetch('/api/appeal/status?w='+encodeURIComponent(w)+'&r='+encodeURIComponent(rq)).then(r=>r.json()).then(j=>{if(j.error){$('s').textContent=j.error;return}showStatus(j)}).catch(()=>$('s').textContent='Could not load this page.')}
else fetch('/api/appeal/info?w='+encodeURIComponent(w)).then(r=>r.json()).then(j=>{if(j.error){$('s').textContent=j.error;return}$('s').textContent='Appeal a ban in '+j.name+'. After sending, you get a private link to check the result.';$('f').hidden=false;if(j.hub){const h=$('hub');h.appendChild(el('b','',"Can't use this page?"));h.appendChild(el('div','','Join the '+j.hub.name+' game on Roblox and appeal from there.'));const a=el('a','lk',j.hub.link);a.href=j.hub.link;a.target='_blank';a.rel='noopener';h.appendChild(a);h.hidden=false}}).catch(()=>$('s').textContent='Could not load this page.');
const gate=()=>{$('b').disabled=!($('u').value.trim()&&$('t').value.trim())};$('u').oninput=$('t').oninput=gate;
$('f').onsubmit=async e=>{e.preventDefault();if($('b').disabled)return;$('b').disabled=true;$('m').innerHTML='';try{const r=await fetch('/api/appeal',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({w,username:$('u').value.trim(),text:$('t').value.trim()})}),j=await r.json();
 if(r.ok){$('f').hidden=true;$('m').appendChild(el('div','m o','Appeal sent. Staff will review it soon.'));if(j.check){const b=el('div','rp');b.appendChild(el('b','','Save this link to check the result and read any reply from staff'));const a=el('a','lk',j.check);a.href=j.check;b.appendChild(a);$('m').appendChild(b)}}
 else{$('m').appendChild(el('div','m e',j.error||'Something went wrong.'));gate()}}catch{$('m').innerHTML='';$('m').appendChild(el('div','m e','No connection. Try again.'));gate()}};</script></body></html>`;

const REPORT_PAGE = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><meta name="robots" content="noindex"><title>Report a player</title><link rel="icon" href="/favicon.svg" type="image/svg+xml"><link rel="icon" href="/favicon-32.png" sizes="32x32" type="image/png"><link rel="apple-touch-icon" href="/apple-touch-icon.png"><style>
:root{--bg:#e9eefb;--card:rgba(255,255,255,.82);--ink:#1d1d1f;--mu:#6e6e73;--ac:#0a7aff;--ln:rgba(0,0,0,.14)}@media(prefers-color-scheme:dark){:root{--bg:#0d1020;--card:rgba(44,44,48,.8);--ink:#f5f5f7;--mu:#98989f;--ac:#0a84ff;--ln:rgba(255,255,255,.18)}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:20px;background:radial-gradient(40% 45% at 15% 20%,#8ab8ff55,transparent 70%),radial-gradient(40% 45% at 85% 85%,#ffc2a155,transparent 70%),var(--bg);color:var(--ink);font:15px/1.5 -apple-system,BlinkMacSystemFont,"SF Pro Text",Inter,system-ui,sans-serif}
.c{width:100%;max-width:460px;background:var(--card);-webkit-backdrop-filter:blur(40px) saturate(180%);backdrop-filter:blur(40px) saturate(180%);border-radius:20px;padding:34px 30px;box-shadow:0 0 0 .5px var(--ln),0 24px 64px rgba(20,24,40,.2)}
h1{font-size:23px;letter-spacing:-.02em;margin:0 0 6px}p{color:var(--mu);margin:0 0 20px}label{display:block;font-weight:600;font-size:13px;margin:14px 0 6px}label small{font-weight:400;color:var(--mu)}
input,textarea{width:100%;border:0;border-radius:9px;padding:10px 12px;font:inherit;color:inherit;background:rgba(127,127,127,.12);box-shadow:inset 0 0 0 .5px var(--ln);outline:0}input:focus,textarea:focus{box-shadow:0 0 0 3px #0a7aff55}textarea{min-height:120px;resize:vertical}
button{margin-top:20px;width:100%;height:42px;border:0;border-radius:10px;font:600 15px inherit;color:#fff;background:linear-gradient(180deg,#3d9bff,var(--ac));cursor:pointer}button[disabled]{opacity:.5}
.m{margin-top:14px;font-size:14px;padding:10px 12px;border-radius:9px}.e{background:rgba(255,59,48,.14);color:#d70015}.o{background:rgba(48,209,88,.16);color:#1f8a3b}.x{font-size:12px;color:var(--mu);margin-top:18px;text-align:center}.hp{position:absolute;left:-9999px;width:1px;height:1px;opacity:0}
</style></head><body><div class="c"><h1 id="h">Report a player</h1><p id="s">Loading...</p><form id="f" hidden novalidate><label for="t1">Player you are reporting</label><input id="t1" maxlength="40" autocomplete="off" placeholder="Their exact Roblox username"><label for="t2">What happened?</label><textarea id="t2" maxlength="1000" placeholder="Say what they did, roughly when, and in which server if you know."></textarea><label for="t3">Evidence link <small>(optional)</small></label><input id="t3" maxlength="300" autocomplete="off" placeholder="https://..."><label for="t4">Your Roblox username <small>(optional, so staff can ask questions)</small></label><input id="t4" maxlength="40" autocomplete="off"><input class="hp" id="hp" tabindex="-1" autocomplete="off" aria-hidden="true"><button id="b" disabled>Send report</button></form><div id="m"></div><div class="x">Reports are read by the game's staff. False reports may be ignored.</div></div>
<script>var w=location.pathname.split('/')[2]||'',$=function(i){return document.getElementById(i)};
function el(t,c,x){var e=document.createElement(t);if(c)e.className=c;if(x!=null)e.textContent=x;return e}
fetch('/api/report/info?w='+encodeURIComponent(w)).then(function(r){return r.json()}).then(function(j){if(j.error){$('s').textContent=j.error;return}$('s').textContent='Report a player in '+j.name+'. Staff will look into it.';$('f').hidden=false}).catch(function(){$('s').textContent='Could not load this page.'});
function gate(){$('b').disabled=!($('t1').value.trim()&&$('t2').value.trim())}$('t1').oninput=$('t2').oninput=gate;
$('f').onsubmit=function(e){e.preventDefault();if($('b').disabled)return;$('b').disabled=true;$('m').innerHTML='';
fetch('/api/report',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({w:w,target:$('t1').value.trim(),text:$('t2').value.trim(),link:$('t3').value.trim(),reporter:$('t4').value.trim(),website:$('hp').value})}).then(function(r){return r.json().then(function(j){return[r,j]})}).then(function(a){if(a[0].ok){$('f').hidden=true;$('m').appendChild(el('div','m o','Report sent. Thank you, staff will look into it.'))}else{$('m').appendChild(el('div','m e',a[1].error||'Something went wrong.'));gate()}}).catch(function(){$('m').appendChild(el('div','m e','No connection. Try again.'));gate()})};</script></body></html>
`;
const LOG_PAGE = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><title>Moderation log</title><link rel="icon" href="/favicon.svg" type="image/svg+xml"><link rel="icon" href="/favicon-32.png" sizes="32x32" type="image/png"><link rel="apple-touch-icon" href="/apple-touch-icon.png"><style>
:root{--bg:#e9eefb;--card:rgba(255,255,255,.82);--ink:#1d1d1f;--mu:#6e6e73;--ac:#0a7aff;--ln:rgba(0,0,0,.12)}@media(prefers-color-scheme:dark){:root{--bg:#0d1020;--card:rgba(44,44,48,.8);--ink:#f5f5f7;--mu:#98989f;--ac:#0a84ff;--ln:rgba(255,255,255,.14)}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;padding:28px 16px;background:radial-gradient(40% 45% at 15% 10%,#8ab8ff55,transparent 70%),var(--bg);color:var(--ink);font:15px/1.5 -apple-system,BlinkMacSystemFont,"SF Pro Text",Inter,system-ui,sans-serif}
.c{max-width:720px;margin:0 auto;background:var(--card);-webkit-backdrop-filter:blur(40px) saturate(180%);backdrop-filter:blur(40px) saturate(180%);border-radius:20px;padding:30px;box-shadow:0 0 0 .5px var(--ln),0 24px 64px rgba(20,24,40,.2)}
h1{font-size:24px;letter-spacing:-.02em;margin:0 0 4px}p{color:var(--mu);margin:0 0 18px}
.sum{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:10px;margin-bottom:18px}.sum div{background:rgba(127,127,127,.1);border-radius:12px;padding:10px 12px}.sum b{display:block;font-size:22px}.sum small{color:var(--mu);font-size:12px}
.r{display:flex;gap:12px;align-items:center;padding:11px 2px;border-top:1px solid var(--ln)}.r time{color:var(--mu);font-size:13px;width:88px;flex:none}.t{font-size:12px;font-weight:700;border-radius:6px;padding:2px 8px;flex:none;background:rgba(127,127,127,.18)}.t.ban{background:rgba(255,59,48,.16);color:#d70015}.t.warn{background:rgba(255,159,10,.18);color:#b25e00}.t.mute{background:rgba(10,122,255,.14);color:var(--ac)}.t.ok{background:rgba(48,209,88,.16);color:#1f8a3b}
.r .w{flex:1;min-width:0}.r .w span{color:var(--mu);font-size:13px;display:block;overflow:hidden;text-overflow:ellipsis}.x{font-size:12px;color:var(--mu);margin-top:18px;text-align:center}
</style></head><body><div class="c"><h1 id="h">Moderation log</h1><p id="s">Loading...</p><div class="sum" id="sm" hidden></div><div id="o"></div><div class="x">Player names are partly hidden. Published by the game's staff.</div></div>
<script>var w=location.pathname.split('/')[2]||'',$=function(i){return document.getElementById(i)};
function el(t,c,x){var e=document.createElement(t);if(c)e.className=c;if(x!=null)e.textContent=x;return e}
var CL={Banned:'ban',Suspended:'ban',Unbanned:'ok',Warned:'warn',Kicked:'warn',Muted:'mute',Unmuted:'ok'};
fetch('/api/publiclog?w='+encodeURIComponent(w)).then(function(r){return r.json()}).then(function(j){if(j.error){$('s').textContent=j.error;return}
$('h').textContent=j.name+' moderation log';$('s').textContent='The most recent actions by staff. Last '+j.days+' days.';
var sm=$('sm');sm.hidden=false;[['Bans',j.counts.bans],['Warnings',j.counts.warns],['Mutes',j.counts.mutes],['Kicks',j.counts.kicks]].forEach(function(x){var d=el('div');d.appendChild(el('b','',x[1]));d.appendChild(el('small','',x[0]));sm.appendChild(d)});
var o=$('o');if(!j.items.length){o.appendChild(el('p','','Nothing to show yet.'));return}
j.items.forEach(function(i){var r=el('div','r');r.appendChild(el('time','',new Date(i.t).toLocaleDateString()));r.appendChild(el('span','t '+(CL[i.type]||''),i.type));var d=el('div','w');d.appendChild(el('div','',i.who+(i.len?' - '+i.len:'')));if(i.reason)d.appendChild(el('span','',i.reason));r.appendChild(d);o.appendChild(r)})}).catch(function(){$('s').textContent='Could not load this page.'});</script></body></html>
`;

const FORM_PAGE = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><meta name="robots" content="noindex"><title>Form</title><link rel="icon" href="/favicon.svg" type="image/svg+xml"><link rel="icon" href="/favicon-32.png" sizes="32x32" type="image/png"><link rel="apple-touch-icon" href="/apple-touch-icon.png"><style>
:root{--bg:#e9eefb;--card:rgba(255,255,255,.84);--ink:#1d1d1f;--mu:#6e6e73;--ac:#0a7aff;--ln:rgba(0,0,0,.14)}@media(prefers-color-scheme:dark){:root{--bg:#0d1020;--card:rgba(44,44,48,.82);--ink:#f5f5f7;--mu:#98989f;--ac:#0a84ff;--ln:rgba(255,255,255,.18)}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:28px 16px;background:radial-gradient(40% 45% at 15% 20%,#8ab8ff55,transparent 70%),radial-gradient(40% 45% at 85% 85%,#c9a1ff44,transparent 70%),var(--bg);color:var(--ink);font:15px/1.5 -apple-system,BlinkMacSystemFont,"SF Pro Text",Inter,system-ui,sans-serif}
.c{width:100%;max-width:560px;background:var(--card);-webkit-backdrop-filter:blur(40px) saturate(180%);backdrop-filter:blur(40px) saturate(180%);border-radius:22px;padding:34px 30px;box-shadow:0 0 0 .5px var(--ln),0 24px 64px rgba(20,24,40,.2)}
.g{font-size:12px;font-weight:650;color:var(--mu);text-transform:uppercase;letter-spacing:.05em;margin:0 0 6px}h1{font-size:25px;letter-spacing:-.02em;margin:0 0 6px}#s{color:var(--mu);margin:0 0 6px;white-space:pre-wrap}
label{display:block;font-weight:600;font-size:14px;margin:20px 0 7px}label i{color:#ff453a;font-style:normal;margin-left:3px}
input,textarea,select{width:100%;border:0;border-radius:10px;padding:11px 12px;font:inherit;color:inherit;background:rgba(127,127,127,.12);box-shadow:inset 0 0 0 .5px var(--ln);outline:0}input:focus,textarea:focus,select:focus{box-shadow:0 0 0 3px #0a7aff55}textarea{min-height:110px;resize:vertical}
button{margin-top:26px;width:100%;height:44px;border:0;border-radius:11px;font:600 15px inherit;color:#fff;background:linear-gradient(180deg,#3d9bff,var(--ac));cursor:pointer}button[disabled]{opacity:.5}
.m{margin-top:16px;font-size:14px;padding:11px 13px;border-radius:10px}.e{background:rgba(255,59,48,.14);color:#d70015}.o{background:rgba(48,209,88,.16);color:#1f8a3b}.n{background:rgba(10,122,255,.12);color:var(--ac)}
.rp{margin-top:12px;padding:12px 14px;border-radius:10px;background:rgba(127,127,127,.12);font-size:14px;white-space:pre-wrap}.rp b{display:block;font-size:12px;color:var(--mu);margin-bottom:4px}
.lk{display:block;margin-top:8px;padding:10px 12px;border-radius:9px;background:rgba(127,127,127,.12);font:13px/1.4 ui-monospace,Menlo,monospace;word-break:break-all;color:var(--ink);text-decoration:none}.go{display:block;margin-top:12px;text-align:center;padding:12px;border-radius:11px;background:linear-gradient(180deg,#3d9bff,var(--ac));color:#fff;font-weight:600;text-decoration:none}
.x{font-size:12px;color:var(--mu);margin-top:20px;text-align:center}.hp{position:absolute;left:-9999px;width:1px;height:1px;opacity:0}
</style></head><body><div class="c"><div class="g" id="g"></div><h1 id="h">Loading…</h1><p id="s"></p><form id="f" hidden novalidate><div id="q"></div><input class="hp" id="hp" tabindex="-1" autocomplete="off" aria-hidden="true"><button id="b">Send</button></form><div id="m"></div><div class="x">Answers go to this game's staff team through Sentinel.</div></div>
<script>const pr=location.pathname.split('/'),w=pr[2]||'',fid=pr[3]||'',rq=new URLSearchParams(location.search).get('r')||'',$=i=>document.getElementById(i);let F=null;
const el=(t,c,x)=>{const e=document.createElement(t);if(c)e.className=c;if(x!=null)e.textContent=x;return e};
const msg=(c,t)=>{$('m').innerHTML='';$('m').appendChild(el('div','m '+c,t))};
function status(j){$('f').hidden=true;$('g').textContent=j.game;$('h').textContent=j.title;$('s').textContent='Sent '+new Date(j.t).toLocaleDateString()+'.';
 msg(j.status==='accepted'?'o':j.status==='declined'?'e':'n',{new:'Waiting for review',accepted:'Accepted',declined:'Not accepted this time',reviewed:'Reviewed by staff'}[j.status]||j.status);
 if(j.reply){const r=el('div','rp');r.appendChild(el('b','','Message from staff'));r.appendChild(el('div','',j.reply));$('m').appendChild(r)}
 if(j.invite){const r=el('div','rp');r.appendChild(el('b','','You are invited to the staff team'));r.appendChild(el('div','','Open this link and sign in with the Roblox account @'+j.inviteFor+'. It only works for that account and expires in 7 days.'));const a=el('a','go','Join the team');a.href=j.invite;r.appendChild(a);$('m').appendChild(r)}
 else if(j.inviteUsed){$('m').appendChild(el('div','rp','Your invite has been used. Welcome aboard.'))}}
function build(j){F=j;document.title=j.title;$('g').textContent=j.game;$('h').textContent=j.title;$('s').textContent=j.desc||'';const q=$('q');
 for(const f of j.fields){const l=el('label','',f.label);l.htmlFor='q_'+f.id;if(f.required)l.appendChild(el('i','','*'));q.appendChild(l);let i;
  if(f.type==='long')i=el('textarea');else if(f.type==='choice'||f.type==='yesno'){i=el('select');i.appendChild(el('option','','Choose…')).value='';for(const o of f.type==='yesno'?['Yes','No']:f.options)i.appendChild(el('option','',o)).value=o}
  else{i=el('input');i.maxLength=f.type==='short'?300:100;if(f.type==='number')i.inputMode='decimal';if(f.type==='roblox'){i.placeholder='Roblox username';i.autocomplete='off';i.spellcheck=false}}
  i.id='q_'+f.id;i.dataset.id=f.id;q.appendChild(i)}
 $('f').hidden=false}
if(rq)fetch('/api/form/status?w='+encodeURIComponent(w)+'&f='+encodeURIComponent(fid)+'&r='+encodeURIComponent(rq)).then(r=>r.json()).then(j=>{if(j.error){$('h').textContent='Not found';$('s').textContent=j.error;return}status(j)}).catch(()=>{$('h').textContent='Could not load';$('s').textContent='Check your connection and try again.'});
else fetch('/api/form/info?w='+encodeURIComponent(w)+'&f='+encodeURIComponent(fid)).then(r=>r.json()).then(j=>{if(j.error){$('h').textContent='Form closed';$('s').textContent=j.error;return}build(j)}).catch(()=>{$('h').textContent='Could not load';$('s').textContent='Check your connection and try again.'});
$('f').onsubmit=async e=>{e.preventDefault();const ans={};for(const i of $('q').querySelectorAll('[data-id]'))ans[i.dataset.id]=i.value.trim();
 const miss=F.fields.find(f=>f.required&&!ans[f.id]);if(miss){msg('e','Please answer: '+miss.label);const x=$('q_'+miss.id);if(x)x.focus();return}
 $('b').disabled=true;try{const r=await fetch('/api/form/submit',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({w,f:fid,answers:ans,website:$('hp').value})}),j=await r.json();
  if(r.ok){$('f').hidden=true;msg('o','Sent. Staff will review it soon.');if(j.check){const b=el('div','rp');b.appendChild(el('b','','Save this link to check the result'+(F.kind==='application'?' and get your invite if you are accepted':'')));const a=el('a','lk',j.check);a.href=j.check;b.appendChild(a);$('m').appendChild(b)}}
  else{msg('e',j.error||'Something went wrong.');$('b').disabled=false}}catch{msg('e','No connection. Try again.');$('b').disabled=false}};</script></body></html>`;
const STATUS_PAGE = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><title>Sentinel status</title><link rel="icon" href="/favicon.svg" type="image/svg+xml"><link rel="icon" href="/favicon-32.png" sizes="32x32" type="image/png"><link rel="apple-touch-icon" href="/apple-touch-icon.png"><style>
:root{--bg:#f5f5f7;--card:#fff;--ink:#1d1d1f;--mu:#6e6e73;--ln:rgba(0,0,0,.1)}@media(prefers-color-scheme:dark){:root{--bg:#1c1c1e;--card:#2a2a2d;--ink:#f5f5f7;--mu:#98989f;--ln:rgba(255,255,255,.12)}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 -apple-system,BlinkMacSystemFont,"SF Pro Text",Inter,system-ui,sans-serif;padding:48px 16px}.w{max-width:560px;margin:0 auto}h1{font-size:26px;letter-spacing:-.02em;margin:0 0 4px}p{color:var(--mu);margin:0 0 22px}
.big{display:flex;align-items:center;gap:12px;padding:18px 20px;border-radius:16px;background:var(--card);box-shadow:0 0 0 .5px var(--ln);font-weight:600;font-size:17px;margin-bottom:14px}.d{width:12px;height:12px;border-radius:50%;background:#98989f;flex:none}.d.g{background:#30d158}.d.r{background:#ff453a}.d.y{background:#ff9f0a}.big.ok{background:rgba(48,209,88,.12);color:#1f7a35;box-shadow:0 0 0 .5px rgba(48,209,88,.35)}.big.bad{background:rgba(255,69,58,.1);color:#c4271c;box-shadow:0 0 0 .5px rgba(255,69,58,.35)}@media(prefers-color-scheme:dark){.big.ok{color:#5fe07f}.big.bad{color:#ff7b72}}.big .d{width:14px;height:14px}.big.ok .d{animation:pl 2s infinite}@keyframes pl{0%{box-shadow:0 0 0 0 rgba(48,209,88,.5)}70%{box-shadow:0 0 0 9px rgba(48,209,88,0)}100%{box-shadow:0 0 0 0 rgba(48,209,88,0)}}@media(prefers-reduced-motion:reduce){.big.ok .d{animation:none}}.big small{margin-left:auto;font-size:12px;font-weight:400;color:var(--mu)}
.c{background:var(--card);border-radius:16px;box-shadow:0 0 0 .5px var(--ln)}.row{display:flex;align-items:center;gap:12px;padding:14px 20px;border-top:.5px solid var(--ln)}.row:first-child{border-top:0}.row span{flex:1}.row span.d{flex:none}.row small{color:var(--mu)}.x{font-size:12px;color:var(--mu);text-align:center;margin-top:18px}a{color:#0a7aff}</style></head>
<body><div class="w"><img src="/logo.svg" alt="" width="44" height="44" style="display:block;margin:0 0 14px"><h1>Sentinel status</h1><p>Live health of this Sentinel site. Checked every 30 seconds.</p><div class="big"><span class="d" id="bd"></span><span id="bt">Checking…</span><small id="bu"></small></div><div class="c" id="rows"></div><div class="x">For uptime monitors: <a href="/api/status">/api/status</a> returns JSON, with HTTP 503 when the database is down.</div></div>
<script>const $=i=>document.getElementById(i);const row=(ok,t,s)=>'<div class="row"><span class="d '+(ok===null?'':ok?'g':'r')+'"></span><span>'+t+'</span><small>'+s+'</small></div>';
async function go(){try{const j=await (await fetch('/api/status',{cache:'no-store'})).json();$('bd').className='d '+(j.ok?'g':'r');$('bd').parentNode.className='big '+(j.ok?'ok':'bad');$('bu').textContent='Updated '+new Date().toLocaleTimeString([],{hour:'numeric',minute:'2-digit'});$('bt').textContent=j.ok?'All systems working':'Something is wrong. We are on it.';
 $('rows').innerHTML=row(true,'Website','Responding')+row(j.database.ok,'Database',j.database.ok?j.database.ms+' ms':'Not reachable')+row(j.backups.ok,'Nightly backups',j.backups.lastRun?'Last run '+new Date(j.backups.lastRun).toLocaleString():'Not run yet')+row(j.discordBot?true:null,'Discord bot',j.discordBot?'Set up':'Not set up on this site')+row(j.signIn.length?true:false,'Sign-in',j.signIn.map(x=>x[0].toUpperCase()+x.slice(1)).join(' and ')||'Not set up')}
 catch{$('bd').className='d r';$('bd').parentNode.className='big bad';$('bt').textContent='The website is not responding.';$('rows').innerHTML=''}}go();setInterval(go,30000);</script></body></html>`;

// ---- whole-site maintenance: read at most every 5 seconds per server, and never block on a database hiccup ----
const MC = { v: null, t: 0 };
async function maintState() {
  if (Date.now() - MC.t < 5000) return MC.v;
  try { const r = await sbGet('select=maint:value->maint&key=in.(g:stats)'); MC.v = (r[0] && r[0].maint) || null; MC.t = Date.now(); } catch { MC.t = Date.now() - 3000; }
  return MC.v;
}
const MAINT_PAGE = msg => `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><meta http-equiv="refresh" content="60"><meta name="color-scheme" content="light dark"><title>Back soon</title><link rel="icon" href="/favicon.svg" type="image/svg+xml"><link rel="icon" href="/favicon-32.png" sizes="32x32" type="image/png"><style>
:root{--bg:#f4f6fb;--card:#fff;--ink:#14161f;--mu:#6b7186;--ln:#e3e6f0}@media(prefers-color-scheme:dark){:root{--bg:#0b0d13;--card:#12151f;--ink:#eceef6;--mu:#8b90a6;--ln:#232738}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;background:var(--bg);color:var(--ink);font:16px/1.55 Inter,-apple-system,system-ui,sans-serif}
.c{max-width:430px;width:100%;text-align:center;background:var(--card);border:1px solid var(--ln);border-radius:22px;padding:38px 30px;box-shadow:0 30px 70px -40px rgba(0,0,0,.4)}
img{width:56px;height:56px;margin-bottom:14px}h1{margin:0 0 8px;font-size:24px;letter-spacing:-.02em}p{margin:0;color:var(--mu)}.s{margin-top:22px;font-size:13px;color:var(--mu)}
.bar{height:5px;border-radius:5px;margin:22px auto 0;width:130px;background:repeating-linear-gradient(45deg,#f5b800 0 10px,#1b1b1f 10px 20px)}
</style></head><body><div class="c"><img src="/favicon.svg" alt=""><h1>Back soon</h1><p>${esc(msg || 'Sentinel is down for a short maintenance break.')}</p><div class="bar"></div><div class="s">This page checks again by itself.</div></div></body></html>`;
async function route(req, res, url, p) {
  try {
    const ip = ipOf(req); SITE_NOW = site(req);
    const MS = await maintState();
    if (MS && MS.on && MS.full && !/^\/(admin|status|api\/status|api\/cron)(\/|$)/.test(p)) {
      res.setHeader('Retry-After', '120'); res.setHeader('Cache-Control', 'no-store');
      if (p.startsWith('/api/') || p.startsWith('/game/') || p === '/logout' || req.method !== 'GET') return send(res, 503, { error: MS.message || 'Sentinel is down for a short maintenance break. Please check back soon.', code: 'maintenance' });
      res.writeHead(503, { 'Content-Type': 'text/html; charset=utf-8' }); return res.end(MAINT_PAGE(MS.message));
    }
    if (req.method === 'GET' && p === '/') { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); return res.end(fs.readFileSync(path.join(__dirname, '..', 'index.html'))); }
    if (req.method === 'GET' && p.startsWith('/legal/')) { const n = p.slice(7); if (!LEGAL[n]) return send(res, 404, { error: 'not found' }); res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); return res.end(legalPage(n)); }
    if (req.method === 'GET' && /^\/appeal\/[a-f0-9]{12}$/.test(p)) { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }); return res.end(APPEAL_PAGE); }
    if (req.method === 'GET' && /^\/report\/[a-f0-9]{12}$/.test(p)) { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }); return res.end(REPORT_PAGE); }
    if (req.method === 'GET' && /^\/log\/[a-f0-9]{12}$/.test(p)) { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }); return res.end(LOG_PAGE); }
    if (req.method === 'GET' && /^\/f\/[a-f0-9]{12}\/[a-f0-9]{6}$/.test(p)) { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }); return res.end(FORM_PAGE); }
    if (p === '/api/form/info' || p === '/api/form/status' || (p === '/api/form/submit' && req.method === 'POST')) {
      const A = req.method === 'POST' ? await body(req) : Object.fromEntries(url.searchParams), wid = String(A.w || ''), fid = String(A.f || '');
      const w0 = p === '/api/form/submit' ? (limit('form:' + ip, 6, 3600000) || limit('formw:' + wid, 150, 3600000) || await slimit('form:' + ip, 10, 3600000)) : limit('formi:' + ip, 60, 60000); if (w0) return tooMany(res, w0);
      if (!/^[a-f0-9]{12}$/.test(wid) || !/^[a-f0-9]{6}$/.test(fid)) return send(res, 404, { error: 'This form link is not valid.' });
      setWid(wid); await need('core', ...(p === '/api/form/info' ? [] : ['forms'])); const F = D.meta && !D.meta.deleted && (D.forms || []).find(x => x.id === fid);
      if (p === '/api/form/status') {
        const m = /^([a-f0-9]{8})\.([\w-]{12})$/.exec(String(A.r || '')), x = m && FR.find(y => y.id === m[1] && y.form === fid);
        if (!x || !x.tok || !same(x.tok, m[2])) return send(res, 404, { error: 'We could not find that response. It may be too old.' });
        const inv = x.invite && D.invites[x.invite] && D.invites[x.invite].exp > Date.now() ? `${site(req)}/#/join/${x.invite}` : null;
        return send(res, 200, { status: x.status, reply: x.reply || null, title: x.formTitle, game: D.meta.name, t: x.t, invite: inv, inviteFor: inv && x.who ? x.who.name : null, inviteUsed: !!(x.invite && !D.invites[x.invite] && x.status === 'accepted') });
      }
      if (!F || F.audience !== 'public' || !F.open) return send(res, 404, { error: 'This form is closed or no longer exists.' });
      if (p === '/api/form/info') return send(res, 200, { title: F.title, desc: F.desc, kind: F.kind, game: D.meta.name, fields: F.fields.map(({ id, label, type, required, options }) => ({ id, label, type, required, options })) });
      if (A.website) return send(res, 200, { ok: true }); // a bot filled the hidden field
      const r = await readAnswers(F, A.answers); if (r.err) return send(res, 400, { error: r.err });
      if (r.who && FR.some(x => x.form === fid && x.status === 'new' && x.who && x.who.id === r.who.id)) return send(res, 409, { error: 'You already sent this form. Please wait for staff to review it.' });
      const id = crypto.randomBytes(4).toString('hex'), tok = rnd(9);
      FR.unshift({ id, tok, form: fid, formTitle: F.title, kind: F.kind, t: Date.now(), answers: r.answers, who: r.who, status: 'new' }); if (FR.length > 500) FR.length = 500;
      D.formsNew = (D.formsNew || 0) + 1; feed(`New ${F.title} response${r.who ? ' from ' + r.who.name : ''}`);
      if (!botPost({ embeds: [dEmbed(`New response: ${F.title}`, r.answers.slice(0, 6).map(a => `**${a.label}**\n${(a.value || '—').slice(0, 300)}`).join('\n\n'), [['From', r.who ? r.who.name : null]], 0x0a7aff)], components: [{ type: 1, components: F.kind === 'custom' ? [dBtn('Mark reviewed', `fr:${id}:r`, 1)] : [dBtn(F.kind === 'application' && F.rank ? 'Accept and invite' : 'Accept', `fr:${id}:a`, 3), dBtn('Decline', `fr:${id}:d`, 4)] }] })) notify('forms', `New response: ${F.title}`, r.who ? `From ${r.who.name}` : 'Someone sent the form', [], 0x0a7aff);
      return send(res, 200, { ok: true, check: `${site(req)}/f/${wid}/${fid}?r=${id}.${tok}` });
    }
    if (req.method === 'GET' && p === '/api/appeal/status') {
      const wid = String(url.searchParams.get('w') || ''), m = /^([a-f0-9]{8})\.([\w-]{12})$/.exec(String(url.searchParams.get('r') || ''));
      const w0 = limit('appst:' + ip, 30, 60000); if (w0) return tooMany(res, w0);
      if (!/^[a-f0-9]{12}$/.test(wid) || !m) return send(res, 404, { error: 'This link is not valid.' });
      setWid(wid); await need('core'); const a = D.meta && !D.meta.deleted && D.appeals.find(x => x.id === m[1]);
      if (!a || !a.tok || !same(a.tok, m[2])) return send(res, 404, { error: 'We could not find that appeal. It may be too old.' });
      return send(res, 200, { status: a.status, reply: a.reply || null, t: a.t, reviewed: a.reviewed || null, game: D.meta.name, waiting2: !!(a.approvals && a.approvals.length && a.status === 'open') });
    }
    if (req.method === 'GET' && p === '/api/appeal/info') {
      const wid = String(url.searchParams.get('w') || ''); if (!/^[a-f0-9]{12}$/.test(wid)) return send(res, 404, { error: 'This appeal link is not valid.' });
      const w0 = limit('appinfo:' + ip, 60, 60000); if (w0) return tooMany(res, w0);
      setWid(wid); await need('core'); if (!D.meta || D.meta.deleted) return send(res, 404, { error: 'This appeal link is not valid.' });
      if (D.settings.appeals === false) return send(res, 403, { error: 'Appeals are closed for this game.' });
      return send(res, 200, { name: D.meta.name, hub: hubOn() ? { name: hubMain().name, link: hubLink(hubMain()) } : null });
    }
    if (req.method === 'POST' && p === '/api/appeal') {
      const A = await body(req), wid = String(A.w || ''); if (!/^[a-f0-9]{12}$/.test(wid)) return send(res, 404, { error: 'This appeal link is not valid.' });
      const w0 = limit('appeal:' + ip, 5, 3600000) || limit('appeali:' + ip, 8, APPEAL_WINDOW) || limit('appealw:' + wid, 60, 3600000) || await slimit('appeal:' + ip, 8, 864e5); if (w0) return tooMany(res, w0);
      const uname = cleanName(A.username, 40), text = cleanName(A.text, 1000); if (!/^\w{3,20}$/.test(uname)) return send(res, 400, { error: 'Enter your exact Roblox username.' });
      if (!text) return send(res, 400, { error: 'Write a short note for staff first.' });
      setWid(wid); await need('core', 'play', 'live'); if (!D.meta || D.meta.deleted || D.meta.suspended || D.settings.appeals === false) return send(res, 403, { error: 'Appeals are closed for this game.' });
      const [c0, o0] = appealMake(await findId(uname), uname, text); if (c0 !== 200) return send(res, c0, o0);
      return send(res, 200, { ok: true, check: `${site(req)}/appeal/${wid}?r=${o0.aid}.${o0.tok}` });
    }
    if (req.method === 'POST' && (p === '/hub/list' || p === '/hub/appeal')) { // the Sentinel appeal game: a banned player's Roblox ID comes from Roblox's own server, so no username is typed
      const A = await body(req), h = await hubAuth(A.key); if (!h) return send(res, 403, { error: 'This appeal game is not registered with Sentinel.' });
      const pid = A.userId; if (!Number.isInteger(pid) || pid < 1) return send(res, 400, { error: 'bad request' });
      const w0 = limit('hub:' + h.id, 900, 60000) || limit('hubu:' + pid, 20, 60000); if (w0) return tooMany(res, w0);
      const pname = cleanName(A.name, 40) || 'User ' + pid;
      if (Date.now() - (h.last || 0) > 300000) res.after.push(async () => { const list = (await hubsLoad(true)).map(x => x.id === h.id ? { ...x, last: Date.now() } : x); await hubsSave(list); }); // when it last checked in, for the admin console
      if (p === '/hub/list') { // every workspace with a running ban on this player
        const rows = await sbGet('select=key,bans:value->bans,meta:value->meta,settings:value->settings&key=like.w*:core'), games = [];
        for (const r of rows) {
          const b = r.bans && r.bans[pid]; if (!r.meta || r.meta.deleted || r.meta.suspended || !b || !live(b)) continue;
          const st = r.settings || {}, open = st.appeals !== false && st.hubAppeals !== false, aps = r.key ? ((await sbGet(`select=appeals:value->appeals&key=eq.${r.key}`))[0] || {}).appeals || [] : [], mine = aps.filter(x => x.uid === pid).sort((x, y) => y.t - x.t);
          D.appeals = aps; const why = open ? appealWait(pid) : 'This game does not take appeals here.'; D.appeals = [];
          games.push({ wid: r.key.slice(1, 13), game: String(r.meta.name || '').slice(0, 60), reason: String(b.reason || 'No reason given').slice(0, 160), expires: b.expires || null, can: !why, why, appeal: mine[0] ? { status: mine[0].status, t: mine[0].t, reply: mine[0].reply || null } : null });
          if (games.length >= 20) break;
        }
        return send(res, 200, { games, hub: h.name });
      }
      const wid = String(A.wid || ''), text = cleanName(A.text, 1000); if (!/^[a-f0-9]{12}$/.test(wid)) return send(res, 404, { error: 'That game was not found.' });
      if (text.length < 5) return send(res, 400, { error: 'Write a few words for staff first.' });
      setWid(wid); await need('core', 'play', 'live'); if (!D.meta || D.meta.deleted || D.meta.suspended || D.settings.appeals === false || D.settings.hubAppeals === false) return send(res, 403, { error: 'This game does not take appeals here.' });
      const [c0, o0] = appealMake(pid, pname, text, h.name); return send(res, c0, c0 === 200 ? { ok: true } : o0);
    }
    if (req.method === 'GET' && p === '/api/report/info') {
      const wid = String(url.searchParams.get('w') || ''); if (!/^[a-f0-9]{12}$/.test(wid)) return send(res, 404, { error: 'This report link is not valid.' });
      const w0 = limit('repinfo:' + ip, 60, 60000); if (w0) return tooMany(res, w0);
      setWid(wid); await need('core'); if (!D.meta || D.meta.deleted || D.meta.suspended) return send(res, 404, { error: 'This report link is not valid.' });
      if (!D.settings.webReports) return send(res, 403, { error: 'This game is not taking web reports right now. Use !modcall in game instead.' });
      return send(res, 200, { name: D.meta.name });
    }
    if (req.method === 'POST' && p === '/api/report') {
      const A = await body(req), wid = String(A.w || ''); if (!/^[a-f0-9]{12}$/.test(wid)) return send(res, 404, { error: 'This report link is not valid.' });
      if (A.website) return send(res, 200, { ok: true }); // a bot filled the hidden field
      const w0 = limit('webrep:' + ip, 4, 3600000) || limit('webrepw:' + wid, 100, 3600000) || await slimit('webrep:' + ip, 8, 864e5); if (w0) return tooMany(res, w0);
      const tname = cleanName(A.target, 40), text = cleanName(A.text, 1000), rname = cleanName(A.reporter, 40), link = String(A.link || '').trim().slice(0, 300);
      if (!/^\w{3,20}$/.test(tname)) return send(res, 400, { error: 'Enter the exact Roblox username of the player.' });
      if (text.length < 5) return send(res, 400, { error: 'Say what happened in a few words.' });
      if (link && !/^https?:\/\/\S+$/i.test(link)) return send(res, 400, { error: 'The evidence link must start with https://' });
      setWid(wid); await need('core', 'play', 'live', 'calls'); if (!D.meta || D.meta.deleted || D.meta.suspended || !D.settings.webReports) return send(res, 403, { error: 'This game is not taking web reports right now.' });
      const tid = await findId(tname); if (!tid) return send(res, 404, { error: 'We could not find a Roblox player with that username.' });
      const rid = rname && /^\w{3,20}$/.test(rname) ? await findId(rname) : null;
      const call = { id: ++D.callSeq, t: Date.now(), from: { userId: rid || 0, name: rid ? rname : 'Web report' }, text: `Reporting ${tname}: ${text}${link ? '\nEvidence: ' + link : ''}`, server: 'web', status: 'open', by: null, note: '', chat: [], web: true, target: { userId: tid, name: tname } };
      const lead = callMerge(call); D.calls.unshift(call); D.calls.length = Math.min(D.calls.length, 100); daily().r++;
      abuseTick('pub'); feed(`Web report #${call.id} about ${tname}${lead ? ` (grouped with #${lead.id})` : ''}`); notify('reports', `Web report #${call.id} about ${tname}`, text, [['From', rid ? rname : 'Anonymous']], 0x635bff);
      return send(res, 200, { ok: true });
    }
    if (req.method === 'GET' && p === '/api/publiclog') {
      const wid = String(url.searchParams.get('w') || ''); if (!/^[a-f0-9]{12}$/.test(wid)) return send(res, 404, { error: 'This page is not valid.' });
      const w0 = limit('publog:' + ip, 40, 60000); if (w0) return tooMany(res, w0);
      setWid(wid); await need('core', 'logs'); if (!D.meta || D.meta.deleted || D.meta.suspended || !D.settings.publicLog) return send(res, 404, { error: 'This game does not publish a moderation log.' });
      const DAYS = 30, cut = Date.now() - DAYS * 864e5, mask = n => { n = String(n || '?'); return n.slice(0, 2) + '***'; };
      const all = Object.values(D.logs).flat().filter(e => e && e.time > cut && ['Banned', 'Suspended', 'Unbanned', 'Warned', 'Kicked', 'Muted', 'Unmuted'].includes(e.type)).sort((a, b) => b.time - a.time);
      const counts = { bans: all.filter(e => e.type === 'Banned' || e.type === 'Suspended').length, warns: all.filter(e => e.type === 'Warned').length, mutes: all.filter(e => e.type === 'Muted').length, kicks: all.filter(e => e.type === 'Kicked').length };
      return send(res, 200, { name: D.meta.name, days: DAYS, counts, items: all.slice(0, 50).map(e => ({ t: e.time, type: e.type, who: mask(e.name), len: e.minutes > 0 ? fmtMin(e.minutes) : (e.type === 'Banned' || e.type === 'Muted' ? 'permanent' : ''), reason: String(e.reason || '').slice(0, 140) })) });
    }
    if (p === '/api/cron/tick' && (req.method === 'GET' || req.method === 'POST')) { // daily summaries and game health. Needs TICK_SECRET (or CRON_SECRET), in the Authorization header or, only for pingers that cannot send one, ?key=
      const w0 = limit('tick:' + ip, 30, 60000); if (w0) return tooMany(res, w0);
      const hk = String(req.headers.authorization || '').replace(/^Bearer /, ''), k = hk || String(url.searchParams.get('key') || '');
      if (!k || !((TICK_SECRET.length >= 16 && same(k, TICK_SECRET)) || (CRON_SECRET.length >= 16 && same(k, CRON_SECRET)))) return send(res, 403, { error: 'Not allowed' });
      const r0 = await tickRun(); await need('glob'); G.lastTick = { t: Date.now(), ...r0 }; return send(res, 200, r0);
    }
    if (p === '/api/cron' && (req.method === 'GET' || req.method === 'POST')) {
      const w0 = limit('cron:' + ip, 30, 60000); if (w0) return tooMany(res, w0);
      const auth = String(req.headers.authorization || '').replace(/^Bearer /, ''); if (!(CRON_SECRET.length >= 16 && same(auth, CRON_SECRET)) && !(ADMIN_TOKEN.length >= 16 && same(auth, ADMIN_TOKEN))) return send(res, 403, { error: 'Not allowed' });
      let r0; try { r0 = await cronRun(); } catch (e) { await opsAlert('Nightly job failed', String((e && e.message) || e).slice(0, 400)); throw e; }
      try { const rl = await sbGet('select=key&key=like.rl:*'), cut = Math.floor(Date.now() / 60000), old = rl.map(x => x.key).filter(k2 => +k2.split(':')[1] < cut); for (let i = 0; i < old.length; i += 80) await sbDel(`key=in.(${old.slice(i, i + 80).join(',')})`); r0.limiterRowsCleared = old.length; } catch {}
      await need('glob'); G.lastCron = { t: Date.now(), ok: !r0.partial, snapshotted: r0.snapshotted };
      if (r0.partial) await opsAlert('Nightly backup did not finish', `Backed up ${r0.snapshotted} workspaces before running out of time. The rest will be picked up tomorrow.`);
      return send(res, 200, r0);
    }
    if (req.method === 'GET' && (p === '/status' || p === '/api/status')) {
      const w0 = limit('status:' + ip, 30, 60000); if (w0) return tooMany(res, w0);
      const t0 = Date.now(); let dbOk = true; try { await need('glob'); } catch { dbOk = false; }
      const st = { ok: dbOk, maintenance: !!(dbOk && G.maint && G.maint.on), time: new Date().toISOString(), database: { ok: dbOk, ms: Date.now() - t0 }, backups: { lastRun: dbOk && G.lastCron ? new Date(G.lastCron.t).toISOString() : null, ok: dbOk && G.lastCron ? G.lastCron.ok && Date.now() - G.lastCron.t < 36 * 36e5 : null }, discordBot: discordOn(), signIn: providers() };
      if (p === '/api/status') { res.writeHead(dbOk ? 200 : 503, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); return res.end(JSON.stringify(st)); }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }); return res.end(STATUS_PAGE);
    }
    // the admin page itself needs the password: without a valid session cookie only the lock screen is sent
    const admSession = () => { const d = unpack(cookiesOf(req).adm); return !!(d && d.a === 1); };
    if (req.method === 'GET' && p === '/admin') { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Robots-Tag': 'noindex', 'X-Frame-Options': 'DENY' }); return res.end(ADMIN_TOKEN.length >= 16 && admSession() ? ADMIN_PAGE : ADMIN_GATE()); }
    if (req.method === 'POST' && p === '/admin/login') {
      if (ADMIN_TOKEN.length < 16) return send(res, 404, { error: 'The admin console is off. Set ADMIN_TOKEN (16+ characters) in Vercel to turn it on.' });
      const w1 = limit('admtry:' + ip, 40, 900000); if (w1) return tooMany(res, w1);
      const L = await body(req); await need('glob'); G.adminLog ||= []; const who = hash('ip:' + ip).toString('hex').slice(0, 8);
      if (!same(String(L.token || ''), ADMIN_TOKEN)) { G.adminLog.unshift({ t: Date.now(), text: 'Failed sign-in attempt', bad: 1, who }); G.adminLog.length = Math.min(G.adminLog.length, 300); return send(res, 403, { error: 'Wrong password' }); }
      G.adminLog.unshift({ t: Date.now(), text: 'Signed in', who }); G.adminLog.length = Math.min(G.adminLog.length, 300);
      res.setHeader('Set-Cookie', mkCookie('adm', pack({ a: 1, e: Date.now() + 8 * 3600000 }), { maxAge: 28800 })); return ok(res);
    }
    if (req.method === 'POST' && p === '/admin/logout') { res.setHeader('Set-Cookie', clearCookie('adm')); return ok(res); }
    if (req.method === 'POST' && p === '/admin/api') {
      if (ADMIN_TOKEN.length < 16) return send(res, 404, { error: 'The admin console is off. Set ADMIN_TOKEN (16+ characters) in Vercel to turn it on.' });
      const w0 = admSession() ? 0 : limit('admtry:' + ip, 40, 900000); if (w0) return tooMany(res, w0);
      if (!admSession() && !same(String(req.headers['x-admin-token'] || ''), ADMIN_TOKEN)) return send(res, 403, { error: 'Wrong token' });
      const A = await body(req), wid = String(A.wid || ''); await need('glob'); G.adminLog ||= [];
      const alog = t => { G.adminLog.unshift({ t: Date.now(), text: t }); G.adminLog.length = Math.min(G.adminLog.length, 300); };
      const WID = /^[a-f0-9]{12}$/, UID = /^[gr]_\d{1,32}$/;
      if (await adminMore(A, res, alog)) return;
      if (A.op === 'list') { const rows = await sbGet('select=key,meta:value->meta,members:value->members&key=like.w*:core'); return send(res, 200, { workspaces: rows.filter(r => r.meta).map(r => ({ id: r.key.slice(1, 13), name: r.meta.name, owner: r.meta.owner, created: r.meta.created, deleted: r.meta.deleted || null, suspended: r.meta.suspended || null, members: Object.keys(r.members || {}).length })).sort((a, b) => (a.deleted ? 1 : 0) - (b.deleted ? 1 : 0) || b.created - a.created) }); }
      if (A.op === 'exportAll') {
        alog('Downloaded the full site export');
        const rows = (await sbGet('select=key,value,version&key=like.*&order=key')).filter(r => !/^(bk|rl):/.test(r.key)), out = JSON.stringify({ format: 'sentinel-site-export', v: 1, exportedAt: new Date().toISOString(), rows });
        if (out.length > 4e6) return send(res, 413, { error: 'Your site is too big to download here. Use the Supabase CLI (supabase db dump) instead.' });
        res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); return res.end(out);
      }
      if (A.op === 'discordRegister') {
        if (!discordOn()) return send(res, 400, { error: 'Set DISCORD_APP_ID, DISCORD_PUBLIC_KEY and DISCORD_BOT_TOKEN in Vercel first, then redeploy.' });
        const r = await fetch(`${DISCORD.api}/applications/${DISCORD.app}/commands`, { method: 'PUT', headers: { 'Content-Type': 'application/json', Authorization: 'Bot ' + DISCORD.token }, body: JSON.stringify(DISCORD_COMMANDS), signal: AbortSignal.timeout(8000) });
        const t = await r.text(); return r.ok ? (alog('Registered the Discord commands'), send(res, 200, { ok: true, count: DISCORD_COMMANDS.length })) : send(res, 400, { error: `Discord said ${r.status}: ${t.slice(0, 200)}` });
      }
      if (A.op === 'mfaReset') {
        const t = String(A.uid || '').trim(); if (!/^[gr]_\d{1,32}$/.test(t)) return send(res, 400, { error: 'A user id looks like r_123456 or g_123456.' });
        setUid(t); await need('user'); if (!U) return send(res, 404, { error: 'No such user' }); const had = !!(U.mfa && U.mfa.on); delete U.mfa; delete U.mfaPending; alog('Reset two-step for ' + t); return send(res, 200, { ok: true, had });
      }
      if (A.op === 'feedback') { await need('fb'); return send(res, 200, { items: FB.slice(0, 200) }); }
      if (A.op === 'feedbackReply' || A.op === 'feedbackDelete') {
        await need('fb'); const i = FB.findIndex(f => f.id === String(A.id || '')); if (i < 0) return send(res, 404, { error: 'Not found' });
        if (A.op === 'feedbackDelete') { FB.splice(i, 1); alog('Deleted a feedback message'); } else { alog('Replied to a feedback message'); FB[i].reply = String(A.reply || '').slice(0, 2000).trim() || null; FB[i].repliedAt = FB[i].reply ? Date.now() : null; }
        return ok(res);
      }
      // ---- workspace controls ----
      if (['wsDetail', 'wsRename', 'wsBin', 'wsPurge', 'wsRotate', 'wsSuspend', 'wsViewAs', 'wsCaps', 'wsRemind'].includes(A.op)) {
        if (!WID.test(wid)) return send(res, 400, { error: 'bad workspace' });
        setWid(wid); await need('core', ...(A.op === 'wsDetail' ? ['live'] : [])); if (!D.meta) return send(res, 404, { error: 'No such workspace' });
        const nm = D.meta.name;
        if (A.op === 'wsDetail') {
          const lv = Object.values(R.servers).filter(x => Date.now() - x.last < LIVE_MS), cnt = o => Object.values(o || {}).filter(live).length;
          return send(res, 200, {
            meta: { id: wid, name: nm, owner: D.meta.owner, created: D.meta.created, deleted: D.meta.deleted || null, suspended: D.meta.suspended || null, rot: D.meta.rot || 0, placeId: D.meta.placeId || null, placeLock: !!D.meta.placeLock, lastPlace: D.meta.lastPlace ?? null, scriptV: D.meta.scriptV || 0, latestScript: latestScript(), connectedAt: D.meta.connectedAt || null, openCloud: !!D.meta.oc, group: (D.meta.group && D.meta.group.name) || null, require2fa: !!D.meta.require2fa, discord: !!(D.discord && D.discord.guild) },
            members: Object.entries(D.members).map(([id, m]) => ({ id, name: m.name, rank: (D.ranks[m.rank] || {}).name || m.rank, joined: m.joined, owner: id === D.meta.owner })).sort((a, b) => (b.owner ? 1 : 0) - (a.owner ? 1 : 0) || a.joined - b.joined),
            counts: { bans: cnt(D.bans), mutes: cnt(D.mutes), appeals: D.appeals.length, openAppeals: D.appeals.filter(a => a.status === 'open').length, forms: D.forms.length, ranks: Object.keys(D.ranks).length, rules: D.rulebook.length, shifts: D.shifts.length },
            servers: lv.map(x => ({ players: (x.players || []).length, sv: x.sv, chat: x.chat || '', since: x.first || x.last })), audit: D.audit.slice(0, 15), caps: { members: capOf('members'), logbook: capOf('logbook') }, usage: { members: Object.keys(D.members).length, logbook: D.meta.logN || 0 } });
        }
        if (A.op === 'wsViewAs') { // read-only support view, 15 minutes, written to the workspace's own audit log
          if (D.meta.deleted) return send(res, 400, { error: 'This workspace is in the recycle bin.' });
          const exp = Date.now() + 15 * 60000; audit('Site admin', 'Opened a read-only support view of this workspace (15 minutes)'); alog(`Opened a read-only support view of "${nm}" (${wid})`);
          res.setHeader('Set-Cookie', mkCookie('va', pack({ va: 1, w: wid, u: D.meta.owner, e: exp }), { maxAge: 900 })); return send(res, 200, { ok: true, exp });
        }
        if (A.op === 'wsCaps') {
          const mN = +A.members, lN = +A.logbook; if (!Number.isInteger(mN) || mN < 1 || mN > 5000 || !Number.isInteger(lN) || lN < 1000 || lN > 1000000) return send(res, 400, { error: 'Members 1 to 5000, logbook 1000 to 1000000.' });
          D.meta.caps = { members: mN, logbook: lN }; audit('Site admin', `Set limits: ${mN} members, ${lN} logbook entries`); alog(`Set limits for "${nm}" (${wid}): ${mN} members, ${lN} logbook entries`); return ok(res);
        }
        if (A.op === 'wsRemind') { // an Inbox notice and Home banner for the owner
          const sv = scriptInfo().outdated, cv = clientInfo().outdated; if (!sv && !cv) return send(res, 400, { error: 'This workspace is up to date.' });
          const text = `A newer Sentinel ${sv && cv ? 'game script and player script are' : sv ? 'game script is' : 'player script is'} available. Open Settings, then Game, and paste the new version into your game.`;
          D.notices = [...(D.notices || []).filter(n => n && n.kind !== 'update' && n.exp > Date.now()), { id: rnd(6), kind: 'update', t: Date.now(), exp: Date.now() + 14 * 864e5, title: 'Please update your Sentinel scripts', text }];
          audit('Site admin', 'Sent a reminder to update the Sentinel scripts'); alog(`Reminded "${nm}" (${wid}) to update its scripts`); return ok(res);
        }
        if (A.op === 'wsRename') { const n2 = cleanName(A.name); if (n2.length < 2) return send(res, 400, { error: 'Name is too short' }); D.meta.name = n2; audit('Site admin', `Renamed the workspace from "${nm}"`); alog(`Renamed workspace ${wid} from "${nm}" to "${n2}"`); return ok(res); }
        if (A.op === 'wsSuspend') {
          if (A.on) { D.meta.suspended = { t: Date.now(), reason: cleanName(A.reason, 200) }; audit('Site admin', 'Suspended the workspace'); alog(`Suspended workspace "${nm}" (${wid})` + (D.meta.suspended.reason ? ': ' + D.meta.suspended.reason : '')); }
          else { delete D.meta.suspended; audit('Site admin', 'Lifted the suspension'); alog(`Lifted the suspension on "${nm}" (${wid})`); }
          return ok(res);
        }
        if (A.op === 'wsRotate') { D.meta.rot = (D.meta.rot || 0) + 1; const nc = newCode(wid); D.meta.codeHash = nc.hash; audit('Site admin', 'Made a new game code'); alog(`Made a new game code for "${nm}" (${wid})`); return send(res, 200, { ok: true, code: nc.code }); }
        if (A.op === 'wsBin') {
          if (D.meta.deleted) return send(res, 400, { error: 'Already in the recycle bin' });
          G.workspaces = Math.max(0, G.workspaces - 1); D.meta.deleted = Date.now(); audit('Site admin', 'Moved the workspace to the recycle bin'); alog(`Moved "${nm}" (${wid}) to the recycle bin`); return ok(res);
        }
        // wsPurge: gone for good, with the typed name as the safety catch
        if (cleanName(A.confirm) !== nm) return send(res, 400, { error: 'Type the workspace name exactly to confirm' });
        const guild = D.discord && D.discord.guild; if (!D.meta.deleted) G.workspaces = Math.max(0, G.workspaces - 1);
        alog(`PERMANENTLY deleted workspace "${nm}" (${wid})`);
        res.after.push(async () => { await sbDel(`key=like.w${wid}:*`); await sbDel(`key=like.bk:*:${wid}:*`); if (/^\d{5,25}$/.test(guild || '')) await sbDel(`key=in.(dg:${guild})`); });
        return ok(res);
      }
      if (A.op === 'live') {
        const rows = await sbGet('select=key,servers:value->servers&key=like.w*:live'), names = Object.fromEntries((await sbGet('select=key,meta:value->meta&key=like.w*:core')).filter(r => r.meta).map(r => [r.key.slice(1, 13), r.meta.name]));
        const out = []; for (const r of rows) { const sv = Object.values(r.servers || {}).filter(x => Date.now() - x.last < LIVE_MS); if (sv.length) out.push({ id: r.key.slice(1, 13), name: names[r.key.slice(1, 13)] || '(unknown)', servers: sv.length, players: sv.reduce((a, x) => a + (x.players || []).length, 0), sv: Math.max(...sv.map(x => x.sv || 1)), chat: [...new Set(sv.map(x => x.chat).filter(Boolean))], seen: Math.max(...sv.map(x => x.last)) }); }
        return send(res, 200, { latest: latestScript(), items: out.sort((a, b) => b.players - a.players) });
      }
      // ---- accounts ----
      if (A.op === 'userSearch') {
        const q = String(A.q || '').trim().toLowerCase(); if (q.length < 2) return send(res, 400, { error: 'Type at least 2 characters.' });
        const rows = await sbGet('select=key,name:value->name,provider:value->provider,workspaces:value->workspaces,roblox:value->roblox,mfaOn:value->mfa->on,revoked:value->revoked,created:value->created&key=like.u:*');
        const names = Object.fromEntries((await sbGet('select=key,meta:value->meta&key=like.w*:core')).filter(r => r.meta).map(r => [r.key.slice(1, 13), { name: r.meta.name, deleted: !!r.meta.deleted, owner: r.meta.owner }]));
        const hit = rows.filter(r => { const id = r.key.slice(2); return id.toLowerCase().includes(q) || String(r.name || '').toLowerCase().includes(q) || String((r.roblox && r.roblox.name) || '').toLowerCase().includes(q) || String((r.roblox && r.roblox.id) || '') === q; }).slice(0, 30); // name, Roblox name or Roblox id
        return send(res, 200, { items: hit.map(r => { const id = r.key.slice(2); return { id, name: r.name, provider: r.provider, roblox: r.roblox ? r.roblox.name || null : null, mfa: !!r.mfaOn, revoked: r.revoked || null, created: r.created || null, workspaces: (r.workspaces || []).filter(w => names[w]).map(w => ({ id: w, name: names[w].name, deleted: names[w].deleted, owner: names[w].owner === id })) }; }) });
      }
      if (['userSignOut', 'userDelete', 'userExport'].includes(A.op)) {
        const t = String(A.uid || '').trim(); if (!UID.test(t)) return send(res, 400, { error: 'A user id looks like r_123456 or g_123456.' });
        setUid(t); await need('user'); if (!U) return send(res, 404, { error: 'No such user' });
        if (A.op === 'userSignOut') { U.revoked = Date.now(); alog(`Signed ${t} out everywhere`); return ok(res); }
        const mrows = (await sbGet('select=key,meta:value->meta,members:value->members&key=like.w*:core')).filter(r => r.meta && r.members && r.members[t]);
        if (A.op === 'userExport') {
          await need('fb'); const { mfa, ...rest } = U; alog(`Exported the data held about ${t}`);
          return send(res, 200, { exportedAt: new Date().toISOString(), id: t, account: { ...rest, mfa: mfa ? { on: !!mfa.on } : null }, memberships: mrows.map(r => ({ workspace: r.key.slice(1, 13), name: r.meta.name, deleted: !!r.meta.deleted, owner: r.meta.owner === t, member: r.members[t] })), feedback: FB.filter(f => f.uid === t) });
        }
        const owned = mrows.filter(r => r.meta.owner === t && !r.meta.deleted); if (owned.length) return send(res, 400, { error: 'This person owns ' + owned.map(r => '"' + r.meta.name + '"').join(', ') + '. Delete or hand over those workspaces first.' });
        if (String(A.confirm || '').trim() !== t) return send(res, 400, { error: 'Type the exact user id to confirm' });
        await need('fb'); FB = FB.filter(f => f.uid !== t); alog(`Deleted the account ${t}`);
        res.after.push(async () => {
          for (const r of mrows) for (let i = 0; i < 4; i++) { const [row] = await sbGet(`select=key,value,version&key=in.(${r.key})`); if (!row) break; const v = row.value; delete v.members[t]; v.audit = [{ t: Date.now(), user: 'Site admin', text: 'Removed a deleted account from the team' }, ...(v.audit || [])].slice(0, 300); const rr = await sbf(`${SB_URL}/rest/v1/rpc/panel_commit`, { method: 'POST', headers: sbHeaders(), body: JSON.stringify({ changes: [{ key: r.key, expect: row.version, value: v }] }) }); if (rr.ok && (await rr.json()) === true) break; }
          await sbDel(`key=in.(u:${t})`);
        });
        return ok(res);
      }
      // ---- site-wide ----
      if (A.op === 'announce') { if (A.on && !String(A.text || '').trim()) return send(res, 400, { error: 'Write the message first.' }); G.announce = A.on ? { text: String(A.text).replace(/[\u0000-\u001f<>]/g, ' ').trim().slice(0, 240), kind: A.kind === 'warn' ? 'warn' : 'info', t: Date.now() } : null; alog(A.on ? 'Posted a site announcement' : 'Removed the site announcement'); return ok(res); }
      if (A.op === 'maintenance') { MC.t = 0; G.maint = A.on ? { on: true, full: !!A.full, message: String(A.message || '').replace(/[\u0000-\u001f<>]/g, ' ').trim().slice(0, 240), t: Date.now() } : null; alog(A.on ? 'Turned maintenance mode ON (' + (A.full ? 'whole website' : 'panel only') + ')' : 'Turned maintenance mode off'); return ok(res); }
      if (A.op === 'site') return send(res, 200, { announce: G.announce || null, maint: G.maint || null });
      if (A.op === 'adminLog') return send(res, 200, { items: G.adminLog });
      if (A.op === 'health') {
        const t0 = Date.now(); let dbOk = true, n = 0; try { n = (await sbGet('select=key&key=like.w*:core')).length; } catch { dbOk = false; }
        let dc = null; if (discordOn()) { try { const r = await fetch(`${DISCORD.api}/users/@me`, { headers: { Authorization: 'Bot ' + DISCORD.token }, signal: AbortSignal.timeout(4000) }); dc = r.ok ? 'ok' : r.status === 401 ? 'The bot token was refused' : 'Discord said ' + r.status; } catch { dc = 'Could not reach Discord'; } }
        let rb = 'ok'; try { const r = await fetch(`${RBX_USERS}/v1/users/1`, { signal: AbortSignal.timeout(4000) }); if (!r.ok && r.status >= 500) rb = 'Roblox said ' + r.status; } catch { rb = 'Could not reach Roblox'; }
        return send(res, 200, { db: { ok: dbOk, ms: Date.now() - t0 }, workspaces: { live: G.workspaces, rows: n, max: MAX_WORKSPACES }, backups: G.lastCron || null, tick: G.lastTick || null, discord: { configured: discordOn(), status: dc }, roblox: rb, signIn: providers(), config: { signupsOpen: SIGNUPS_OPEN, maxPerUser: MAX_PER_USER, legalReviewed: !!cfg.legalReviewed, cronSecret: CRON_SECRET.length >= 16, tickSecret: TICK_SECRET.length >= 16, callRetentionDays: cfg.callRetentionDays, alertWebhook: !!env.ALERT_WEBHOOK }, now: Date.now() });
      }
      if (!/^[a-f0-9]{12}$/.test(wid)) return send(res, 400, { error: 'bad workspace' });
      if (A.op === 'snaps') return send(res, 200, { snaps: await listSnapshots(wid) });
      if (A.op === 'snapshotNow') return (await snapshot(wid, bkDay())) ? (alog('Backed up workspace ' + wid), ok(res)) : send(res, 404, { error: 'No such workspace' });
      if (A.op === 'download') { setWid(wid); await need(...BK_ROWS); if (!D.meta) return send(res, 404, { error: 'No such workspace' }); return send(res, 200, backupFile()); }
      if (A.op === 'restoreSnapshot') return (await restoreSnapshot(wid, String(A.date || ''), 'Site admin')) ? (alog(`Restored workspace ${wid} from the backup of ${String(A.date).slice(0, 12)}`), ok(res)) : send(res, 404, { error: 'That backup does not exist' });
      if (A.op === 'restoreDeleted') {
        setWid(wid); await need('core', 'glob'); if (!D.meta || !D.meta.deleted) return send(res, 400, { error: 'That workspace is not in the recycle bin' });
        delete D.meta.deleted; G.workspaces++; audit('Site admin', 'Restored the deleted workspace'); alog(`Restored the deleted workspace "${D.meta.name}" (${wid})`); const owner = D.meta.owner;
        if (/^[gr]_\d{1,32}$/.test(owner)) { setUid(owner); await need('user'); if (U && !U.workspaces.includes(wid)) U.workspaces.push(wid); }
        return ok(res);
      }
      return send(res, 400, { error: 'bad request' });
    }
    if (p.startsWith('/auth/')) return await authRoute(req, res, url, p, ip);

    if (req.method === 'POST' && p === '/api/discord') {
      if (!DISCORD.pub) return send(res, 404, { error: 'Discord is not set up on this site.' });
      if (!dVerify(req)) return send(res, 401, { error: 'invalid request signature' });
      const I = await body(req);
      if (I.type === 1) return send(res, 200, { type: 1 }); // Discord checking the endpoint
      const reply = (content, extra = {}) => send(res, 200, { type: 4, data: { content: String(content).slice(0, 1900), flags: 64, allowed_mentions: { parse: [] }, ...extra } });
      const gid = String(I.guild_id || ''), du = I.member && I.member.user;
      if (!/^\d{5,25}$/.test(gid) || !du) return reply('Use Sentinel commands inside your Discord server.');
      const did = String(du.id), perms = BigInt(String(I.member.permissions || '0').replace(/\D/g, '') || '0'), manage = (perms & 0x20n) === 0x20n || (perms & 0x8n) === 0x8n;
      const wl = limit('dsc:' + did, 30, 60000); if (wl) return reply(`Slow down a little. Try again in ${wl} seconds.`);
      const D0 = I.data || {}, sub = I.type === 2 && D0.name === 'sentinel' ? (D0.options || [])[0] || {} : null, val = (o, n) => (((o && o.options) || []).find(x => x.name === n) || {}).value;
      if (sub && sub.name === 'link') {
        if (!manage) return reply('You need the Manage Server permission to link this server.');
        const m = /^([a-f0-9]{12})-([A-Za-z0-9]{8})$/.exec(String(val(sub, 'code') || '').trim()); if (!m) return reply('That code does not look right. Copy it from Sentinel, Settings, Discord.');
        setWid(m[1]); CTX.guild = gid; await need('core', 'dguild');
        const c = D.meta && !D.meta.deleted && D.discordCodes[m[2]]; if (!c || c.kind !== 'guild' || c.exp < Date.now()) return reply('That code has expired or was already used. Make a new one in Sentinel.');
        if (DG.wid && DG.wid !== CTX.wid) return reply('This server is already linked to another Sentinel workspace. Unlink it there first.');
        const same0 = D.discord && D.discord.guild === gid;
        if (D.discord && !same0 && /^\d{5,25}$/.test(D.discord.guild)) return reply('This workspace is linked to a different Discord server. Unlink it in Sentinel first.');
        delete D.discordCodes[m[2]];
        D.discord = { guild: gid, at: Date.now(), by: c.by, channel: same0 ? D.discord.channel : null, users: same0 ? D.discord.users : {} }; DG = { wid: CTX.wid };
        audit(c.by, 'Linked a Discord server'); return reply(`Linked to **${D.meta.name}**.\nNext: run \`/sentinel channel\` in your staff channel, and ask each staff member to run \`/sentinel me\` with the code from their Sentinel settings.`);
      }
      CTX.guild = gid; await need('dguild'); if (!DG.wid) return reply('This server is not linked to Sentinel yet. The owner can link it from Sentinel, Settings, Discord.');
      setWid(DG.wid); await need('core', 'logs', 'play', 'cmds', 'live', 'chat', 'forms');
      if (!D.meta || D.meta.deleted || !D.discord || D.discord.guild !== gid) return reply('This server is no longer linked. Link it again from Sentinel.');
      if (sub && sub.name === 'me') {
        const code = String(val(sub, 'code') || '').trim().toUpperCase(), c = D.discordCodes[code];
        if (!c || c.kind !== 'user' || c.exp < Date.now() || !D.members[c.uid]) return reply('That code has expired or was already used. Make a new one in Sentinel, Settings, Discord.');
        for (const [k2, v2] of Object.entries(D.discord.users)) if (v2 === c.uid) delete D.discord.users[k2];
        D.discord.users[did] = c.uid; delete D.discordCodes[code]; audit(D.members[c.uid].name, 'Linked their Discord account'); return reply(`Done. Your Discord account is linked to **${D.members[c.uid].name}** in Sentinel. Commands now use your Sentinel rank.`);
      }
      if (sub && (sub.name === 'channel' || sub.name === 'unlink')) {
        if (!manage) return reply('You need the Manage Server permission for that.');
        if (sub.name === 'channel') { const ch = String(I.channel_id || (I.channel && I.channel.id) || ''); if (!/^\d{5,25}$/.test(ch)) return reply('Run this inside a text channel.'); D.discord.channel = ch; audit('Discord', 'Set the Discord alerts channel'); return reply('Sentinel will post ban appeals, applications and unban approvals in this channel, with buttons. Make sure the bot can send messages here.'); }
        delete D.discord; DG = {}; audit('Discord', 'Unlinked the Discord server'); return reply('This server is no longer linked to Sentinel.');
      }
      const muid = D.discord.users[did], mem = muid && D.members[muid];
      if (!mem) return reply('Link your Discord account first: in Sentinel open Settings, Discord, copy your code, then run `/sentinel me code:YOURCODE` here.');
      const u = who(muid);
      if (D.meta.require2fa && isAdminLevel(u)) { setUid(muid); await need('user'); if (!(U && U.mfa && U.mfa.on)) return reply('This workspace requires two-step verification for your role. Turn it on in Sentinel, Settings, Security first.'); }
      if (I.type === 2) {
        const cn = D0.name; if (!['warn', 'kick', 'mute', 'ban', 'unban', 'lookup'].includes(cn)) return reply('Unknown command.');
        const pname = cleanName(val(D0, 'player'), 40).replace(/^@/, ''); if (!/^\w{3,20}$/.test(pname)) return reply('Type their exact Roblox username.');
        const t = await findPlayer(pname); if (!t) return reply(`Could not find a Roblox player called ${pname}.`);
        if (cn === 'lookup') return reply('', { embeds: [lookupEmbed(t, site(req))] });
        const B2 = { action: cn, userId: t.id, name: t.name, reason: cleanName(val(D0, 'reason'), 300) };
        if (cn === 'mute') B2.minutes = clampInt(val(D0, 'minutes'), 1, 525600);
        if (cn === 'ban') B2.minutes = val(D0, 'days') ? clampInt(val(D0, 'days'), 1, 3650) * 1440 : 0;
        const [c, r] = doAction(u, muid, B2); if (c !== 200) return reply(r.error || 'That did not work.');
        return reply(r.pending ? r.msg : `${{ warn: 'Warned', kick: 'Kicked', mute: 'Muted', ban: B2.minutes ? 'Suspended' : 'Banned', unban: 'Unbanned' }[cn]} **${t.name}**${['mute', 'ban'].includes(cn) && B2.minutes ? ' for ' + fmtMin(B2.minutes) : ''}. Reason: ${B2.reason || 'No reason given'}${r.warn ? '\n⚠️ ' + r.warn : ''}`);
      }
      if (I.type === 3) {
        const [k, a, b2] = String(D0.custom_id || '').split(':'); let c, r, label;
        if (k === 'ap') { [c, r] = reviewAppeal(u, muid, { id: a, decision: b2 === 'a' ? 'accept' : 'deny' }); label = r.pending ? `Approved by ${u.user}. One more staff member needs to approve.` : `${b2 === 'a' ? 'Accepted' : 'Denied'} by ${u.user}`; }
        else if (k === 'ub' && /^\d+$/.test(a)) { [c, r] = doAction(u, muid, { action: 'unban', userId: +a, name: (D.bans[+a] || {}).name || a, reason: 'Approved from Discord' }); label = r.pending ? `Requested by ${u.user}. Waiting for a second approval.` : `Unbanned by ${u.user}`; }
        else if (k === 'fr') { [c, r] = reviewForm(u, muid, { rid: a, decision: { a: 'accept', d: 'decline', r: 'reviewed' }[b2] }, site(req)); label = `${{ a: 'Accepted', d: 'Declined', r: 'Marked reviewed' }[b2] || 'Reviewed'} by ${u.user}${r && r.link ? `\nInvite, locked to the applicant: ${r.link}` : ''}`; }
        else return reply('That button no longer works.');
        if (c !== 200) return reply(r.error || 'That did not work.');
        return send(res, 200, { type: 7, data: { content: label, embeds: (I.message && I.message.embeds) || [], components: r.pending ? (I.message && I.message.components) || [] : [], allowed_mentions: { parse: [] } } });
      }
      return reply('That is not supported.');
    }
    if (req.method === 'POST' && p === '/game/sync') { // the Roblox script checks in here with its workspace's game key
      const b = await body(req), k = String(b.key || '').replace(/[\[\]\s"'`]/g, ''), isNew = /^[a-f0-9]{12}-[A-Za-z0-9]{28}$/.test(k), [wid, rot, sig] = isNew ? [k.slice(0, 12)] : k.split('.');
      if (!/^[a-f0-9]{12}$/.test(wid || '') || (!isNew && (!/^\d{1,6}$/.test(rot || '') || !sig || !same(k, gameKey(wid, +rot))))) { const w = limit('badkey:' + ip, 30, 60000); return w ? tooMany(res, w) : send(res, 403, { error: 'bad key' }); }
      const job = String(b.jobId || 'studio').slice(0, 64), w1 = limit(`sync:${wid}:${job}`, 120, 60000) || limit('sync:' + wid, 1500, 60000); if (w1) { logEvent('rate_limit', 'Game sync from server ' + job.slice(0, 8) + ' was slowed down', wid); return tooMany(res, w1); } // Bridge v21 also checks in right after chat, at most once a second
      setWid(wid);
      const ev = Array.isArray(b.events) ? b.events : [], chatty = ev.some(e => e && (e.type === 'chat' || e.type === 'modcall'));
      const shards = [...new Set([...(Array.isArray(b.players) ? b.players : []), ...ev].map(x => x && Number.isInteger(x.userId) && x.userId > 0 ? shOf(x.userId) : null).filter(Boolean))];
      await need('core', 'play', 'live', 'cmds', 'cbo', ...shards, ...(chatty ? ['chat'] : []), ...(ev.some(e => e && e.type === 'modcall') ? ['calls'] : []));
      if (!D.meta || D.meta.deleted) return send(res, 403, { error: 'bad key' });
      if (D.meta.suspended) return send(res, 403, { error: 'This workspace is suspended. Contact the Sentinel team.' });
      const rej = (why, x) => { if (Date.now() - ((D.meta.reject || {}).t || 0) > 30000) D.meta.reject = { t: Date.now(), why, ...x }; }; // why the last check-in was refused, for the owner's setup page (at most twice a minute)
      if (isNew ? !D.meta.codeHash || !same(codeHash(k.slice(13)), D.meta.codeHash) : (D.meta.codeHash || (D.meta.rot || 0) !== +rot)) { rej('code'); const w = limit('badkey:' + ip, 30, 60000); return w ? tooMany(res, w) : send(res, 403, { error: 'bad key' }); }
      const raw = Number.isInteger(b.placeId) ? b.placeId : 0, near = (x, y) => x === y || (x > 1e14 && y > 1e14 && x.toPrecision(14) === y.toPrecision(14)); // Roblox's JSONEncode keeps 14 digits, so 15-digit place IDs arrive rounded
      const place = D.meta.placeId && near(raw, D.meta.placeId) ? D.meta.placeId : raw; b.placeId = place;
      if (D.meta.placeLock && D.meta.placeId && place !== D.meta.placeId) { rej('place', { place, want: D.meta.placeId }); return send(res, 403, { error: 'This game key is locked to a different place' }); }
      if ((D.meta.lastPlace ?? null) !== place) D.meta.lastPlace = place;
      const sv = Number.isInteger(b.scriptV) && b.scriptV > 0 && b.scriptV < 1000 ? b.scriptV : 1; if (sv > (D.meta.scriptV || 0)) D.meta.scriptV = sv; // the highest version seen, so old servers that are still shutting down don't matter
      const cv = Number.isInteger(b.clientV) && b.clientV > 0 && b.clientV < 1000 ? b.clientV : 0; if (cv > (D.meta.clientV || 0)) D.meta.clientV = cv; // the newest player script seen, same rule
      if (!D.meta.connectedAt) D.meta.connectedAt = Date.now();
      if (D.meta.reject) delete D.meta.reject;
      const rjOn = rule('rapidjoin').enabled && ev.some(e => e && e.type === 'join');
      if ((chatty && (rule('flaggedmute').enabled || AM_RULES.some(k => rule(k).enabled))) || rjOn) await need('logs');
      if (rjOn) await need('chat');
      if (ev.some(e => e && e.type === 'ack')) await need('logs');
      if (D.meta.group && D.meta.group.id && Date.now() - ((D.meta.group.last || {}).t || 0) > 10 * 60000) await groupSync(req);
      const joined = ev.filter(e => e && e.type === 'join' && Number.isInteger(e.userId) && e.userId > 0).map(e => e.userId), fresh = new Set(joined.filter(id => !(id in D.play)));
      const out = sync(b); healthSync(Date.now()); await signalCheck(req, fresh, joined); await banSyncPull();
      return send(res, 200, out);
    }

    // ---- the website ----
    if (!p.startsWith('/api/') && p !== '/logout') return send(res, 404, { error: 'not found' });
    const w0 = limit('ip:' + ip, 300, 60000); if (w0) return tooMany(res, w0);
    const ck = cookiesOf(req), VA = viewAsOf(req), uid = VA ? VA.u : sessionUid(req);
    if (VA) { // the site admin's read-only support view of one workspace, as its owner
      ck.ws = VA.w; CTX.ro = true;
      if (p === '/logout') { res.setHeader('Set-Cookie', clearCookie('va')); return ok(res); }
      if (req.method !== 'GET') return send(res, 403, { error: 'This is a read-only support view. Nothing can be changed here.', code: 'readonly' });
    }
    if (req.method === 'POST' && p === '/logout') { res.setHeader('Set-Cookie', [clearCookie('sid'), clearCookie('ws'), clearCookie('mp')]); return ok(res); }

    if (req.method === 'POST' && p === '/api/mfa/login') {
      const w = limit('mfal:' + ip, 30, 600000) || await slimit('mfal:' + ip, 40, 600000); if (w) return tooMany(res, w);
      const mp = unpack(ck.mp); if (!mp || !/^[gr]_\d{1,32}$/.test(mp.u || '')) return send(res, 401, { error: 'That sign-in expired. Please sign in again.', code: 'signin' });
      setUid(mp.u); await need('user'); if (!U || !U.mfa || !U.mfa.on) return send(res, 401, { error: 'That sign-in expired. Please sign in again.', code: 'signin' });
      const t = mfaTry(U.mfa, (await body(req)).code); if (!t.ok) return send(res, t.code, { error: t.err });
      res.setHeader('Set-Cookie', [mkCookie('sid', pack({ u: mp.u, i: Date.now(), e: Date.now() + 7 * 864e5 })), clearCookie('mp')]); return send(res, 200, { ok: true, recovery: !!t.recovery, left: U.mfa.rec.length });
    }
    if (p === '/api/me') {
      await need('glob');
      const base = { providers: providers(), signupsOpen: SIGNUPS_OPEN, user: null, workspaces: [], current: null, maxPerUser: MAX_PER_USER, announce: G.announce || null, maint: G.maint && G.maint.on ? { message: G.maint.message || '', full: !!G.maint.full } : null };
      if (!uid) { const mp = unpack(cookiesOf(req).mp); return send(res, 200, mp && /^[gr]_\d{1,32}$/.test(mp.u || '') ? { ...base, pending2fa: true } : base); }
      setUid(uid); await need('user'); if (!U) return send(res, 200, base);
      if (!VA && revoked(U, req)) { res.setHeader('Set-Cookie', clearCookie('sid')); return send(res, 200, base); }
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
      return send(res, 200, { ...base, ...(VA ? { viewAs: { exp: VA.e, workspace: VA.w } } : {}), user: { id: uid, name: U.name, provider: U.provider, roblox, mfa: !!(U.mfa && U.mfa.on) }, workspaces: list, current: cur });
    }
    if (p === '/api/gjoin/info') {
      const w = limit('gjinfo:' + ip, 30, 60000); if (w) return tooMany(res, w);
      const wid = String(url.searchParams.get('w') || ''); if (!/^[a-f0-9]{12}$/.test(wid)) return send(res, 404, { error: 'This join link is not valid.' });
      setWid(wid); await need('core'); const G0 = D.meta && !D.meta.deleted && D.meta.group;
      return G0 && G0.autoJoin ? send(res, 200, { workspace: D.meta.name, group: G0.name }) : send(res, 404, { error: 'This workspace does not let group members join with a link.' });
    }
    if (p === '/api/invite') {
      const w = limit('invite:' + ip, 20, 60000); if (w) return tooMany(res, w);
      const code = url.searchParams.get('code') || ''; if (!/^[a-f0-9]{28}$/.test(code)) return send(res, 404, { error: 'This invite link is not valid.' });
      setWid(code.slice(0, 12)); await need('core'); const inv = D.meta && !D.meta.deleted && D.invites[code];
      return inv && inv.exp > Date.now() ? send(res, 200, { workspace: D.meta.name, role: (D.ranks[inv.rank] || {}).name || 'Member', lock: inv.lock ? { id: inv.lock.id, name: inv.lock.name } : null }) : send(res, 404, { error: 'This invite has expired or was already used.' });
    }
    if (!uid) return send(res, 401, { error: 'Please sign in', code: 'signin' });
    const w2 = limit('u:' + uid, 180, 60000); if (w2) return tooMany(res, w2);
    setUid(uid);

    if (p === '/api/mfa' && req.method === 'GET') { await need('user'); const m = U && U.mfa; return send(res, 200, { on: !!(m && m.on), recLeft: m && m.on ? (m.rec || []).length : 0, since: (m && m.at) || null }); }
    if (req.method === 'POST' && p.startsWith('/api/mfa/')) {
      const w = limit('mfa:' + uid, 20, 600000); if (w) return tooMany(res, w);
      await need('user'); if (!U) return send(res, 401, { error: 'Please sign in', code: 'signin' }); const Bm = await body(req), m = U.mfa;
      if (p === '/api/mfa/setup') {
        if (m && m.on) return send(res, 400, { error: 'Two-step verification is already on.' });
        const key = crypto.randomBytes(20); U.mfaPending = { s: ocEnc(key.toString('hex')), t: Date.now() }; const secret = b32(key);
        return send(res, 200, { secret, uri: `otpauth://totp/Sentinel:${encodeURIComponent(U.name)}?secret=${secret}&issuer=Sentinel&algorithm=SHA1&digits=6&period=30` });
      }
      if (p === '/api/mfa/enable') {
        const pend = U.mfaPending; if (m && m.on) return send(res, 400, { error: 'Two-step verification is already on.' });
        if (!pend || Date.now() - pend.t > 900000) return send(res, 400, { error: 'That setup took too long. Start again.' });
        const c = totpCheck(Buffer.from(ocDec(pend.s), 'hex'), Bm.code, 0); if (!c) return send(res, 400, { error: 'That code is not right. Check the 6 digits in your authenticator app.' });
        const rc = newRecovery(); U.mfa = { s: pend.s, on: true, rec: rc.hashes, at: Date.now(), last: c, fails: 0, lock: 0 }; delete U.mfaPending;
        return send(res, 200, { ok: true, codes: rc.codes });
      }
      if (!m || !m.on) return send(res, 400, { error: 'Two-step verification is not on.' });
      const t = mfaTry(m, Bm.code); if (!t.ok) return send(res, t.code, { error: t.err });
      if (p === '/api/mfa/disable') { delete U.mfa; delete U.mfaPending; return ok(res); }
      if (p === '/api/mfa/recovery') { const rc = newRecovery(); m.rec = rc.hashes; return send(res, 200, { ok: true, codes: rc.codes }); }
      return send(res, 404, { error: 'not found' });
    }
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
      const w = limit('join:' + uid, 10, 3600000) || await slimit('join:' + uid, 15, 3600000); if (w) return tooMany(res, w);
      const code = String((await body(req)).code || ''); if (!/^[a-f0-9]{28}$/.test(code)) return send(res, 400, { error: 'This invite link is not valid.' });
      setWid(code.slice(0, 12)); await need('user', 'core'); if (!U) return send(res, 401, { error: 'Please sign in', code: 'signin' });
      if (D.meta && D.members[uid]) { res.setHeader('Set-Cookie', mkCookie('ws', CTX.wid, { maxAge: 31536000 })); return send(res, 200, { ok: true, id: CTX.wid }); }
      const inv = D.meta && !D.meta.deleted && D.invites[code]; if (!inv || inv.exp < Date.now()) return send(res, 404, { error: 'This invite has expired or was already used.' });
      if (Object.keys(D.members).length >= capOf('members')) return send(res, 403, { error: 'This workspace has reached its member limit. Ask the owner to contact the Sentinel team.' });
      const irank = D.ranks[inv.rank];
      if (irank && irank.perms.some(x => ADMINP.includes(x)) && !inv.lock) return send(res, 403, { error: 'This invite is for a rank with admin powers but is not locked to a Roblox account, so it cannot be used. Ask for a new one.' });
      if (inv.lock) { // only the Roblox account the invite was made for can use it
        const mine = uid[0] === 'r' ? uid.slice(2) : (U.roblox && U.roblox.id) || '';
        if (String(mine) !== String(inv.lock.id)) { audit(U.name, `Tried to use an invite locked to @${inv.lock.name}`); return send(res, 403, { error: `This invite is locked to the Roblox account @${inv.lock.name}. Sign in with that Roblox account, or link it in Settings, then open the link again.`, code: 'locked', lock: { id: inv.lock.id, name: inv.lock.name } }); }
      }
      if (Object.keys(D.members).length >= 50) return send(res, 400, { error: 'This workspace is full.' });
      const rk = D.ranks[inv.rank] ? inv.rank : Object.entries(D.ranks).sort((a, b) => a[1].pos - b[1].pos)[0][0];
      D.members[uid] = { name: U.name, rank: rk, joined: Date.now() }; delete D.invites[code]; audit(U.name, `Joined as ${D.ranks[rk].name}`);
      if (!U.workspaces.includes(CTX.wid)) U.workspaces.push(CTX.wid);
      res.setHeader('Set-Cookie', mkCookie('ws', CTX.wid, { maxAge: 31536000 })); return send(res, 200, { ok: true, id: CTX.wid });
    }
    if (req.method === 'POST' && p === '/api/gjoin') {
      const w = limit('gjoin:' + uid, 10, 3600000) || await slimit('gjoin:' + uid, 15, 3600000); if (w) return tooMany(res, w);
      const wid = String((await body(req)).w || ''); if (!/^[a-f0-9]{12}$/.test(wid)) return send(res, 404, { error: 'This join link is not valid.' });
      setWid(wid); await need('user', 'core'); if (!U) return send(res, 401, { error: 'Please sign in', code: 'signin' });
      const G0 = D.meta && !D.meta.deleted && D.meta.group; if (!G0 || !G0.autoJoin) return send(res, 404, { error: 'This workspace does not let group members join with a link.' });
      if (D.members[uid]) { res.setHeader('Set-Cookie', mkCookie('ws', CTX.wid, { maxAge: 31536000 })); return send(res, 200, { ok: true, id: CTX.wid, already: true }); }
      const rid = uid[0] === 'r' ? uid.slice(2) : (U.roblox && U.roblox.id) || ''; if (!rid) return send(res, 403, { error: 'Sign in with Roblox, or link your Roblox account, so Sentinel can check your group role.', code: 'needroblox' });
      let role; try { role = await groupRoleOf(G0.id, rid); } catch { return send(res, 502, { error: 'Roblox did not answer. Try again in a minute.' }); }
      const rk = role && G0.map[role]; if (!rk || !D.ranks[rk]) return send(res, 403, { error: `Your role in ${G0.name} does not give access to this workspace. Ask the owner for an invite.` });
      if (Object.keys(D.members).length >= 50) return send(res, 400, { error: 'This workspace is full.' });
      D.members[uid] = { name: U.name, rank: rk, joined: Date.now(), group: role, robloxId: rid }; audit(U.name, `Joined as ${D.ranks[rk].name} through the Roblox group`);
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
    setWid(ck.ws); await need('core', 'user', 'glob', ...(NEEDS[p] || []));
    if (G.maint && G.maint.on) return send(res, 503, { error: G.maint.message || 'Sentinel is down for a short maintenance break. Please check back soon.', code: 'maintenance' });
    if (!U || (!VA && revoked(U, req))) { res.setHeader('Set-Cookie', clearCookie('sid')); return send(res, 401, { error: 'Please sign in again.', code: 'signin' }); }
    if (!D.meta || D.meta.deleted) return send(res, 404, { error: 'That workspace no longer exists', code: 'no_workspace' });
    const mem = D.members[uid]; if (!mem) return send(res, 403, { error: 'You are not a member of this workspace', code: 'no_workspace' });
    if (D.meta.suspended) return send(res, 403, { error: 'This workspace is suspended' + (D.meta.suspended.reason ? ': ' + D.meta.suspended.reason : '.') + ' Contact the Sentinel team if you think this is a mistake.', code: 'suspended' });
    if (U) { // keep name and linked Roblox account in sync with the person's account
      if (mem.name !== U.name) mem.name = U.name;
      const rid = uid[0] === 'r' ? uid.slice(2) : (U.roblox && U.roblox.id) || null; if ((mem.robloxId || null) !== rid) mem.robloxId = rid;
    }
    const u = who(uid);
    if (!VA && D.meta.require2fa && isAdminLevel(u) && !(U && U.mfa && U.mfa.on)) { // this workspace requires two-step for administrators
      if (p === '/api/state') return send(res, 200, { need2fa: true, me: { uid, name: mem.name, owner: u.isOwner, pos: 0, perms: [], rank: mem.rank }, workspace: { id: CTX.wid, name: D.meta.name } });
      return send(res, 403, { error: 'This workspace requires two-step verification for your role. Turn it on in Settings, Security.', code: 'need2fa' });
    }
    for (const [c, i] of Object.entries(D.invites)) if (i.exp < Date.now()) delete D.invites[c];
    const B = req.method === 'POST' ? await body(req) : {};

    if (p === '/api/state') {
      if (D.meta.group && D.meta.group.id && Date.now() - ((D.meta.group.last || {}).t || 0) > 6 * 36e5) await groupSync(req);
      const now = Date.now(), wr = x => ({ ...x, risk: riskOf(x.userId, now) }), players = allPlayers().map(wr), bans = Object.values(D.bans).filter(live).map(wr), mutes = Object.values(D.mutes).filter(live).map(wr), ws = weekStart(now);
      const days = [...Array(14)].map((_, i) => dayKey(now - (13 - i) * 864e5)), ser = f => days.map(d => (D.daily[d] || {})[f] || 0);
      const onLeave = id => D.loa.some(x => x.uid === id && x.status === 'approved' && x.start <= now && x.end >= now);
      const gm = Object.keys(D.members).filter(id => id[0] === 'g'); // Google members may have linked a Roblox account: pick that up for activity tracking
      if (gm.length) { const r = await sbf(`${SB_URL}/rest/v1/panel_kv?select=key,roblox:value->roblox&key=in.(${gm.map(id => 'u:' + id).join(',')})`, { headers: sbHeaders() });
        if (r.ok) for (const row of await r.json()) { const m = D.members[row.key.slice(2)], rid = (row.roblox && row.roblox.id) || null; if (m && (m.robloxId || null) !== rid) m.robloxId = rid; } }
      const team = Object.entries(D.members).map(([id, m]) => { const rid = m.robloxId || (id[0] === 'r' ? id.slice(2) : null), pl = rid ? D.play[rid] : null;
        return { uid: id, name: m.name, rank: m.rank, group: !!m.group, owner: id === D.meta.owner, via: id[0] === 'g' ? 'Google' : 'Roblox', joined: m.joined, linked: !!rid, robloxId: rid,
          week: pl && pl.weekStart === ws ? Math.round(pl.week) : 0, onLeave: onLeave(id), online: !!rid && players.some(x => String(x.userId) === String(rid)) }; })
        .sort((a, b) => memberPos(b.uid) - memberPos(a.uid) || a.name.localeCompare(b.name));
      return send(res, 200, {
        connected: liveServers() > 0, serverCount: liveServers(), players, bans, mutes, feed: (D.feed || []).slice(0, 20), history: R.history,
        servers: Object.entries(R.servers).filter(([, s]) => now - s.last < LIVE_MS).map(([id, s]) => ({ id: id.slice(0, 8), players: s.players.length, uptime: now - (s.first || now), v: s.sv || 1, closing: !!(s.closed && now - s.closed < 180000) })),
        presets: presets(), myStrikes: (D.strikes || []).filter(x => x.uid === uid && x.status === 'active' && (!x.expires || x.expires > now)).map(({ id, level, reason, by, t, expires }) => ({ id, level, reason, by, t, expires })),
        me: { uid, name: mem.name, rank: mem.rank, owner: u.isOwner, perms: [...u.perms], linked: !!mem.robloxId, pos: u.pos, mfa: !!(U && U.mfa && U.mfa.on), admin: isAdminLevel(u) },
        workspace: { id: CTX.wid, name: D.meta.name, require2fa: !!D.meta.require2fa, machine: machineOn(), features: { chatLogs: feat('chatLogs'), machineBans: feat('machineBans') }, ...(u.isOwner && D.meta.oc && D.meta.oc.last && !D.meta.oc.last.ok && D.meta.oc.last.machine ? { machineErr: { t: D.meta.oc.last.t, msg: D.meta.oc.last.msg } } : {}), group: D.meta.group && D.meta.group.id ? { id: D.meta.group.id, name: D.meta.group.name, autoJoin: !!D.meta.group.autoJoin } : null, everConnected: !!D.meta.connectedAt, ...(has(u, 'automations.manage') ? { script: scriptInfo(), client: clientInfo() } : {}), ...(u.isOwner ? { placeId: D.meta.placeId || null, placeLock: !!D.meta.placeLock, lastPlace: D.meta.lastPlace ?? null } : {}) },
        ranks: Object.entries(D.ranks).map(([id, r]) => ({ id, ...r, count: Object.values(D.members).filter(m => m.rank === id).length })).sort((a, b) => b.pos - a.pos),
        perms: PERMS.map(([id, label, group, danger]) => ({ id, label, group, danger: !!danger })), team,
        invites: has(u, 'team.manage') ? Object.entries(D.invites).map(([code, i]) => ({ code, rank: i.rank, exp: i.exp, by: i.by, lock: i.lock ? i.lock.name : null })) : [],
        audit: has(u, 'audit.view') ? D.audit.slice(0, 150) : [], rulebook: D.rulebook,
        loa: { mine: D.loa.filter(x => x.uid === uid).slice(0, 20), all: has(u, 'loa.review') ? D.loa.slice(0, 80) : [] },
        webhook: has(u, 'webhooks.manage') ? { set: !!(D.webhook && D.webhook.url), hint: D.webhook && D.webhook.url ? D.webhook.url.slice(-6) : '', events: (D.webhook || DEFAULT_WEBHOOK()).events } : null,
        series: { players: ser('u'), peak: ser('p'), actions: ser('a'), reports: ser('r'), joins: ser('j'), days },
        openCalls: new Set(D.calls.filter(c => c.status !== 'resolved').map(grpOf)).size, calls: callsOut(), hub: hubMain() ? { name: hubMain().name, link: hubLink(hubMain()) } : null, vaultDays: vaultDays(), playbooks: playbooks(), mergeMin: MERGE_MIN.includes(D.settings.mergeMin) ? D.settings.mergeMin : 10,
        session: D.session && { ...D.session, attendees: Object.entries(D.session.attendees).map(([userId, name]) => ({ userId: +userId, name })) }, sessions: D.sessions.slice(0, 15),
        board: Object.entries(D.play).map(([id, x]) => ({ userId: +id, name: x.name, week: x.weekStart === ws ? Math.round(x.week) : 0, total: Math.round(x.total), points: x.points }))
          .sort((a, b) => b.week - a.week || b.points - a.points).slice(0, 50),
        chat: has(u, 'chat.view') ? R.chat.slice(-100).reverse() : [], flagWords: D.flagWords, cuss: has(u, 'automations.manage') ? cussList() : null, cussDefault: !D.cussWords, chatDays: chatDays(), alertWords: has(u, 'automations.manage') ? D.alertWords : null, alertDest: D.settings.alertDest || 'inbox', digest: u.isOwner ? { on: false, hour: 9, tz: '', ...(D.settings.digest || {}) } : null, health: { last: Math.max(D.meta.lastSyncAt || 0, ...Object.values(R.servers).map(x => x.last)), active: D.meta.activeAt || 0, down: D.meta.health && D.meta.health.down ? D.meta.health.since : 0, quiet: healthDue({ ...D.meta, health: null }, now) ? D.meta.lastSyncAt : 0 }, alerts: has(u, 'chat.view') ? (D.alerts || []).filter(a => now - a.t < 7 * 864e5) : [], escal: (D.escal || []).filter(x => (x.status !== 'resolved' || Date.now() - x.t < 7 * 864e5) && (x.byUid === uid || escSenior(uid, x))).map(x => escOut(x, uid)), onboarding: obState(uid), onboardAll: u.isOwner || has(u, 'staff.review') ? Object.entries(D.members).filter(([id]) => id !== D.meta.owner).map(([id, m]) => { const o = obState(id); return { uid: id, name: m.name, rank: m.rank, skip: !!D.onboard.skip[id], n: o ? o.n : 0, total: o ? o.items.length : 0, items: o ? o.items : [] }; }) : null, obLists: u.isOwner ? Object.fromEntries(Object.keys(D.ranks).map(k => [k, obList(k)])) : null, obAuto: OB_AUTO, training: { on: !!D.settings.training, can: !!D.settings.training && (u.isOwner || has(u, 'training.use')) }, trainStats: u.isOwner || has(u, 'staff.review') ? Object.entries(D.training.results || {}).filter(([id]) => D.members[id]).map(([id, l]) => ({ uid: id, name: D.members[id].name, n: l.length, right: l.filter(r => r.match).length, last: l[0] ? l[0].t : null })) : null, notices: (u.isOwner || has(u, 'automations.manage')) ? (D.notices || []).filter(n => n.exp > Date.now()) : [], announcements: annFor(u), limits: u.isOwner ? { members: { n: Object.keys(D.members).length, max: capOf('members') }, logbook: { n: D.meta.logN || 0, max: capOf('logbook') } } : null, settings: D.settings, appealsOn: D.settings.appeals !== false, appeals: has(u, 'appeals.review') ? D.appeals.slice(0, 60).map(({ tok, ...a }) => a) : [], replies: D.settings.replies || DEFAULT_REPLIES, formsNew: has(u, 'forms.review') ? D.formsNew || 0 : 0, shiftNext: (D.shifts.filter(x => shEnd(x) > now && x.signups.some(sg => sg.uid === uid)).sort((a, b) => a.start - b.start)[0] || null), signals: has(u, 'mod.kick') ? Object.entries(D.signals).filter(([, x]) => x.status === 'open').sort((a, b) => b[1].t - a[1].t).slice(0, 30).map(([id, x]) => ({ userId: +id, ...x })) : [], signalsOn: D.settings.signals !== false, onDuty: [...new Set(D.shifts.filter(x => x.start <= now && shEnd(x) > now).flatMap(x => x.signups.map(sg => sg.uid)))], staffForms: D.forms.filter(f => f.audience === 'staff' && f.open).map(f => ({ id: f.id, title: f.title })), twoPerson: !!D.settings.twoPerson, approvals: D.settings.approvals || {}, pending: (D.pending || []).filter(x => now - x.t < APPR_MS).map(x => ({ id: x.id, kind: x.kind, text: x.text, by: x.by, t: x.t, reason: x.reason, mine: x.byUid === uid, can: canApprove(x, u, uid) })).filter(x => x.mine || x.can), sync: has(u, 'automations.manage') ? { from: (D.settings.sync || {}).from || [] } : null, signalsDone: has(u, 'mod.kick') ? Object.entries(D.signals).filter(([, x]) => x.status !== 'open').sort((a, b) => (b[1].done || b[1].t) - (a[1].done || a[1].t)).slice(0, 30).map(([id, x]) => ({ userId: +id, ...x })) : [], watch: D.watch,
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
    if (p === '/api/analytics') {
      const rng = [7, 14, 30].includes(+url.searchParams.get('range')) ? +url.searchParams.get('range') : 30, now = Date.now();
      const days = [...Array(rng)].map((_, i) => dayKey(now - (rng - 1 - i) * 864e5)), ser = f => days.map(d => (D.daily[d] || {})[f] || 0);
      const cut = now - rng * 864e5, ent = Object.values(D.logs).flat().filter(e => e && e.time > cut && MOD_TYPES.includes(e.type));
      const types = Object.fromEntries(MOD_TYPES.map(t => [t, ent.filter(e => e.type === t).length])), by = {};
      for (const e of ent) { const k = e.by || 'Automation'; by[k] = (by[k] || 0) + 1; }
      const sum = a => a.reduce((x, y) => x + y, 0), ap = D.appeals.filter(a => a.t > cut);
      return send(res, 200, { range: rng, days, joins: ser('j'), peak: ser('p'), unique: ser('u'), actions: ser('a'), reports: ser('r'), types,
        staff: Object.entries(by).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([name, n]) => ({ name, n })),
        totals: { joins: sum(ser('j')), unique: sum(ser('u')), actions: sum(ser('a')), reports: sum(ser('r')), peak: Math.max(0, ...ser('p')) },
        appeals: { sent: ap.length, accepted: ap.filter(a => a.status === 'accepted').length, denied: ap.filter(a => a.status === 'denied').length, open: D.appeals.filter(a => a.status === 'open').length } });
    }
    if (p === '/api/logbook') {
      const type = url.searchParams.get('type') || '', q = cleanName(url.searchParams.get('q'), 60).toLowerCase();
      let all = []; for (const [id, list] of Object.entries(D.logs)) for (const e of list) all.push({ ...e, userId: +id, name: e.name || (D.play[id] || {}).name || 'User ' + id });
      if (type) all = all.filter(e => TYPE_GROUP[e.type] === type);
      if (q) all = all.filter(e => `${e.name} ${e.reason} ${e.by}`.toLowerCase().includes(q));
      all.sort((a, b) => b.time - a.time); return send(res, 200, { entries: all.slice(0, 200).map(e => ({ ...e, ...entryState(e, e.userId) })), total: all.length });
    }
    if (req.method === 'POST' && p === '/api/action') {
      if (Array.isArray(B.boxes) && B.boxes.length) B.boxes = feat('chatLogs') ? await ownBoxes(B.boxes) : []; // chat log boxes attached as evidence, only this workspace's
      const [c, o] = doAction(u, uid, B); return send(res, c, o);
    }
    if (req.method === 'GET' && p === '/api/entry') {
      const id = +url.searchParams.get('userId'), e = (D.logs[id] || []).find(x => x.id === url.searchParams.get('id'));
      return e ? send(res, 200, { entry: { ...e, userId: id, ...entryState(e, id) } }) : send(res, 404, { error: 'That entry no longer exists.' });
    }
    if (req.method === 'POST' && p === '/api/entry') {
      const id = B.userId; if (!Number.isInteger(id) || id < 1) return send(res, 400, { error: 'bad userId' });
      if (B.op === 'note') { if (!has(u, 'logbook.note')) return deny(res); const t = cleanName(B.text, 500); if (!t) return send(res, 400, { error: 'Write a note first' }); logEntry(id, cleanName(B.name, 40) || 'User ' + id, { type: 'Note', reason: t, by: u.user, byUid: uid, ...(B.pin ? { pin: true } : {}) }); return ok(res); }
      if (B.op === 'train') { if (!has(u, 'staff.review')) return deny(res); const e = (D.logs[id] || []).find(x => x.id === B.id); if (!e || !TR_TYPES[e.type]) return send(res, 404, { error: 'That entry cannot be used for training.' }); if (B.on) e.train = true; else delete e.train; audit(u.user, `${B.on ? 'Marked' : 'Unmarked'} a ${e.type.toLowerCase()} entry for training`); return ok(res); }
      if (B.op === 'pin') { if (!has(u, 'logbook.note')) return deny(res); const e = (D.logs[id] || []).find(x => x.id === B.id && x.type === 'Note'); if (!e) return send(res, 404, { error: 'That note no longer exists.' }); e.pin = !!B.on; audit(u.user, `${e.pin ? 'Pinned' : 'Unpinned'} a note on ${e.name}`); return ok(res); }
      if (B.op === 'evidence') {
        if (!has(u, 'logbook.note')) return deny(res);
        const e = (D.logs[id] || []).find(x => x.id === B.id); if (!e) return send(res, 404, { error: 'That entry no longer exists.' });
        const links = cleanLinks([B.url], 1), t = cleanName(B.note, 500); if (!links.length && !t) return send(res, 400, { error: B.url ? 'Links must start with https:// or http://' : 'Add a link or a note.' });
        if (links.length) { e.ev = [...(e.ev || []), ...links].slice(0, 10); }
        if (t) e.note = ((e.note ? e.note + '\n' : '') + `${u.user}: ${t}`).slice(-1500);
        audit(u.user, `Added evidence to a ${e.type.toLowerCase()} for ${e.name}`); return ok(res);
      }
      if (B.op === 'revert') {
        if (!has(u, 'logbook.revert')) return deny(res);
        const e = (D.logs[id] || []).find(x => x.id === B.id); if (!e || e.status === 'reverted') return send(res, 404, { error: 'Entry not found or already reverted' });
        if (e.type === 'Banned' && D.bans[id] && D.bans[id].entry === e.id && needSecond(u, D.bans[id])) return send(res, 409, { error: 'Lifting a permanent ban needs two staff members. Use Unban instead, and a second person can approve it.' });
        e.status = 'reverted'; e.revertedBy = u.user; e.revertedAt = Date.now(); if (D.play[id] && D.play[id].rk) D.play[id].rk = D.play[id].rk.filter(r => r[2] !== e.id); // a reverted entry no longer counts toward the risk score
        if ((e.type === 'Banned' || e.type === 'Suspended') && D.bans[id] && D.bans[id].entry === e.id) { delete D.bans[id]; unbanCmd(id); }
        if (e.type === 'Muted' && D.mutes[id] && D.mutes[id].entry === e.id) delete D.mutes[id];
        if (e.type === 'Points' && e.amount) playOf(id, e.name).points -= e.amount;
        audit(u.user, `Reverted ${e.type.toLowerCase()} for ${e.name}`); const uw = (e.type === 'Banned' || e.type === 'Suspended') ? unbanWarn() : null; return send(res, 200, { ok: true, ...(uw ? { warn: uw } : {}) });
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
    if (req.method === 'GET' && p === '/api/reputation') { // one player's standing, for staff only. Advice: nothing here acts on its own
      const id = +url.searchParams.get('userId'); if (!Number.isInteger(id) || id < 1) return send(res, 400, { error: 'bad userId' });
      const now = Date.now(), pl = D.play[id] || {}, logs = D.logs[id] || [], PUN = ['Warned', 'Muted', 'Kicked', 'Suspended', 'Banned'];
      const pun = logs.filter(e => PUN.includes(e.type)).slice().reverse().map(e => ({ ...e, ...entryState(e, id) }));
      const flags = (pl.rk || []).filter(r => r[0] === 'box' || r[0] === 'boxStrong').map(([k, t]) => ({ t, strong: k === 'boxStrong' })).reverse();
      const last = Math.max(0, ...pun.filter(e => e.status !== 'reverted').map(e => e.time), ...flags.map(x => x.t));
      const calls = D.calls.filter(c => c.target && c.target.userId === id).map(c => ({ id: c.id, t: c.t, text: c.text, status: c.status, outcome: c.outcome || null, grp: grpOf(c), from: c.web && !(c.from.userId > 0) ? 'Anonymous web report' : c.from.name, note: c.note || '' }));
      return send(res, 200, { userId: id, name: pl.name || (logs[0] || {}).name || 'User ' + id, risk: riskOf(id, now), clean: last ? { since: last, days: Math.floor((now - last) / 864e5) } : null,
        trust: (pl.adj || []).slice().reverse().map(a => ({ ...a, fading: Math.max(0, Math.round(a.pts * Math.pow(0.5, (now - a.t) / 864e5 / RISK_W.halfLifeDays))) })),
        punishments: pun, notes: logs.filter(e => e.type === 'Note' && e.status !== 'reverted').slice().reverse(), flags,
        reports: { open: calls.filter(c => c.status !== 'resolved'), past: calls.filter(c => c.status === 'resolved').slice(0, 30) },
        appeals: D.appeals.filter(a => a.uid === id).map(a => ({ id: a.id, t: a.t, status: a.status, text: a.text, banReason: a.banReason || '', reply: a.reply || null })),
        vault: has(u, 'logbook.note') ? vaultItems().filter(x => x.uid === id).map(vaultMeta) : null, canTrust: has(u, 'staff.review') });
    }
    if (req.method === 'POST' && p === '/api/reputation') { // restore trust: a negative adjustment to the risk score. The logbook is never touched
      if (!has(u, 'staff.review')) return deny(res);
      const id = B.userId; if (!Number.isInteger(id) || id < 1) return send(res, 400, { error: 'bad userId' });
      if (B.op === 'trust') {
        const pts = B.points, reason = cleanName(B.reason, 300);
        if (!Number.isInteger(pts) || pts < 5 || pts > 50) return send(res, 400, { error: 'Pick between 5 and 50 points.' });
        if (reason.length < 5) return send(res, 400, { error: 'Say briefly why, so other staff understand.' });
        const pl = playOf(id, cleanName(B.name, 40) || (D.play[id] || {}).name || 'User ' + id); (pl.adj ||= []).push({ id: rnd(6), t: Date.now(), pts, reason, by: u.user, byUid: uid });
        if (pl.adj.length > 30) pl.adj.splice(0, pl.adj.length - 30);
        audit(u.user, `Restored trust for ${pl.name} by ${pts} points: ${reason}`); return ok(res);
      }
      if (B.op === 'untrust') {
        const a = ((D.play[id] || {}).adj || []).find(x => x.id === B.id); if (!a || a.reverted) return send(res, 404, { error: 'That adjustment is not there any more.' });
        a.reverted = { t: Date.now(), by: u.user }; audit(u.user, `Reversed a trust adjustment for ${D.play[id].name}`); return ok(res);
      }
      return send(res, 400, { error: 'bad request' });
    }
    if (req.method === 'GET' && p === '/api/vault') { // a list without the contents: opening an item is logged
      if (!has(u, 'logbook.note')) return deny(res);
      const id = +url.searchParams.get('userId') || 0, cs = String(url.searchParams.get('case') || ''), all = vaultItems(), used = vaultSize();
      const items = cs ? all.filter(x => (x.cases || []).includes(cs)) : id ? all.filter(x => x.uid === id) : [];
      return send(res, 200, { items: items.map(vaultMeta), used, cap: VAULT_CAP, warn: used >= VAULT_CAP * 0.8, days: vaultDays(), canDeleteAll: has(u, 'logbook.revert') });
    }
    if (req.method === 'GET' && p === '/api/vault/item') {
      if (!has(u, 'logbook.note')) return deny(res);
      const x = vaultItems().find(x => x.id === url.searchParams.get('id')); if (!x) return send(res, 404, { error: 'This item has expired or was deleted.' });
      (x.log ||= []).push({ t: Date.now(), who: u.user }); if (x.log.length > 50) x.log.splice(0, x.log.length - 50);
      return send(res, 200, { item: x });
    }
    if (req.method === 'POST' && p === '/api/vault') {
      if (B.op === 'days') { if (!has(u, 'automations.manage')) return deny(res); if (!VAULT_DAYS.includes(B.days)) return send(res, 400, { error: 'Pick 30, 90, 180 or 365 days.' }); D.settings.vaultDays = B.days; audit(u.user, `New evidence vault items are kept for ${B.days} days`); return ok(res); }
      if (!has(u, 'logbook.note')) return deny(res);
      const items = vaultItems();
      if (B.op === 'add') {
        const kind = ['link', 'note', 'box'].includes(B.kind) ? B.kind : ''; if (!kind) return send(res, 400, { error: 'bad request' });
        const cs = String(B.case || ''); if (cs && !CASE_RE.test(cs)) return send(res, 400, { error: 'bad request' });
        const ci = cs ? caseInfo(cs) : null; if (cs && !ci) return send(res, 404, { error: 'That report, appeal or escalation is not there any more.' });
        const uid0 = ci && ci.uid ? ci.uid : Number.isInteger(B.userId) && B.userId > 0 ? B.userId : 0; if (!uid0 && !cs) return send(res, 400, { error: 'bad request' });
        const x = { id: rnd(8), uid: uid0 || null, name: cleanName(B.name, 40) || (ci && ci.name) || (D.play[uid0] || {}).name || '', cases: cs ? [cs] : [], kind, title: cleanName(B.title, 80), by: u.user, byUid: uid, t: Date.now(), exp: Date.now() + vaultDays() * 864e5, log: [] };
        if (kind === 'link') { const l = cleanLinks([B.url], 1); if (!l.length) return send(res, 400, { error: 'Links must start with https:// or http://' }); x.url = l[0]; x.title ||= l[0].slice(0, 80); }
        if (kind === 'note') { x.text = String(B.text || '').replace(/\r/g, '').trim().slice(0, 2000); if (x.text.length < 2) return send(res, 400, { error: 'Write the note first.' }); x.title ||= x.text.slice(0, 60); }
        if (kind === 'box') {
          if (!feat('chatLogs')) return send(res, 404, { error: 'Chat logs are not turned on for this workspace yet.' }); if (!has(u, 'chatlogs.view')) return deny(res);
          const bid = String(B.box || '').toUpperCase(); if (!BOX_ID_RE.test(bid)) return send(res, 400, { error: 'That is not a chat box ID.' });
          const bx = await boxGet(bid); if (!bx) return send(res, 404, { error: 'No chat box with that ID in this workspace.' });
          x.box = bid; x.server = String(bx.server || '').slice(0, 8); x.msgs = (bx.msgs || []).slice(0, 50).map(m => ({ t: m.t, userId: m.userId, name: m.name, text: String(m.text || '').slice(0, 300), ...(m.flags && m.flags.length ? { flags: m.flags } : {}) })); x.title ||= 'Chat box ' + bid;
        }
        if (vaultSize() + JSON.stringify(x).length > VAULT_CAP) return send(res, 413, { error: 'The evidence vault is full. Delete old items, or keep new items for a shorter time in Settings, Automations.' });
        items.push(x); audit(u.user, `Added ${kind === 'box' ? 'a chat box copy' : 'a ' + kind} to the evidence vault${x.name ? ' for ' + x.name : ''}`);
        return send(res, 200, { ok: true, id: x.id, warn: vaultSize() >= VAULT_CAP * 0.8 });
      }
      const x = items.find(x => x.id === B.id); if (!x) return send(res, 404, { error: 'This item has expired or was deleted.' });
      if (B.op === 'delete') { if (x.byUid !== uid && !has(u, 'logbook.revert')) return deny(res); VT.items = items.filter(y => y !== x); audit(u.user, `Deleted "${x.title}" from the evidence vault`); return ok(res); }
      if (B.op === 'attach' || B.op === 'detach') {
        const cs = String(B.case || ''); if (!CASE_RE.test(cs)) return send(res, 400, { error: 'bad request' });
        if (B.op === 'attach') { if (!caseInfo(cs)) return send(res, 404, { error: 'That report, appeal or escalation is not there any more.' }); if (!x.cases.includes(cs)) x.cases.push(cs); }
        else x.cases = x.cases.filter(c => c !== cs);
        audit(u.user, `${B.op === 'attach' ? 'Attached' : 'Detached'} "${x.title}" ${B.op === 'attach' ? 'to' : 'from'} ${cs.replace(':', ' ')}`); return ok(res);
      }
      return send(res, 400, { error: 'bad request' });
    }
    if (req.method === 'POST' && p === '/api/call' && B.op === 'fromBox') { // "Report this box" from Chat logs: a new report with the box attached
      if (!feat('chatLogs')) return send(res, 404, { error: 'Chat logs are not turned on for this workspace yet.' });
      if (!has(u, 'chatlogs.view')) return deny(res);
      const id = String(B.id || '').toUpperCase(); if (!BOX_ID_RE.test(id)) return send(res, 400, { error: 'That is not a chat box ID.' });
      const bx = await boxGet(id);
      if (!bx) return send(res, 404, { error: 'No chat box with that ID in this workspace.' });
      const note = cleanName(B.note, 200), msgs = (bx.msgs || []).slice(0, 15);
      const call = { id: ++D.callSeq, t: Date.now(), from: { userId: 0, name: u.user }, staff: true, text: `Chat box ${id} reported by ${u.user}${note ? ': ' + note : ''}`, server: String(bx.server || '').slice(0, 8), status: 'open', by: null, note: '', box: id, chat: msgs.map(m => ({ t: m.t, userId: m.userId, name: m.name, text: m.text, flagged: !!(m.flags && m.flags.length) })) };
      callMerge(call); D.calls.unshift(call); D.calls.length = Math.min(D.calls.length, 100); daily().r++; feed(`Report #${call.id}: chat box ${id}`, u.user); audit(u.user, `Reported chat box ${id}`);
      return send(res, 200, { ok: true, id: call.id });
    }
    if (req.method === 'POST' && p === '/api/call') {
      if (!has(u, 'reports.handle')) return deny(res);
      const c = D.calls.find(c => c.id === B.id); if (!c) return send(res, 404, { error: 'No such report' });
      const g = grpOf(c), mem = grpMembers(g);
      if (B.op === 'claim' && c.status === 'open') { const now = mem.filter(x => x.status === 'open'); for (const x of now) { x.status = 'claimed'; x.by = u.user; } obTick(uid, 'report'); callTell(now, 'info', 'Report update', 'is being handled by a moderator.'); return send(res, 200, { ok: true, join: callOut(c).join || '' }); }
      else if ((B.op === 'resolve' || B.op === 'dismiss') && c.status !== 'resolved') { // closes every report in the group; each reporter hears about their own
        const note = cleanName(B.note, 200), now = mem.filter(x => x.status !== 'resolved'), dis = B.op === 'dismiss';
        for (const x of now) { x.status = 'resolved'; x.outcome = dis ? 'dismissed' : 'resolved'; x.by = x.by || u.user; x.note = note; x.resolved = Date.now(); }
        obTick(uid, 'report'); callTell(now, dis ? 'info' : 'ok', dis ? 'Report closed' : 'Report resolved', dis ? 'was closed. Staff looked into it and took no action.' : `resolved${note ? ': ' + note : '.'}`);
        feed(`Report #${g} ${dis ? 'closed, no action' : 'resolved'}${now.length > 1 ? ` (${now.length} reports)` : ''}`, u.user);
      }
      else if (B.op === 'merge') { // put a report (and anything grouped under it) into another report's group
        const into = D.calls.find(x => x.id === B.into); if (!into) return send(res, 404, { error: 'No such report' });
        const tg = grpOf(into); if (tg === g) return send(res, 400, { error: 'These reports are already together.' });
        if (c.status === 'resolved' || into.status === 'resolved') return send(res, 400, { error: 'Only open reports can be merged.' });
        for (const x of mem) x.grp = tg; audit(u.user, `Merged report #${c.id} into #${tg}`);
      }
      else if (B.op === 'unmerge') {
        if (mem.length < 2) return send(res, 400, { error: 'This report is not merged with any other.' });
        if (c.grp) delete c.grp;
        else { const rest = mem.filter(x => x !== c).sort((a, b) => a.t - b.t), nl = rest[0]; delete nl.grp; for (const x of rest.slice(1)) x.grp = nl.id; }
        audit(u.user, `Took report #${c.id} out of a merged group`);
      }
      return ok(res);
    }
    if (p.startsWith('/api/chatlogs') && !feat('chatLogs')) return send(res, 404, { error: 'Chat logs are not turned on for this workspace yet.', off: true });
    if (p === '/api/chatlogs' || p === '/api/chatlogs/box') { if (!has(u, 'chatlogs.view')) return deny(res); return chatLogs(url, p, res); }
    if (p === '/api/chatlogs/usage') { // Settings: how much of the chat log limit this workspace uses
      if (!u.isOwner && !has(u, 'chatlogs.view')) return deny(res);
      let x = null; try { const r = await cbFetch('rpc/chat_box_usage', { method: 'POST', body: JSON.stringify({ w: CTX.wid }), ms: 4000 }); if (r.ok) x = (await r.json())[0] || { n: 0, bytes: 0 }; } catch {}
      return send(res, 200, x ? { setup: true, days: chatDays(), n: +x.n || 0, bytes: +x.bytes || 0, maxN: CB_MAX_N, maxBytes: CB_MAX_BYTES } : { setup: false, days: chatDays() });
    }
    if (p === '/api/escalate') { // send a case up to a senior; seniors take, return or resolve it
      D.escal ||= [];
      if (req.method === 'GET') { const x = D.escal.find(y => y.id === url.searchParams.get('id')); if (!x || !(x.byUid === uid || escSenior(uid, x))) return send(res, 404, { error: 'That case is not there any more.' }); return send(res, 200, { item: escOut(x, uid), ref: escRef(x) }); }
      if (B.op === 'send') {
        const kind = B.kind; if (!ESC_KINDS[kind]) return send(res, 400, { error: 'bad request' });
        if (!escCan(u, kind)) return deny(res);
        let ref, title;
        if (kind === 'report') { const c = D.calls.find(c => c.id === +B.ref); if (!c) return send(res, 404, { error: 'That report is not there any more.' }); ref = c.id; title = `Report #${c.id}`; }
        else if (kind === 'appeal') { const a = D.appeals.find(a => a.id === B.ref); if (!a) return send(res, 404, { error: 'That appeal is not there any more.' }); ref = a.id; title = `Appeal from ${a.name}`; }
        else { const pid = +(B.ref && B.ref.userId), e = (D.logs[pid] || []).find(e => e.id === (B.ref && B.ref.entryId)); if (!e) return send(res, 404, { error: 'That logbook entry is not there any more.' }); ref = { userId: pid, entryId: e.id }; title = `${e.type}: ${e.name}`; }
        const to = B.to === 'any' ? 'any' : String(B.to || ''); if (to !== 'any' && !(D.ranks[to] && D.ranks[to].pos > u.pos)) return send(res, 400, { error: 'Pick a rank above yours, or any senior.' });
        const probe = { kind, to, byPos: u.pos, byUid: uid };
        if (u.isOwner || !Object.keys(D.members).some(m => m !== D.meta.owner && escSenior(m, probe))) return send(res, 409, { error: 'No one above you can take this.' });
        if (D.escal.some(y => y.status !== 'resolved' && escSame(y, { kind, ref }))) return send(res, 409, { error: 'This is already sent up.' });
        const note = cleanName(B.note, 300), x = { id: rnd(6), kind, ref, title, to, note, by: u.user, byUid: uid, byPos: u.pos, t: Date.now(), status: 'open', log: [{ t: Date.now(), who: u.user, what: 'Sent up', note }] };
        D.escal.unshift(x); const keep = D.escal.filter(y => y.status !== 'resolved'), done = D.escal.filter(y => y.status === 'resolved').slice(0, 100); D.escal = [...keep, ...done].sort((a, b) => b.t - a.t).slice(0, 300);
        audit(u.user, `Sent ${title} up to ${to === 'any' ? 'any senior' : D.ranks[to].name}${note ? ': ' + note : ''}`); return send(res, 200, { ok: true, id: x.id });
      }
      const x = D.escal.find(y => y.id === B.id); if (!x) return send(res, 404, { error: 'That case is not there any more.' });
      const note = cleanName(B.note, 300), step = what => { x.log.push({ t: Date.now(), who: u.user, what, note }); audit(u.user, `${what}: ${x.title}${note ? ' (' + note + ')' : ''}`); };
      if (B.op === 'resend') { if (x.byUid !== uid || x.status !== 'returned') return deny(res); x.status = 'open'; x.takenBy = null; step('Sent up again'); return ok(res); }
      if (!escSenior(uid, x)) return deny(res);
      if (B.op === 'take') { if (x.status !== 'open') return send(res, 409, { error: 'Someone already has this.' }); x.status = 'taken'; x.takenBy = u.user; x.takenUid = uid; step('Taken'); return ok(res); }
      if (B.op === 'return') { if (x.status === 'resolved') return send(res, 409, { error: 'This is already resolved.' }); if (!note) return send(res, 400, { error: 'Add a note for the person who sent it.' }); x.status = 'returned'; step('Returned'); return ok(res); }
      if (B.op === 'resolve') { if (x.status === 'resolved') return send(res, 409, { error: 'This is already resolved.' }); x.status = 'resolved'; x.takenBy ||= u.user; step('Resolved'); return ok(res); }
      return send(res, 400, { error: 'bad request' });
    }
    if (req.method === 'POST' && p === '/api/onboard') {
      D.onboard ||= { lists: {}, done: {}, skip: {} };
      if (B.op === 'event') { if (B.ev !== 'rulebook') return send(res, 400, { error: 'bad request' }); obTick(uid, 'rulebook'); return ok(res); }
      if (B.op === 'tick') { const st = obState(uid), it = st && st.items.find(i => i.id === B.id && !i.auto); if (!it) return send(res, 404, { error: 'Not on your checklist.' }); const d = (D.onboard.done[uid] ||= {}); if (B.on) d[it.id] = Date.now(); else delete d[it.id]; return ok(res); }
      if (!u.isOwner) return ownerOnly(res);
      if (B.op === 'list') {
        if (!D.ranks[B.rank]) return send(res, 400, { error: 'Pick a rank.' });
        const items = (Array.isArray(B.items) ? B.items : []).slice(0, 15).map(i => ({ id: /^[\w-]{1,20}$/.test(i && i.id || '') ? i.id : rnd(5), label: cleanName(i && i.label, 80), auto: OB_AUTO[i && i.auto] ? i.auto : '' })).filter(i => i.label);
        D.onboard.lists[B.rank] = items; audit(u.user, `Changed the onboarding checklist for ${D.ranks[B.rank].name}`); return ok(res);
      }
      if (B.op === 'reset') { if (!D.ranks[B.rank]) return send(res, 400, { error: 'Pick a rank.' }); delete D.onboard.lists[B.rank]; audit(u.user, `Reset the onboarding checklist for ${D.ranks[B.rank].name}`); return ok(res); }
      if (B.op === 'restart') { if (!D.members[B.uid] || B.uid === D.meta.owner) return send(res, 404, { error: 'No such member.' }); delete D.onboard.skip[B.uid]; delete D.onboard.done[B.uid]; audit(u.user, `Restarted onboarding for ${D.members[B.uid].name}`); return ok(res); }
      return send(res, 400, { error: 'bad request' });
    }
    if (p === '/api/training') { // practice on anonymised cases. Never touches real players
      D.training ||= { cases: [], results: {} };
      if (req.method === 'POST' && B.op === 'toggle') { if (!u.isOwner) return ownerOnly(res); D.settings.training = !!B.on; audit(u.user, B.on ? 'Turned on the training page' : 'Turned off the training page'); return ok(res); }
      if (req.method === 'POST' && ['add', 'edit', 'del'].includes(B.op)) {
        if (!u.isOwner) return ownerOnly(res);
        if (B.op === 'del') { D.training.cases = D.training.cases.filter(c => c.id !== B.id); audit(u.user, 'Deleted a practice case'); return ok(res); }
        const text = cleanName(B.text, 600), action = ['warn', 'mute', 'kick', 'ban', 'none'].includes(B.action) ? B.action : null; if (!text || !action) return send(res, 400, { error: 'Write what happened and pick the right action.' });
        const c = { id: B.op === 'edit' ? String(B.id) : 'c' + rnd(6), text, chat: (Array.isArray(B.chat) ? B.chat : []).map(x => cleanName(x, 200)).filter(Boolean).slice(0, 15), action, minutes: ['mute', 'ban'].includes(action) ? clampInt(B.minutes, 0, 525600) : 0, note: cleanName(B.note, 400), t: Date.now(), by: u.user };
        if (B.op === 'edit') { const i = D.training.cases.findIndex(x => x.id === c.id); if (i < 0) return send(res, 404, { error: 'No such case.' }); D.training.cases[i] = c; } else { if (D.training.cases.length >= 100) return send(res, 400, { error: 'Up to 100 practice cases.' }); D.training.cases.unshift(c); }
        audit(u.user, B.op === 'edit' ? 'Edited a practice case' : 'Wrote a practice case'); return ok(res);
      }
      if (!D.settings.training) return send(res, 404, { error: 'The training page is turned off.', off: true });
      if (!has(u, 'training.use') && !u.isOwner) return deny(res);
      const cases = trCases(), mine = D.training.results[uid] || [];
      if (req.method === 'GET') { const seen = new Set(mine.map(r => r.id)); return send(res, 200, { cases: cases.map(({ answer, note, ...c }) => ({ ...c, answered: seen.has(c.id) })).sort((a, b) => (a.answered ? 1 : 0) - (b.answered ? 1 : 0) || b.t - a.t).slice(0, 60), done: mine.length, right: mine.filter(r => r.match).length, own: u.isOwner ? D.training.cases : undefined }); }
      if (B.op !== 'answer') return send(res, 400, { error: 'bad request' });
      const c = cases.find(x => x.id === B.id); if (!c) return send(res, 404, { error: 'That case is not there any more.' });
      const pick = { action: ['warn', 'mute', 'kick', 'ban', 'none'].includes(B.action) ? B.action : 'none', minutes: clampInt(B.minutes, 0, 525600) }, match = trMatch(pick, c.answer);
      D.training.results[uid] = [{ t: Date.now(), id: c.id, pick, answer: c.answer, match }, ...mine.filter(r => r.id !== c.id)].slice(0, 100);
      obTick(uid, 'practice'); return send(res, 200, { ok: true, match, answer: c.answer, note: c.note });
    }
    if (req.method === 'POST' && p === '/api/digest') { // the owner's daily summary
      if (!u.isOwner) return ownerOnly(res);
      const hour = clampInt(B.hour, 0, 23), tz = String(B.tz || 'UTC').slice(0, 64); if (!Number.isInteger(hour) || !localDay(tz, Date.now())) return send(res, 400, { error: 'Pick an hour and a valid time zone.' });
      const was = D.settings.digest || {}; D.settings.digest = { on: !!B.on, hour, tz };
      if (B.on && (!was.on || was.hour !== hour || was.tz !== tz)) D.meta.digestDay = digestSlot(D.settings.digest, Date.now()); // the first one comes at the next chosen hour, not straight away
      audit(u.user, B.on ? `Turned on the daily summary (${String(hour).padStart(2, '0')}:00, ${tz})` : 'Turned off the daily summary'); return ok(res);
    }
    if (req.method === 'POST' && p === '/api/alertwords') { // watch words for chat alerts
      if (!has(u, 'automations.manage')) return deny(res);
      if (B.dest !== undefined && !['inbox', 'discord', 'both'].includes(B.dest)) return send(res, 400, { error: 'Pick Inbox, Discord or both.' });
      const seen = new Set(), words = (Array.isArray(B.words) ? B.words : []).map(x => ({ w: cleanName(x && x.w, 60).toLowerCase(), whole: !!(x && x.whole) })).filter(x => x.w && cussTokens(x.w).length && !seen.has(x.w) && seen.add(x.w)).slice(0, 100);
      const old = Object.fromEntries((D.alertWords || []).map(a => [a.w, a.id]));
      D.alertWords = words.map(x => ({ id: old[x.w] || rnd(5), ...x }));
      if (B.dest !== undefined) D.settings.alertDest = B.dest;
      audit(u.user, 'Updated the chat alert words'); return ok(res);
    }
    if (req.method === 'POST' && p === '/api/cusswords') { // the swear word and slur list behind the chat log flags
      if (!has(u, 'automations.manage')) return deny(res);
      const tidy = a => [...new Set((Array.isArray(a) ? a : []).map(w => String(w).toLowerCase().replace(/[^a-z*]/g, '').slice(0, 30)).filter(w => w.length >= 2))].slice(0, 300);
      D.cussWords = B.reset ? null : { mild: tidy(B.mild), strong: tidy(B.strong) }; audit(u.user, B.reset ? 'Reset the chat log word list' : 'Updated the chat log word list'); return ok(res);
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
      for (const [k, def] of Object.entries(base)) if (k !== 'enabled') { const v = (B.params || {})[k]; next[k] = typeof def === 'number' ? (k === 'percent' ? clampInt(v, 50, 100) : clampInt(v, 1, 100000)) : k === 'action' ? (['warn', 'mute', 'kick'].includes(v) ? v : def) : cleanName(v ?? def, 120); }
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
        if (Object.keys(D.members).length >= capOf('members')) return send(res, 400, { error: `Your workspace has reached its limit of ${capOf('members')} members.` });
        if (Object.keys(D.members).length >= 50) return send(res, 400, { error: 'This workspace is full (50 people).' });
        const hrs = [1, 24, 72, 168].includes(+B.hours) ? +B.hours : 24, uname = cleanName(B.roblox, 40).replace(/^@/, '');
        let lock = null;
        if (uname) {
          if (!/^[A-Za-z0-9_]{3,20}$/.test(uname)) return send(res, 400, { error: 'Roblox usernames are 3 to 20 letters, numbers or underscores.' });
          lock = await rbxUser(uname); if (!lock) return send(res, 400, { error: `Could not find a Roblox account called ${uname}. Check the spelling.` });
        }
        if (r.perms.some(x => ADMINP.includes(x)) && !lock) return send(res, 400, { error: 'Invites for ranks with admin powers must be locked to one Roblox account. Enter their Roblox username.' });
        const code = CTX.wid + crypto.randomBytes(8).toString('hex'); D.invites[code] = { rank: B.rank, exp: Date.now() + hrs * 36e5, by: u.user, ...(lock ? { lock } : {}) }; audit(u.user, `Created an invite for ${r.name}${lock ? ', locked to @' + lock.name : ', open to anyone with the link'}`);
        return send(res, 200, { ok: true, code, link: `${site(req)}/#/join/${code}`, lock: lock ? lock.name : null });
      }
      if (B.op === 'revoke') { delete D.invites[String(B.code || '')]; audit(u.user, 'Revoked an invite'); return ok(res); }
      const t = String(B.uid || ''), m = D.members[t];
      if (!m) return send(res, 404, { error: 'No such member' });
      if (t === D.meta.owner) return send(res, 400, { error: 'The owner cannot be changed.' });
      if (!above(u, memberPos(t))) return send(res, 403, { error: 'You can only manage members below your rank.' });
      if (B.op === 'remove') { audit(u.user, `Removed ${m.name}`); delete D.members[t]; return ok(res); }
      if (B.op === 'setrank' && m.group && D.meta.group && D.meta.group.id) return send(res, 409, { error: `${m.name}'s rank comes from your Roblox group. Change their role in the group instead.` });
      if (B.op === 'setrank') { const r = D.ranks[B.rank]; if (!r || !above(u, r.pos)) return send(res, 403, { error: 'You can only give ranks below your own.' });
        if (m.rank === B.rank) return ok(res);
        if (!u.isOwner && approvalOn('rank')) { const pl = { uid: t, name: m.name, rank: B.rank, rankName: r.name }; if (approverExists('rank', uid, pl)) { const it = propose('rank', u, uid, pl, `set ${m.name} to ${r.name}`, ''); if (!it) return send(res, 429, { error: 'Too many requests are waiting for approval. Ask someone to clear them first.' }); return send(res, 200, { ok: true, pending: true, msg: PEND_MSG }); } }
        m.rank = B.rank; audit(u.user, `Set ${m.name} to ${r.name}`); return ok(res); }
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
      const w0 = limit('fb:' + uid, 6, 3600000) || await slimit('fb:' + uid, 10, 3600000); if (w0) return tooMany(res, w0);
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
    if (p === '/api/shifts' && req.method === 'GET') {
      const now = Date.now(), list = D.shifts.filter(x => shEnd(x) > now - 30 * 864e5).sort((a, b) => a.start - b.start);
      const need2 = [...new Set(list.filter(x => x.start < now).flatMap(x => x.signups.map(s => ridOf(s.uid)).filter(Boolean).map(r => shOf(+r))))]; if (need2.length) await need(...need2);
      for (const x of list) if (shEnd(x) < now - 5 * 60000 && !x.att) { x.att = {}; for (const sg of x.signups) { const rid = ridOf(sg.uid); x.att[sg.uid] = rid ? Math.round(inGameSecs(+rid, x.start, shEnd(x)) / 60) : null; } } // freeze attendance once a shift is over
      return send(res, 200, { shifts: list.map(x => shiftView(x, uid)) });
    }
    if (req.method === 'POST' && p === '/api/approvals') { // sign off, decline or withdraw a request that needs a second person
      const now = Date.now(), it = (D.pending || []).find(x => x.id === B.id && now - x.t < APPR_MS);
      if (!it) return send(res, 404, { error: 'That request is gone. It was already handled, or it expired.' });
      if (B.op === 'cancel' || B.op === 'deny') {
        if (B.op === 'cancel' ? it.byUid !== uid : !canApprove(it, u, uid)) return deny(res);
        D.pending = D.pending.filter(x => x !== it); audit(u.user, `${B.op === 'cancel' ? 'Withdrew' : 'Declined'} the request to ${it.text}`); return ok(res);
      }
      if (B.op !== 'approve') return send(res, 400, { error: 'bad request' });
      if (it.byUid === uid) return send(res, 409, { error: 'You asked for this, so a different staff member has to approve it.' });
      if (!canApprove(it, u, uid)) return send(res, 403, { error: 'Your rank does not allow you to approve this.' });
      const pl = it.payload;
      if (it.kind === 'rank') {
        const m = D.members[pl.uid]; if (!m || !D.ranks[pl.rank]) { D.pending = D.pending.filter(x => x !== it); return send(res, 404, { error: 'That person or rank no longer exists, so the request was dropped.' }); }
        if (m.group && D.meta.group && D.meta.group.id) { D.pending = D.pending.filter(x => x !== it); return send(res, 409, { error: `${m.name}'s rank comes from your Roblox group, so the request was dropped.` }); }
        m.rank = pl.rank; audit(u.user, `Approved: set ${m.name} to ${D.ranks[pl.rank].name} (asked by ${it.by})`);
      } else if (it.kind === 'permBan') {
        if (D.bans[pl.userId] && live(D.bans[pl.userId]) && !D.bans[pl.userId].expires) { D.pending = D.pending.filter(x => x !== it); return send(res, 409, { error: `${pl.name} is already permanently banned.` }); }
        act({ action: 'ban', userId: pl.userId, name: pl.name, reason: cleanName(`${pl.reason} (approved by ${u.user})`, 400), minutes: 0, by: it.by, byUid: it.byUid, ruleId: pl.ruleId || null, alts: pl.alts !== false, extra: { ...(pl.ev && pl.ev.length ? { ev: pl.ev } : {}), ...(pl.note ? { note: pl.note } : {}) } });
        audit(u.user, `Approved: permanently ban ${pl.name} (asked by ${it.by})`);
      } else if (it.kind === 'wsDelete') {
        await need('glob'); G.workspaces = Math.max(0, G.workspaces - 1); D.meta.deleted = now; audit(u.user, `Approved: delete the workspace (asked by ${it.by})`);
        D.pending = D.pending.filter(x => x !== it); res.setHeader('Set-Cookie', clearCookie('ws')); return send(res, 200, { ok: true, deleted: true });
      }
      D.pending = D.pending.filter(x => x !== it); return ok(res);
    }
    if (req.method === 'POST' && p === '/api/signals') {
      if (B.op === 'toggle') { if (!has(u, 'automations.manage')) return deny(res); D.settings.signals = !!B.on; audit(u.user, B.on ? 'Turned on alt-account hints' : 'Turned off alt-account hints'); return ok(res); }
      if (!has(u, 'mod.kick')) return deny(res);
      const x = D.signals[B.userId]; if (!x) return send(res, 404, { error: 'Nothing to dismiss.' });
      if (B.op === 'watch') {
        if (Object.keys(D.watch).length >= 200 && !D.watch[B.userId]) return send(res, 400, { error: 'The watchlist is full (200 players).' });
        D.watch[B.userId] = { name: x.name, by: u.user, t: Date.now(), reason: cleanName('Possible alt' + (x.of ? ' of ' + x.of.name : ''), 200) };
        x.status = 'watching'; x.by = u.user; x.done = Date.now(); audit(u.user, `Put ${x.name} on the watchlist from the alt-account queue`); return ok(res);
      }
      x.status = 'dismissed'; x.by = u.user; x.done = Date.now(); audit(u.user, `Dismissed the alt-account hint for ${x.name}`); return ok(res);
    }
    if (req.method === 'POST' && p === '/api/shifts') {
      const x = D.shifts.find(y => y.id === B.id), now = Date.now();
      if (B.op === 'create') {
        if (!has(u, 'shifts.manage')) return deny(res);
        const title = cleanName(B.title, 60) || 'Moderation shift', start = Number(B.start), mins = clampInt(B.mins, 15, 720), slots = clampInt(B.slots, 1, 50), notes = cleanName(B.notes, 200), rep = clampInt(B.repeat, 0, 8);
        if (!Number.isFinite(start) || start < now - 36e5 || start > now + 120 * 864e5) return send(res, 400, { error: 'Pick a start time in the next few months.' });
        D.shifts = D.shifts.filter(y => shEnd(y) > now - 30 * 864e5);
        if (D.shifts.length + rep + 1 > 200) return send(res, 400, { error: 'Too many shifts planned. Delete some first.' });
        const ids = []; for (let i = 0; i <= rep; i++) { const id = crypto.randomBytes(4).toString('hex'); ids.push(id); D.shifts.push({ id, title, start: start + i * 7 * 864e5, mins, slots, notes, by: u.user, signups: [] }); }
        audit(u.user, `Planned ${rep ? rep + 1 + ' weekly shifts' : 'a shift'}: ${title}`);
        notify('shifts', `New shift${rep ? 's' : ''}: ${title}`, `<t:${Math.floor(start / 1000)}:F> for ${fmtMin(mins)}${rep ? `, every week for ${rep + 1} weeks` : ''}. ${slots} spot${slots === 1 ? '' : 's'}. Sign up in Sentinel.${notes ? '\n' + notes : ''}`, [['Planned by', u.user]], 0x5e5ce6);
        return send(res, 200, { ok: true, ids });
      }
      if (!x) return send(res, 404, { error: 'That shift no longer exists.' });
      if (B.op === 'delete') { if (!has(u, 'shifts.manage')) return deny(res); D.shifts = D.shifts.filter(y => y !== x); audit(u.user, `Deleted the shift ${x.title}`); return ok(res); }
      if (B.op === 'remove') { if (!has(u, 'shifts.manage')) return deny(res); x.signups = x.signups.filter(sg => sg.uid !== B.uid); return ok(res); }
      if (B.op === 'claim') {
        if (shEnd(x) < now) return send(res, 400, { error: 'That shift is over.' });
        if (x.signups.some(sg => sg.uid === uid)) return ok(res);
        if (x.signups.length >= x.slots) return send(res, 409, { error: 'That shift is full.' });
        x.signups.push({ uid, name: u.user, t: now }); return ok(res);
      }
      if (B.op === 'leave') { if (x.start < now) return send(res, 400, { error: 'The shift already started. Ask a lead to take you off.' }); x.signups = x.signups.filter(sg => sg.uid !== uid); return ok(res); }
      return send(res, 400, { error: 'bad request' });
    }
    if (p === '/api/forms' && req.method === 'GET') {
      const canR = has(u, 'forms.review');
      return send(res, 200, { forms: D.forms.map(f => ({ ...f, count: FR.filter(x => x.form === f.id).length, fresh: FR.filter(x => x.form === f.id && x.status === 'new').length })), responses: canR ? FR.slice(0, 300).map(({ tok, ...x }) => x) : [], mine: FR.filter(x => x.byUid === uid).slice(0, 30).map(({ tok, ...x }) => x), base: `${site(req)}/f/${CTX.wid}/` });
    }
    if (req.method === 'POST' && p === '/api/forms') {
      if (B.op === 'save' || B.op === 'delete' || B.op === 'toggle') {
        if (!has(u, 'forms.manage')) return deny(res);
        const ex = D.forms.find(f => f.id === B.id);
        if (B.op === 'delete') { if (!ex) return send(res, 404, { error: 'That form no longer exists.' }); D.forms = D.forms.filter(f => f !== ex); audit(u.user, `Deleted the form ${ex.title}`); return ok(res); }
        if (B.op === 'toggle') { if (!ex) return send(res, 404, { error: 'That form no longer exists.' }); ex.open = !!B.open; audit(u.user, `${ex.open ? 'Opened' : 'Closed'} the form ${ex.title}`); return ok(res); }
        const c = cleanForm(B.form, u); if (typeof c === 'string') return send(res, 400, { error: c });
        if (ex) { Object.assign(ex, c, { updated: Date.now(), by: u.user }); audit(u.user, `Edited the form ${c.title}`); return send(res, 200, { ok: true, id: ex.id }); }
        if (D.forms.length >= 20) return send(res, 400, { error: 'You can have up to 20 forms. Delete one first.' });
        const id = crypto.randomBytes(3).toString('hex'); D.forms.push({ id, ...c, created: Date.now(), by: u.user }); audit(u.user, `Created the form ${c.title}`); return send(res, 200, { ok: true, id });
      }
      if (B.op === 'submit') { // staff-only forms, filled in from inside Sentinel
        const F = D.forms.find(f => f.id === B.id && f.audience === 'staff' && f.open); if (!F) return send(res, 404, { error: 'This form is closed or no longer exists.' });
        const w1 = limit('formsub:' + uid, 20, 3600000); if (w1) return tooMany(res, w1);
        const r = await readAnswers(F, B.answers); if (r.err) return send(res, 400, { error: r.err });
        FR.unshift({ id: crypto.randomBytes(4).toString('hex'), form: F.id, formTitle: F.title, kind: F.kind, t: Date.now(), answers: r.answers, who: r.who, by: u.user, byUid: uid, status: 'new' }); if (FR.length > 500) FR.length = 500;
        D.formsNew = (D.formsNew || 0) + 1; notify('forms', `New response: ${F.title}`, `From ${u.user}`, [], 0x0a7aff); return ok(res);
      }
      if (B.op === 'review') { const [c, o] = reviewForm(u, uid, B, site(req)); return send(res, c, o); }
      return send(res, 400, { error: 'bad request' });
    }
    if (req.method === 'POST' && p === '/api/appeals') {
      if (B.op === 'toggle') { if (!has(u, 'automations.manage')) return deny(res); D.settings.appeals = !!B.on; audit(u.user, B.on ? 'Opened ban appeals' : 'Closed ban appeals'); return ok(res); }
      if (B.op === 'webreports') { if (!has(u, 'automations.manage')) return deny(res); D.settings.webReports = !!B.on; audit(u.user, B.on ? 'Opened the web report form' : 'Closed the web report form'); return ok(res); }
      if (B.op === 'hubappeals') { if (!has(u, 'automations.manage')) return deny(res); D.settings.hubAppeals = !!B.on; audit(u.user, B.on ? 'Banned players can appeal from the Sentinel appeal game' : 'Banned players can no longer appeal from the Sentinel appeal game'); return ok(res); }
      if (B.op === 'warnack') { if (!has(u, 'automations.manage')) return deny(res); D.settings.warnAck = !!B.on; audit(u.user, B.on ? 'Warned players are now asked to acknowledge the warning' : 'Warned players are no longer asked to acknowledge the warning'); return ok(res); }
      if (B.op === 'mergemin') { if (!has(u, 'automations.manage')) return deny(res); if (!MERGE_MIN.includes(B.min)) return send(res, 400, { error: 'Pick 5, 10 or 30 minutes.' }); D.settings.mergeMin = B.min; audit(u.user, `Reports about the same player within ${B.min} minutes are now grouped`); return ok(res); }
      if (B.op === 'publiclog') { if (!has(u, 'automations.manage')) return deny(res); D.settings.publicLog = !!B.on; audit(u.user, B.on ? 'Published the moderation log' : 'Made the moderation log private'); return ok(res); }
      if (B.op === 'approvals') { if (!u.isOwner) return ownerOnly(res); if (!APPR_KINDS[B.key]) return send(res, 400, { error: 'bad request' }); D.settings.approvals = { ...(D.settings.approvals || {}), [B.key]: !!B.on }; audit(u.user, `${B.on ? 'Turned on' : 'Turned off'} second approval for ${APPR_KINDS[B.key].toLowerCase()}`); return ok(res); }
      if (B.op === 'syncadd' || B.op === 'syncremove') {
        if (!u.isOwner) return ownerOnly(res);
        const wid = String(B.wid || ''), sy = D.settings.sync ||= { from: [], at: 0 };
        if (B.op === 'syncremove') { const f = sy.from.find(x => x.id === wid); sy.from = sy.from.filter(x => x.id !== wid); if (f) audit(u.user, `Stopped copying bans from ${f.name}`); return ok(res); }
        if (!/^[a-f0-9]{12}$/.test(wid) || wid === CTX.wid) return send(res, 400, { error: 'Pick one of your other workspaces.' });
        if (sy.from.some(x => x.id === wid)) return ok(res);
        if (sy.from.length >= 5) return send(res, 400, { error: 'You can copy bans from up to 5 games.' });
        const rows = await sbGet(`select=key,meta:value->meta&key=in.(w${wid}:core)`), m = rows[0] && rows[0].meta;
        if (!m || m.deleted || m.owner !== D.meta.owner) return send(res, 400, { error: 'You can only copy bans from games you own. Pick one of your other workspaces.' });
        sy.from.push({ id: wid, name: m.name }); sy.at = 0; audit(u.user, `Started copying bans from ${m.name}`); return ok(res);
      }
      if (B.op === 'twoperson') { if (!has(u, 'automations.manage')) return deny(res); D.settings.twoPerson = !!B.on; audit(u.user, B.on ? 'Lifting permanent bans now needs two staff' : 'Lifting permanent bans no longer needs two staff'); return ok(res); }
      if (B.op === 'replies') {
        if (!has(u, 'automations.manage')) return deny(res);
        const list = (Array.isArray(B.replies) ? B.replies : []).map(x => cleanName(x, 300)).filter(Boolean).slice(0, 12); D.settings.replies = list; audit(u.user, 'Edited the appeal quick replies'); return ok(res);
      }
      const [c, o] = reviewAppeal(u, uid, B); return send(res, c, o);
    }
    if (req.method === 'POST' && p === '/api/playbooks') { // written steps for common cases; they only fill in the Moderate window
      if (!has(u, 'automations.manage')) return deny(res);
      if (B.reset) { delete D.settings.playbooks; audit(u.user, 'Reset playbooks'); return ok(res); }
      const raw = Array.isArray(B.playbooks) ? B.playbooks : []; if (raw.length > 20) return send(res, 400, { error: 'You can save up to 20 playbooks.' });
      const words = a => (Array.isArray(a) ? a : []).map(w => cleanName(w, 30).toLowerCase()).filter(Boolean).slice(0, 15);
      const list = []; for (const x of raw) {
        const name = cleanName(x && x.name, 40), steps = (Array.isArray(x && x.steps) ? x.steps : []).map(t => cleanName(t, 200)).filter(Boolean).slice(0, 12);
        if (!name || !steps.length) return send(res, 400, { error: 'Each playbook needs a name and at least one step.' });
        const m = (x && x.match) || {};
        list.push({ id: typeof x.id === 'string' && /^[A-Za-z0-9_-]{1,8}$/.test(x.id) && !list.some(y => y.id === x.id) ? x.id : rnd(4), name, when: cleanName(x.when, 200), steps, preset: typeof x.preset === 'string' && presets().some(y => y.id === x.preset) ? x.preset : '', match: { flags: (Array.isArray(m.flags) ? m.flags : []).filter(f => PB_FLAGS.includes(f)), words: words(m.words) } });
      }
      D.settings.playbooks = list; audit(u.user, `Saved ${list.length} playbook${list.length === 1 ? '' : 's'}`); return ok(res);
    }
    if (req.method === 'POST' && p === '/api/presets') { // saved reasons and lengths staff can pick when moderating
      if (!has(u, 'automations.manage')) return deny(res);
      if (B.reset) { delete D.settings.presets; audit(u.user, 'Reset reason presets'); return ok(res); }
      const raw = Array.isArray(B.presets) ? B.presets : []; if (raw.length > 20) return send(res, 400, { error: 'You can save up to 20 presets.' });
      const list = []; for (const x of raw) {
        const action = ['warn', 'kick', 'mute', 'ban'].includes(x && x.action) ? x.action : '', name = cleanName(x && x.name, 30), reason = cleanName(x && x.reason, 200);
        if (!action || !name || !reason) return send(res, 400, { error: 'Each preset needs a name, an action and a reason.' });
        list.push({ id: typeof x.id === 'string' && /^[A-Za-z0-9_-]{1,8}$/.test(x.id) && !list.some(y => y.id === x.id) ? x.id : rnd(4), name, action, minutes: action === 'mute' || action === 'ban' ? clampInt(x.minutes, 0, 525600) : 0, reason });
      }
      D.settings.presets = list; audit(u.user, `Saved ${list.length} reason preset${list.length === 1 ? '' : 's'}`); return ok(res);
    }
    if (req.method === 'POST' && p === '/api/server') { // close one live server: everyone in it is removed, and it cannot be rejoined while it empties
      if (!has(u, 'servers.manage')) return deny(res);
      const w = limit('close:' + uid, 10, 600000); if (w) return tooMany(res, w);
      const full = Object.keys(R.servers).find(k => k.slice(0, 8) === String(B.id)), sv = full && R.servers[full];
      if (!sv || Date.now() - sv.last > LIVE_MS) return send(res, 404, { error: 'That server has already closed.' });
      if (B.op !== 'close') return send(res, 400, { error: 'bad request' });
      const why = cleanName(B.reason, 120), msg = `This server was closed by a moderator${why ? ': ' + why : ''}. Rejoin to play in a new one.`.slice(0, 300);
      sv.closed = Date.now(); sv.closeMsg = msg; for (const pl of sv.players) cmd({ type: 'kick', userId: pl.userId, target: full, reason: 'Server closed', display: msg });
      feed(`Closed server ${String(B.id)} (${sv.players.length} player${sv.players.length === 1 ? '' : 's'} removed)${why ? ': ' + why : ''}`, u.user);
      return send(res, 200, { ok: true, removed: sv.players.length });
    }
    if (req.method === 'POST' && p === '/api/strikes') { // staff warnings and strikes
      if (!has(u, 'staff.review')) return deny(res);
      D.strikes ||= []; const now = Date.now(), liveS = x => x.status === 'active' && (!x.expires || x.expires > now);
      if (B.op === 'add') {
        const m = D.members[B.uid]; if (!m) return send(res, 404, { error: 'That person is not on your team.' });
        if (B.uid === uid) return send(res, 400, { error: 'You cannot give yourself a strike.' });
        if (B.uid === D.meta.owner || !above(u, memberPos(B.uid))) return send(res, 403, { error: 'You can only do this for people ranked below you.' });
        const reason = cleanName(B.reason, 300); if (!reason) return send(res, 400, { error: 'Write what happened.' });
        if (D.strikes.filter(liveS).length >= 300) return send(res, 400, { error: 'Too many active strikes. Remove old ones first.' });
        const level = B.level === 'warning' ? 'warning' : 'strike', days = clampInt(B.days, 0, 3650);
        D.strikes.unshift({ id: rnd(6), uid: B.uid, name: m.name, level, reason, by: u.user, byUid: uid, t: now, expires: days > 0 ? now + days * 864e5 : null, status: 'active' }); D.strikes.length = Math.min(D.strikes.length, 500);
        audit(u.user, `Gave ${m.name} a staff ${level}: ${reason}`); return ok(res);
      }
      if (B.op === 'remove') {
        const x = D.strikes.find(y => y.id === B.id && y.status === 'active'); if (!x) return send(res, 404, { error: 'That strike was already removed.' });
        if (!u.isOwner && x.byUid !== uid && !above(u, memberPos(x.uid))) return deny(res);
        x.status = 'removed'; x.removedBy = u.user; x.removedAt = now; audit(u.user, `Removed a staff ${x.level} from ${x.name}`); return ok(res);
      }
      return send(res, 400, { error: 'bad request' });
    }
    if (req.method === 'GET' && p === '/api/staffperf') { // what each staff member has done lately
      if (!has(u, 'staff.review')) return deny(res);
      const days = [7, 30, 90].includes(+url.searchParams.get('days')) ? +url.searchParams.get('days') : 30, now = Date.now(), cut = now - days * 864e5, ws = weekStart(now), by = {}, kind = { Warned: 'warn', Kicked: 'kick', Muted: 'mute', Suspended: 'ban', Banned: 'ban', Note: 'notes' };
      for (const list of Object.values(D.logs)) for (const e of list) { if (!e.byUid || e.time < cut || !kind[e.type]) continue; const r = (by[e.byUid] ||= { warn: 0, kick: 0, mute: 0, ban: 0, notes: 0, undone: 0, last: 0 }); r[kind[e.type]]++; if (e.status === 'reverted') r.undone++; if (e.time > r.last) r.last = e.time; }
      const handled = {}; for (const c of D.calls) if (c.by && c.status === 'resolved' && (c.resolved || c.t) > cut) handled[c.by] = (handled[c.by] || 0) + 1;
      const liveS = x => x.status === 'active' && (!x.expires || x.expires > now), onLeave = id => D.loa.some(x => x.uid === id && x.status === 'approved' && x.start <= now && x.end >= now);
      const rows = Object.entries(D.members).map(([id, m]) => { const r = by[id] || { warn: 0, kick: 0, mute: 0, ban: 0, notes: 0, undone: 0, last: 0 }, rid = m.robloxId || (id[0] === 'r' ? id.slice(2) : null), pl = rid ? D.play[rid] : null, rk = D.ranks[m.rank], sk = (D.strikes || []).filter(x => x.uid === id && liveS(x));
        return { uid: id, name: m.name, rank: m.rank, robloxId: rid || null, owner: id === D.meta.owner, below: id !== uid && id !== D.meta.owner && above(u, memberPos(id)), ...r, actions: r.warn + r.kick + r.mute + r.ban, reports: handled[m.name] || 0, linked: !!rid, week: pl && pl.weekStart === ws ? Math.round(pl.week) : 0, quota: rk ? rk.quota || 0 : 0, strikes: sk.filter(x => x.level === 'strike').length, warnings: sk.filter(x => x.level === 'warning').length, onLeave: onLeave(id) }; })
        .sort((a, b) => b.actions - a.actions || a.name.localeCompare(b.name));
      return send(res, 200, { days, rows, strikes: (D.strikes || []).slice(0, 120).map(x => ({ ...x, live: liveS(x) })) });
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
        if (B.events && !u.isOwner && OWNER_EVENTS.some(k => k in B.events && !!B.events[k] !== !!D.webhook.events[k])) return send(res, 403, { error: 'Only the workspace owner can turn this notification on or off.' });
        if (B.events) for (const k of [...new Set([...Object.keys(D.webhook.events), ...OWNER_EVENTS])]) if (k in B.events) D.webhook.events[k] = !!B.events[k];
        audit(u.user, 'Updated Discord notifications'); return ok(res);
      }
      if (B.op === 'test') { if (!D.webhook.url) return send(res, 400, { error: 'Add a webhook URL first' }); HOOKS.push({ url: D.webhook.url, body: { username: 'Sentinel', allowed_mentions: { parse: [] }, embeds: [{ title: 'Sentinel is connected', description: `Notifications for ${D.meta.name} will appear in this channel.`, color: 0x635bff }] } }); return ok(res); }
      return send(res, 400, { error: 'bad request' });
    }
    // ---- owner only: the game connection ----
    if (p === '/api/setup') { if (!u.isOwner) return ownerOnly(res); return send(res, 200, { hasCode: !!D.meta.codeHash, origin: site(req), name: D.meta.name, placeId: D.meta.placeId || null, placeLock: !!D.meta.placeLock, lastPlace: D.meta.lastPlace ?? null, connectedAt: D.meta.connectedAt || null, reject: D.meta.reject && Date.now() - D.meta.reject.t < 10 * 60000 ? D.meta.reject : null, oc: D.meta.oc ? { universe: D.meta.oc.universe || '', last: D.meta.oc.last || null, machine: !!D.meta.oc.machine } : null }); }
    if (p === '/api/bridge') {
      if (!u.isOwner) return ownerOnly(res);
      if (url.searchParams.get('client')) { // the small optional LocalScript that hides a muted player's chat bar
        let cl; try { cl = fs.readFileSync(path.join(__dirname, '..', 'SentinelClient.lua'), 'utf8'); } catch { return send(res, 500, { error: 'SentinelClient.lua is missing from the deployment' }); }
        const ch = { 'Content-Type': 'text/plain; charset=utf-8' }; if (url.searchParams.get('download')) ch['Content-Disposition'] = 'attachment; filename="Sentinel.client.lua"';
        res.writeHead(200, ch); return res.end(cl);
      }
      let lua; try { lua = fs.readFileSync(path.join(__dirname, '..', 'SentinelBridge.lua'), 'utf8'); } catch { return send(res, 500, { error: 'SentinelBridge.lua is missing from the deployment' }); }
      lua = lua.replace(/^local URL = ".*"$/m, () => 'local URL = ' + JSON.stringify(site(req))).replace(/^local KEY = ".*"$/m, 'local KEY = "[INPUT CODE HERE]"').replace(/^local INTERVAL = \d+/m, 'local INTERVAL = 10');
      const h = { 'Content-Type': 'text/plain; charset=utf-8' }; if (url.searchParams.get('download')) h['Content-Disposition'] = 'attachment; filename="Sentinel.server.lua"';
      res.writeHead(200, h); return res.end(lua);
    }
    if (p === '/api/discord/setup' && req.method === 'GET') {
      const L = D.discord && D.discord.guild ? D.discord : null;
      return send(res, 200, { configured: discordOn(), invite: DISCORD.app ? `https://discord.com/oauth2/authorize?client_id=${DISCORD.app}&scope=bot%20applications.commands&permissions=18432` : null, linked: L ? { guild: L.guild, channel: L.channel, at: L.at, users: Object.keys(L.users || {}).length } : null, me: !!(L && Object.values(L.users || {}).includes(uid)), owner: u.isOwner });
    }
    if (req.method === 'POST' && p === '/api/discord/code') {
      const now = Date.now(); for (const [k, v] of Object.entries(D.discordCodes)) if (v.exp < now) delete D.discordCodes[k];
      if (Object.keys(D.discordCodes).length > 60) return send(res, 429, { error: 'Too many codes right now. Try again in a few minutes.' });
      if (B.kind === 'guild') { if (!u.isOwner) return ownerOnly(res); const k = randSecret(8); D.discordCodes[k] = { kind: 'guild', by: u.user, exp: now + 15 * 60000 }; return send(res, 200, { code: `${CTX.wid}-${k}`, exp: now + 15 * 60000 }); }
      if (!D.discord || !D.discord.guild) return send(res, 400, { error: 'Your owner has not linked a Discord server yet.' });
      let k; do { k = randSecret(6).toUpperCase(); } while (D.discordCodes[k]);
      for (const [k2, v] of Object.entries(D.discordCodes)) if (v.uid === uid) delete D.discordCodes[k2];
      D.discordCodes[k] = { kind: 'user', uid, exp: now + 15 * 60000 }; return send(res, 200, { code: k, exp: now + 15 * 60000 });
    }
    if (req.method === 'POST' && p === '/api/discord/unlink') {
      if (!D.discord || !D.discord.guild) return ok(res);
      if (B.me) { for (const [k, v] of Object.entries(D.discord.users || {})) if (v === uid) delete D.discord.users[k]; return ok(res); }
      if (!u.isOwner) return ownerOnly(res);
      CTX.guild = D.discord.guild; await need('dguild'); if (DG.wid === CTX.wid) DG = {}; delete D.discord; audit(u.user, 'Unlinked the Discord server'); return ok(res);
    }
    if (p === '/api/group' && req.method === 'GET') { if (!u.isOwner) return ownerOnly(res); return send(res, 200, { group: D.meta.group || null, ranks: Object.entries(D.ranks).map(([id, r]) => ({ id, name: r.name, pos: r.pos, admin: r.perms.some(x => ADMINP.includes(x)) })).sort((a, b) => b.pos - a.pos), joinLink: `${site(req)}/#/g/${CTX.wid}` }); }
    if (req.method === 'POST' && p === '/api/group') {
      if (!u.isOwner) return ownerOnly(res);
      if (B.op === 'connect') {
        const m = /(\d{1,15})/.exec(String(B.group || '')); if (!m) return send(res, 400, { error: 'Paste your Roblox group link or its ID number.' });
        let gi; try { gi = await groupInfo(m[1]); } catch { return send(res, 400, { error: 'Could not find that Roblox group. Check the link or ID.' }); }
        D.meta.group = { ...gi, map: {}, removeLeft: true, autoJoin: false, at: Date.now(), last: null }; audit(u.user, `Connected the Roblox group ${gi.name}`); return send(res, 200, { ok: true, group: D.meta.group });
      }
      const G0 = D.meta.group; if (!G0) return send(res, 400, { error: 'Connect a Roblox group first.' });
      if (B.op === 'roles') { try { const gi = await groupInfo(G0.id); G0.name = gi.name; G0.roles = gi.roles; } catch { return send(res, 502, { error: 'Roblox did not answer. Try again in a minute.' }); } return ok(res); }
      if (B.op === 'save') {
        const map = {}; for (const r of G0.roles) { const rk = String((B.map || {})[r.id] || ''); if (rk && D.ranks[rk]) map[r.id] = rk; }
        G0.map = map; G0.removeLeft = !!B.removeLeft; G0.autoJoin = !!B.autoJoin; G0.last = null;
        audit(u.user, `Updated Roblox group rank mapping (${Object.keys(map).length} role${Object.keys(map).length === 1 ? '' : 's'} mapped)`); return ok(res);
      }
      if (B.op === 'sync') { const r = await groupSync(req, u.user + ' (sync)'); return send(res, 200, { ok: true, result: r }); }
      if (B.op === 'disconnect') { for (const m of Object.values(D.members)) delete m.group; audit(u.user, `Disconnected the Roblox group ${G0.name}`); delete D.meta.group; return ok(res); }
      return send(res, 400, { error: 'bad request' });
    }
    if (req.method === 'POST' && p === '/api/workspace') {
      if (!u.isOwner) return ownerOnly(res);
      if (B.op === 'require2fa') {
        const on = !!B.on; if (on && !(U && U.mfa && U.mfa.on)) return send(res, 400, { error: 'Turn on two-step verification for your own account first, so you do not lock yourself out.' });
        D.meta.require2fa = on; audit(u.user, on ? 'Required two-step verification for administrators' : 'Stopped requiring two-step verification'); return ok(res);
      }
      if (B.op === 'ocsave') {
        const key = String(B.key || '').replace(/\s+/g, ''), uni = String(B.universe || '').replace(/\s/g, '');
        if (uni && !/^\d{3,20}$/.test(uni)) return send(res, 400, { error: 'The Universe ID is only numbers.' });
        if (!D.meta.oc && key.length < 20) return send(res, 400, { error: 'Paste your Roblox API key.' });
        if (key && (key.length < 20 || key.length > 4000 || !/^[\x21-\x7e]+$/.test(key))) return send(res, 400, { error: key.length < 20 ? 'That key is too short. Copy the whole key from Roblox.' : 'That key has characters a Roblox key never has. Copy it again from Roblox.' });
        D.meta.oc = { ...(D.meta.oc || {}), ...(key ? { key: ocEnc(key) } : {}), universe: uni, last: null }; delete D.meta.oc.uni; audit(u.user, 'Saved the Roblox Open Cloud key'); return ok(res);
      }
      if (B.op === 'ocmachine') { if (!D.meta.oc || !D.meta.oc.key) return send(res, 400, { error: 'Save a Roblox API key first.' }); D.meta.oc.machine = !!B.on; audit(u.user, B.on ? 'Turned on machine bans (Roblox alt detection)' : 'Turned off machine bans'); return ok(res); }
      if (B.op === 'chatdays') { const d = +B.days; if (![7, 14, 30].includes(d)) return send(res, 400, { error: 'Pick 7, 14 or 30 days.' }); D.settings.chatDays = d; audit(u.user, `Set chat logs to be kept for ${d} days`); return ok(res); }
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
        if (approvalOn('wsDelete') && approverExists('wsDelete', uid, {})) { const it = propose('wsDelete', u, uid, {}, `delete the workspace ${D.meta.name}`, ''); if (!it) return send(res, 429, { error: 'Too many requests are waiting for approval.' }); return send(res, 200, { ok: true, pending: true, msg: PEND_MSG }); }
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
        reportsFiled: D.calls.filter(c => c.from.userId === id), chatInStoredReports: D.calls.flatMap(c => c.chat.filter(m => m.userId === id).map(m => ({ report: c.id, ...m }))), recentChat: R.chat.filter(m => m.userId === id), chatLogs: await boxesOf(id), evidenceVault: vaultItems().filter(x => x.uid === id).map(({ log, ...x }) => x) };
      res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Disposition': `attachment; filename="player-${id}.json"` }); return res.end(JSON.stringify(data, null, 2));
    }
    if (req.method === 'POST' && p === '/api/erase') {
      if (!has(u, 'privacy.manage')) return deny(res);
      const id = B.userId; if (!Number.isInteger(id) || id < 1) return send(res, 400, { error: 'bad userId' });
      await erasePlayer(id); audit(u.user, `Erased stored data for user ${id}`); return ok(res);
    }
    send(res, 404, { error: 'not found' });
  } catch (e) { res.failed = true; if (p === '/game/sync') logEvent('sync_error', String((e && e.message) || e)); send(res, 500, { error: String(e) }); await opsAlert('Sentinel server error', `${req.method} ${String(req.url || '').split('?')[0].slice(0, 80)}\n${String((e && e.message) || e).slice(0, 400)}`); }
}

// ---- one request: read body, run, save, replay if another request got there first ----
const makeOut = () => { const o = { code: 200, headers: {}, body: '', failed: false, after: [], setHeader(k, v) { o.headers[k] = v; }, writeHead(c, h) { o.code = c; Object.assign(o.headers, h || {}); }, end(d) { o.body = d === undefined ? '' : d; } }; return o; };
const flush = (o, res) => { res.statusCode = o.code; for (const [k, v] of Object.entries(o.headers)) res.setHeader(k, v); res.end(o.body); };
async function readBody(req) {
  if (req.method === 'GET' || req.method === 'HEAD') return {};
  try { if (req.body !== undefined && req.body !== null) { // Vercel's helpers already parsed it (set NODEJS_HELPERS=0 to get the exact bytes)
    if (Buffer.isBuffer(req.body)) { req._raw = req.body.toString(); return JSON.parse(req._raw || '{}'); }
    if (typeof req.body === 'string') { req._raw = req.body; return JSON.parse(req.body || '{}'); }
    req._raw = JSON.stringify(req.body); return req.body; } } catch { return {}; }
  return new Promise(r => { let d = ''; req.on('data', c => { d += c; if (d.length > (String(req.url).startsWith('/api/backup/import') ? 4e6 : 1e5)) req.destroy(); }); req.on('end', () => { req._raw = d; try { r(JSON.parse(d || '{}')); } catch { r({}); } }); });
}
async function handle(req, res) {
  const url = new URL(req.url, 'http://x'), p = url.pathname;
  if (CONFIG_ERROR.length) { res.statusCode = 500; res.setHeader('Content-Type', 'text/plain'); return res.end('Sentinel is not configured. Missing Vercel environment variables: ' + CONFIG_ERROR.join(', ')); }
  req._body = await readBody(req);
  for (let attempt = 0; attempt < 6; attempt++) {
    resetState();
    const out = makeOut();
    await flagsLoad().catch(() => {}); await hubsLoad().catch(() => {});
    await route(req, out, url, p);
    if (CTX.ro) { await sendEvents(); return flush(out, res); } // read-only support view: nothing is saved, sent to games or posted
    if (!out.failed) await runOC().catch(() => {});
    if (out.failed || await commit()) { await sendHooks(); await sendBot(); if (!out.failed) await sendBoxes(); await sendEvents(); for (const f of out.after) await f().catch(() => {}); return flush(out, res); }
    await new Promise(r => setTimeout(r, 25 + Math.random() * 100)); // lost a race with another request: run again on fresh data
  }
  res.statusCode = 503; res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify({ error: 'Busy, please try again' }));
}
let chain = Promise.resolve(); // one request at a time per instance (state is shared in-process while a request runs)
const serial = fn => { const run = chain.then(fn); chain = run.catch(() => {}); return run; };
module.exports = (req, res) => serial(() => handle(req, res)).catch(e => { console.error(e); try { res.statusCode = 500; res.setHeader('Content-Type', 'text/plain'); res.end('Error: ' + e.message); } catch {} });
