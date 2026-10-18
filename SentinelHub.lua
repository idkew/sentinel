-- Sentinel appeal game: the server half. Only for the official Sentinel appeal game, not for normal games (those use SentinelBridge).
-- Put this Script in ServerScriptService and SentinelHubClient in StarterPlayerScripts. Turn on Allow HTTP Requests in Game Settings, Security.
-- Banned players join, see every game that banned them, and send an appeal to that game's staff. Roblox tells this server who the player is, so nobody can appeal for someone else.

local HUB_KEY = "PASTE HUB KEY HERE" -- from the Sentinel admin console, Appeal games. Keep it secret: it lives only in this server script
local URL = "https://sentinel-beryl-nine.vercel.app"
local HUB_VERSION = 1

local Players = game:GetService("Players")
local HttpService = game:GetService("HttpService")
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local TextService = game:GetService("TextService")

local remote = ReplicatedStorage:FindFirstChild("SentinelHub")
if not remote then
	remote = Instance.new("RemoteFunction")
	remote.Name = "SentinelHub"
	remote.Parent = ReplicatedStorage
end

if string.find(HUB_KEY, "PASTE", 1, true) then
	warn("[Sentinel] No hub key set. Paste the key from the admin console, Appeal games, over PASTE HUB KEY HERE at the top of SentinelHub.")
end

local function post(path, body) -- returns true and the reply, or false and a message the player can read
	body.key = HUB_KEY
	body.hubV = HUB_VERSION
	local ok, res = pcall(HttpService.RequestAsync, HttpService, {
		Url = URL .. path, Method = "POST", Headers = { ["Content-Type"] = "application/json" }, Body = HttpService:JSONEncode(body),
	})
	if not ok then
		warn("[Sentinel] Can't reach Sentinel (is Allow HTTP Requests on?): " .. tostring(res))
		return false, "Sentinel can't be reached right now. Try again in a minute."
	end
	local okJ, data = pcall(HttpService.JSONDecode, HttpService, res.Body)
	if not okJ or type(data) ~= "table" then data = {} end
	if not res.Success then
		if res.StatusCode == 403 then warn("[Sentinel] The hub key was refused. Check it in the admin console, Appeal games.") end
		return false, type(data.error) == "string" and data.error or "Something went wrong. Try again in a minute."
	end
	return true, data
end

-- Text from outside Roblox (game names, ban reasons, staff replies) must go through Roblox's filter before a player sees it
local function filtered(text, userId)
	if type(text) ~= "string" or text == "" then return "" end
	local ok, res = pcall(function()
		return TextService:FilterStringAsync(text, userId):GetNonChatStringForUserAsync(userId)
	end)
	if ok and typeof(res) == "string" then return res end
	return "(hidden by Roblox's text filter)"
end

local last = {} -- one request every 2 seconds per player is plenty
remote.OnServerInvoke = function(plr, op, wid, text)
	if last[plr] and os.clock() - last[plr] < 2 then return { error = "One moment, then try again." } end
	last[plr] = os.clock()
	if op == "list" then
		local ok, data = post("/hub/list", { userId = plr.UserId, name = plr.Name })
		if not ok then return { error = data } end
		local games = {}
		for _, g in ipairs(type(data.games) == "table" and data.games or {}) do
			if type(g) == "table" and type(g.wid) == "string" then
				local ap = type(g.appeal) == "table" and g.appeal or nil
				table.insert(games, {
					wid = g.wid, game = filtered(g.game, plr.UserId), reason = filtered(g.reason, plr.UserId),
					expires = type(g.expires) == "number" and g.expires or nil, can = g.can == true, why = type(g.why) == "string" and g.why or "",
					status = ap and type(ap.status) == "string" and ap.status or nil, reply = ap and filtered(ap.reply, plr.UserId) or "",
				})
			end
		end
		return { games = games }
	elseif op == "appeal" then
		if type(wid) ~= "string" or not string.match(wid, "^%x+$") or #wid ~= 12 then return { error = "Pick a game first." } end
		if type(text) ~= "string" then return { error = "Write your appeal first." } end
		text = string.sub(text, 1, 1000)
		if #string.gsub(text, "%s", "") < 5 then return { error = "Write a few words for staff first." } end
		local ok, data = post("/hub/appeal", { userId = plr.UserId, name = plr.Name, wid = wid, text = text })
		if not ok then return { error = data } end
		print("[Sentinel] Appeal sent for " .. plr.Name)
		return { ok = true }
	end
	return { error = "bad request" }
end

Players.PlayerRemoving:Connect(function(p) last[p] = nil end)
print("[Sentinel] Appeal game script version " .. HUB_VERSION .. " is running")
