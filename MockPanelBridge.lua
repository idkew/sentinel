--[[
	MockPanelBridge - connects your Roblox game to the web panel (server.js). Does REAL moderation:
	  * Ban / suspend  -> Roblox's own ban system (Players:BanAsync), applied to the whole experience
	  * Kick           -> Player:Kick()
	  * Mute           -> TextChatService (muted players' messages are dropped)
	  * Warn/announce  -> on-screen banner
	  * Chat monitor   -> every chat message is sent to the panel (kept in memory there, never saved)
	  * Players can type in chat:   !modcall <message>   (report to moderators)   and   !attend   (join a session)

	SETUP
	1. Put this in a *Script* in ServerScriptService.
	2. Paste the game key that server.js printed into KEY below.
	3. Enable HTTP requests: Studio > Game Settings > Security > "Allow HTTP Requests"
	   (or tick HttpEnabled on HttpService in the Explorer).
	4. URL: the default works for Studio testing on your own computer. For a LIVE game you must host
	   server.js online and use its https:// address here. Live Roblox servers cannot reach localhost.
	5. TextChatService > ChatVersion should be "TextChatService" (the default for new places).
]]

local HttpService = game:GetService("HttpService")
local Players = game:GetService("Players")
local TextChatService = game:GetService("TextChatService")
local Debris = game:GetService("Debris")

local URL = "http://127.0.0.1:3000"
local KEY = "PASTE_GAME_KEY_HERE"
local INTERVAL = 4
local MODCALL_COOLDOWN = 30 -- seconds between ModCalls per player

local pending, muted, busy = {}, {}, false
local seen, hidden, seenCount, lastCall = {}, {}, 0, {}
local COLORS = {
	red = Color3.fromRGB(229, 56, 79),
	blue = Color3.fromRGB(47, 91, 255),
	green = Color3.fromRGB(20, 164, 77),
}

local function queue(ev)
	table.insert(pending, ev)
	if #pending > 300 then table.remove(pending, 1) end -- never grow forever if the panel is down
end

local function banner(plr, text, color)
	local pg = plr:FindFirstChild("PlayerGui")
	if not pg then return end
	local gui = Instance.new("ScreenGui")
	gui.ResetOnSpawn, gui.DisplayOrder = false, 200
	local l = Instance.new("TextLabel")
	l.AnchorPoint, l.Position = Vector2.new(0.5, 0), UDim2.fromScale(0.5, 0.05)
	l.Size = UDim2.fromOffset(460, 54)
	l.BackgroundColor3, l.TextColor3 = color, Color3.new(1, 1, 1)
	l.Font, l.TextSize, l.TextWrapped = Enum.Font.GothamBold, 16, true
	l.Text = text
	Instance.new("UICorner", l).CornerRadius = UDim.new(0, 12)
	l.Parent = gui
	gui.Parent = pg
	Debris:AddItem(gui, 7)
end

------------------------------------------------------------------ chat: monitor, commands, mute
-- returns true when the message was a panel command (so it can be hidden from public chat)
local function onChat(userId, text)
	local plr = Players:GetPlayerByUserId(userId)
	if not plr then return false end
	text = string.sub(text, 1, 200)
	local command, rest = string.match(text, "^!(%a+)%s*(.*)$")
	command = command and string.lower(command)
	if command == "attend" then
		queue({ type = "attend", userId = userId, name = plr.Name })
		return true
	elseif command == "modcall" then
		if os.clock() - (lastCall[userId] or -999) < MODCALL_COOLDOWN then
			banner(plr, "Please wait a moment before sending another ModCall.", COLORS.red)
		else
			lastCall[userId] = os.clock()
			queue({ type = "modcall", userId = userId, name = plr.Name, text = rest })
		end
		return true
	end
	queue({ type = "chat", userId = userId, name = plr.Name, text = text })
	return false
end

local function setupChat()
	if TextChatService.ChatVersion == Enum.ChatVersion.TextChatService then
		local channels = TextChatService:WaitForChild("TextChannels", 30)
		local ch = channels and channels:WaitForChild("RBXGeneral", 30)
		if not ch then
			warn("[Panel] RBXGeneral chat channel not found. Chat monitor, mutes and !commands won't work.")
			return
		end
		-- Runs on the server for every message (once per recipient, so ids are de-duplicated)
		ch.ShouldDeliverCallback = function(message, _target)
			local src = message.TextSource
			if not src then return true end
			if muted[src.UserId] then return false end
			local id = message.MessageId
			if hidden[id] then return false end
			if not seen[id] then
				seen[id] = true
				seenCount += 1
				if seenCount > 500 then seen, hidden, seenCount = {}, {}, 0 end
				if onChat(src.UserId, message.Text) then
					hidden[id] = true
					return false
				end
			end
			return true
		end
	else
		warn("[Panel] Legacy chat detected: the chat monitor and commands work, but mutes need TextChatService.")
		local function hook(p)
			p.Chatted:Connect(function(msg)
				if not muted[p.UserId] then onChat(p.UserId, msg) end
			end)
		end
		Players.PlayerAdded:Connect(hook)
		for _, p in Players:GetPlayers() do hook(p) end
	end
end

local function applyMutes()
	local channels = TextChatService:FindFirstChild("TextChannels")
	local ch = channels and channels:FindFirstChild("RBXGeneral")
	if not ch then return end
	for _, p in Players:GetPlayers() do
		local src = ch:FindFirstChild(p.Name)
		if src and src:IsA("TextSource") then src.CanSend = not muted[p.UserId] end
	end
end

------------------------------------------------------------------ commands from the panel
local function doBan(userId, reason, seconds)
	local ok, err = pcall(Players.BanAsync, Players, {
		UserIds = { userId }, Duration = seconds, DisplayReason = reason,
		PrivateReason = "Banned from web panel", ApplyToUniverse = true,
	})
	if not ok then
		warn("[Panel] BanAsync failed (" .. tostring(err) .. "). Kicking instead; the panel keeps re-kicking while the ban is active.")
		local plr = Players:GetPlayerByUserId(userId)
		if plr then plr:Kick("Banned: " .. reason) end
	end
end

local function handle(c)
	local plr = c.userId and Players:GetPlayerByUserId(c.userId)
	if c.type == "kick" then
		if plr then plr:Kick("[Panel] " .. tostring(c.reason)) end
	elseif c.type == "ban" then
		doBan(c.userId, tostring(c.reason), c.seconds)
	elseif c.type == "unban" then
		pcall(Players.UnbanAsync, Players, { UserIds = { c.userId }, ApplyToUniverse = true })
	elseif c.type == "message" then
		local color = (c.kind == "ok" and COLORS.green) or (c.kind == "info" and COLORS.blue) or COLORS.red
		if plr then banner(plr, tostring(c.text), color) end
	elseif c.type == "announce" then
		for _, p in Players:GetPlayers() do banner(p, tostring(c.text), COLORS.blue) end
	end
end

local function sync()
	if busy then return end
	busy = true
	local list = {}
	for _, p in Players:GetPlayers() do
		table.insert(list, { userId = p.UserId, name = p.Name, displayName = p.DisplayName })
	end
	local sent = table.clone(pending)
	local ok, res = pcall(HttpService.RequestAsync, HttpService, {
		Url = URL .. "/game/sync", Method = "POST", Headers = { ["Content-Type"] = "application/json" },
		Body = HttpService:JSONEncode({ key = KEY, jobId = game.JobId, players = list, events = sent }),
	})
	busy = false
	if not ok or not res.Success then
		warn("[Panel] Can't reach the panel (HttpEnabled on? server.js running? key correct?): " .. tostring(ok and res.StatusCode or res))
		return
	end
	pending = table.move(pending, #sent + 1, #pending, 1, {}) -- drop only what was delivered
	local data = HttpService:JSONDecode(res.Body)
	for _, c in data.commands or {} do task.spawn(handle, c) end
	muted = {}
	for _, id in data.muted or {} do muted[id] = true end
	local okMute, muteErr = pcall(applyMutes)
	if not okMute then warn("[Panel] Mute error: " .. tostring(muteErr)) end
end

Players.PlayerAdded:Connect(function(p)
	queue({ type = "join", userId = p.UserId, name = p.Name })
	task.defer(sync)
end)
Players.PlayerRemoving:Connect(function(p)
	queue({ type = "leave", userId = p.UserId, name = p.Name })
end)
for _, p in Players:GetPlayers() do queue({ type = "join", userId = p.UserId, name = p.Name }) end

task.spawn(setupChat)
task.spawn(function()
	while true do
		sync()
		task.wait(INTERVAL)
	end
end)
print("[Panel] Connected to " .. URL)
