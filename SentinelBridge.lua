--[[
	SentinelBridge - connects your Roblox game to the Sentinel website. Does REAL moderation:
	  * Ban / suspend  -> Roblox's own ban system (Players:BanAsync), applied to the whole experience
	  * Kick           -> Player:Kick()
	  * Mute           -> TextChatService (muted players' messages are dropped)
	  * Warn/announce  -> on-screen banner
	  * Chat monitor   -> every chat message is sent to the panel (kept in memory there, never saved)
	  * Players can type in chat:   !modcall <message>   (report to moderators)   and   !attend   (join a session)

	SETUP
	1. Put this in a *Script* in ServerScriptService.
	2. Download this file from the Sentinel website (Settings > Game). It already has your game's key and
	   website address filled in below, so you do not need to edit anything.
	3. Enable HTTP requests: Studio > Game Settings > Security > "Allow HTTP Requests"
	   (or tick HttpEnabled on HttpService in the Explorer).
	4. TextChatService > ChatVersion should be "TextChatService" (the default for new places).
	   Keep your game key private. If it ever leaks, make a new one in Settings > Game and download again.
]]

local HttpService = game:GetService("HttpService")
local Players = game:GetService("Players")
local TextChatService = game:GetService("TextChatService")
local Debris = game:GetService("Debris")

local SCRIPT_VERSION = 6 -- raised whenever this script changes, so Sentinel can tell you when to update
local URL = "http://127.0.0.1:3000"
local KEY = "[INPUT CODE HERE]" -- paste your game code from the Sentinel website between the quotes
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

local TweenService = game:GetService("TweenService")
local STYLES = {
	warn = { color = Color3.fromRGB(255, 159, 10), glyph = "!", title = "Warning" },
	red = { color = Color3.fromRGB(255, 69, 58), glyph = "!", title = "Notice" },
	blue = { color = Color3.fromRGB(10, 132, 255), glyph = "i", title = "Notice" },
	green = { color = Color3.fromRGB(48, 209, 88), glyph = "\u{2713}", title = "Done" },
}
local activeBanner = {}

-- a small frosted card that slides in from the top, matching the Sentinel website
local function banner(plr, text, kind, title)
	local pg = plr:FindFirstChild("PlayerGui")
	if not pg then return end
	local st = STYLES[kind] or STYLES.red
	if activeBanner[plr] then activeBanner[plr]:Destroy() end

	local gui = Instance.new("ScreenGui")
	gui.Name, gui.ResetOnSpawn, gui.DisplayOrder, gui.IgnoreGuiInset = "SentinelBanner", false, 200, true

	local card = Instance.new("CanvasGroup")
	card.AnchorPoint = Vector2.new(0.5, 0)
	card.Position = UDim2.new(0.5, 0, 0, -110)
	card.Size = UDim2.new(0.92, 0, 0, 0)
	card.AutomaticSize = Enum.AutomaticSize.Y
	card.BackgroundColor3 = Color3.fromRGB(28, 28, 31)
	card.BackgroundTransparency = 0.04
	card.BorderSizePixel = 0
	card.GroupTransparency = 1
	card.Parent = gui
	Instance.new("UICorner", card).CornerRadius = UDim.new(0, 16)
	local limit = Instance.new("UISizeConstraint", card)
	limit.MaxSize = Vector2.new(400, math.huge)
	limit.MinSize = Vector2.new(220, 0)
	local stroke = Instance.new("UIStroke", card)
	stroke.Color, stroke.Transparency, stroke.Thickness = Color3.new(1, 1, 1), 0.86, 1
	-- padding lives on an inner frame so the countdown bar can sit on the card's real bottom edge
	local inner = Instance.new("Frame")
	inner.BackgroundTransparency = 1
	inner.Size = UDim2.new(1, 0, 0, 0)
	inner.AutomaticSize = Enum.AutomaticSize.Y
	inner.Parent = card
	local pad = Instance.new("UIPadding", inner)
	pad.PaddingTop, pad.PaddingBottom = UDim.new(0, 14), UDim.new(0, 17)
	pad.PaddingLeft, pad.PaddingRight = UDim.new(0, 14), UDim.new(0, 16)

	local row = Instance.new("Frame")
	row.BackgroundTransparency = 1
	row.Size = UDim2.new(1, 0, 0, 0)
	row.AutomaticSize = Enum.AutomaticSize.Y
	row.Parent = inner
	local rowLayout = Instance.new("UIListLayout", row)
	rowLayout.FillDirection, rowLayout.Padding = Enum.FillDirection.Horizontal, UDim.new(0, 12)

	local icon = Instance.new("TextLabel")
	icon.Size = UDim2.fromOffset(30, 30)
	icon.BackgroundColor3 = st.color
	icon.TextColor3 = Color3.new(1, 1, 1)
	icon.Font, icon.TextSize, icon.Text = Enum.Font.GothamBold, 17, st.glyph
	icon.Parent = row
	Instance.new("UICorner", icon).CornerRadius = UDim.new(1, 0)

	local col = Instance.new("Frame")
	col.BackgroundTransparency = 1
	col.Size = UDim2.new(1, -42, 0, 0)
	col.AutomaticSize = Enum.AutomaticSize.Y
	col.Parent = row
	local colLayout = Instance.new("UIListLayout", col)
	colLayout.Padding = UDim.new(0, 2)

	local head = Instance.new("TextLabel")
	head.BackgroundTransparency = 1
	head.Size = UDim2.new(1, 0, 0, 0)
	head.AutomaticSize = Enum.AutomaticSize.Y
	head.TextXAlignment, head.TextWrapped = Enum.TextXAlignment.Left, true
	head.TextColor3 = Color3.fromRGB(245, 245, 247)
	head.Font, head.TextSize = Enum.Font.GothamBold, 14
	head.Text = title or st.title
	head.LayoutOrder = 1
	head.Parent = col

	local body = Instance.new("TextLabel")
	body.BackgroundTransparency = 1
	body.Size = UDim2.new(1, 0, 0, 0)
	body.AutomaticSize = Enum.AutomaticSize.Y
	body.TextXAlignment, body.TextYAlignment, body.TextWrapped = Enum.TextXAlignment.Left, Enum.TextYAlignment.Top, true
	body.TextColor3 = Color3.fromRGB(190, 190, 197)
	body.Font, body.TextSize = Enum.Font.GothamMedium, 14
	body.Text = text
	body.LayoutOrder = 2
	body.Parent = col

	local bar = Instance.new("Frame") -- thin countdown line along the bottom
	bar.AnchorPoint, bar.Position = Vector2.new(0, 1), UDim2.new(0, 0, 1, 0)
	bar.Size = UDim2.new(1, 0, 0, 3)
	bar.BackgroundColor3, bar.BackgroundTransparency, bar.BorderSizePixel = st.color, 0.35, 0
	bar.ZIndex = 5
	bar.Parent = card

	gui.Parent = pg
	activeBanner[plr] = gui
	local SHOW = 6
	TweenService:Create(card, TweenInfo.new(0.5, Enum.EasingStyle.Quint, Enum.EasingDirection.Out), { Position = UDim2.new(0.5, 0, 0, 18), GroupTransparency = 0 }):Play()
	TweenService:Create(bar, TweenInfo.new(SHOW, Enum.EasingStyle.Linear), { Size = UDim2.new(0, 0, 0, 3) }):Play()
	task.delay(SHOW, function()
		if not gui.Parent then return end
		local out = TweenService:Create(card, TweenInfo.new(0.35, Enum.EasingStyle.Quad, Enum.EasingDirection.In), { Position = UDim2.new(0.5, 0, 0, -110), GroupTransparency = 1 })
		out:Play()
		out.Completed:Wait()
		gui:Destroy()
		if activeBanner[plr] == gui then activeBanner[plr] = nil end
	end)
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
			banner(plr, "Please wait a moment before sending another report.", "red", "Slow down")
		else
			lastCall[userId] = os.clock()
			queue({ type = "modcall", userId = userId, name = plr.Name, text = rest })
		end
		return true
	end
	queue({ type = "chat", userId = userId, name = plr.Name, text = text })
	return false
end

local mutedNote = {}
local function setupChat()
	if TextChatService.ChatVersion == Enum.ChatVersion.TextChatService then
		local channels = TextChatService:WaitForChild("TextChannels", 30)
		local ch = channels and channels:WaitForChild("RBXGeneral", 30)
		if not ch then
			warn("[Sentinel] RBXGeneral chat channel not found. Chat monitor, mutes and !commands won't work.")
			return
		end
		-- Runs on the server for every message (once per recipient, so ids are de-duplicated)
		ch.ShouldDeliverCallback = function(message, _target)
			local src = message.TextSource
			if not src then return true end
			if muted[src.UserId] then
				-- tell them why nothing happens, at most every 8 seconds
				if os.clock() - (mutedNote[src.UserId] or -999) > 8 then
					mutedNote[src.UserId] = os.clock()
					local mp = Players:GetPlayerByUserId(src.UserId)
					if mp then banner(mp, "You are muted and can't chat right now.", "red", "Muted") end
				end
				return false
			end
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
		warn("[Sentinel] Legacy chat detected: the chat monitor and commands work, but mutes need TextChatService.")
		local function hook(p)
			p.Chatted:Connect(function(msg)
				if not muted[p.UserId] then onChat(p.UserId, msg) end
			end)
		end
		Players.PlayerAdded:Connect(hook)
		for _, p in Players:GetPlayers() do hook(p) end
	end
end

local lastMuteErr = ""
-- takes chat privileges away from muted players (and gives them back when the mute ends).
-- CanSend = false on the player's TextSource is what Roblox itself uses to stop a player chatting.
local function applyMutes()
	if TextChatService.ChatVersion ~= Enum.ChatVersion.TextChatService then
		lastMuteErr = next(muted) and "legacy chat: mutes need TextChatService" or ""
		return
	end
	local channels = TextChatService:FindFirstChild("TextChannels")
	if not channels then lastMuteErr = "no TextChannels"; return end
	local missing, failed
	for _, p in Players:GetPlayers() do
		local isMuted = muted[p.UserId] == true
		local found = false
		for _, ch in channels:GetChildren() do
			if ch:IsA("TextChannel") then
				-- Roblox names TextSources after the player, not the UserId, so match on the UserId property instead
				for _, src in ch:GetChildren() do
					if src:IsA("TextSource") and src.UserId == p.UserId then
						found = true
						if src.CanSend == isMuted then
							local okSet = pcall(function() src.CanSend = not isMuted end)
							if not okSet or src.CanSend == isMuted then failed = p.Name end
						end
					end
				end
			end
		end
		if isMuted and not found then missing = p.Name end
	end
	lastMuteErr = failed and ("could not switch off chat for " .. failed) or (missing and ("no chat channel yet for " .. missing) or "")
end

local function chatMode()
	if TextChatService.ChatVersion ~= Enum.ChatVersion.TextChatService then return "legacy" end
	local channels = TextChatService:FindFirstChild("TextChannels")
	if not (channels and channels:FindFirstChild("RBXGeneral")) then return "nochannel" end
	return "text"
end

-- a player who joins (or a channel that appears) while muted is silenced straight away
local function watchChannel(ch)
	if not ch:IsA("TextChannel") then return end
	ch.ChildAdded:Connect(function(src)
		if src:IsA("TextSource") and muted[src.UserId] then src.CanSend = false end
	end)
end
task.spawn(function()
	local channels = TextChatService:WaitForChild("TextChannels", 30)
	if not channels then return end
	for _, ch in channels:GetChildren() do watchChannel(ch) end
	channels.ChildAdded:Connect(watchChannel)
end)

------------------------------------------------------------------ commands from the panel
local function doBan(userId, reason, seconds)
	local ok, err = pcall(Players.BanAsync, Players, {
		UserIds = { userId }, Duration = seconds, DisplayReason = reason,
		PrivateReason = "Banned from web panel", ApplyToUniverse = true,
	})
	if ok then print("[Sentinel] Roblox ban applied to user " .. tostring(userId)) end
	if not ok then
		warn("[Sentinel] BanAsync failed (" .. tostring(err) .. "). Kicking instead; the panel keeps re-kicking while the ban is active.")
		local plr = Players:GetPlayerByUserId(userId)
		if plr then plr:Kick("Banned: " .. reason) end
	end
end

local function handle(c)
	local plr = c.userId and Players:GetPlayerByUserId(c.userId)
	if c.type == "kick" then
		if plr then plr:Kick("[Sentinel] " .. tostring(c.reason)) end
	elseif c.type == "ban" then
		doBan(c.userId, tostring(c.reason), c.seconds)
	elseif c.type == "unban" then
		local ok, err
		for attempt = 1, 4 do
			ok, err = pcall(Players.UnbanAsync, Players, { UserIds = { c.userId }, ApplyToUniverse = true })
			if ok then break end
			task.wait(3 * attempt)
		end
		if ok then
			print("[Sentinel] Lifted the Roblox ban on user " .. tostring(c.userId))
		else
			warn("[Sentinel] Could not lift the Roblox ban on user " .. tostring(c.userId) .. ": " .. tostring(err))
		end
	elseif c.type == "message" then
		local kind = (c.kind == "warn" and "warn") or (c.kind == "ok" and "green") or (c.kind == "info" and "blue") or "red"
		if plr then banner(plr, tostring(c.body or c.text), kind, c.title) end
	elseif c.type == "announce" then
		for _, p in Players:GetPlayers() do banner(p, tostring(c.text), "blue", "Announcement") end
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
		Body = HttpService:JSONEncode({ key = KEY, jobId = game.JobId, placeId = game.PlaceId, players = list, events = sent, scriptV = SCRIPT_VERSION, chat = chatMode(), muteErr = lastMuteErr }),
	})
	busy = false
	if not ok or not res.Success then
		warn("[Sentinel] Can't reach the panel (Allow HTTP Requests on? Is the game key still valid?): " .. tostring(ok and res.StatusCode or res))
		return
	end
	pending = table.move(pending, #sent + 1, #pending, 1, {}) -- drop only what was delivered
	local data = HttpService:JSONDecode(res.Body)
	for _, c in data.commands or {} do task.spawn(handle, c) end
	muted = {}
	for _, id in data.muted or {} do muted[id] = true end
	local okMute, muteErr = pcall(applyMutes)
	if not okMute then warn("[Sentinel] Mute error: " .. tostring(muteErr)) end
end

Players.PlayerAdded:Connect(function(p)
	queue({ type = "join", userId = p.UserId, name = p.Name })
	task.defer(sync)
end)
Players.PlayerRemoving:Connect(function(p)
	queue({ type = "leave", userId = p.UserId, name = p.Name })
end)
for _, p in Players:GetPlayers() do queue({ type = "join", userId = p.UserId, name = p.Name }) end

local rawKey = KEY
KEY = string.gsub(KEY, "[%[%]%s\"']", "") -- brackets, quotes and spaces never belong in a game code
if KEY == "" or string.find(KEY, "INPUT", 1, true) then
	warn("[Sentinel] No game code set. Open the Sentinel website, copy your game code and paste it over INPUT CODE HERE at the top of this script. Remove the [ ] brackets too, but keep the quotes.")
	return
end
if KEY ~= rawKey then print("[Sentinel] Removed extra [ ] or spaces from your game code. You can delete them from the script too.") end
task.spawn(setupChat)
task.spawn(function()
	while true do
		sync()
		task.wait(INTERVAL)
	end
end)
print("[Sentinel] Connected to " .. URL)
