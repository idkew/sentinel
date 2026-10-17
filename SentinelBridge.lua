--[[
	SentinelBridge - connects your Roblox game to the Sentinel website. Does REAL moderation:
	  * Ban / suspend  -> Roblox's own ban system (Players:BanAsync), applied to the whole experience
	  * Kick           -> Player:Kick()
	  * Mute           -> TextChatService (muted players' messages are dropped)
	  * Warn/announce  -> on-screen banner (a dark card with a timer line that runs round its border; smoothest with the optional SentinelClient script)
	  * Chat monitor   -> every chat message is sent to the panel (kept in memory there, never saved)
	  * Players can type in chat:   !modcall <message>   (report to moderators)   and   !attend   (join a session)
	  * Report button  -> the optional SentinelClient script adds a Report button (pick a player + details); this script receives it

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

local SCRIPT_VERSION = 19 -- raised whenever this script changes, so Sentinel can tell you when to update
local URL = "http://127.0.0.1:3000"
local KEY = "[INPUT CODE HERE]" -- paste your game code from the Sentinel website between the quotes
local INTERVAL = 4
local MODCALL_COOLDOWN = 30 -- seconds between ModCalls per player
local LOGO_IMAGE = 0 -- the Sentinel logo on in-game banners: upload logo-512.png in Studio (Asset Manager, Images) and put its image id here. 0 = no logo

local pending, muted, busy = {}, {}, false
local chatOff = {} -- muted players whose chat box is taken away (the rest of the muted can type, but nobody sees it)
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
local TextService = game:GetService("TextService")
local ReplicatedStorage = game:GetService("ReplicatedStorage")

------------------------------------------------------------------ notice card (the same block sits in SentinelBridge and SentinelClient)
-- A dark card with an icon, a title and a message. A coloured line runs round its border as the timer:
-- it starts at the top-centre, runs down both sides and meets at the bottom-centre.
local NOTICE_STYLES = {
	warn = { color = Color3.fromRGB(255, 159, 10), glyph = "!", title = "Warning" },
	red = { color = Color3.fromRGB(255, 69, 58), glyph = "!", title = "Notice" },
	blue = { color = Color3.fromRGB(10, 132, 255), glyph = "i", title = "Notice" },
	green = { color = Color3.fromRGB(48, 209, 88), glyph = "\u{2713}", title = "Done" },
}
-- the Sentinel logo on every banner. The game script puts its LOGO_IMAGE on ReplicatedStorage.SentinelNotice, so both scripts show the same one
local function noticeLogo()
	local ev = ReplicatedStorage:FindFirstChild("SentinelNotice")
	local id = ev and ev:GetAttribute("Logo")
	if typeof(id) == "string" then id = tonumber(string.match(id, "%d+")) end
	if typeof(id) == "number" and id > 0 then return "rbxassetid://" .. string.format("%d", id) end
	return nil
end
local RING_R, RING_T, RING_M = 18, 2, 8 -- corner radius, line thickness, spare room round the card so the line is never cut off

-- Which parts of the card's border are drawn once the timer is p (0 to 1) of the way round.
-- Works in card pixels and gives six rectangles (three per side); the border is only visible inside them.
-- Each part is cut with a straight line: vertical on the top and bottom, horizontal on the sides.
local function ringRects(W, H, r, p, pad)
	local hw = W / 2
	r = math.min(r, hw, H / 2)
	local q = math.pi * r / 4 -- half of a rounded corner
	local top, side = hw - r, H - 2 * r
	local L1, L2, L3 = top + q, q + side + q, q + (hw - r)
	local d = math.max(0, math.min(1, p)) * (L1 + L2 + L3)
	local OV = 2.5 -- the parts overlap a little so there is never a hairline gap between them
	local c45 = r * (1 - math.sqrt(0.5)) -- the 45 degree point of a corner sits this far in from the card's edge
	local x45, y45a, y45c = W - c45, c45, H - c45
	local right = {}
	if d > 0 then -- along the top, then round the first half of the top corner
		local x
		if d >= L1 then x = x45 + OV
		elseif d <= top then x = hw + d
		else x = (W - r) + r * math.sin((d - top) / r) end
		right[1] = { hw - 0.5, -pad, x, y45a + OV }
	end
	local s = d - L1
	if s > 0 then -- round the rest of that corner, down the side, into the first half of the bottom corner
		local y
		if s >= L2 then y = y45c + OV
		elseif s <= q then y = r - r * math.cos(math.pi / 4 + s / r)
		elseif s <= q + side then y = r + (s - q)
		else y = (H - r) + r * math.sin((s - q - side) / r) end
		right[2] = { x45 - OV, y45a - OV, W + pad, y }
	end
	s = s - L2
	if s > 0 then -- the rest of the bottom corner, then along the bottom to the middle
		local x
		if s <= q then x = (W - r) + r * math.cos(math.pi / 4 + s / r)
		else x = (W - r) - (s - q) end
		right[3] = { math.max(x, hw - 0.5), y45c - OV, W + pad, H + pad }
	end
	local out = {}
	for i = 1, 3 do
		local a = right[i]
		out[i] = a or false
		out[i + 3] = a and { W - a[3], a[2], W - a[1], a[4] } or false -- the left side is the mirror image
	end
	return out
end

local function buildNotice(gui, text, kind, title, fixed)
	local st = NOTICE_STYLES[kind] or NOTICE_STYLES.red
	local logo = noticeLogo()
	local R, T, M = RING_R, RING_T, RING_M
	local function make(class, props, parent)
		local o = Instance.new(class)
		for k, v in pairs(props) do o[k] = v end
		o.Parent = parent
		return o
	end

	local root = make("CanvasGroup", {
		Name = "Notice", AnchorPoint = Vector2.new(0.5, 0), Position = UDim2.new(0.5, 0, 0, -6),
		BackgroundTransparency = 1, GroupTransparency = 1, BorderSizePixel = 0,
	}, gui)
	if fixed then
		root.Size = UDim2.fromOffset(fixed.w + 2 * M, fixed.h + 2 * M)
	else
		root.Size = UDim2.new(0.92, 0, 0, 0)
		root.AutomaticSize = Enum.AutomaticSize.Y
		make("UISizeConstraint", { MinSize = Vector2.new(240, 0), MaxSize = Vector2.new(380 + 2 * M, math.huge) }, root)
	end
	make("UIPadding", { PaddingTop = UDim.new(0, M), PaddingBottom = UDim.new(0, M), PaddingLeft = UDim.new(0, M), PaddingRight = UDim.new(0, M) }, root)
	local scale = make("UIScale", { Scale = 0.95 }, root)

	local card = make("Frame", {
		Name = "Card", BackgroundColor3 = Color3.fromRGB(20, 20, 23), BackgroundTransparency = 0.03, BorderSizePixel = 0, Active = true,
	}, root)
	if fixed then
		card.Size = UDim2.fromOffset(fixed.w, fixed.h)
	else
		card.Size = UDim2.new(1, 0, 0, 0)
		card.AutomaticSize = Enum.AutomaticSize.Y
	end
	make("UICorner", { CornerRadius = UDim.new(0, R) }, card)
	make("UIStroke", { Color = Color3.new(1, 1, 1), Transparency = 0.9, Thickness = T }, card) -- the faint track the line runs along

	local inner = make("Frame", { Name = "Inner", BackgroundTransparency = 1, BorderSizePixel = 0 }, card)
	if fixed then
		inner.Size = UDim2.fromOffset(fixed.w, fixed.h)
	else
		inner.Size = UDim2.new(1, 0, 0, 0)
		inner.AutomaticSize = Enum.AutomaticSize.Y
	end
	make("UIPadding", { PaddingTop = UDim.new(0, 14), PaddingBottom = UDim.new(0, 14), PaddingLeft = UDim.new(0, 14), PaddingRight = UDim.new(0, logo and 40 or 18) }, inner)
	if logo then
		make("ImageLabel", { Name = "Logo", Image = logo, BackgroundTransparency = 1, BorderSizePixel = 0, Size = UDim2.fromOffset(20, 20), AnchorPoint = Vector2.new(1, 0), Position = UDim2.new(1, -14, 0, 14), ScaleType = Enum.ScaleType.Fit, ZIndex = 2 }, card)
	end
	local row = make("Frame", { BackgroundTransparency = 1, BorderSizePixel = 0, Size = UDim2.new(1, 0, 0, 0), AutomaticSize = Enum.AutomaticSize.Y }, inner)
	make("UIListLayout", { FillDirection = Enum.FillDirection.Horizontal, Padding = UDim.new(0, 12), SortOrder = Enum.SortOrder.LayoutOrder }, row)

	local icon = make("TextLabel", {
		Size = UDim2.fromOffset(30, 30), BackgroundColor3 = st.color, BackgroundTransparency = 0.82, BorderSizePixel = 0,
		TextColor3 = st.color, Font = Enum.Font.GothamBold, TextSize = 16, Text = st.glyph, LayoutOrder = 1,
	}, row)
	make("UICorner", { CornerRadius = UDim.new(1, 0) }, icon)

	local col = make("Frame", { BackgroundTransparency = 1, BorderSizePixel = 0, Size = UDim2.new(1, -42, 0, 0), AutomaticSize = Enum.AutomaticSize.Y, LayoutOrder = 2 }, row)
	make("UIListLayout", { Padding = UDim.new(0, 2), SortOrder = Enum.SortOrder.LayoutOrder }, col)
	make("TextLabel", {
		BackgroundTransparency = 1, Size = UDim2.new(1, 0, 0, 18), TextXAlignment = Enum.TextXAlignment.Left, TextTruncate = Enum.TextTruncate.AtEnd,
		TextColor3 = Color3.fromRGB(246, 246, 248), Font = Enum.Font.GothamBold, TextSize = 14, Text = title or st.title, LayoutOrder = 1,
	}, col)
	make("TextLabel", {
		BackgroundTransparency = 1, Size = UDim2.new(1, 0, 0, 0), AutomaticSize = Enum.AutomaticSize.Y,
		TextXAlignment = Enum.TextXAlignment.Left, TextYAlignment = Enum.TextYAlignment.Top, TextWrapped = true,
		TextColor3 = Color3.fromRGB(176, 176, 185), Font = Enum.Font.GothamMedium, TextSize = 13, Text = text, LayoutOrder = 2,
	}, col)

	-- the timer line: six clip windows, each showing part of a copy of the card's border
	local ring = make("Frame", { Name = "Timer", BackgroundTransparency = 1, BorderSizePixel = 0, Size = UDim2.new(), ZIndex = 5 }, card)
	local segs = {}
	for i = 1, 6 do
		local clip = make("Frame", { BackgroundTransparency = 1, BorderSizePixel = 0, ClipsDescendants = true, Visible = false, ZIndex = 5 }, ring)
		local line = make("Frame", { BackgroundTransparency = 1, BorderSizePixel = 0, ZIndex = 5 }, clip)
		make("UICorner", { CornerRadius = UDim.new(0, R) }, line)
		make("UIStroke", { Color = st.color, Thickness = T }, line)
		segs[i] = { clip = clip, line = line }
	end

	local n = { root = root, card = card }
	-- p runs from 0 (nothing drawn) to 1 (the whole border drawn)
	function n.progress(p)
		local W, H
		if fixed then
			W, H = fixed.w, fixed.h
		else
			local a = card.AbsoluteSize
			W, H = a.X / scale.Scale, a.Y / scale.Scale
			-- lock the height the first time: the line's bottom pieces reach past the card's edge, and an auto-sized card would grow to fit them every frame
			if card.AutomaticSize ~= Enum.AutomaticSize.None and H >= 2 * R + 4 then
				card.AutomaticSize, root.AutomaticSize = Enum.AutomaticSize.None, Enum.AutomaticSize.None
				card.Size = UDim2.new(1, 0, 0, H)
				root.Size = UDim2.new(0.92, 0, 0, H + 2 * M)
			end
		end
		if W < 2 * R + 4 or H < 2 * R + 4 then return end
		local rects = ringRects(W, H, R, p, T + 1)
		for i = 1, 6 do
			local seg, rc = segs[i], rects[i]
			if rc then
				local l, t = math.floor(rc[1]), math.floor(rc[2])
				seg.clip.Position = UDim2.fromOffset(l, t)
				seg.clip.Size = UDim2.fromOffset(math.max(0, rc[3] - l), math.max(0, rc[4] - t))
				seg.line.Size = UDim2.fromOffset(W, H)
				seg.line.Position = UDim2.fromOffset(-l, -t)
				seg.clip.Visible = true
			else
				seg.clip.Visible = false
			end
		end
	end
	local function play(inward, quick)
		local info = inward and TweenInfo.new(0.55, Enum.EasingStyle.Quint, Enum.EasingDirection.Out)
			or TweenInfo.new(quick and 0.16 or 0.3, Enum.EasingStyle.Quad, Enum.EasingDirection.In)
		local a = TweenService:Create(root, info, { Position = UDim2.new(0.5, 0, 0, inward and 10 or -4), GroupTransparency = inward and 0 or 1 })
		TweenService:Create(scale, info, { Scale = inward and 1 or 0.97 }):Play()
		a:Play()
		return a
	end
	function n.show() play(true) end
	function n.hide(quick) return play(false, quick) end
	return n
end

-- Players who also have the optional SentinelClient script get their banners drawn on their own screen, which is smooth at any frame rate.
-- Everyone else gets the same card built here on the server. It looks the same, but it animates a little less smoothly.
local noticeEvent = ReplicatedStorage:FindFirstChild("SentinelNotice")
if not noticeEvent then
	noticeEvent = Instance.new("RemoteEvent")
	noticeEvent.Name = "SentinelNotice"
	noticeEvent.Parent = ReplicatedStorage
end
noticeEvent:SetAttribute("Logo", LOGO_IMAGE)
local clientReady, clientVer, activeBanner = {}, {}, {}
noticeEvent.OnServerEvent:Connect(function(plr, msg, ver)
	if msg ~= "ready" then return end
	clientReady[plr] = true
	clientVer[plr] = (type(ver) == "number" and ver >= 1 and ver < 1000) and math.floor(ver) or 1
end)
local function newestClient() -- the newest SentinelClient version among the players here (0 when nobody has it), so the website can tell you when to update it
	local v = 0
	for _, x in pairs(clientVer) do
		if x > v then v = x end
	end
	return v
end

local function serverBanner(plr, pg, text, kind, title)
	if activeBanner[plr] then activeBanner[plr]:Destroy() end
	local okSize, size = pcall(function()
		return TextService:GetTextSize(text, 13, Enum.Font.GothamMedium, Vector2.new(340 - 14 - (noticeLogo() and 40 or 18) - 42, 1000))
	end)
	local bodyH = okSize and size.Y or 16 * math.ceil(#text / 36)
	local gui = Instance.new("ScreenGui")
	gui.Name, gui.ResetOnSpawn, gui.DisplayOrder, gui.IgnoreGuiInset = "SentinelBanner", false, 200, true
	gui.Parent = pg
	activeBanner[plr] = gui
	local n = buildNotice(gui, text, kind, title, { w = 340, h = 28 + math.max(30, 20 + bodyH) })
	n.show()
	task.spawn(function()
		local show = math.max(5, math.min(9, 4.5 + #text / 25))
		task.wait(0.4) -- let the card finish sliding in before the line starts
		local start = os.clock()
		while activeBanner[plr] == gui and gui.Parent do
			local p = (os.clock() - start) / show
			if p >= 1 then break end
			n.progress(p)
			task.wait(0.05)
		end
		if activeBanner[plr] ~= gui or not gui.Parent then return end
		n.progress(1)
		n.hide()
		task.wait(0.4)
		gui:Destroy()
		if activeBanner[plr] == gui then activeBanner[plr] = nil end
	end)
end

local function bannerNow(plr, text, kind, title)
	local pg = plr:FindFirstChild("PlayerGui")
	if not pg then return end
	text = string.sub(tostring(text), 1, 300)
	if title ~= nil then title = string.sub(tostring(title), 1, 40) end
	if clientReady[plr] then
		noticeEvent:FireClient(plr, text, kind, title)
	else
		serverBanner(plr, pg, text, kind, title)
	end
end

-- a banner must never be able to break anything else (like hiding a !command from chat), so errors are caught and printed instead
local function banner(plr, text, kind, title)
	local ok, err = pcall(bannerNow, plr, text, kind, title)
	if not ok then warn("[Sentinel] Could not show a banner to " .. plr.Name .. ": " .. tostring(err)) end
end

------------------------------------------------------------------ chat: monitor, commands, mute
-- returns true when the message was a panel command (so it can be hidden from public chat)
local diagText -- filled in below, once the mute code exists
local function onChat(userId, text)
	local plr = Players:GetPlayerByUserId(userId)
	if not plr then return false end
	text = string.sub(text, 1, 200)
	local command, rest = string.match(text, "^!(%a+)%s*(.*)$")
	command = command and string.lower(command)
	if command == "sentinel" then
		print("[Sentinel] !sentinel from " .. plr.Name .. " (player script: " .. (clientReady[plr] and ("version " .. tostring(clientVer[plr])) or "not seen") .. ")")
		local okDiag, diag = pcall(diagText, plr)
		banner(plr, okDiag and diag or ("The check failed: " .. tostring(diag)), "blue", "Sentinel check")
		return true
	elseif command == "attend" then
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

-- the Report button in SentinelClient sends here. The button can name a player, so staff see who was reported.
local reportEvent = ReplicatedStorage:FindFirstChild("SentinelReport")
if not reportEvent then
	reportEvent = Instance.new("RemoteEvent")
	reportEvent.Name = "SentinelReport"
	reportEvent.Parent = ReplicatedStorage
end
reportEvent.OnServerEvent:Connect(function(plr, targetUserId, text)
	if typeof(text) ~= "string" then text = "" end
	text = string.sub(text, 1, 200)
	local target = typeof(targetUserId) == "number" and Players:GetPlayerByUserId(targetUserId) or nil
	if target == plr then target = nil end
	if text == "" and not target then return end
	if os.clock() - (lastCall[plr.UserId] or -999) < MODCALL_COOLDOWN then
		banner(plr, "Please wait a moment before sending another report.", "red", "Slow down")
		return
	end
	lastCall[plr.UserId] = os.clock()
	queue({ type = "modcall", userId = plr.UserId, name = plr.Name, text = text, target = target and { userId = target.UserId, name = target.Name } or nil })
end)

local mutedNote = {}
-- every other chat channel (team chat, quick words and so on) also refuses a muted player's messages
local function guardChannel(ch)
	if not ch:IsA("TextChannel") or ch.Name == "RBXGeneral" then return end
	ch.ShouldDeliverCallback = function(message, _target)
		local src = message.TextSource
		if src and muted[src.UserId] then return false end
		return true
	end
end
local function setupChat()
	if TextChatService.ChatVersion == Enum.ChatVersion.TextChatService then
		local channels = TextChatService:WaitForChild("TextChannels", 30)
		local ch = channels and channels:WaitForChild("RBXGeneral", 30)
		if not ch then
			warn("[Sentinel] RBXGeneral chat channel not found. Chat monitor, mutes and !commands won't work.")
			return
		end
		-- a problem with another channel must never stop the main chat hook below from being set up
		local function guard(c)
			local ok, err = pcall(guardChannel, c)
			if not ok then warn("[Sentinel] Could not guard chat channel " .. c.Name .. ": " .. tostring(err)) end
		end
		for _, other in channels:GetChildren() do guard(other) end
		channels.ChildAdded:Connect(guard)
		-- Runs on the server for every message (once per recipient, so ids are de-duplicated)
		ch.ShouldDeliverCallback = function(message, _target)
			local src = message.TextSource
			if not src then return true end
			if muted[src.UserId] then
				-- a muted player can still ask !sentinel what state they are in (nobody else sees it)
				local cmdName = string.lower(string.match(message.Text or "", "^!(%a+)") or "")
				if cmdName == "sentinel" then
					if not seen[message.MessageId] then
						seen[message.MessageId] = true
						onChat(src.UserId, message.Text)
					end
					return false
				end
				-- tell them why, at most every 8 seconds
				if os.clock() - (mutedNote[src.UserId] or -999) > 8 then
					mutedNote[src.UserId] = os.clock()
					local mp = Players:GetPlayerByUserId(src.UserId)
					if mp then
						if chatOff[src.UserId] then
							banner(mp, "You are muted and can't chat right now.", "red", "Muted")
						else
							banner(mp, "You are muted. You can still type, but nobody can see your messages.", "red", "Muted")
						end
					end
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

local lastMuteErr, lastMuteSig = "", nil
-- takes chat privileges away from muted players (and gives them back when the mute ends).
-- CanSend = false on the player's TextSource is what Roblox itself uses to stop a player chatting.
local function applyMutes()
	-- lets the optional Sentinel client script hide a muted player's chat bar
	for _, p in Players:GetPlayers() do
		local isOff = chatOff[p.UserId] == true
		if p:GetAttribute("SentinelMuted") ~= (isOff or nil) then p:SetAttribute("SentinelMuted", isOff or nil) end
	end
	if TextChatService.ChatVersion ~= Enum.ChatVersion.TextChatService then
		lastMuteErr = next(muted) and "legacy chat: mutes need TextChatService" or ""
		return
	end
	local channels = TextChatService:FindFirstChild("TextChannels")
	if not channels then lastMuteErr = "no TextChannels"; return end
	local missing, failed
	for _, p in Players:GetPlayers() do
		local isMuted = chatOff[p.UserId] == true -- only players whose chat box is taken away need their chat source switched off
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
	local nowMuted = {}
	for id in muted do table.insert(nowMuted, tostring(id)) end
	table.sort(nowMuted)
	local sig = table.concat(nowMuted, ",")
	if sig ~= lastMuteSig then
		lastMuteSig = sig
		print("[Sentinel] Muted players now: " .. (sig == "" and "none" or sig))
	end
	lastMuteErr = failed and ("could not switch off chat for " .. failed) or (missing and ("no chat channel yet for " .. missing) or "")
end

local function chatMode()
	if TextChatService.ChatVersion ~= Enum.ChatVersion.TextChatService then return "legacy" end
	local channels = TextChatService:FindFirstChild("TextChannels")
	if not (channels and channels:FindFirstChild("RBXGeneral")) then return "nochannel" end
	return "text"
end

diagText = function(plr)
	local mode = chatMode()
	local n, mine, canSend = 0, 0, "n/a"
	local channels = TextChatService:FindFirstChild("TextChannels")
	if channels then
		for _, ch in channels:GetChildren() do
			if ch:IsA("TextChannel") then
				for _, src in ch:GetChildren() do
					if src:IsA("TextSource") and src.UserId == plr.UserId then
						mine += 1
						canSend = tostring(src.CanSend)
					end
				end
			end
		end
	end
	local off = 0
	for _ in muted do n += 1 end
	for _ in chatOff do off += 1 end
	local me = muted[plr.UserId] and (chatOff[plr.UserId] and "YOU ARE MUTED (chat box removed). " or "YOU ARE MUTED (can type, nobody sees it). ") or "You are not muted. "
	return me .. string.format("Script v%d. Chat: %s. Your chat sources: %d (can send: %s). Muted players now: %d (chat box removed for %d).%s",
		SCRIPT_VERSION, mode, mine, canSend, n, off, lastMuteErr ~= "" and (" Problem: " .. lastMuteErr) or "")
end

-- a player who joins (or a channel that appears) while muted is silenced straight away
local function watchChannel(ch)
	if not ch:IsA("TextChannel") then return end
	ch.ChildAdded:Connect(function(src)
		if src:IsA("TextSource") and chatOff[src.UserId] then src.CanSend = false end
	end)
end
task.spawn(function()
	local channels = TextChatService:WaitForChild("TextChannels", 30)
	if not channels then return end
	for _, ch in channels:GetChildren() do watchChannel(ch) end
	channels.ChildAdded:Connect(watchChannel)
end)

------------------------------------------------------------------ commands from the panel
-- Roblox runs the ban screen message through its text filter and shows ##### for anything it dislikes, so check the wording first
local function survivesFilter(text, userId)
	local ok, res = pcall(function()
		return TextService:FilterStringAsync(text, userId):GetNonChatStringForUserAsync(userId)
	end)
	if ok and typeof(res) == "string" then return not string.find(res, "#", 1, true) end
	return true -- could not check, so go ahead with it
end
local function doBan(userId, reason, seconds, why)
	if not survivesFilter(reason, userId) then
		for _, text in ipairs({ "You are banned from this experience. Reason: " .. tostring(why or "No reason given") .. ".", "You are banned from this experience." }) do
			reason = text
			if survivesFilter(text, userId) then break end
		end
	end
	local ok, err = pcall(Players.BanAsync, Players, {
		UserIds = { userId }, Duration = seconds, DisplayReason = reason,
		PrivateReason = "Banned from web panel", ApplyToUniverse = true,
	})
	if ok then print("[Sentinel] Roblox ban applied to user " .. tostring(userId)) end
	if not ok then
		warn("[Sentinel] BanAsync failed (" .. tostring(err) .. "). Kicking instead; the panel keeps re-kicking while the ban is active.")
		local plr = Players:GetPlayerByUserId(userId)
		if plr then plr:Kick(reason) end
	end
end

local function handle(c)
	local plr = c.userId and Players:GetPlayerByUserId(c.userId)
	if c.type == "kick" then
		if plr then plr:Kick(tostring(c.display or ("[Sentinel] " .. tostring(c.reason)))) end
	elseif c.type == "ban" then
		doBan(c.userId, tostring(c.display or c.reason), c.seconds, c.reason)
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
		Body = HttpService:JSONEncode({ key = KEY, jobId = game.JobId, placeId = game.PlaceId, players = list, events = sent, scriptV = SCRIPT_VERSION, clientV = newestClient(), chat = chatMode(), muteErr = lastMuteErr }),
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
	chatOff = {}
	if data.muteHide then
		for _, id in data.muteHide do chatOff[id] = true end
	else
		for id in muted do chatOff[id] = true end -- an older panel: every mute takes the chat box away
	end
	local okMute, muteErr = pcall(applyMutes)
	if not okMute then warn("[Sentinel] Mute error: " .. tostring(muteErr)) end
end

Players.PlayerAdded:Connect(function(p)
	queue({ type = "join", userId = p.UserId, name = p.Name })
	task.defer(sync)
end)
Players.PlayerRemoving:Connect(function(p)
	clientReady[p], clientVer[p], activeBanner[p] = nil, nil, nil
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
