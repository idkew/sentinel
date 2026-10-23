--[[
	SentinelBridge - connects your Roblox game to the Sentinel website. Does REAL moderation:
	  * Ban / suspend  -> Roblox's own ban system (Players:BanAsync), applied to the whole experience
	  * Kick           -> Player:Kick()
	  * Mute           -> TextChatService (muted players' messages are dropped)
	  * Warn/announce  -> on-screen banner (a dark card with a timer line that runs round its border; smoothest with the optional SentinelClient script)
	  * Chat monitor   -> every chat message is sent to the panel (kept in memory there, never saved)
	  * Players can type in chat:   !modcall <message>   (report to moderators),   !attend   (join a session)
	                                and   !rejoin   (move to a fresh server; the owner can switch it off on the website)
	  * Replays        -> when the owner turns them on, the last 5 minutes of player positions, deaths, joins, leaves and chat
	                      are kept in this server's memory and uploaded only when something happens (a report, a moderation
	                      action, a chat alert, an exploit flag, or staff typing !replay), with 30 more seconds after it.
	                      If nothing happens, nothing leaves the server. Staff watch them on the website: opening a replay
	                      makes the server upload what it has straight away, and recording carries on.
	                      An outline of the map (the 300 largest anchored parts, as plain rectangles) is sent with each replay.
	                      If the server closes while a replay is recording, what was recorded so far is uploaded straight away.
	  * Exploit flags  -> speed, teleport and fly are measured here on the server and sent to Sentinel for staff to review.
	                      Nothing ever happens to a player automatically because of a flag.

	EXPLOIT FLAGS AND YOUR GAME
	  Teleports your own server scripts make (setting the character's CFrame, or PivotTo) are ignored automatically.
	  Game mechanics that make players move very fast or stay in the air (gliders, jetpacks, grappling hooks,
	  launch pads) need an exemption while they run, or they can be flagged:
	      player:SetAttribute("SentinelExempt", workspace:GetServerTimeNow() + 10) -- exempt for the next 10 seconds
	      player:SetAttribute("SentinelExempt", true)                              -- always exempt (for example admins)
	  Players standing on moving or unanchored parts, seated, climbing or swimming are never checked for speed or fly.
	  Admin fly and noclip commands are checked like any other movement, so exempt staff who use them.
	  If your game sets PlatformStand from a LocalScript (some gliders and vehicles do), exempt those players too.
	  To see what the checks measure, set DEBUG_FLAGS = true below and watch the Developer Console (Server tab).
	  * Report button  -> the optional SentinelClient script adds a Report button (pick a player + details); this script receives it
	  * Staff bar      -> staff in the ranks the owner picks get a bar at the bottom of the screen (SentinelClient 7 draws it).
	                      Their requests come here, and this script asks Sentinel with the game key and the Roblox ID that
	                      Roblox gives this server. The player's screen never sees the key, and Sentinel checks their rank every time.

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

local SCRIPT_VERSION = 31 -- raised whenever this script changes, so Sentinel can tell you when to update
local URL = "http://127.0.0.1:3000"
local KEY = "[INPUT CODE HERE]" -- paste your game code from the Sentinel website between the quotes
local INTERVAL = 4
local MODCALL_COOLDOWN = 30 -- seconds between ModCalls per player
local DEBUG_FLAGS = false -- true prints what the exploit checks measure for every player, once a second (Developer Console, Server). Turn it off again after testing
local LOGO_IMAGE = 0 -- the Sentinel logo on in-game banners: upload logo-512.png in Studio (Asset Manager, Images) and put its image id here. 0 = no logo

local pending, muted, busy = {}, {}, false
local chatOff = {} -- muted players whose chat box is taken away (the rest of the muted can type, but nobody sees it)
local seen, hidden, seenCount, lastCall = {}, {}, 0, {}
local lastRejoin, rejoining = {}, {} -- !rejoin: last use per player, and players being moved
local rpEv, rpTrigger -- replays: set in the replays section further down (chat, deaths and exploit flags call them)
local COLORS = {
	red = Color3.fromRGB(229, 56, 79),
	blue = Color3.fromRGB(47, 91, 255),
	green = Color3.fromRGB(20, 164, 77),
}

local syncSoon -- set further down: sends chat and reports right away instead of at the next check-in
local lastSent = 0

local function queue(ev)
	table.insert(pending, ev)
	if #pending > 300 then table.remove(pending, 1) end -- never grow forever if the panel is down
end

local TweenService = game:GetService("TweenService")
local TextService = game:GetService("TextService")
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local TeleportService = game:GetService("TeleportService")
local RunService = game:GetService("RunService")

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

local function buildNotice(gui, text, kind, title, fixed, button) -- button: optional label for one button under the message, such as "I understand"
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
	local btn
	if button then
		local hold = make("Frame", { BackgroundTransparency = 1, BorderSizePixel = 0, Size = UDim2.new(1, 0, 0, 40), LayoutOrder = 3 }, col)
		btn = make("TextButton", {
			Name = "Button", Size = UDim2.fromOffset(130, 30), Position = UDim2.fromOffset(0, 10), BackgroundColor3 = st.color, BorderSizePixel = 0, AutoButtonColor = true,
			TextColor3 = Color3.fromRGB(20, 20, 23), Font = Enum.Font.GothamBold, TextSize = 13, Text = button,
		}, hold)
		make("UICorner", { CornerRadius = UDim.new(0, 8) }, btn)
	end

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

	local n = { root = root, card = card, button = btn }
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
local clientReady, clientVer, activeBanner, ackWant, devSent = {}, {}, {}, {}, {} -- ackWant: warnings each player was asked to acknowledge; devSent: device settings already sent this session
local DEV_KEYS = { ms = true, vol = true, q = true, cm = true, mm = true, tc = true, tm = true, inv = true, gs = true, full = true, tz = true, vw = true, vh = true, inp = true }
noticeEvent.OnServerEvent:Connect(function(plr, msg, ver)
	if msg == "ack" then -- the player pressed "I understand" on a warning. Only a warning that was sent to them counts
		local w = ackWant[plr]
		if type(ver) == "string" and w and w[ver] then
			w[ver] = nil
			queue({ type = "ack", userId = plr.UserId, name = plr.Name, entry = ver })
			if syncSoon then syncSoon() end
		end
		return
	end
	if msg == "dev" then -- Roblox settings saved on the player's computer or phone, once per session (linked accounts). The website keeps only a one-way code of them
		if devSent[plr] or type(ver) ~= "table" then return end
		devSent[plr] = true
		local fp = {}
		for k, v in pairs(ver) do
			if DEV_KEYS[k] and type(v) == "number" and v == v and math.abs(v) < 1e7 then fp[k] = math.floor(v) end
		end
		if type(ver.loc) == "string" and #ver.loc <= 20 and not ver.loc:find("[^%w%-_]") then fp.loc = ver.loc end
		if type(ver.now) == "number" and ver.now == ver.now then -- how far the device clock is off, minus half the round trip
			local okP, ping = pcall(function() return plr:GetNetworkPing() end)
			fp.sk = math.floor(ver.now - DateTime.now().UnixTimestampMillis + (okP and ping or 0) * 1000)
		end
		queue({ type = "dev", userId = plr.UserId, name = plr.Name, fp = fp })
		if syncSoon then syncSoon() end
		return
	end
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

local function bannerNow(plr, text, kind, title, ack)
	local pg = plr:FindFirstChild("PlayerGui")
	if not pg then return end
	text = string.sub(tostring(text), 1, 300)
	if title ~= nil then title = string.sub(tostring(title), 1, 40) end
	if clientReady[plr] and ack and (clientVer[plr] or 0) >= 5 then -- player script 5 or newer shows an "I understand" button; nothing is ever blocked
		ackWant[plr] = ackWant[plr] or {}
		ackWant[plr][ack] = true
		noticeEvent:FireClient(plr, text, kind, title, { ack = ack })
	elseif clientReady[plr] then
		noticeEvent:FireClient(plr, text, kind, title)
	else
		serverBanner(plr, pg, text, kind, title)
	end
end

-- a banner must never be able to break anything else (like hiding a !command from chat), so errors are caught and printed instead
local function banner(plr, text, kind, title, ack)
	local ok, err = pcall(bannerNow, plr, text, kind, title, ack)
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
	elseif command == "replay" then -- staff only: the website checks who is staff and answers
		queue({ type = "replay", userId = userId, name = plr.Name })
		if syncSoon then syncSoon() end
		return true
	elseif command == "rejoin" then
		if os.clock() - (lastRejoin[userId] or -999) < 30 then
			banner(plr, "You can use !rejoin again in a few seconds.", "red", "Slow down")
		elseif RunService:IsStudio() then
			banner(plr, "!rejoin doesn't work in Studio, because Roblox can't move players there. Try it in a live server.", "blue", "Rejoin")
		elseif game.PrivateServerId ~= "" then
			banner(plr, "!rejoin only works in public servers. Leave and join again instead.", "blue", "Rejoin")
		else
			lastRejoin[userId] = os.clock()
			queue({ type = "rejoin", userId = userId, name = plr.Name })
			banner(plr, "Finding you a new server...", "blue", "Rejoin")
			if syncSoon then syncSoon() end
		end
		return true
	elseif command == "modcall" then
		if os.clock() - (lastCall[userId] or -999) < MODCALL_COOLDOWN then
			banner(plr, "Please wait a moment before sending another report.", "red", "Slow down")
		else
			lastCall[userId] = os.clock()
			queue({ type = "modcall", userId = userId, name = plr.Name, text = rest })
			if syncSoon then syncSoon() end
		end
		return true
	end
	queue({ type = "chat", userId = userId, name = plr.Name, text = text })
	rpEv("chat", userId, text)
	if syncSoon then syncSoon() end
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

------------------------------------------------------------------ the in-game staff bar
local barList, barLast = {}, {} -- who gets the bar in this server (from Sentinel on every check-in), and each one's last request
local BAR_OPS = { home = true, players = true, history = true, act = true, reports = true, report = true, announce = true, lockdown = true, replay = true }
local function barArgs(a) -- only the fields the bar uses, with the right types and lengths
	if type(a) ~= "table" then a = {} end
	local out = {}
	for _, k in ipairs({ "target", "minutes", "id", "mins" }) do
		local v = a[k]
		if type(v) == "number" and v == v and v >= 0 and v < 1e15 then out[k] = math.floor(v) end
	end
	for k, n in pairs({ action = 10, reason = 300, text = 200, note = 200, ["do"] = 10 }) do
		if type(a[k]) == "string" then out[k] = string.sub(a[k], 1, n) end
	end
	if a.all == true then out.all = true end
	if a.on == true then out.on = true end
	return out
end
local function barFilter(plr, list, field) -- Roblox's rules: text other people wrote goes through the text filter before it is shown in game
	local done = {}
	for i, x in ipairs(list) do
		local t = type(x) == "table" and x[field]
		if type(t) ~= "string" or t == "" then
			done[i] = true
		else
			task.spawn(function()
				local ok, res = pcall(function()
					return TextService:FilterStringAsync(t, plr.UserId):GetNonChatStringForUserAsync(plr.UserId)
				end)
				x[field] = ok and type(res) == "string" and res or ""
				done[i] = true
			end)
		end
	end
	local t0 = os.clock()
	while os.clock() - t0 < 6 do
		local all = true
		for i = 1, #list do if not done[i] then all = false end end
		if all then return end
		task.wait(0.05)
	end
	for i, x in ipairs(list) do if not done[i] then x[field] = "" end end -- the filter was too slow: hide it rather than show it unfiltered
end
local function barAsk(plr, op, a) -- returns what the bar shows: { ok = true, data = ... } or { ok = false, error = "..." }
	if not barList[plr.UserId] then return { ok = false, error = "The staff bar is not turned on for you." } end
	if type(op) ~= "string" or not BAR_OPS[op] then return { ok = false, error = "Unknown request." } end
	if os.clock() - (barLast[plr.UserId] or -999) < 0.5 then return { ok = false, error = "Slow down a little." } end
	barLast[plr.UserId] = os.clock()
	local body = barArgs(a)
	body.key, body.jobId, body.userId, body.op = KEY, game.JobId, plr.UserId, op
	local ok, res = pcall(HttpService.RequestAsync, HttpService, {
		Url = URL .. "/game/staff", Method = "POST", Headers = { ["Content-Type"] = "application/json" }, Body = HttpService:JSONEncode(body),
	})
	if not ok then return { ok = false, error = "Sentinel can't be reached right now. Try again in a minute." } end
	local okJ, data = pcall(HttpService.JSONDecode, HttpService, res.Body)
	if not okJ or type(data) ~= "table" then data = {} end
	if not res.Success then return { ok = false, error = type(data.error) == "string" and data.error or "Something went wrong. Try again." } end
	if op == "reports" and type(data.reports) == "table" then barFilter(plr, data.reports, "text") end
	if op == "history" and type(data.entries) == "table" then barFilter(plr, data.entries, "reason") end
	return { ok = true, data = data }
end
local staffFn = ReplicatedStorage:FindFirstChild("SentinelStaff")
if not staffFn then
	staffFn = Instance.new("RemoteFunction")
	staffFn.Name = "SentinelStaff"
	staffFn.Parent = ReplicatedStorage
end
staffFn.OnServerInvoke = barAsk
local function applyBar(list) -- the player script shows the bar while SentinelStaff is set on the player
	barList = {}
	for _, id in ipairs(list) do
		if type(id) == "number" then barList[id] = true end
	end
	for _, p in ipairs(Players:GetPlayers()) do
		local want = barList[p.UserId] or nil
		if p:GetAttribute("SentinelStaff") ~= want then p:SetAttribute("SentinelStaff", want) end
	end
end

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
				-- a muted player can still ask !sentinel what state they are in, or !rejoin (the mute follows them; nobody else sees it)
				local cmdName = string.lower(string.match(message.Text or "", "^!(%a+)") or "")
				if cmdName == "sentinel" or cmdName == "rejoin" then
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
local function doBan(userId, reason, seconds, why, alts)
	if not survivesFilter(reason, userId) then
		for _, text in ipairs({ "You are banned from this experience. Reason: " .. tostring(why or "No reason given") .. ".", "You are banned from this experience." }) do
			reason = text
			if survivesFilter(text, userId) then break end
		end
	end
	local ok, err = pcall(Players.BanAsync, Players, {
		UserIds = { userId }, Duration = seconds, DisplayReason = reason,
		PrivateReason = "Banned from web panel", ApplyToUniverse = true,
		ExcludeAltAccounts = (alts == false), -- Roblox also bans the accounts it links to this player, unless staff turned that off for this ban
	})
	if ok then print("[Sentinel] Roblox ban applied to user " .. tostring(userId)) end
	if not ok then
		warn("[Sentinel] BanAsync failed (" .. tostring(err) .. "). Kicking instead; the panel keeps re-kicking while the ban is active.")
		local plr = Players:GetPlayerByUserId(userId)
		if plr then plr:Kick(reason) end
	end
end

local restarting, bouncing = false, {} -- bouncing: players only passing through this server after a Sentinel restart
local function restartMove(list) -- everyone goes to a private holding server first, which sends them on to a normal server once this one is gone
	if #list == 0 then return end
	local opts = Instance.new("TeleportOptions")
	opts.ShouldReserveServer = true
	opts:SetTeleportData({ sentinelRestart = true })
	local ok, err = pcall(function() TeleportService:TeleportAsync(game.PlaceId, list, opts) end)
	if not ok then warn("[Sentinel] Restart could not move players: " .. tostring(err)) end
end
local function restartServer(msg)
	if restarting then return end
	restarting = true
	for _, p in Players:GetPlayers() do banner(p, msg, "blue", "Server restarting") end
	if RunService:IsStudio() then
		warn("[Sentinel] Restart can't move players in Studio. Try it in a live server.")
		restarting = false
		return
	end
	print("[Sentinel] Restarting this server: moving everyone to a new one")
	task.wait(5)
	restartMove(Players:GetPlayers())
	task.wait(25) -- anyone the move missed is removed, so this server can close
	for _, p in Players:GetPlayers() do p:Kick("This server restarted. Rejoin to play in a new one.") end
end
local function passingThrough(p) -- arrived in the holding server from a Sentinel restart
	if game.PrivateServerId == "" or game.PrivateServerOwnerId ~= 0 then return false end
	local ok, d = pcall(function() return p:GetJoinData() end)
	return ok and type(d) == "table" and type(d.TeleportData) == "table" and d.TeleportData.sentinelRestart == true
end

------------------------------------------------------------------ exploit flags: speed, teleport, fly (measured on the server only)
local XD = { on = true, lvl = "low" } -- switched and tuned from the website at every check-in
local XL = {
	low = { sm = 1.8, sa = 8, tp = 120, fly = 8 },
	medium = { sm = 1.5, sa = 6, tp = 80, fly = 6 },
	high = { sm = 1.3, sa = 4, tp = 60, fly = 4 },
}
local XCOOL, XHOUR = 120, 6 -- one flag per player and type every 2 minutes, at most 6 per player an hour
local xs = {} -- per player: recent samples, hits, game moves
local cfOK, cfWarned = true, false -- false once the "moved by the game" signal looks unreliable in this server
local S = Enum.HumanoidStateType
local XDEVICE = { [S.PlatformStanding] = true } -- states the player's own device reports. Fly and noclip tools use them, so they are still checked (PlatformStand set by a server script is skipped)
local XSKIP = { [S.Seated] = "seated", [S.Climbing] = "climbing", [S.Swimming] = "swimming", [S.Ragdoll] = "ragdoll", [S.FallingDown] = "falling down", [S.Physics] = "physics", [S.PlatformStanding] = "platform stand", [S.Dead] = "dead" }
local rayParams = RaycastParams.new()
rayParams.FilterType = Enum.RaycastFilterType.Exclude
local function xInt(v) return { math.floor(v.X + 0.5), math.floor(v.Y + 0.5), math.floor(v.Z + 0.5) } end
local function xExempt(p)
	local v = p:GetAttribute("SentinelExempt")
	if v == true then return true end
	return type(v) == "number" and v > workspace:GetServerTimeNow()
end
local function xChar(p, char) -- a new character: start fresh, and listen for moves the game makes
	local st = xs[p]
	if not st then return end
	st.spawn, st.samples, st.hits, st.air = os.clock(), {}, { speed = {}, teleport = {} }, nil
	local hum = char:WaitForChild("Humanoid", 10)
	if hum then hum.Died:Connect(function() rpEv("death", p.UserId) end) end
	local hrp = char:WaitForChild("HumanoidRootPart", 10)
	if not hrp or xs[p] ~= st then return end
	hrp:GetPropertyChangedSignal("CFrame"):Connect(function() -- fires when a server script sets the CFrame (teleports, PivotTo), not for normal movement
		st.moved = os.clock()
		st.cfN = st.cfN + 1
	end)
end
local function xWatch(p)
	xs[p] = { spawn = os.clock(), samples = {}, hits = { speed = {}, teleport = {} }, last = {}, sent = {}, cfN = 0, cfWin = {} }
	p.CharacterAdded:Connect(function(char) xChar(p, char) end)
	if p.Character then task.spawn(xChar, p, p.Character) end
end
local function xFlag(p, st, kind, ev)
	local now = os.clock()
	if now - (st.last[kind] or -1e9) < XCOOL then return end
	local recent = 0
	for _, t in st.sent do if now - t < 3600 then recent += 1 end end
	if recent >= XHOUR then return end
	st.last[kind] = now
	table.insert(st.sent, now)
	if #st.sent > 20 then table.remove(st.sent, 1) end
	ev.at = os.time()
	queue({ type = "xflag", userId = p.UserId, name = p.Name, kind = kind, ev = ev })
	rpTrigger({ k = "xflag", uid = p.UserId, x = kind })
	if DEBUG_FLAGS then print("[Sentinel debug] FLAG " .. kind .. " for " .. p.Name) end
end
local function xHits(list, now, window)
	local keep = {}
	for _, t in list do if now - t <= window then table.insert(keep, t) end end
	return keep
end
local function xSample(p, now)
	local st = xs[p]
	local char = p.Character
	local hum = char and char:FindFirstChildOfClass("Humanoid")
	local hrp = char and char:FindFirstChild("HumanoidRootPart")
	if not (st and hum and hrp) then return end
	local L = XL[XD.lvl] or XL.low
	local state = hum:GetState()
	local why = nil
	if now - (st.spawn or 0) < 10 then why = "just spawned"
	elseif hum.Health <= 0 then why = "dead"
	elseif xExempt(p) then why = "exempt"
	elseif hum.SeatPart or hum.Sit then why = "seated"
	elseif hum.PlatformStand then why = "platform stand"
	elseif XSKIP[state] and not XDEVICE[state] then why = XSKIP[state]
	elseif hrp.AssemblyRootPart ~= hrp then why = "attached to something"
	elseif cfOK and now - (st.moved or -1e9) < 3 then why = "moved by the game"
	end
	rayParams.FilterDescendantsInstances = { char }
	local hit = workspace:Raycast(hrp.Position, Vector3.new(0, -6, 0), rayParams) -- ground within about 3 studs of the feet
	local part = hit and hit.Instance
	local moving = part ~= nil and part:IsA("BasePart") and (not part.Anchored or part.AssemblyLinearVelocity.Magnitude > 1)
	local prev = st.samples[#st.samples]
	-- jumping, falling or knocked back: the height changes. Hovering in the air at one height is not excused (fly tools)
	local free = (state == S.Freefall or state == S.Jumping) and prev ~= nil and math.abs(hrp.Position.Y - prev.p.Y) > 1
	local smp = { t = now, p = hrp.Position, ws = hum.WalkSpeed, skip = why, ground = hit ~= nil, moving = moving, free = free, cf = st.cfN }
	table.insert(st.samples, smp)
	if #st.samples > 12 then table.remove(st.samples, 1) end
	local hd, dt = 0, 1
	if prev then
		dt = math.max(0.2, now - prev.t)
		local d = smp.p - prev.p
		hd = Vector3.new(d.X, 0, d.Z).Magnitude / dt
	end
	-- is the "moved by the game" signal trustworthy here? While a player just walks it should almost never fire
	if cfOK and prev and (not why or why == "moved by the game") and not free and hd > 2 then
		table.insert(st.cfWin, smp.cf ~= prev.cf)
		if #st.cfWin > 30 then table.remove(st.cfWin, 1) end
		local n = 0
		for _, fired in st.cfWin do if fired then n += 1 end end
		if #st.cfWin >= 30 and n > 24 then
			cfOK = false
			if not cfWarned then
				cfWarned = true
				warn("[Sentinel] The game-teleport signal fires all the time in this server, so it is no longer used here. Teleport checks now use distance and SentinelExempt only.")
			end
		end
	end
	local reason = why
	if XD.on and not why and prev and not prev.skip then
		local d = smp.p - prev.p
		local flat = Vector3.new(d.X, 0, d.Z).Magnitude
		local up = math.max(0, d.Y) -- falling is never a teleport
		local tpLimit = math.max(L.tp, math.max(prev.ws, smp.ws) * 3 * dt)
		if math.max(flat, up) > tpLimit then -- teleport
			st.hits.teleport = xHits(st.hits.teleport, now, 30)
			table.insert(st.hits.teleport, now)
			if #st.hits.teleport >= 2 then
				st.hits.teleport = {}
				xFlag(p, st, "teleport", { dist = math.floor(math.max(flat, up) + 0.5), lim = math.floor(tpLimit + 0.5), from = xInt(prev.p), to = xInt(smp.p) })
			end
		elseif moving or prev.moving then
			reason = "on a moving part"
		elseif not free and not prev.free then -- speed, on the ground only
			local limit = math.max(prev.ws, smp.ws) * L.sm + L.sa
			if hd > limit then
				st.hits.speed = xHits(st.hits.speed, now, 10)
				table.insert(st.hits.speed, now)
				if #st.hits.speed >= 3 then
					st.hits.speed = {}
					xFlag(p, st, "speed", { v = math.floor(hd + 0.5), lim = math.floor(limit + 0.5), ws = math.floor(smp.ws + 0.5), from = xInt(prev.p), to = xInt(smp.p) })
				end
			end
		end
	end
	-- fly: in the air, nothing below, not falling, for several seconds
	if XD.on and not why and not moving and not smp.ground and hum.FloorMaterial == Enum.Material.Air then
		local a = st.air
		if not a then
			st.air = { t = now, top = smp.p.Y, from = smp.p }
		elseif smp.p.Y < a.top - 2 then
			st.air = nil -- falling
		else
			a.top = math.max(a.top, smp.p.Y)
			if now - a.t >= L.fly then
				xFlag(p, st, "fly", { air = math.floor(now - a.t + 0.5), y = math.floor(smp.p.Y + 0.5), from = xInt(a.from), to = xInt(smp.p) })
				st.air = nil
			end
		end
	else
		st.air = nil
	end
	if DEBUG_FLAGS then
		local n = 0
		for _, fired in st.cfWin do if fired then n += 1 end end
		print(string.format("[Sentinel debug] %s: speed %.1f (limit %.1f, walk speed %d) | in the air %.1f s | ground below %s | moving part %s | game moved them %d of %d samples%s | %s",
			p.Name, hd, math.max(smp.ws, prev and prev.ws or 0) * L.sm + L.sa, math.floor(smp.ws + 0.5), st.air and (now - st.air.t) or 0,
			smp.ground and "yes" or "no", moving and "yes" or "no", n, #st.cfWin, cfOK and "" or " (signal not used)",
			reason and ("skipped: " .. reason) or (XD.on and "checked" or "checks are off")))
	end
end

------------------------------------------------------------------ replays: a rolling recording in memory, uploaded only when something happens
local RP = { on = false, min = 5, after = 30 } -- from the website at every check-in. Off until the owner turns it on
local RP_HZ, RP_MAXP, RP_MAXLEN, RP_CHUNK, RP_MAXBYTES = 2, 50, 600, 60000, 1500000 -- 2 samples a second, 50 players, 10 minute clips, 60 KB chunks, 1.5 MB per clip
local RP0 = os.clock()
local RP_EPOCH = DateTime.now().UnixTimestampMillis - RP0 * 1000 -- wall-clock time of tick 0
local rpFrames, rpEvents, rpNames = {}, {}, {}
local rpClip = nil -- the clip being recorded: { k0, stop, why }
local function rpK() return math.floor((os.clock() - RP0) * RP_HZ + 0.5) end
rpEv = function(kind, uid, text)
	if not RP.on then return end
	table.insert(rpEvents, { rpK(), kind, uid, text })
	if #rpEvents > 3000 then table.remove(rpEvents, 1) end
end
rpTrigger = function(why) -- start a clip (with the minutes before), or make the running one longer
	if not RP.on then return end
	local k = rpK()
	why = type(why) == "table" and why or { k = "staff" }
	if rpClip then
		why.at = k - rpClip.k0
		rpClip.stop = math.min(math.max(rpClip.stop, k + RP.after * RP_HZ), rpClip.k0 + RP_MAXLEN * RP_HZ)
		if #rpClip.why < 20 then table.insert(rpClip.why, why) end
	else
		local first = rpFrames[1] and rpFrames[1][1] or k
		local k0 = math.max(first, k - RP.min * 60 * RP_HZ)
		why.at = k - k0
		rpClip = { k0 = k0, stop = k + RP.after * RP_HZ, why = { why } }
	end
end
local rpMapCache = nil -- the map outline, worked out once per server
local function rpMap() -- large anchored parts as rectangles seen from above: { x, z, width, depth, rotation }. At most 300, no images, about 6 KB
	if rpMapCache then return rpMapCache end
	local list, seen = {}, 0
	for _, d in workspace:GetDescendants() do
		seen += 1
		if seen % 2000 == 0 then task.wait() end -- big maps: never hold up the game
		if seen > 50000 then break end
		if d:IsA("BasePart") and d.Anchored and d.Transparency < 0.95 and not d:IsA("Terrain") then
			local sz = d.Size
			local w, dp = sz.X, sz.Z
			if math.max(w, dp) >= 8 and w * dp >= 16 and sz.Y >= 0.5 then
				local p = d.Position
				table.insert(list, { math.floor(p.X + 0.5), math.floor(p.Z + 0.5), math.floor(w + 0.5), math.floor(dp + 0.5), math.floor(d.Orientation.Y + 0.5), w * dp })
			end
		end
	end
	table.sort(list, function(a, b) return a[6] > b[6] end)
	local out = {}
	for i = 1, math.min(300, #list) do
		local a = list[i]
		out[i] = { a[1], a[2], a[3], a[4], a[5] }
	end
	rpMapCache = out
	return out
end
local function rpCut(json, i) -- a chunk end that never splits a multi-byte character
	local j = math.min(#json, i + RP_CHUNK - 1)
	while j < #json and j > i do
		local b = string.byte(json, j + 1)
		if b < 128 or b >= 192 then break end
		j -= 1
	end
	return j
end
local function rpBuild(c, kEnd) -- delta-encoded tracks: per player, runs of [tick, x, y, z, state, then dx, dy, dz, state for every next sample]
	local tracks, users, names, last = {}, {}, {}, {}
	for _, f in rpFrames do
		local k = f[1]
		if k >= c.k0 and k <= kEnd then
			local d = f[2]
			for i = 1, #d, 5 do
				local uid, x, y, z, st = d[i], d[i + 1], d[i + 2], d[i + 3], d[i + 4]
				local key = tostring(uid)
				local segs = tracks[key]
				if not segs then
					segs = {}
					tracks[key] = segs
					table.insert(users, uid)
					names[key] = rpNames[uid] or key
				end
				local L = last[uid]
				if L and L.k == k - 1 then
					local seg = segs[#segs]
					table.insert(seg, x - L.x) table.insert(seg, y - L.y) table.insert(seg, z - L.z) table.insert(seg, st)
				else
					table.insert(segs, { k - c.k0, x, y, z, st })
				end
				last[uid] = { k = k, x = x, y = y, z = z }
			end
		end
	end
	local ev = {}
	for _, e in rpEvents do
		if e[1] >= c.k0 and e[1] <= kEnd then table.insert(ev, { e[1] - c.k0, e[2], e[3], e[4] }) end
	end
	local t0 = math.floor(RP_EPOCH + c.k0 * 1000 / RP_HZ)
	return { v = 1, hz = RP_HZ, t0 = t0, len = kEnd - c.k0, names = names, tracks = tracks, ev = ev }, users, names, t0
end
local function rpSend(c, kEnd, closing) -- closing: the server is shutting down or someone is waiting to watch, so upload faster
	local okB, clip, users, names, t0 = pcall(rpBuild, c, kEnd)
	if not okB then warn("[Sentinel] Could not build a replay: " .. tostring(clip)) return end
	local json = HttpService:JSONEncode(clip)
	if #json > RP_MAXBYTES then
		warn("[Sentinel] This replay is too big to upload (" .. math.floor(#json / 1000) .. " KB), so it was not saved.")
		return
	end
	local id = HttpService:GenerateGUID(false)
	local cuts, i = {}, 1
	while i <= #json do
		local j = rpCut(json, i)
		table.insert(cuts, string.sub(json, i, j))
		i = j + 1
	end
	local okM, map = pcall(rpMap)
	local head = { t0 = t0, t1 = t0 + math.floor(clip.len * 1000 / RP_HZ), users = users, names = names, why = c.why, hz = RP_HZ, map = okM and map or nil }
	for seq, part in cuts do
		local sent = false
		for attempt = 1, closing and 2 or 3 do
			local ok, res = pcall(HttpService.RequestAsync, HttpService, {
				Url = URL .. "/game/replay", Method = "POST", Headers = { ["Content-Type"] = "application/json" },
				Body = HttpService:JSONEncode({ key = KEY, jobId = game.JobId, clip = id, seq = seq, total = #cuts, head = seq == 1 and head or nil, data = part }),
			})
			if ok and res.Success then sent = true break end
			if ok and (res.StatusCode == 413 or res.StatusCode == 409 or res.StatusCode == 403) then
				warn("[Sentinel] Replay not saved: " .. (res.StatusCode == 413 and "replay storage is full" or res.StatusCode == 409 and "replays are switched off" or "the game key was refused"))
				return
			end
			task.wait(closing and 1 or 3 * attempt)
		end
		if not sent then
			warn("[Sentinel] Could not upload a replay (the website did not answer), so it was not saved.")
			return
		end
		task.wait(closing and 0.5 or 2) -- at most one chunk every 2 seconds, well inside Roblox's HTTP limits
	end
end
local function rpNow() -- someone on the website wants to watch: end the clip here and upload it at once. Recording carries on
	if not rpClip then return end
	local c = rpClip
	rpClip = nil
	task.spawn(rpSend, c, rpK(), true)
end
local function rpSample()
	local k = rpK()
	local d, n = {}, 0
	for _, p in Players:GetPlayers() do
		if n < RP_MAXP and not bouncing[p] then
			local char = p.Character
			local hrp = char and char:FindFirstChild("HumanoidRootPart")
			local hum = char and char:FindFirstChildOfClass("Humanoid")
			if hrp and hum then
				local st = hum:GetState()
				local code = 0 -- 0 on the ground, 1 in the air, 2 seated, 3 dead, 4 climbing or swimming
				if hum.Health <= 0 or st == S.Dead then code = 3
				elseif hum.SeatPart or hum.Sit then code = 2
				elseif st == S.Freefall or st == S.Jumping or st == S.Flying then code = 1
				elseif st == S.Climbing or st == S.Swimming then code = 4 end
				local pos = hrp.Position
				table.insert(d, p.UserId) table.insert(d, math.floor(pos.X * 2 + 0.5)) table.insert(d, math.floor(pos.Y * 2 + 0.5)) table.insert(d, math.floor(pos.Z * 2 + 0.5)) table.insert(d, code)
				rpNames[p.UserId] = p.Name
				n += 1
			end
		end
	end
	table.insert(rpFrames, { k, d })
	local keepFrom = k - RP.min * 60 * RP_HZ
	if rpClip then keepFrom = math.min(keepFrom, rpClip.k0) end -- never drop what the clip being recorded still needs
	while rpFrames[1] and rpFrames[1][1] < keepFrom do table.remove(rpFrames, 1) end
	while rpEvents[1] and rpEvents[1][1] < keepFrom do table.remove(rpEvents, 1) end
	if rpClip and k >= rpClip.stop then
		local c = rpClip
		rpClip = nil
		task.spawn(rpSend, c, k)
	end
end

------------------------------------------------------------------ !rejoin: a fresh server of the same game
local function rejoinPlayer(plr, via)
	rejoining[plr] = true
	local ok, err = pcall(function()
		if via then -- this server is closing: pass through a holding server so they never land back here
			local opts = Instance.new("TeleportOptions")
			opts.ShouldReserveServer = true
			opts:SetTeleportData({ sentinelRestart = true })
			TeleportService:TeleportAsync(game.PlaceId, { plr }, opts)
		else
			TeleportService:TeleportAsync(game.PlaceId, { plr })
		end
	end)
	if not ok then
		rejoining[plr] = nil
		warn("[Sentinel] !rejoin could not move " .. plr.Name .. ": " .. tostring(err))
		banner(plr, "Couldn't move you to a new server. Leave and join again.", "red", "Rejoin")
	end
end
TeleportService.TeleportInitFailed:Connect(function(plr)
	if rejoining[plr] then
		rejoining[plr] = nil
		banner(plr, "Couldn't move you to a new server. Leave and join again.", "red", "Rejoin")
	end
end)

local function handle(c)
	local plr = c.userId and Players:GetPlayerByUserId(c.userId)
	if c.type == "kick" then
		if plr then plr:Kick(tostring(c.display or ("[Sentinel] " .. tostring(c.reason)))) end
	elseif c.type == "ban" then
		doBan(c.userId, tostring(c.display or c.reason), c.seconds, c.reason, c.alts)
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
		local ack = type(c.ack) == "string" and #c.ack <= 40 and not muted[c.userId] and c.ack or nil -- a muted player is never asked to acknowledge
		if plr then banner(plr, tostring(c.body or c.text), kind, c.title, ack) end
	elseif c.type == "announce" then
		for _, p in Players:GetPlayers() do banner(p, tostring(c.text), "blue", "Announcement") end
	elseif c.type == "replay" then
		rpTrigger(type(c.why) == "table" and c.why or { k = "staff" })
		if c.now == true then rpNow() end
	elseif c.type == "rejoin" then
		if plr then task.spawn(rejoinPlayer, plr, c.via == true) end
	elseif c.type == "restart" then
		task.spawn(restartServer, tostring(c.display or "This server is restarting. You will be moved to a new server in a few seconds."))
	end
end

local function sync()
	if busy then return end
	busy = true
	lastSent = os.clock()
	local list = {}
	for _, p in Players:GetPlayers() do
		if not bouncing[p] then table.insert(list, { userId = p.UserId, name = p.Name, displayName = p.DisplayName }) end
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
	if type(data.rp) == "table" then -- replay settings from the website
		local was = RP.on
		RP.on = data.rp.on == true
		RP.min = math.clamp(tonumber(data.rp.min) or 5, 1, 10)
		RP.after = math.clamp(tonumber(data.rp.after) or 30, 10, 300)
		if was and not RP.on then rpFrames, rpEvents, rpClip = {}, {}, nil end -- switched off: forget everything
	end
	if type(data.xd) == "table" then -- exploit flag settings from the website
		XD.on = data.xd.on ~= false
		XD.lvl = XL[data.xd.lvl] and data.xd.lvl or "low"
	end
	if type(data.bar) == "table" then applyBar(data.bar) end
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

local soonQueued, running = false, false
syncSoon = function() -- at most one extra check-in a second, so busy chat never hits the rate limit
	if soonQueued or not running then return end
	soonQueued = true
	task.delay(math.max(0, lastSent + 1 - os.clock()), function()
		while busy do task.wait(0.2) end
		soonQueued = false
		sync()
	end)
end

Players.PlayerAdded:Connect(function(p)
	if passingThrough(p) then -- wait a moment so the old server is gone, then go on to a normal server
		bouncing[p] = true
		task.delay(8, function()
			for attempt = 1, 3 do
				if p.Parent ~= Players then return end
				pcall(function() TeleportService:TeleportAsync(game.PlaceId, { p }) end)
				task.wait(10)
			end
			if p.Parent == Players then p:Kick("The server restarted. Rejoin to keep playing.") end
		end)
		return
	end
	if restarting then task.defer(restartMove, { p }) end -- joined while this server is restarting: moved along too
	xWatch(p)
	rpEv("join", p.UserId, p.Name)
	queue({ type = "join", userId = p.UserId, name = p.Name, age = p.AccountAge, follow = (p.FollowUserId and p.FollowUserId > 0) and p.FollowUserId or nil }) -- follow: the player they joined by following, if any (helps spot one person switching accounts)
	task.defer(sync)
end)
Players.PlayerRemoving:Connect(function(p)
	barLast[p.UserId] = nil
	clientReady[p], clientVer[p], activeBanner[p], ackWant[p], devSent[p] = nil, nil, nil, nil, nil
	xs[p], lastRejoin[p.UserId], rejoining[p] = nil, nil, nil
	if bouncing[p] then bouncing[p] = nil return end
	rpEv("leave", p.UserId)
	queue({ type = "leave", userId = p.UserId, name = p.Name })
end)
for _, p in Players:GetPlayers() do
	queue({ type = "join", userId = p.UserId, name = p.Name, age = p.AccountAge })
	xWatch(p)
end

local rawKey = KEY
KEY = string.gsub(KEY, "[%[%]%s\"']", "") -- brackets, quotes and spaces never belong in a game code
if KEY == "" or string.find(KEY, "INPUT", 1, true) then
	warn("[Sentinel] No game code set. Open the Sentinel website, copy your game code and paste it over INPUT CODE HERE at the top of this script. Remove the [ ] brackets too, but keep the quotes.")
	return
end
if KEY ~= rawKey then print("[Sentinel] Removed extra [ ] or spaces from your game code. You can delete them from the script too.") end
task.spawn(setupChat)
running = true
task.spawn(function()
	while true do
		sync()
		task.wait(INTERVAL)
	end
end)
task.spawn(function() -- replays: 2 samples a second, only while the owner has them on
	while true do
		task.wait(1 / RP_HZ)
		if RP.on then
			local ok, err = pcall(rpSample)
			if not ok then warn("[Sentinel] Replay recording error: " .. tostring(err)) end
		end
	end
end)
game:BindToClose(function() -- the server is closing (last player left, restart or shutdown): upload the clip being recorded now, or it is lost
	if not rpClip then return end
	local c = rpClip
	rpClip = nil
	local ok, err = pcall(rpSend, c, rpK(), true)
	if not ok then warn("[Sentinel] Could not upload a replay while closing: " .. tostring(err)) end
end)
task.spawn(function() -- exploit checks, once a second
	while true do
		task.wait(1)
		local now = os.clock()
		for _, p in Players:GetPlayers() do
			if not bouncing[p] then
				local ok, err = pcall(xSample, p, now)
				if not ok and DEBUG_FLAGS then warn("[Sentinel debug] check failed for " .. p.Name .. ": " .. tostring(err)) end
			end
		end
	end
end)
print("[Sentinel] Connected to " .. URL)
