--[[
	Sentinel player script (optional, but recommended)

	WHAT IT DOES
	  1. When a moderator mutes a player in Sentinel, this hides that player's chat bar and chat window (including Quick Words) completely,
	     and brings it back when the mute ends. Without it, a muted player's messages are still
	     stopped by the server, but they can still type.
	  2. Draws warnings and announcements from your moderators as a card with a timer line that runs round its border, smoothly at any frame rate.
	     It needs SentinelBridge version 14 or newer in ServerScriptService.
	  3. Adds a small Report button. Players pick who they are reporting (optional), say what happened and press Send.
	     The report lands in Reports on your Sentinel website with the chat around that moment attached.
	     It needs SentinelBridge version 13 or newer in ServerScriptService. Set SHOW_REPORT_BUTTON to false below to turn the button off.
	  4. Staff in the ranks the owner picks on the website (Settings, Game) get a bar at the bottom of the screen to moderate players,
	     handle reports and use server tools without leaving the game. Their rank decides what they can do, the same as on the website.
	     It needs SentinelBridge version 31 or newer. Nobody else ever sees the bar.

	HOW TO ADD IT (1 minute)
	  1. In Roblox Studio, open the Explorer and find StarterPlayer, then StarterPlayerScripts.
	  2. Hover StarterPlayerScripts, click the +, and choose LocalScript.
	  3. Delete what is inside it and paste this whole file.
	  4. Publish your game. You do NOT need to put your game code in this one.

	It only changes the player's own screen. Your main Sentinel script (in ServerScriptService)
	still does the real muting, so this one is just the visible part.
]]

local Players = game:GetService("Players")
local TextChatService = game:GetService("TextChatService")
local StarterGui = game:GetService("StarterGui")

local CLIENT_VERSION = 7 -- raised whenever this script changes, so the Sentinel website can tell you when to update it
local player = Players.LocalPlayer
local savedInput = nil -- what the chat bar was set to before we hid it
local hidden = false

local function hideChat()
	if hidden then return end
	hidden = true
	pcall(function()
		local cfg = TextChatService:FindFirstChildOfClass("ChatInputBarConfiguration")
		if cfg then
			savedInput = cfg.Enabled
			cfg.Enabled = false
		end
	end)
	pcall(function() StarterGui:SetCore("ChatBarDisabled", true) end) -- the old chat
	-- also hides the whole chat window, which is where Roblox's "Quick Words" button lives
	pcall(function() StarterGui:SetCoreGuiEnabled(Enum.CoreGuiType.Chat, false) end)
end

local function showChat()
	if not hidden then return end
	hidden = false
	pcall(function()
		local cfg = TextChatService:FindFirstChildOfClass("ChatInputBarConfiguration")
		if cfg then cfg.Enabled = savedInput ~= false end
	end)
	pcall(function() StarterGui:SetCore("ChatBarDisabled", false) end)
	pcall(function() StarterGui:SetCoreGuiEnabled(Enum.CoreGuiType.Chat, true) end)
end

local function apply()
	if player:GetAttribute("SentinelMuted") == true then hideChat() else showChat() end
end

player:GetAttributeChangedSignal("SentinelMuted"):Connect(apply)
apply()

------------------------------------------------------------------ report button
local SHOW_REPORT_BUTTON = true
local BUTTON_POSITION = UDim2.new(0, 10, 0.5, 0) -- left edge, middle of the screen. Change this if it covers something in your game.
local REPORT_COOLDOWN = 30 -- the game script enforces this too

local ReplicatedStorage = game:GetService("ReplicatedStorage")

local C = { -- the website's dark colours
	bg = Color3.fromRGB(28, 28, 30), card = Color3.fromRGB(44, 44, 46), line = Color3.fromRGB(255, 255, 255), text = Color3.fromRGB(245, 245, 247),
	muted = Color3.fromRGB(152, 152, 157), accent = Color3.fromRGB(10, 132, 255), red = Color3.fromRGB(255, 105, 97),
}
local SANS = "rbxasset://fonts/families/BuilderSans.json" -- Roblox's clean system-style font, the closest match to the website
local function font(weight) return Font.new(SANS, weight or Enum.FontWeight.Regular) end

local function make(class, props, parent)
	local o = Instance.new(class)
	for k, v in pairs(props) do o[k] = v end
	o.Parent = parent
	return o
end

local function buildReport()
	local reportEvent = ReplicatedStorage:WaitForChild("SentinelReport", 20)
	if not reportEvent then return end -- the game script is older than version 13, so there is nothing to send to

	local gui = make("ScreenGui", { Name = "SentinelReport", ResetOnSpawn = false, DisplayOrder = 150 }, player:WaitForChild("PlayerGui"))

	local open = make("TextButton", {
		Name = "Open", Size = UDim2.fromOffset(80, 32), AnchorPoint = Vector2.new(0, 0.5), Position = BUTTON_POSITION,
		BackgroundColor3 = C.bg, BackgroundTransparency = 0.08, Text = "Report", TextColor3 = C.text,
		FontFace = font(Enum.FontWeight.SemiBold), TextSize = 15, AutoButtonColor = false,
	}, gui)
	make("UICorner", { CornerRadius = UDim.new(0, 9) }, open)
	make("UIStroke", { Color = C.line, Thickness = 1, Transparency = 0.86, ApplyStrokeMode = Enum.ApplyStrokeMode.Border }, open)
	open.MouseEnter:Connect(function() open.BackgroundColor3 = C.card end)
	open.MouseLeave:Connect(function() open.BackgroundColor3 = C.bg end)

	local panel = make("Frame", {
		Name = "Panel", Visible = false, Size = UDim2.fromOffset(320, 380), AnchorPoint = Vector2.new(0.5, 0.5),
		Position = UDim2.fromScale(0.5, 0.5), BackgroundColor3 = C.bg,
	}, gui)
	make("UICorner", { CornerRadius = UDim.new(0, 14) }, panel)
	make("UIStroke", { Color = C.line, Thickness = 1, Transparency = 0.86, ApplyStrokeMode = Enum.ApplyStrokeMode.Border }, panel)

	local function label(text, y, size, color, font)
		return make("TextLabel", {
			BackgroundTransparency = 1, Position = UDim2.fromOffset(16, y), Size = UDim2.fromOffset(288, size + 6), Text = text,
			TextColor3 = color, FontFace = font, TextSize = size, TextXAlignment = Enum.TextXAlignment.Left,
		}, panel)
	end
	label("Report a problem", 12, 18, C.text, font(Enum.FontWeight.Bold))
	label("Who is it about? (optional)", 40, 13, C.muted, font())

	local list = make("ScrollingFrame", {
		Position = UDim2.fromOffset(16, 64), Size = UDim2.fromOffset(288, 120), BackgroundColor3 = C.card, BorderSizePixel = 0,
		ScrollBarThickness = 4, CanvasSize = UDim2.new(), AutomaticCanvasSize = Enum.AutomaticSize.Y,
	}, panel)
	make("UICorner", { CornerRadius = UDim.new(0, 8) }, list)
	make("UIListLayout", { Padding = UDim.new(0, 2), SortOrder = Enum.SortOrder.LayoutOrder }, list)

	label("What happened?", 192, 13, C.muted, font())
	local box = make("TextBox", {
		Position = UDim2.fromOffset(16, 216), Size = UDim2.fromOffset(288, 86), BackgroundColor3 = C.card, BorderSizePixel = 0,
		Text = "", PlaceholderText = "Describe it in a sentence or two", PlaceholderColor3 = C.muted, TextColor3 = C.text,
		FontFace = font(), TextSize = 14, TextWrapped = true, MultiLine = true, ClearTextOnFocus = false,
		TextXAlignment = Enum.TextXAlignment.Left, TextYAlignment = Enum.TextYAlignment.Top,
	}, panel)
	make("UICorner", { CornerRadius = UDim.new(0, 8) }, box)
	make("UIPadding", { PaddingLeft = UDim.new(0, 8), PaddingRight = UDim.new(0, 8), PaddingTop = UDim.new(0, 6) }, box)
	box:GetPropertyChangedSignal("Text"):Connect(function()
		if #box.Text > 200 then box.Text = string.sub(box.Text, 1, 200) end
	end)

	local status = label("", 306, 12, C.red, font())

	local function button(text, x, color)
		local b = make("TextButton", {
			Position = UDim2.fromOffset(x, 332), Size = UDim2.fromOffset(140, 36), BackgroundColor3 = color, Text = text,
			TextColor3 = C.text, FontFace = font(Enum.FontWeight.SemiBold), TextSize = 15, AutoButtonColor = true,
		}, panel)
		make("UICorner", { CornerRadius = UDim.new(0, 8) }, b)
		return b
	end
	local send, cancel = button("Send report", 16, C.accent), button("Cancel", 164, C.card)

	local selected = nil
	local rows = {}
	local function paint()
		for id, row in pairs(rows) do
			row.BackgroundColor3 = (id == (selected or 0)) and C.accent or C.card
		end
	end
	local function addRow(id, text, order)
		local row = make("TextButton", {
			Size = UDim2.new(1, -6, 0, 28), BackgroundColor3 = C.card, BorderSizePixel = 0, Text = "  " .. text, TextColor3 = C.text,
			FontFace = font(), TextSize = 14, TextXAlignment = Enum.TextXAlignment.Left, LayoutOrder = order, AutoButtonColor = false,
		}, list)
		make("UICorner", { CornerRadius = UDim.new(0, 6) }, row)
		row.Activated:Connect(function()
			selected = id ~= 0 and id or nil
			paint()
		end)
		rows[id] = row
	end
	local function refresh()
		for _, row in pairs(rows) do row:Destroy() end
		rows = {}
		addRow(0, "No one in particular", 0)
		local others = {}
		for _, p in Players:GetPlayers() do
			if p ~= player then table.insert(others, p) end
		end
		table.sort(others, function(a, b) return string.lower(a.Name) < string.lower(b.Name) end)
		for i, p in others do
			addRow(p.UserId, p.DisplayName ~= p.Name and (p.DisplayName .. " (@" .. p.Name .. ")") or p.Name, i)
		end
		if selected and not rows[selected] then selected = nil end
		paint()
	end

	local lastSent = -999
	open.Activated:Connect(function()
		panel.Visible = not panel.Visible
		status.Text = ""
		if panel.Visible then refresh() end
	end)
	cancel.Activated:Connect(function() panel.Visible = false end)
	Players.PlayerAdded:Connect(function() if panel.Visible then refresh() end end)
	Players.PlayerRemoving:Connect(function() if panel.Visible then task.defer(refresh) end end)

	send.Activated:Connect(function()
		local text = string.gsub(box.Text, "^%s*(.-)%s*$", "%1")
		if text == "" and not selected then
			status.Text = "Pick a player or describe what happened."
			return
		end
		if os.clock() - lastSent < REPORT_COOLDOWN then
			status.Text = "Please wait a moment before sending another report."
			return
		end
		lastSent = os.clock()
		reportEvent:FireServer(selected, text)
		box.Text, selected, status.Text, panel.Visible = "", nil, "", false
		open.Text = "Sent"
		task.delay(3, function() open.Text = "Report" end)
	end)
end

if SHOW_REPORT_BUTTON then
	task.spawn(function()
		local ok, err = pcall(buildReport)
		if not ok then warn("[Sentinel] Could not build the Report button: " .. tostring(err)) end
	end)
end

------------------------------------------------------------------ banners
-- Warnings, mute notices and announcements from your moderators. They are drawn here, on the player's own screen, so the
-- slide-in and the timer line run at the player's full frame rate. (Without this script the game script draws them itself.)
-- It needs SentinelBridge version 14 or newer in ServerScriptService.
local TweenService = game:GetService("TweenService")
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

local currentNotice = nil -- the function that closes the banner on screen
local noticeRemote = nil -- ReplicatedStorage.SentinelNotice, once the game script has made it
local ACK_SECONDS = 120 -- a warning that asks for "I understand" stays this long; after that the website shows it as not acknowledged
local function showNotice(text, kind, title, opts)
	if typeof(text) ~= "string" then return end
	if typeof(kind) ~= "string" then kind = "red" end
	if typeof(title) ~= "string" then title = nil end
	text = string.sub(text, 1, 300)
	local ack = typeof(opts) == "table" and typeof(opts.ack) == "string" and #opts.ack <= 40 and opts.ack or nil
	if currentNotice then currentNotice(true) end -- any newer banner (a mute, for example) replaces this one
	local gui = Instance.new("ScreenGui")
	gui.Name, gui.ResetOnSpawn, gui.DisplayOrder, gui.IgnoreGuiInset = "SentinelBanner", false, 200, true
	gui.Parent = player:WaitForChild("PlayerGui")
	local n = buildNotice(gui, text, kind, title, nil, ack and "I understand" or nil)
	local conn
	local finished = false
	local function finish(quick)
		if finished then return end
		finished = true
		if conn then conn:Disconnect() end
		n.hide(quick)
		task.delay(quick and 0.2 or 0.4, function() gui:Destroy() end)
		if currentNotice == finish then currentNotice = nil end
	end
	currentNotice = finish
	n.show()
	if ack and n.button then -- only the button closes it; the player can keep moving and chatting meanwhile
		n.button.Activated:Connect(function()
			if finished then return end
			if noticeRemote then noticeRemote:FireServer("ack", ack) end
			finish(false)
		end)
	else
		n.card.InputBegan:Connect(function(input) -- tap or click the card to close it early
			if input.UserInputType == Enum.UserInputType.MouseButton1 or input.UserInputType == Enum.UserInputType.Touch then finish(false) end
		end)
	end
	local show = ack and ACK_SECONDS or math.max(5, math.min(9, 4.5 + #text / 25)) -- seconds on screen: longer messages stay longer
	local start = os.clock() + 0.4 -- let the card finish sliding in before the line starts
	conn = RunService.RenderStepped:Connect(function()
		local p = (os.clock() - start) / show
		n.progress(math.max(0, p))
		if p >= 1 then finish(false) end
	end)
end

task.spawn(function()
	local noticeEvent = ReplicatedStorage:WaitForChild("SentinelNotice", 30)
	if not noticeEvent then return end -- the game script is older than version 14: it draws the banners itself
	noticeRemote = noticeEvent
	noticeEvent.OnClientEvent:Connect(function(text, kind, title, opts)
		local ok, err = pcall(showNotice, text, kind, title, opts)
		if not ok then warn("[Sentinel] Could not show a banner: " .. tostring(err)) end
	end)
	noticeEvent:FireServer("ready", CLIENT_VERSION) -- tells the game script to send banners here instead of drawing them itself, and which version this is
	task.wait(5)
	-- Linked accounts: Roblox settings saved on this computer or phone are the same for every account on it.
	-- Sent once. The website keeps only a one-way code of them, never the values, and never an IP address.
	local function get(f)
		local ok, v = pcall(f)
		if ok then return v end
		return nil
	end
	local s = get(function() return UserSettings():GetService("UserGameSettings") end)
	local uis = game:GetService("UserInputService")
	local lt, ut = os.date("*t"), os.date("!*t")
	local dd = lt.yday - ut.yday
	if dd > 1 then dd = -1 elseif dd < -1 then dd = 1 end
	local vp = get(function() return workspace.CurrentCamera.ViewportSize end)
	local inp = 0
	for i, on in { uis.TouchEnabled, uis.KeyboardEnabled, uis.MouseEnabled, uis.GamepadEnabled, uis.VREnabled, get(function() return game:GetService("GuiService"):IsTenFootInterface() end) } do
		if on then inp += 2 ^ (i - 1) end
	end
	local fp = {
		ms = s and get(function() return math.floor(s.MouseSensitivity * 10000 + 0.5) end),
		vol = s and get(function() return math.floor(s.MasterVolume * 100 + 0.5) end),
		q = s and get(function() return s.SavedQualityLevel.Value end),
		cm = s and get(function() return s.ComputerCameraMovementMode.Value end),
		mm = s and get(function() return s.ComputerMovementMode.Value end),
		tc = s and get(function() return s.TouchCameraMovementMode.Value end),
		tm = s and get(function() return s.TouchMovementMode.Value end),
		inv = s and get(function() return s.CameraYInverted and 1 or 0 end),
		gs = s and get(function() return math.floor(s.GamepadCameraSensitivity * 1000 + 0.5) end),
		full = s and get(function() return s:InFullScreen() and 1 or 0 end),
		loc = get(function() return game:GetService("LocalizationService").SystemLocaleId end),
		tz = dd * 1440 + (lt.hour * 60 + lt.min) - (ut.hour * 60 + ut.min),
		vw = vp and math.floor(vp.X) or nil,
		vh = vp and math.floor(vp.Y) or nil,
		inp = inp,
		now = get(function() return DateTime.now().UnixTimestampMillis end),
	}
	noticeEvent:FireServer("dev", fp)
end)

------------------------------------------------------------------ staff bar
-- Staff in the ranks the owner picked get a bar at the bottom of their screen. Every request goes to the game script, which asks
-- Sentinel with the game key; Sentinel checks their rank every time, so this script only draws what it is sent back.
-- It needs SentinelBridge version 31 or newer. Nobody else ever gets the bar.
local BAR_BG = Color3.fromRGB(14, 14, 16)
local LENGTHS = {
	mute = { { 5, "5 min" }, { 15, "15 min" }, { 60, "1 hour" }, { 1440, "1 day" } },
	ban = { { 1440, "1 day" }, { 10080, "7 days" }, { 43200, "30 days" }, { 0, "Permanent" } },
}
local VERB = { warn = "Warned", kick = "Kicked", mute = "Muted", ban = "Banned" }

local function buildBar()
	while player:GetAttribute("SentinelStaff") ~= true do player:GetAttributeChangedSignal("SentinelStaff"):Wait() end
	local fn = ReplicatedStorage:WaitForChild("SentinelStaff", 30)
	if not fn then return end -- the game script is older than version 31
	local function ask(op, args)
		local ok, r = pcall(fn.InvokeServer, fn, op, args or {})
		if not ok or typeof(r) ~= "table" then return nil, "Sentinel can't be reached right now." end
		if r.ok ~= true then return nil, typeof(r.error) == "string" and r.error or "Something went wrong." end
		return typeof(r.data) == "table" and r.data or {}
	end

	local gui = make("ScreenGui", { Name = "SentinelStaffBar", ResetOnSpawn = false, DisplayOrder = 140, IgnoreGuiInset = true }, player:WaitForChild("PlayerGui"))
	local uiScale = make("UIScale", {}, gui)
	local function fit() -- smaller on phones, so the panel always fits above the bar
		local cam = workspace.CurrentCamera
		local v = cam and cam.ViewportSize or Vector2.new(1000, 800)
		uiScale.Scale = math.clamp(math.min(v.X / 420, (v.Y - 20) / 560, 1), 0.5, 1)
	end
	fit()
	if workspace.CurrentCamera then workspace.CurrentCamera:GetPropertyChangedSignal("ViewportSize"):Connect(fit) end
	local function round(o, r) make("UICorner", { CornerRadius = r and UDim.new(0, r) or UDim.new(1, 0) }, o) end
	local function edge(o) make("UIStroke", { Color = C.line, Thickness = 1, Transparency = 0.88, ApplyStrokeMode = Enum.ApplyStrokeMode.Border }, o) end
	local function pad(o, x, y) make("UIPadding", { PaddingLeft = UDim.new(0, x), PaddingRight = UDim.new(0, x), PaddingTop = UDim.new(0, y or 0), PaddingBottom = UDim.new(0, y or 0) }, o) end

	-- the bar: clock, tabs, and their own face (tap it to fold the bar away)
	local bar = make("Frame", {
		AnchorPoint = Vector2.new(0.5, 1), Position = UDim2.new(0.5, 0, 1, -14), Size = UDim2.fromOffset(0, 48), AutomaticSize = Enum.AutomaticSize.X,
		BackgroundColor3 = BAR_BG, BackgroundTransparency = 0.04,
	}, gui)
	round(bar)
	edge(bar)
	make("UIPadding", { PaddingLeft = UDim.new(0, 16), PaddingRight = UDim.new(0, 6) }, bar)
	make("UIListLayout", { FillDirection = Enum.FillDirection.Horizontal, VerticalAlignment = Enum.VerticalAlignment.Center, Padding = UDim.new(0, 4), SortOrder = Enum.SortOrder.LayoutOrder }, bar)
	local clock = make("TextLabel", { BackgroundTransparency = 1, Size = UDim2.fromOffset(50, 36), Text = "", TextColor3 = C.text, FontFace = font(Enum.FontWeight.SemiBold), TextSize = 15 }, bar)
	task.spawn(function()
		while gui.Parent do
			clock.Text = os.date("%H:%M")
			task.wait(5)
		end
	end)
	local tabs = {}
	for i, t in { { "home", "Home" }, { "players", "Players" }, { "reports", "Reports" }, { "tools", "Tools" } } do
		local b = make("TextButton", {
			Size = UDim2.fromOffset(0, 34), AutomaticSize = Enum.AutomaticSize.X, BackgroundColor3 = C.card, BackgroundTransparency = 1, Text = t[2],
			TextColor3 = C.muted, FontFace = font(Enum.FontWeight.SemiBold), TextSize = 14, AutoButtonColor = false, LayoutOrder = i,
		}, bar)
		round(b)
		pad(b, 12)
		tabs[t[1]] = b
	end
	tabs.reports.Visible, tabs.tools.Visible = false, false -- until Sentinel says what their rank allows
	local face = make("ImageButton", { Size = UDim2.fromOffset(36, 36), BackgroundColor3 = C.card, Image = "", LayoutOrder = 10, AutoButtonColor = false }, bar)
	round(face)
	task.spawn(function()
		local ok, img = pcall(Players.GetUserThumbnailAsync, Players, player.UserId, Enum.ThumbnailType.HeadShot, Enum.ThumbnailSize.Size48x48)
		if ok then face.Image = img end
	end)

	-- the panel above the bar
	local panel = make("Frame", { Visible = false, AnchorPoint = Vector2.new(0.5, 1), Position = UDim2.new(0.5, 0, 1, -74), Size = UDim2.fromOffset(380, 460), BackgroundColor3 = C.bg }, gui)
	round(panel, 16)
	edge(panel)
	local title = make("TextLabel", {
		BackgroundTransparency = 1, Position = UDim2.fromOffset(18, 12), Size = UDim2.new(1, -70, 0, 26), Text = "", TextColor3 = C.text,
		FontFace = font(Enum.FontWeight.Bold), TextSize = 18, TextXAlignment = Enum.TextXAlignment.Left, TextTruncate = Enum.TextTruncate.AtEnd,
	}, panel)
	local close = make("TextButton", {
		AnchorPoint = Vector2.new(1, 0), Position = UDim2.new(1, -12, 0, 12), Size = UDim2.fromOffset(28, 28), BackgroundColor3 = C.card,
		Text = "\u{00D7}", TextColor3 = C.muted, FontFace = font(Enum.FontWeight.Bold), TextSize = 18,
	}, panel)
	round(close)
	local body = make("ScrollingFrame", {
		Position = UDim2.fromOffset(12, 48), Size = UDim2.new(1, -24, 1, -60), BackgroundTransparency = 1, BorderSizePixel = 0,
		ScrollBarThickness = 4, CanvasSize = UDim2.new(), AutomaticCanvasSize = Enum.AutomaticSize.Y,
	}, panel)
	make("UIListLayout", { Padding = UDim.new(0, 8), SortOrder = Enum.SortOrder.LayoutOrder }, body)
	make("UIPadding", { PaddingLeft = UDim.new(0, 6), PaddingRight = UDim.new(0, 10), PaddingBottom = UDim.new(0, 6) }, body)

	-- small building blocks for the panel
	local order = 0
	local function nxt() order += 1 return order end
	local function text(parent, s, size, color, bold)
		return make("TextLabel", {
			BackgroundTransparency = 1, Size = UDim2.new(1, 0, 0, 0), AutomaticSize = Enum.AutomaticSize.Y, Text = s, TextColor3 = color or C.text,
			FontFace = font(bold and Enum.FontWeight.SemiBold or nil), TextSize = size or 14, TextWrapped = true, TextXAlignment = Enum.TextXAlignment.Left, LayoutOrder = nxt(),
		}, parent)
	end
	local function card(parent, color)
		local f = make("Frame", { Size = UDim2.new(1, 0, 0, 0), AutomaticSize = Enum.AutomaticSize.Y, BackgroundColor3 = color or C.card, LayoutOrder = nxt() }, parent or body)
		round(f, 10)
		pad(f, 12, 10)
		make("UIListLayout", { Padding = UDim.new(0, 6), SortOrder = Enum.SortOrder.LayoutOrder }, f)
		return f
	end
	local function buttons(parent, list) -- list of { label, colour, function }; returns the buttons
		local row = make("Frame", { Size = UDim2.new(1, 0, 0, 0), AutomaticSize = Enum.AutomaticSize.Y, BackgroundTransparency = 1, LayoutOrder = nxt() }, parent)
		make("UIListLayout", { FillDirection = Enum.FillDirection.Horizontal, Wraps = true, Padding = UDim.new(0, 6), SortOrder = Enum.SortOrder.LayoutOrder }, row)
		local out = {}
		for i, x in list do
			local b = make("TextButton", {
				Size = UDim2.fromOffset(0, 32), AutomaticSize = Enum.AutomaticSize.X, BackgroundColor3 = x[2], Text = x[1], TextColor3 = C.text,
				FontFace = font(Enum.FontWeight.SemiBold), TextSize = 14, AutoButtonColor = true, LayoutOrder = i,
			}, row)
			round(b, 8)
			pad(b, 12)
			b.Activated:Connect(x[3])
			out[i] = b
		end
		return out
	end
	local function input(parent, placeholder, max, tall)
		local box = make("TextBox", {
			Size = UDim2.new(1, 0, 0, tall and 64 or 34), BackgroundColor3 = parent == body and C.card or C.bg, Text = "", PlaceholderText = placeholder,
			PlaceholderColor3 = C.muted, TextColor3 = C.text, FontFace = font(), TextSize = 14, ClearTextOnFocus = false, TextWrapped = tall == true, MultiLine = tall == true,
			TextXAlignment = Enum.TextXAlignment.Left, TextYAlignment = tall and Enum.TextYAlignment.Top or Enum.TextYAlignment.Center, LayoutOrder = nxt(),
		}, parent)
		round(box, 8)
		pad(box, 10, tall and 6 or 0)
		box:GetPropertyChangedSignal("Text"):Connect(function()
			if #box.Text > max then box.Text = string.sub(box.Text, 1, max) end
		end)
		return box
	end
	local function trim(s) return (string.gsub(s, "^%s*(.-)%s*$", "%1")) end

	-- pages. gen goes up whenever another page opens, so an answer that arrives late is dropped
	local me, current, gen, busy = nil, nil, 0, false
	local pages = {}
	local function applyTabs()
		local can = me and me.can or {}
		tabs.reports.Visible = can.reports == true
		tabs.tools.Visible = can.announce == true or can.lockdown == true or can.replay == true
	end
	local function show(name, arg)
		gen += 1
		local my = gen
		current = name
		for _, c in body:GetChildren() do
			if c:IsA("GuiObject") then c:Destroy() end
		end
		order = 0
		body.CanvasPosition = Vector2.zero
		title.Text = ({ home = "Home", players = "Players", reports = "Reports", tools = "Server tools" })[name] or ""
		local tab = (name == "player" or name == "act") and "players" or name
		for k, b in tabs do
			b.BackgroundTransparency = k == tab and 0 or 1
			b.TextColor3 = k == tab and C.text or C.muted
		end
		panel.Visible = true
		task.spawn(function()
			local ok, err = pcall(pages[name], arg, my)
			if not ok then warn("[Sentinel] Staff bar: " .. tostring(err)) end
		end)
	end
	local function hidePanel()
		gen += 1
		panel.Visible, current = false, nil
		for _, b in tabs do
			b.BackgroundTransparency = 1
			b.TextColor3 = C.muted
		end
	end
	local function run(job) -- one request at a time from a button
		if busy then return end
		busy = true
		task.spawn(function()
			local ok, err = pcall(job)
			busy = false
			if not ok then warn("[Sentinel] Staff bar: " .. tostring(err)) end
		end)
	end
	local function result(d, err, okText, back, arg)
		if d then
			if d.pending then showNotice(typeof(d.msg) == "string" and d.msg or "Saved. A second staff member must approve it.", "blue", "Waiting for approval")
			else showNotice(okText, "green", "Done") end
			if back then show(back, arg) end
		else
			showNotice(err, "red", "Not done")
		end
	end

	pages.home = function(_, my)
		local d, err = ask("home")
		if my ~= gen then return end
		if not d then text(body, err, 14, C.red) return end
		me = d
		applyTabs()
		text(body, tostring(d.name or "") .. "  \u{00B7}  " .. tostring(d.rank or ""), 14, C.muted)
		if d.lockdown and d.lockdown.on then
			local c = card(body, Color3.fromRGB(92, 28, 28))
			text(c, "Raid lockdown is on", 15, C.text, true)
			text(c, tostring(d.lockdown.kept or 0) .. " new accounts kept out so far", 13, C.text)
		end
		local c = card()
		text(c, "This server", 13, C.muted)
		text(c, string.format("%d players, %d staff", d.here or 0, d.hereStaff or 0), 16, C.text, true)
		c = card()
		text(c, "Whole game", 13, C.muted)
		text(c, string.format("%d players, %d staff, %d servers", d.all or 0, d.allStaff or 0, d.servers or 0), 16, C.text, true)
		if d.can and d.can.reports then
			c = card()
			text(c, "Open reports", 13, C.muted)
			text(c, tostring(d.reports or 0), 16, C.text, true)
		end
	end

	local search = ""
	pages.players = function(_, my)
		local d, err = ask("players")
		if my ~= gen then return end
		if not d then text(body, err, 14, C.red) return end
		local box = input(body, "Search players", 20)
		box.Text = search
		local rows = {}
		for _, p in d.players or {} do
			local b = make("TextButton", { Size = UDim2.new(1, 0, 0, 46), BackgroundColor3 = C.card, AutoButtonColor = true, Text = "", LayoutOrder = nxt() }, body)
			round(b, 10)
			local dn = typeof(p.displayName) == "string" and p.displayName ~= "" and p.displayName ~= p.name and p.displayName or nil
			make("TextLabel", {
				BackgroundTransparency = 1, Position = UDim2.fromOffset(12, 5), Size = UDim2.new(1, -24, 0, 20), Text = dn and (dn .. "  @" .. p.name) or p.name,
				TextColor3 = C.text, FontFace = font(Enum.FontWeight.SemiBold), TextSize = 15, TextXAlignment = Enum.TextXAlignment.Left, TextTruncate = Enum.TextTruncate.AtEnd,
			}, b)
			local tags = {}
			if p.staff then table.insert(tags, "Staff") end
			if p.muted then table.insert(tags, "Muted") end
			if p.watch then table.insert(tags, "On the watchlist") end
			if (p.warns or 0) > 0 then table.insert(tags, p.warns .. (p.warns == 1 and " warning" or " warnings")) end
			if (p.bans or 0) > 0 then table.insert(tags, p.bans .. (p.bans == 1 and " ban" or " bans")) end
			if (p.notes or 0) > 0 then table.insert(tags, p.notes .. (p.notes == 1 and " note" or " notes")) end
			make("TextLabel", {
				BackgroundTransparency = 1, Position = UDim2.fromOffset(12, 25), Size = UDim2.new(1, -24, 0, 16), Text = #tags > 0 and table.concat(tags, "  \u{00B7}  ") or "Nothing in the logbook",
				TextColor3 = C.muted, FontFace = font(), TextSize = 12, TextXAlignment = Enum.TextXAlignment.Left, TextTruncate = Enum.TextTruncate.AtEnd,
			}, b)
			b.Activated:Connect(function() show("player", p) end)
			table.insert(rows, { b = b, key = string.lower(p.name .. " " .. (dn or "")) })
		end
		if #rows == 0 then text(body, "Nobody is in this server.", 14, C.muted) end
		local function filter()
			search = box.Text
			local q = string.lower(trim(box.Text))
			for _, r in rows do r.b.Visible = q == "" or string.find(r.key, q, 1, true) ~= nil end
		end
		box:GetPropertyChangedSignal("Text"):Connect(filter)
		filter()
	end

	pages.player = function(p, my)
		title.Text = p.name
		buttons(body, { { "\u{2190} Players", C.card, function() show("players") end } })
		local h = ask("history", { target = p.userId })
		if my ~= gen then return end
		local c = card()
		text(c, "Latest in the logbook", 13, C.muted)
		if h and #(h.entries or {}) > 0 then
			for _, e in h.entries do
				local line = tostring(e.type) .. (e.undone and " (undone)" or "") .. ((e.reason and e.reason ~= "") and (": " .. tostring(e.reason)) or "")
				text(c, line .. "  \u{00B7}  " .. tostring(e.by or ""), 13, e.undone and C.muted or C.text)
			end
		else
			text(c, h and "Nothing yet." or "Could not load it.", 13, C.muted)
		end
		local allow = {}
		for _, a in (me and me.can and me.can.act) or {} do allow[a] = true end
		local list = {}
		for _, a in { "warn", "kick", "mute", "ban" } do
			if allow[a] then
				table.insert(list, { a:sub(1, 1):upper() .. a:sub(2), a == "warn" and C.accent or C.card, function() show("act", { p = p, a = a }) end })
			end
		end
		if p.muted and allow.mute then
			table.insert(list, { "Unmute", C.card, function()
				run(function()
					local d, err = ask("act", { target = p.userId, action = "unmute" })
					result(d, err, p.name .. " can chat again.", "players")
				end)
			end })
		end
		if #list > 0 then buttons(body, list) else text(body, "Your rank can't moderate players.", 13, C.muted) end
	end

	pages.act = function(x)
		local p, a = x.p, x.a
		title.Text = a:sub(1, 1):upper() .. a:sub(2) .. " " .. p.name
		buttons(body, { { "\u{2190} Back", C.card, function() show("player", p) end } })
		local mins = 0
		if LENGTHS[a] then
			text(body, "How long?", 13, C.muted)
			local opts = {}
			for _, L in LENGTHS[a] do
				if not (a == "ban" and L[1] == 0 and not (me and me.can and me.can.permban)) then table.insert(opts, L) end
			end
			mins = opts[1][1]
			local btns
			local function paint()
				for i, b in btns do b.BackgroundColor3 = opts[i][1] == mins and C.accent or C.card end
			end
			local list = {}
			for _, L in opts do table.insert(list, { L[2], C.card, function() mins = L[1] paint() end }) end
			btns = buttons(body, list)
			paint()
		end
		text(body, "Reason", 13, C.muted)
		local box = input(body, a == "kick" and "Why? They see this when they are removed." or "Why? It goes in the logbook.", 300, true)
		local status = text(body, "", 13, C.red)
		buttons(body, { { a:sub(1, 1):upper() .. a:sub(2) .. " " .. p.name, a == "warn" and C.accent or Color3.fromRGB(196, 43, 28), function()
			local why = trim(box.Text)
			if why == "" then status.Text = "Write a reason." return end
			run(function()
				local d, err = ask("act", { target = p.userId, action = a, minutes = mins, reason = why })
				if d then result(d, nil, VERB[a] .. " " .. p.name .. ".", "players") else status.Text = err end
			end)
		end } })
	end

	pages.reports = function(_, my)
		local d, err = ask("reports")
		if my ~= gen then return end
		if not d then text(body, err, 14, C.red) return end
		if #(d.reports or {}) == 0 then text(body, "No open reports.", 14, C.muted) end
		local function doIt(id, what, done)
			return function()
				run(function()
					local d2, e2 = ask("report", { id = id, ["do"] = what })
					result(d2, e2, "Report #" .. id .. " " .. done .. ".", "reports")
				end)
			end
		end
		for _, r in d.reports or {} do
			local c = card()
			text(c, "#" .. r.id .. "  " .. tostring(r.from) .. (r.target ~= "" and (" about " .. tostring(r.target)) or ""), 14, C.text, true)
			text(c, r.text ~= "" and r.text or "(text hidden)", 13, r.text ~= "" and C.text or C.muted)
			text(c, (r.status == "claimed" and ("Claimed by " .. tostring(r.by)) or "Open") .. (r.here and "  \u{00B7}  in this server" or ""), 12, C.muted)
			local list = {}
			if r.status == "open" then table.insert(list, { "Claim", C.accent, doIt(r.id, "claim", "is yours") }) end
			table.insert(list, { "Resolve", C.bg, doIt(r.id, "resolve", "resolved") })
			table.insert(list, { "Dismiss", C.bg, doIt(r.id, "dismiss", "closed") })
			buttons(c, list)
		end
	end

	pages.tools = function(_, my)
		local d = ask("home")
		if my ~= gen then return end
		if d then me = d applyTabs() end
		local can = me and me.can or {}
		if can.announce then
			local c = card()
			text(c, "Announce", 15, C.text, true)
			local box = input(c, "Message for everyone in game", 200, true)
			local function send(all)
				return function()
					local t = trim(box.Text)
					if t == "" then showNotice("Write the message first.", "red", "Not sent") return end
					run(function()
						local r, err = ask("announce", { text = t, all = all })
						if r then box.Text = "" end
						result(r, err, all and "Sent to every server." or "Sent to this server.")
					end)
				end
			end
			buttons(c, { { "This server", C.accent, send(false) }, { "Every server", C.bg, send(true) } })
		end
		if can.lockdown then
			local on = me.lockdown and me.lockdown.on
			local c = card()
			text(c, "Raid lockdown", 15, C.text, true)
			text(c, on and "On. New accounts are kept out of the game." or "Keeps brand-new accounts out of the game.", 13, C.muted)
			local function turn(o, mins)
				return function()
					run(function()
						local r, err = ask("lockdown", { on = o, mins = mins })
						result(r, err, o and "Raid lockdown is on." or "Raid lockdown is lifted.", "tools")
					end)
				end
			end
			if on then buttons(c, { { "Lift lockdown", C.bg, turn(false, 0) } })
			else buttons(c, { { "For 30 minutes", Color3.fromRGB(196, 43, 28), turn(true, 30) }, { "Until lifted", C.bg, turn(true, 0) } }) end
		end
		if can.replay then
			local c = card()
			text(c, "Replay", 15, C.text, true)
			text(c, "Save the last few minutes of this server for the website.", 13, C.muted)
			buttons(c, { { "Save replay", C.accent, function()
				run(function()
					local r, err = ask("replay")
					result(r, err, "Saving a replay. It will be on the website in about a minute.")
				end)
			end } })
		end
	end

	for k, b in tabs do
		b.Activated:Connect(function()
			if panel.Visible and (current == k or (k == "players" and (current == "player" or current == "act"))) then hidePanel() else show(k) end
		end)
	end
	close.Activated:Connect(hidePanel)
	local folded = false
	face.Activated:Connect(function() -- fold the bar down to just their face, and back
		folded = not folded
		clock.Visible = not folded
		tabs.home.Visible, tabs.players.Visible = not folded, not folded
		if folded then
			tabs.reports.Visible, tabs.tools.Visible = false, false
			hidePanel()
		else
			applyTabs()
		end
	end)

	local function greet() -- "Hey, name." for a few seconds when the bar first appears
		local pill = make("TextLabel", {
			AnchorPoint = Vector2.new(0.5, 1), Position = UDim2.new(0.5, 0, 1, -74), Size = UDim2.fromOffset(0, 44), AutomaticSize = Enum.AutomaticSize.X,
			BackgroundColor3 = BAR_BG, Text = "Hey, " .. player.DisplayName .. ".", TextColor3 = C.text, FontFace = font(Enum.FontWeight.SemiBold), TextSize = 18,
		}, gui)
		round(pill)
		pad(pill, 22)
		task.delay(3.5, function()
			TweenService:Create(pill, TweenInfo.new(0.4), { BackgroundTransparency = 1, TextTransparency = 1 }):Play()
			task.wait(0.5)
			pill:Destroy()
		end)
	end
	greet()
	task.spawn(function()
		local d = ask("home")
		if d then me = d if not folded then applyTabs() end end
	end)
	local function onAttr() -- Sentinel can take the bar away (rank changed, or the owner unticked it)
		local on = player:GetAttribute("SentinelStaff") == true
		gui.Enabled = on
		if not on then hidePanel() end
	end
	player:GetAttributeChangedSignal("SentinelStaff"):Connect(onAttr)
end

task.spawn(function()
	local ok, err = pcall(buildBar)
	if not ok then warn("[Sentinel] Could not build the staff bar: " .. tostring(err)) end
end)
