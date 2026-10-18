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

local CLIENT_VERSION = 5 -- raised whenever this script changes, so the Sentinel website can tell you when to update it
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
end)
