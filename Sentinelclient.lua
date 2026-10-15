--[[
	Sentinel player script (optional, but recommended)

	WHAT IT DOES
	  1. When a moderator mutes a player in Sentinel, this hides that player's chat bar and chat window (including Quick Words) completely,
	     and brings it back when the mute ends. Without it, a muted player's messages are still
	     stopped by the server, but they can still type.
	  2. Adds a small Report button. Players pick who they are reporting (optional), say what happened and press Send.
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

local C = {
	bg = Color3.fromRGB(24, 28, 40), card = Color3.fromRGB(36, 42, 60), text = Color3.fromRGB(235, 239, 250),
	muted = Color3.fromRGB(150, 160, 185), accent = Color3.fromRGB(94, 124, 255), red = Color3.fromRGB(255, 120, 120),
}

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
		Name = "Open", Size = UDim2.fromOffset(74, 32), AnchorPoint = Vector2.new(0, 0.5), Position = BUTTON_POSITION,
		BackgroundColor3 = C.bg, BackgroundTransparency = 0.1, Text = "Report", TextColor3 = C.text,
		Font = Enum.Font.GothamMedium, TextSize = 14, AutoButtonColor = true,
	}, gui)
	make("UICorner", { CornerRadius = UDim.new(1, 0) }, open)
	make("UIStroke", { Color = C.accent, Thickness = 1.5, Transparency = 0.25 }, open)

	local panel = make("Frame", {
		Name = "Panel", Visible = false, Size = UDim2.fromOffset(320, 380), AnchorPoint = Vector2.new(0.5, 0.5),
		Position = UDim2.fromScale(0.5, 0.5), BackgroundColor3 = C.bg,
	}, gui)
	make("UICorner", { CornerRadius = UDim.new(0, 14) }, panel)
	make("UIStroke", { Color = C.accent, Thickness = 1, Transparency = 0.5 }, panel)

	local function label(text, y, size, color, font)
		return make("TextLabel", {
			BackgroundTransparency = 1, Position = UDim2.fromOffset(16, y), Size = UDim2.fromOffset(288, size + 6), Text = text,
			TextColor3 = color, Font = font, TextSize = size, TextXAlignment = Enum.TextXAlignment.Left,
		}, panel)
	end
	label("Report a problem", 12, 18, C.text, Enum.Font.GothamBold)
	label("Who is it about? (optional)", 40, 13, C.muted, Enum.Font.Gotham)

	local list = make("ScrollingFrame", {
		Position = UDim2.fromOffset(16, 64), Size = UDim2.fromOffset(288, 120), BackgroundColor3 = C.card, BorderSizePixel = 0,
		ScrollBarThickness = 4, CanvasSize = UDim2.new(), AutomaticCanvasSize = Enum.AutomaticSize.Y,
	}, panel)
	make("UICorner", { CornerRadius = UDim.new(0, 8) }, list)
	make("UIListLayout", { Padding = UDim.new(0, 2), SortOrder = Enum.SortOrder.LayoutOrder }, list)

	label("What happened?", 192, 13, C.muted, Enum.Font.Gotham)
	local box = make("TextBox", {
		Position = UDim2.fromOffset(16, 216), Size = UDim2.fromOffset(288, 86), BackgroundColor3 = C.card, BorderSizePixel = 0,
		Text = "", PlaceholderText = "Describe it in a sentence or two", PlaceholderColor3 = C.muted, TextColor3 = C.text,
		Font = Enum.Font.Gotham, TextSize = 14, TextWrapped = true, MultiLine = true, ClearTextOnFocus = false,
		TextXAlignment = Enum.TextXAlignment.Left, TextYAlignment = Enum.TextYAlignment.Top,
	}, panel)
	make("UICorner", { CornerRadius = UDim.new(0, 8) }, box)
	make("UIPadding", { PaddingLeft = UDim.new(0, 8), PaddingRight = UDim.new(0, 8), PaddingTop = UDim.new(0, 6) }, box)
	box:GetPropertyChangedSignal("Text"):Connect(function()
		if #box.Text > 200 then box.Text = string.sub(box.Text, 1, 200) end
	end)

	local status = label("", 306, 12, C.red, Enum.Font.Gotham)

	local function button(text, x, color)
		local b = make("TextButton", {
			Position = UDim2.fromOffset(x, 332), Size = UDim2.fromOffset(140, 36), BackgroundColor3 = color, Text = text,
			TextColor3 = C.text, Font = Enum.Font.GothamMedium, TextSize = 14, AutoButtonColor = true,
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
			Font = Enum.Font.Gotham, TextSize = 13, TextXAlignment = Enum.TextXAlignment.Left, LayoutOrder = order, AutoButtonColor = false,
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
