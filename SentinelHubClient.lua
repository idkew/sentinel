-- Sentinel appeal game: the player's screen. Put this LocalScript in StarterPlayerScripts, next to SentinelHub in ServerScriptService.
-- Shows every game that banned the player and lets them write an appeal. The player can walk around and chat the whole time.

local Players = game:GetService("Players")
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local player = Players.LocalPlayer
local remote = ReplicatedStorage:WaitForChild("SentinelHub", 30)
if not remote then warn("[Sentinel] SentinelHub is missing from ServerScriptService.") return end

local INK, MUTED, CARD, ACCENT = Color3.fromRGB(246, 246, 248), Color3.fromRGB(176, 176, 185), Color3.fromRGB(20, 20, 23), Color3.fromRGB(10, 132, 255)
local function make(class, props, parent)
	local o = Instance.new(class)
	for k, v in pairs(props) do o[k] = v end
	o.Parent = parent
	return o
end
local function label(text, size, color, parent, order, bold)
	return make("TextLabel", {
		BackgroundTransparency = 1, Size = UDim2.new(1, 0, 0, 0), AutomaticSize = Enum.AutomaticSize.Y, TextWrapped = true,
		TextXAlignment = Enum.TextXAlignment.Left, Font = bold and Enum.Font.GothamBold or Enum.Font.GothamMedium,
		TextSize = size, TextColor3 = color, Text = text, LayoutOrder = order or 0,
	}, parent)
end
local function button(text, parent, order, primary)
	local b = make("TextButton", {
		Size = UDim2.new(0, 150, 0, 34), BackgroundColor3 = primary and ACCENT or Color3.fromRGB(58, 58, 64), BorderSizePixel = 0,
		TextColor3 = INK, Font = Enum.Font.GothamBold, TextSize = 14, Text = text, LayoutOrder = order or 0, AutoButtonColor = true,
	}, parent)
	make("UICorner", { CornerRadius = UDim.new(0, 9) }, b)
	return b
end

local gui = make("ScreenGui", { Name = "SentinelAppeals", ResetOnSpawn = false, IgnoreGuiInset = true, DisplayOrder = 50 }, player:WaitForChild("PlayerGui"))
local panel = make("Frame", {
	AnchorPoint = Vector2.new(0.5, 0.5), Position = UDim2.fromScale(0.5, 0.5), Size = UDim2.fromScale(0.92, 0.8),
	BackgroundColor3 = CARD, BackgroundTransparency = 0.03, BorderSizePixel = 0,
}, gui)
make("UISizeConstraint", { MaxSize = Vector2.new(480, 620) }, panel)
make("UICorner", { CornerRadius = UDim.new(0, 18) }, panel)
make("UIStroke", { Color = Color3.new(1, 1, 1), Transparency = 0.9, Thickness = 2 }, panel)
local body = make("ScrollingFrame", {
	BackgroundTransparency = 1, BorderSizePixel = 0, Size = UDim2.fromScale(1, 1), CanvasSize = UDim2.new(), AutomaticCanvasSize = Enum.AutomaticSize.Y,
	ScrollBarThickness = 4, ScrollingDirection = Enum.ScrollingDirection.Y,
}, panel)
make("UIPadding", { PaddingTop = UDim.new(0, 20), PaddingBottom = UDim.new(0, 20), PaddingLeft = UDim.new(0, 20), PaddingRight = UDim.new(0, 20) }, body)
make("UIListLayout", { Padding = UDim.new(0, 10), SortOrder = Enum.SortOrder.LayoutOrder }, body)

local function clear() for _, c in ipairs(body:GetChildren()) do if c:IsA("GuiObject") then c:Destroy() end end end
local STATUS = { open = "Waiting for review", accepted = "Accepted. You have been unbanned.", denied = "Denied" }
local showList

local function showForm(g)
	clear()
	label("Appeal to " .. g.game, 20, INK, body, 1, true)
	label("Banned for: " .. g.reason, 14, MUTED, body, 2)
	local box = make("TextBox", {
		Size = UDim2.new(1, 0, 0, 150), BackgroundColor3 = Color3.fromRGB(44, 44, 48), BorderSizePixel = 0, ClearTextOnFocus = false, MultiLine = true,
		TextWrapped = true, TextXAlignment = Enum.TextXAlignment.Left, TextYAlignment = Enum.TextYAlignment.Top, Font = Enum.Font.GothamMedium, TextSize = 14,
		TextColor3 = INK, PlaceholderText = "Explain what happened and what you will do differently.", PlaceholderColor3 = MUTED, Text = "", LayoutOrder = 3,
	}, body)
	make("UICorner", { CornerRadius = UDim.new(0, 9) }, box)
	make("UIPadding", { PaddingTop = UDim.new(0, 8), PaddingLeft = UDim.new(0, 10), PaddingRight = UDim.new(0, 10) }, box)
	local msg = label("Staff of " .. g.game .. " read this. Sending false information may get a denied appeal.", 13, MUTED, body, 4)
	local row = make("Frame", { BackgroundTransparency = 1, Size = UDim2.new(1, 0, 0, 34), LayoutOrder = 5 }, body)
	make("UIListLayout", { FillDirection = Enum.FillDirection.Horizontal, Padding = UDim.new(0, 10) }, row)
	local send = button("Send appeal", row, 1, true)
	local back = button("Back", row, 2)
	back.Activated:Connect(function() showList() end)
	local sending = false
	send.Activated:Connect(function()
		if sending then return end
		sending = true
		send.Text = "Sending..."
		local ok, res = pcall(function() return remote:InvokeServer("appeal", g.wid, string.sub(box.Text, 1, 1000)) end)
		sending = false
		send.Text = "Send appeal"
		if ok and type(res) == "table" and res.ok then
			clear()
			label("Appeal sent", 20, INK, body, 1, true)
			label("Staff of " .. g.game .. " will review it. Come back to this game to see the answer.", 14, MUTED, body, 2)
			button("Back", body, 3).Activated:Connect(function() showList() end)
		else
			msg.Text = (ok and type(res) == "table" and type(res.error) == "string") and res.error or "Could not send it. Try again in a minute."
			msg.TextColor3 = Color3.fromRGB(255, 105, 97)
		end
	end)
end

showList = function()
	clear()
	label("Appeal a ban", 22, INK, body, 1, true)
	label("Official Sentinel appeal game. These are the games that banned you and use Sentinel.", 14, MUTED, body, 2)
	local wait = label("Loading...", 14, MUTED, body, 3)
	local ok, res = pcall(function() return remote:InvokeServer("list") end)
	if not ok or type(res) ~= "table" then wait.Text = "Could not load your bans. Rejoin to try again." return end
	if res.error then wait.Text = tostring(res.error) return end
	local games = type(res.games) == "table" and res.games or {}
	if #games == 0 then wait.Text = "No game using Sentinel has an active ban on your account." return end
	wait:Destroy()
	for i, g in ipairs(games) do
		local card = make("Frame", { BackgroundColor3 = Color3.fromRGB(36, 36, 40), BorderSizePixel = 0, Size = UDim2.new(1, 0, 0, 0), AutomaticSize = Enum.AutomaticSize.Y, LayoutOrder = 10 + i }, body)
		make("UICorner", { CornerRadius = UDim.new(0, 12) }, card)
		make("UIPadding", { PaddingTop = UDim.new(0, 12), PaddingBottom = UDim.new(0, 12), PaddingLeft = UDim.new(0, 14), PaddingRight = UDim.new(0, 14) }, card)
		make("UIListLayout", { Padding = UDim.new(0, 6), SortOrder = Enum.SortOrder.LayoutOrder }, card)
		label(g.game, 16, INK, card, 1, true)
		label("Banned for: " .. g.reason .. (g.expires and ("  ·  ends " .. os.date("%b %d, %Y", math.floor(g.expires / 1000))) or "  ·  permanent"), 13, MUTED, card, 2)
		if g.status then label("Your last appeal: " .. (STATUS[g.status] or g.status), 13, g.status == "denied" and Color3.fromRGB(255, 105, 97) or g.status == "accepted" and Color3.fromRGB(48, 209, 88) or ACCENT, card, 3, true) end
		if g.reply and g.reply ~= "" then label("Message from staff: " .. g.reply, 13, INK, card, 4) end
		if g.can then
			button("Write an appeal", card, 5, true).Activated:Connect(function() showForm(g) end)
		elseif g.why ~= "" then
			label(g.why, 13, MUTED, card, 5)
		end
	end
	button("Refresh", body, 100).Activated:Connect(function() showList() end)
end

showList()
