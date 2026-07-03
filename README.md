# Discord / Telegram to LINE Forwarder

這是從參考專案抽出的精簡版：

- 保留 Telegram 監聽流程：Telethon `StringSession`、網頁勾選來源、支援 Telegram forum topic、reply 訊息補入。
- 保留 Discord 監聽流程：`discord.py-self` user token、指定 channel ID、訊息編輯更新、reply、embed、component、attachment、圖片 URL 擷取。
- 移除 GPT、AI 解析、Bitget、交易、下單與風控。
- 所有被勾選或設定監聽的來源，收到新訊息後直接推送到 LINE。

## 檔案

可直接推上 GitHub 的檔案：

```text
main.py
requirements.txt
Dockerfile
zbpack.json
.gitignore
README.md
```

不要把 `.env` 或任何 token commit 到 GitHub。所有密鑰都放 Zeabur Environment Variables。

## Zeabur 部署

1. 建立 GitHub repo。
2. 把本資料夾推上 GitHub。
3. 在 Zeabur 建立 Service，選 GitHub repo。
4. Start Command 使用預設 `python main.py`，或使用 Dockerfile 部署。
5. 設定下面的 Environment Variables。

## 必填環境變數

```env
ADMIN_PASSWORD=你的後台登入密碼
LINE_CHANNEL_ACCESS_TOKEN=LINE Messaging API channel access token
LINE_CHANNEL_SECRET=LINE Messaging API channel secret
```

至少要設定其中一種監聽來源：

```env
TG_API_ID=123456
TG_API_HASH=你的 Telegram API hash
TG_SESSION_STRING=你的 Telethon StringSession

DISCORD_USER_TOKEN=你的 Discord user token
```

LINE 收件聊天室可以先留空，部署後用 `/line/webhook` 取得，再回 Zeabur 補上：

```env
LINE_TO=Cxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

## 可選環境變數

```env
PORT=8080
DB_PATH=/tmp/app.db
TG_SOURCE_CHATS=-1001234567890,@channelname,tg-topic:-1001234567890:123
DISCORD_CHANNEL_IDS=123456789012345678,234567890123456789
ALLOW_IMAGE_SIGNAL=true
LINE_MESSAGE_PREFIX=交易訊號通知
TZ=Asia/Taipei
```

如果想讓網頁勾選與 Telegram session 在重部署後保留，請在 Zeabur 掛 persistent volume，並把 `DB_PATH` 改成例如：

```env
DB_PATH=/data/app.db
```

## LINE 設定教學

### 1. 建立 LINE 官方帳號與 Messaging API channel

1. 到 LINE Developers Console 建立 Provider。
2. 建立 Messaging API channel；LINE 會要求連結一個 LINE Official Account。
3. 進入 channel 的 Messaging API 分頁。
4. 發行或複製 `Channel access token`，填入 Zeabur 的 `LINE_CHANNEL_ACCESS_TOKEN`。
5. 複製 `Channel secret`，填入 Zeabur 的 `LINE_CHANNEL_SECRET`。

### 2. 開啟群組使用

1. 到 LINE Official Account Manager。
2. 進入該官方帳號設定。
3. 開啟允許加入群組或多人聊天室。
4. 關閉或調整自動回覆，避免每則訊息都被官方帳號自動回。

### 3. 設定 Webhook

1. 等 Zeabur 部署完成，取得公開網域，例如 `https://your-service.zeabur.app`。
2. 回 LINE Developers Console 的 Messaging API 分頁。
3. Webhook URL 填入：

```text
https://your-service.zeabur.app/line/webhook
```

4. 啟用 `Use webhook`。
5. 按 Verify，成功後代表 LINE 可以打到你的 Zeabur service。

### 4. 取得 LINE_TO

一對一通知：

1. 用你的 LINE 加官方帳號好友。
2. 對官方帳號傳 `/id`。
3. 官方帳號會回覆 `LINE_TO=U...`。
4. 把 `U...` 填入 Zeabur 的 `LINE_TO`。

群組通知：

1. 把官方帳號邀請進你的 LINE 群組。
2. 在群組傳 `/id`。
3. 官方帳號會回覆 `LINE_TO=C...`。
4. 把 `C...` 填入 Zeabur 的 `LINE_TO`。

也可以登入本服務後到 `/line/events` 看最近收到的 LINE event，複製 `line_to` 欄位。

## Telegram 設定教學

### 1. 取得 TG_API_ID / TG_API_HASH

1. 到 https://my.telegram.org 登入。
2. 進入 API development tools。
3. 建立 app。
4. 複製 `api_id` 與 `api_hash` 到 Zeabur：

```env
TG_API_ID=123456
TG_API_HASH=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### 2. 建立 TG_SESSION_STRING

方法 A：用部署後網頁建立

1. 部署後登入後台。
2. 進入 `Telegram 登入`。
3. 輸入手機號碼，格式例如 `+8869xxxxxxxx`。
4. Telegram 收到驗證碼後填入。
5. 若有兩步驟密碼，也填入。
6. 頁面會顯示 `StringSession`。
7. 建議複製到 Zeabur 的 `TG_SESSION_STRING`，然後重新部署或 restart。

方法 B：已經有 `TG_SESSION_STRING`

直接填入 Zeabur：

```env
TG_SESSION_STRING=你的 Telethon StringSession
```

### 3. 勾選 Telegram 來源

1. 登入後台。
2. 進入 `Telegram 來源`。
3. 按 `刷新 Telegram 頻道清單`。
4. 勾選要轉發到 LINE 的群組、頻道或 forum topic。
5. 按 `儲存來源`。

如果清單抓不到，也可手動填：

```text
-1001234567890
@channelname
tg-topic:-1001234567890:123
```

## Discord 設定教學

參考程式使用 Discord user token / self-bot 監聽流程，本版照同樣方式保留。這類用法可能違反 Discord 使用條款，請自行確認帳號風險。

1. Zeabur 設定：

```env
DISCORD_USER_TOKEN=你的 Discord user token
```

2. Discord 開啟 Developer Mode。
3. 右鍵要監聽的頻道，複製 Channel ID。
4. 登入本服務後進入 `設定`。
5. 把 Channel ID 一行一個貼到 `Discord 頻道 ID`。
6. 儲存後，該 channel 的新訊息、編輯、reply、embed、attachment 會轉發到 LINE。

## GitHub 上傳指令

```bash
git init
git add main.py requirements.txt Dockerfile zbpack.json README.md .gitignore
git commit -m "Initial dc tg line forwarder"
git branch -M main
git remote add origin YOUR_GITHUB_REPO_URL
git push -u origin main
```

## 常見問題

- LINE 沒收到：先按控制台的 `送 LINE 測試`，確認 `LINE_CHANNEL_ACCESS_TOKEN` 與 `LINE_TO`。
- 不知道 LINE_TO：確認 webhook URL 啟用，加入好友或邀請進群組後傳 `/id`。
- Telegram 沒收到：確認 `TG_SESSION_STRING` 有效，帳號看得到該群組，且來源有勾選。
- Discord 沒收到：確認 `DISCORD_USER_TOKEN`、Channel ID、帳號是否看得到該頻道。
- 重部署後勾選不見：改用 env `TG_SOURCE_CHATS` / `DISCORD_CHANNEL_IDS`，或使用 persistent volume 搭配 `DB_PATH=/data/app.db`。
