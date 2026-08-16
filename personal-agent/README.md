# Local Personal Agent

要件定義書の確定構成に基づく、単一ユーザー向けローカルPersonal Agent Runtimeです。
Web・LINE・ローカル音声を同じAgent Core、Task State、Event Bus、Personal Memoryへ接続し、
Windows上のBrowser/Auth/Secret Worker、Communication、Calendar、Sandbox経済操作、
Proactive Agentまでを一つの安全境界で扱います。
Phase別の対応範囲は [docs/implementation-status.md](docs/implementation-status.md) にあります。

## 現在できること

- Web PWA、LINE Messaging API、Voice Gatewayのテキスト入力を共通形式で受付
- チャネルをまたいだTask IDの引き継ぎ
- SQLiteによるTask、Plan、Event、Message、Action、Audit、Scheduler Jobの永続化
- `RECEIVED` から `COMPLETED` までの状態遷移とPause/Resume/Cancel
- 再起動時に処理途中のTaskを自動実行せず、安全な `PAUSED` 状態へ復旧
- 時刻、タイマー、アラーム、状態確認、停止をQwenなしのTier 0で処理
- その他の依頼をOpenAI互換のローカルQwen endpointへ送るDeep Path
- Mutation ToolのIdempotency Key、Dry-run、型検証、Policy判定、監査
- stepごとに固定したTool/permission/riskと、Tool Brokerでの`required_permissions`強制
- 外部Web・メール・ファイル内容から後続stepの権限を増やせないCapability Plan
- 永続Timer/AlarmとVoice/PWAへのclaim・ack型通知配信
- Global Pause、Finance Lock、Browser Lock、Secret Lock
- LINE webhookの署名検証、Primary User限定、Webhook再送の重複排除
- Secret系の監査ログ自動redaction
- Voice/LINE/Web会話の共通Raw Event化と90日Retention
- 日本語substring対応SQLite FTSによるPersonal Search
- Evidence付きLong-term Memory、Preference、Entity、Decision Log
- 「覚えて」「忘れて」「メモリ検索」のTier 0処理と必要量だけのQwen context注入
- Safari Activity Batch受信、Sensitive DomainのOrigin-only化、Domain禁止設定
- AES-GCM offline queueを持つSafari Web Extension source
- Windows Playwright Worker、6用途別Persistent Chrome Profile、通常表示Chrome
- 型付きBrowser Primitive、DOM参照ID、DOM→mask済みScreenshot→座標操作の強制順序
- finance allowlist、隔離Download、Mutation Idempotency、Human Takeover lock
- trackedなQwen Chat Completions clientとstep-scoped tool-call loop（最大12 turn）
- Windows user-scoped DPAPI Secret Store、Origin/Action binding、TOTP direct-fill
- `auth.ensure_authenticated`、既存Session優先、曖昧Account停止、OTP Task binding
- 1回限りの承認Grant、WebAuthn UVによるR4/R5承認、PWA承認/OTP/Secret履歴
- LINE/Slack/Gmailを共通形式へ正規化し、検索・thread取得・下書き・送信を分離
- Slack/Gmail tokenをCoreやLLMへ渡さないPrivileged Connector Worker
- ローカルCalendarの検索・空き時間・作成・更新・取消と永続Scheduler
- Agent実行Taskとは別tableのPersonalTodoと構造化Diary、Asia/Tokyoの深夜business date
- Economic Action、確定見積、Budget、Payee、Sandbox送金、照合、`SUBMITTED_UNKNOWN`
- allowlist root内だけのFile検索・読取・コピー・移動・改名・回収可能な削除
- Home Assistantの状態取得・照明・温度・Scene（lock/alarmはfail-closed）
- 既定OFFのProactive検出、quiet hours、通知頻度、根拠付き継続follow-up
- Daily Summary、Memory decay、根拠付きPreference候補、実行無効のWorkflow候補
- System Health、モデル/tool latency、監査検索、暗号化backup、秘密を含まないexport、範囲削除
- 17カテゴリのdry-run Benchmark HarnessとPWA管理画面

外部Mutationは、stepでToolが公開され、必要permissionがgrantされ、Worker Token、Safety Lock、
Risk Policy、承認、Evidenceを通過した場合だけ
実行します。購入・予約は型付きBrowser操作とEconomic Intentで実現できる構成ですが、
実サイトごとの専用Adapterは同梱していません。実銀行への送金は意図的に未接続で、
Money機能はSandboxだけです。実行していないDeep Pathは
`external_action_performed=false`、送信結果が不明な場合は
`external_action_may_have_occurred=true` をEvidenceへ記録します。

## 構成

```text
Voice text / LINE webhook / Web PWA
                  │
                  ▼
             AgentService
        ┌─────────┴─────────┐
        ▼                   ▼
  Tier 0 Router       Local Qwen client
        │                   │
        └─────────┬─────────┘
                  ▼
 Step Capability → Policy → Tool Broker
                  │
                  ▼
 SQLite Task / Action / Audit / FTS Memory / Calendar / Economic Intent
                  │
                  ▼ authenticated loopback
 Windows Playwright Worker → Chrome Profiles / DPAPI Secret Store / Slack / Gmail
```

## 必要環境

- Python 3.11以上
- localhostで動作するOpenAI Chat Completions互換のQwen server
- LINEを使う場合のみLINE Messaging APIのChannel Secret、Access Token
- Browser/Authを使う場合はWindows 11、ChromeまたはPlaywright Chromium、BitLocker/Device Encryption

Cloud LLMは既定で禁止されています。モデルURLのhostがlocalhostまたはloopbackでない
場合は起動時に拒否します。意図的に変更する場合のみ
`PERSONAL_AGENT_ALLOW_REMOTE_MODEL=true` を設定してください。

## セットアップ

```bash
cd personal-agent
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
cp .env.example .env
```

Windows Browser Worker用環境はCoreとは別です。WindowsユーザーのPowerShellから次を一度実行すると、
専用venv、headed Chrome、DPAPI Secret Store、ログオン時Scheduled Task、強い共有token、ACL、
WSL仮想NICだけに限定したFirewall ruleを自動構成し、Coreを再起動します。Firewall設定時だけUACが
1回表示されます。tokenは表示しません。

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install-browser-worker.ps1
```

WorkerはWindows hostの`18790`で待ち受けますが、Windows FirewallではWSL Hyper-V interface、
Worker実行ファイル、TCP 18790、private WSL addressだけに限定されます。アプリ層でも送信元CIDRと
64文字級tokenを検証します。Wi-Fi/LAN/TailscaleからWorkerへ直接接続できません。Production Workerは
Windows以外では起動を拒否します。手動構成を監査する場合は次も利用できます。

```powershell
.\scripts\windows-browser-preflight.ps1
```

既定は `127.0.0.1:8790`、headed Chrome (`channel=chrome`) です。Profileは
`general / communication / shopping / travel / finance / administration` の別々の
user-data directoryです。通常利用中のChrome profileは再利用しません。

### Credential登録

Credential値は `.env`、Core DB、Memory、audit、CLI引数へ入れません。PWAのSafety画面でFace IDまたは
Windows Helloへサインインし、`Secret Broker`の登録フォームへexact Origin、username、password、
任意のTOTP seedを入力できます。値は書き込み専用APIからWindows Workerへ渡り、現在のWindows
ユーザーにbindingしたDPAPI ciphertextとして保存されます。応答にはmetadataしか含まれません。

CLIで登録する場合はWindows側の非表示promptも利用できます。

```powershell
personal-agent-secret put secret://travel/example/main `
  --kind password `
  --account-label main `
  --origin https://login.example.com `
  --action password_fill
```

CLI値は非表示promptから2回入力され、Windowsの現在ユーザーにBindingしたDPAPI ciphertextだけが
独立 `secrets.sqlite3` に保存されます。TOTPは `--kind totp_seed --action totp_fill` で登録します。
モデルとCoreが受け取れるのはCredential IDとmetadataだけです。非Windows開発環境でのみ、
外部Secret Manager等から `PERSONAL_AGENT_SECRET_MASTER_KEY` を注入してFernet backendを
使えます。keyをrepositoryや `.env` へ保存しないでください。

Slack/Gmail connectorもtokenをWindows Secret Storeへ対話登録します。

```powershell
personal-agent-secret put secret://connector/slack/main `
  --kind api_token `
  --account-label main `
  --origin https://slack.com `
  --action connector_request

personal-agent-secret put secret://connector/gmail/main `
  --kind api_token `
  --account-label main `
  --origin https://gmail.googleapis.com `
  --action connector_request
```

Core側には値ではなく参照だけを設定します。

```text
PERSONAL_AGENT_SLACK_CREDENTIAL_ID=secret://connector/slack/main
PERSONAL_AGENT_GMAIL_CREDENTIAL_ID=secret://connector/gmail/main
```

Slackは `chat:write` と `search:read` を持つtoken、Gmailはmessagesのread/send scopeを持つ
access tokenが必要です。OAuth refresh flowは同梱していないため、期限切れtokenはSecret CLIで
再登録してください。Slack送信先は曖昧な表示名ではなくchannel/conversation ID、Gmail送信先は
正確なメールアドレスを使用します。

PWAでSlack/Gmail connectorを失効すると、Core側のpermissionを永続的にOFFにし、到達可能なら
Worker側credentialも同時にdisableします。再有効化にはSecret CLIでのtoken再登録が必要です。

`.env` のモデルURL、モデル名、十分に長いAdmin Tokenを編集した後、環境へ読み込んで
起動します。

```bash
set -a
. ./.env
set +a
personal-agent
```

既定では `http://127.0.0.1:8787` でWeb UIが開きます。このCyborg用に生成済みの`.env`は、
既存Gatewayとの競合を避けて8789番を使用します。SQLiteは`./data/personal-agent.sqlite3` に
作成されます。

このCyborgでは同梱user systemd unitでCoreを常駐化できます。

```bash
mkdir -p data
systemctl --user link "$PWD/deploy/systemd/personal-agent.service"
systemctl --user enable --now personal-agent.service
systemctl --user status personal-agent.service
```

Qwenのmodelと`llama-server`を用意した後は同様にQwen unitを有効化します。

```bash
systemctl --user link "$PWD/deploy/systemd/personal-agent-qwen.service"
systemctl --user enable --now personal-agent-qwen.service
```

## Qwen接続

初期構成は、WSL Ubuntu上のCUDA対応llama.cpp、
`unsloth/Qwen3.6-35B-A3B-GGUF`の`UD-Q4_K_XL`（約22.4GB）に固定します。
同梱launcherは`--n-gpu-layers all --n-cpu-moe 40`を指定するため、40層のMoE expert重みを
CPUへ置き、それ以外のoffload可能な重みをGPUへ置きます。

モデルは起動時に自動downloadしません。WSLのext4 filesystem上へ明示的に取得してください。
`curl`だけで再開downloadとSHA-256検証を行う同梱scriptを使えます。

```bash
./scripts/download-qwen.sh
```

Hugging Face CLIを使う場合は次でも同じartifactを取得できます。

```bash
mkdir -p models
hf download unsloth/Qwen3.6-35B-A3B-GGUF \
  Qwen3.6-35B-A3B-UD-Q4_K_XL.gguf --local-dir ./models
sha256sum models/Qwen3.6-35B-A3B-UD-Q4_K_XL.gguf
```

期待するSHA-256は`.env.example`に固定しています。CUDA対応`llama-server`を用意し、
Coreと同じ`PERSONAL_AGENT_MODEL_API_KEY`を環境へ読み込んで起動します。

```bash
set -a
. ./.env
set +a
./scripts/start-qwen.sh
```

`llama-server`がPATHにない場合は、CUDA対応llama.cpp buildの実行ファイルを指定します。

```text
PERSONAL_AGENT_LLAMA_SERVER_BIN=/path/to/llama.cpp/build/bin/llama-server
```

このCyborgでは公式llama.cpp commit `885c5bbe8e04`をCUDA 13.2 / compute capability 8.9向けに
`$HOME/.local/src/llama.cpp/build/bin/llama-server`へbuildし、`.env`へ設定します。

launcherはQwen endpointをloopbackだけにbindし、llama.cpp内蔵Web UIとslot APIを無効化します。
単一ユーザー用にparallel slotは1です。ContextはRTX 4060 Laptop 8GB / RAM 64GBの初期値として
32768です。VRAM/RAMと実測を確認して
`PERSONAL_AGENT_QWEN_CONTEXT_SIZE`だけを調整できます。`--n-cpu-moe 40`は変更できません。

Qwen 3.6の思考モードは短い応答でも推論tokenだけで出力枠を使い切る場合があるため、Coreは既定で
`chat_template_kwargs.enable_thinking=false`を送ります。必要な検証時だけ
`PERSONAL_AGENT_MODEL_ENABLE_THINKING=true`で再有効化できます。このCyborgで通常応答と実Tool loopを
確認した実測生成速度は約25〜28 token/秒です。

CoreはOpenAI互換の次のendpointへ接続します。

```text
POST http://127.0.0.1:8000/v1/chat/completions
```

接続できない場合、Taskは
`WAITING_EXTERNAL` で保存され、Web UIまたはAPIから再開できます。

## 実サイト認証と強い本人承認

実サイトへのログインは、まず用途別Chrome Profileの既存Sessionを再利用します。Session切れ時は、
Windows WorkerがDPAPI Secret Storeからusername、PasswordまたはTOTP Seedを復号し、値をCoreやQwenへ返さず
対象OriginのBrowser fieldへ直接入力します。Email/SMS OTPはPWAの認証画面へ本人が入力し、
Task・Origin・Account・期限へbindingして一度だけBrowserへ渡します。Passkey、Face ID、3-D Secure、
銀行アプリ承認、CAPTCHAは自動化せず、同じChrome ContextをHuman Takeoverして本人が完了します。

Browser WorkerはURL移動、DOM snapshot、click/type/select/check、upload、隔離download、tab作成・終了・
切替、戻る・進む・再読込、hover、bounded key press、scroll、wait、secretをmaskしたscreenshotを扱います。
外部送信やform確定は`browser.submit`で、期待URLまたは新しい確認表示を送信後に観測できた場合だけ成功に
します。結果を確認できない場合は`submitted_unknown`として同じidempotency keyの自動再送を止めます。
任意JavaScript実行、認証回避、OS全体の遠隔操作は提供しません。

これとは別に、Agent自身のR4/R5 ActionはPWAへ登録したWebAuthn passkeyで承認します。
iPhoneではFace ID、WindowsではWindows Helloを使えます。server challengeにはApproval ID、Task ID、
Tool名、正規化済み引数hash、表示した要約、Risk、期限、nonceをbindingし、exact Origin/RP ID、署名、
user-presence/user-verification flag、sign counterを検証してから1回だけ承認Grantを消費します。
Admin TokenだけではR4/R5を承認できません。WebAuthn未設定またはpasskey未登録時はfail-closedです。

遠隔PWAはさらに、loopbackへ到達するTailscale Serveが付与するidentity、または送信元をPROXY protocolで検証した
Tailnet限定TLS proxyのidentityを`PERSONAL_AGENT_TAILSCALE_ALLOWED_USERS`と完全一致で照合します。
Coreはloopbackにしかbindせず、許可したTailscale identity以外はPWA本体を含め403で拒否します。
許可identityでも、初回passkey登録用endpoint以外の遠隔HTTP APIとVoice WebSocketは、有効な
Secure/HttpOnly passkey sessionがなければ拒否します。
したがってAdmin Tokenはbootstrap authorityであり、通常の遠隔API bearer tokenとしては使えません。

Coreを`100.64.0.0/10`へ直接bindする構成は例外扱いです。この場合はallowed user、remote passkey、
exact WebAuthn設定に加え、`PERSONAL_AGENT_TAILSCALE_PEER_IDENTITIES`へTailscale source IPとidentityの
固定対応を設定しない限り起動を拒否します。直接接続ではクライアントが送った
`Tailscale-User-Login`やproxy markerをidentity根拠として使いません。通常運用ではこの対応表を空にし、
Coreをloopbackのままtrusted proxy経由で利用してください。

iPhoneを含む初回設定は [docs/iphone-setup.md](docs/iphone-setup.md) を参照してください。最初の
passkey登録だけはAdmin Tokenが必要で、2本目以降は登録済みpasskey sessionで許可します。

## LINE

LINE Notifyは2025年3月31日に終了したため、LINE公式アカウントのMessaging APIを使います。
LINE Developers ConsoleでMessaging API channelを作成し、自分のLINEから公式アカウントを
友だち追加します。その後、次の対話式コマンドへChannel secret、Channel access token、
Basic settingsの`Your user ID`を入力します。secret/tokenは画面へ表示されません。

```bash
cd personal-agent
.venv/bin/python scripts/configure-line.py
```

この操作により`.env`の次の3値が設定されます。

```text
PERSONAL_AGENT_LINE_CHANNEL_SECRET=...
PERSONAL_AGENT_LINE_CHANNEL_ACCESS_TOKEN=...
PERSONAL_AGENT_LINE_PRIMARY_USER_ID=U...
```

Webhook URLは次です。

```text
https://your-machine.your-tailnet.ts.net/personal-agent-line-webhook
```

外部公開するのはこの1 pathだけです。PWA、API、Qwenは引き続きTailnet/loopback限定です。
Core内部では`POST /api/channels/line/webhook`へ転送し、生の本文に対するHMAC-SHA256署名が
一致し、eventの`source.userId`がPrimary User IDと完全一致するテキストだけを処理します。

公開経路を設定したら、ConsoleのMessaging APIタブで`Use webhook`をONにし、次を実行します。
token/user IDの有効性、Webhook疎通、本人宛てPush通知をまとめて確認します。

```bash
.venv/bin/python scripts/configure-line.py --activate \
  --webhook-url https://your-machine.your-tailnet.ts.net/personal-agent-line-webhook
```

接続後はLINEからの依頼がWebと同じTask/Memoryへ入り、Webや音声で登録したTimer、Alarm、
ReminderもLINEへPushされます。PWA側の通知は別deliveryとして残るため、LINE送信で消費されません。
送信は同じ`X-Line-Retry-Key`で再試行し、重複Pushを防ぎます。

### 個人LINE Desktop Bridge

Messaging APIでは取得できない個人アカウントの表示内容には、ログイン済みWindows版LINEを使う
ローカルBridgeを用意しています。画面キャプチャはメモリ内だけでWindows日本語OCRへ渡し、画像を
ファイル保存しません。BridgeとCoreはいずれもloopback限定で、BridgeからCoreへ共有トークン付きで
60秒ごとに表示中のチャット一覧プレビューと、現在開いている会話の表示範囲をPushします。

Windowsユーザーの対話セッションから次を一度実行すると、専用venv、強いランダムトークン、ACLを
制限した設定・DB、ログオン時のScheduled Taskを構成し、Coreを再起動します。tokenは表示しません。

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install-line-desktop-bridge.ps1
```

LINEがログイン画面なら、Windows LINEでQRコード等を使って本人がログインしてください。PWAの
Operationsに`LINE Desktop Bridge`状態が表示されます。同期済み本文はChatから検索できますが、
OCRなので誤認識の可能性があります。また未読チャットを自動で開くと既読になるため、既定では
会話をクリックせず、現在描画されている範囲だけを読みます。

送信は既定で無効です。Windows LINEへ本人がログインして対象チャットを表示したあと、次の対話式
コマンドで表示された会話名から送信を許可する宛先だけを選びます。本文やLINE credentialは表示・抽出
しません。

```powershell
powershell -ExecutionPolicy Bypass -File scripts\configure-line-desktop-send.ps1
```

送信時はCoreのR2承認と下書き固定後、Bridgeがallowlistのconversation IDから画面上の行を特定し、
クリック後の会話headerをOCRで再照合してから入力します。送信後に同じ会話のoutgoing本文をOCRで確認
できた場合だけ`ok`にし、確認不能なら`submitted_unknown`として再送しません。停止するには
`-Disable`を付けます。LINEの認証回避、暗号化ローカルDBやcredentialの抽出、削除済みメッセージの
復元は行いません。

## ローカル音声

Windows側で動かす `personal-agent-voice` を同梱しています。openWakeWord、ローカルEnergy
VAD、whisper.cpp、Piper、マイク・スピーカーをつなぎ、STT済みテキストだけをCoreへ渡します。
Wake Word待機中の音声は保存せず、発話中の一時WAVとTTS出力は各処理後に削除します。

Windows側のPython環境で追加依存を導入します。

```powershell
py -m venv .venv-voice
.venv-voice\Scripts\Activate.ps1
pip install -e ".[voice]"
pip install piper-tts
```

次をWindowsの環境変数へ設定します。

```text
PA_VOICE_CORE_URL=http://127.0.0.1:8787
PA_VOICE_WAKE_MODEL=C:\models\hey_jarvis_v0.1.onnx
PA_VOICE_WHISPER_CLI=C:\whisper.cpp\build\bin\Release\whisper-cli.exe
PA_VOICE_WHISPER_MODEL=C:\models\ggml-large-v3-turbo.bin
PA_VOICE_PIPER_MODEL=<インストールした日本語voice名またはmodel path>
PA_VOICE_PIPER_DATA_DIR=C:\models\piper
```

起動:

```powershell
personal-agent-voice
```

openWakeWordは16kHz/16-bit PCMの80ms frame、whisper.cppは16-bit WAVを使用する公式interfaceに
合わせています。Wake Wordモデル、whisper model、Piper voiceは自動downloadせず、明示的に
配置したpathだけを使用します。openWakeWord同梱モデルには非商用条件があるため、用途に応じて
model licenseも確認してください。

独自のVoice Satelliteから接続する場合は、STT済みテキストを次へ渡すと、読み上げるべき
`text` が返ります。

```text
POST /api/channels/voice/input
WebSocket /api/channels/voice/ws
```

HTTP例:

```bash
curl -s http://127.0.0.1:8787/api/channels/voice/input \
  -H 'Content-Type: application/json' \
  -d '{"text":"8時に起こして","source":"voice","conversation_id":"living-room"}'
```

同梱Gatewayは返却された `text` をPiperへ渡します。TTS終了後15秒間はWake Wordなしで
次の発話を受け付け、時間切れ後にWake Word待機へ戻ります。

## Personal MemoryとSafari Activity

全チャネルの会話は共通Raw Eventへ正規化されます。OTP、Password、Bearer Token、カード番号は
永続化前に除去されます。Long-term Memoryは明示的な「覚えて」またはWeb UI操作で作成し、
会話全文を無条件に長期Memory化しません。

Safari Extension sourceは `activity-extension/` にあります。macOS/XcodeでiOS app containerへ
変換する手順は [activity-extension/README.md](activity-extension/README.md) を参照してください。
Coreでは収集が既定OFFです。`.env` にランダムなActivity Tokenを設定し、PWAのSafety画面で
収集を有効化します。

```text
PERSONAL_AGENT_ACTIVITY_TOKEN=十分に長いランダム値
```

銀行・決済・login等のSensitive URLはOriginと時刻だけを保持します。禁止DomainはEvent自体を
保存しません。URL fragmentとtoken/code/password等のquery parameterは送信後の保存前に除去
します。

## Files・Home Assistant・Economic Sandbox

File Toolは `PERSONAL_AGENT_FILES_ROOTS` で明示したrootの内側だけを扱います。symlink経由の
root逸脱、SSH鍵・credential・private keyの読取、既存ファイルへの暗黙上書きを拒否します。
削除は `PERSONAL_AGENT_FILES_TRASH_ROOT` への移動です。ファイル本文は常にuntrusted dataとして
扱い、そこに書かれた指示をAgent命令へ昇格しません。

Home Assistantを使う場合はprivate/loopback/Tailscale内のURLとLong-Lived Access Tokenを設定します。

```text
PERSONAL_AGENT_HOME_ASSISTANT_URL=http://homeassistant.local:8123
PERSONAL_AGENT_HOME_ASSISTANT_TOKEN=...
PERSONAL_AGENT_HOME_ASSISTANT_SAFE_SCENES=scene.relax,scene.movie
```

entity IDは完全一致が必須です。低リスクdomainの照明、一般switch、温度等を扱えます。Sceneは
内容を確認して `SAFE_SCENES` へ明示したIDだけをR2承認後に実行します。lock/alarmや任意script/
automation domainはstrong-auth adapterがない状態では常に拒否します。

購入・予約・送金の安全性はEconomic Intent、確定見積、上限、単位、通貨、Payee、Idempotency、
照合状態で管理します。初期残高・Budget・登録Payeeは確認付きCLIで設定します。

```bash
personal-agent-sandbox set-balance 50000 --currency JPY
personal-agent-sandbox set-budget shopping --per-action 5000 --daily 10000 --monthly 30000
personal-agent-sandbox add-payee payee_family \
  --display-name Family --entity-id entity-family --route-ref secret://money/sandbox/family \
  --per-transfer 5000 --daily 10000 --monthly 30000 --trusted
```

Payeeの `entity-id` は先にMemory Entity APIで作成済みである必要があります。このCLIと送金Toolは
Sandbox DBだけを変更し、`route-ref` の値そのものを読み取らず、実口座・実カードには接続しません。

## Proactive・保守・データ管理

Proactive Agentは既定OFFです。PWAのOps画面で明示的に有効化し、カテゴリ、quiet hours、
最低通知間隔を設定できます。返信待ち、返金、配送、期限、subscription候補を根拠ID付きで検出し、
勝手に外部操作せず、解決まで最大30日の日次follow-upを管理します。

DB quotaの80%到達時は永続通知を作り、Raw Eventは保持期間に従ってpurgeします。秘密値を含まない
JSON export、範囲指定削除、暗号化backupを提供します。backupは実行ユーザーにbindingされ、
restore中はCore/Workerを停止してWALがない状態にしてください。
WindowsではDPAPIを使用します。非Windowsでは `.[auth]` を導入し、外部から
`PERSONAL_AGENT_SECRET_MASTER_KEY` を渡した環境だけで利用できます。

```bash
personal-agent-backup create /safe/offline/core.pa-backup --database core
personal-agent-backup inspect /safe/offline/core.pa-backup
personal-agent-backup restore /safe/offline/core.pa-backup \
  --database core --replace --confirm-replace RESTORE

personal-agent-benchmark --trials 3
```

Benchmarkは外部Mutationを実行しないdry-runです。未設定のoptional connector/hardwareはskip、
実モデルが応答しない場合はerrorとして記録し、成功扱いにしません。Resource efficiencyはHarness内で
未計測のため0点で、System Healthの実測値とは分離しています。

## API

主なendpoint:

```text
POST /api/messages
POST /api/channels/voice/input
POST /api/channels/line/webhook
POST /api/channels/line-desktop/ingest
GET  /api/channels/line-desktop/status
POST /api/channels/line-desktop/sync
GET  /api/search?q=...
GET  /api/events
GET  /api/memories
POST /api/memories
PATCH /api/memories/{memory_id}
DELETE /api/memories/{memory_id}
POST /api/activity/batch
GET  /api/activity/status
PUT  /api/activity/status
GET  /api/tasks
GET  /api/tasks/{task_id}
POST /api/tasks/{task_id}/pause
POST /api/tasks/{task_id}/resume
POST /api/tasks/{task_id}/cancel
GET  /api/scheduler/jobs
GET  /api/communication/search?q=...
POST /api/communication/{source}/sync
GET  /api/calendar/events
GET  /api/calendar/free-busy
POST /api/calendar/events
GET  /api/economic/intents
GET  /api/economic/transactions
GET  /api/economic/budgets
GET  /api/money/payees
GET  /api/proactive/settings
PUT  /api/proactive/settings
POST /api/proactive/scan
GET  /api/opportunities
POST /api/notifications/claim
POST /api/notifications/{notification_id}/ack
GET  /api/system/locks
PUT  /api/system/locks/{lock_name}
GET  /api/audit
GET  /api/approvals
POST /api/approvals/{approval_id}/decision
GET  /api/browser/profiles
DELETE /api/browser/profiles/{profile}
GET  /api/auth/sessions
POST /api/auth/{profile}/otp
GET  /api/secrets
GET  /api/secrets/usage
GET  /api/system/health
GET  /api/metrics
POST /api/benchmark/run
GET  /api/data/export
POST /api/data/delete
```

Mutationと機微なread endpointには `X-Admin-Token` または有効なpasskey sessionが必要です。
R4/R5のAction承認にはsessionだけでなく、そのActionへbindingされた新しいWebAuthn user verificationが
必要です。Taskを別チャネルで継続するには、入力JSONの `task_id` に既存の未完了Task IDを指定します。

## テスト

```bash
.venv/bin/ruff check .
.venv/bin/pytest -q
```

テストは実モデルや外部サービスへ送信せず、Tier 0、状態遷移、再起動復旧、Cross-channel resume、
Kill Switch、Dry-run、Idempotency、redaction、LINE署名、FTS、Retention、Evidence、Activity privacy、
Browser Worker認証、DOM参照、実Chromium操作、SSRF防止、finance allowlist、Takeover lock、
Secret暗号化境界、Origin binding、TOTP、OTP期限、承認single-use、Slack/Gmail正規化、Calendar、
Economic Sandbox、Files/Home境界、Proactive、学習候補、Health、export/delete、暗号化backup、
Benchmark、WebAuthn challenge binding・有効期限・single-use・passkey sessionを検証します。

## 安全上の既定値

- `finance_lock=true`
- `secret_lock=true`
- `activity_capture_enabled=false`
- Remote model禁止
- Coreはloopback限定。Browser WorkerはloopbackまたはFirewall・送信元CIDR・tokenでWSLだけに限定
- Browserからlocalhost/LAN/private networkへのnavigation禁止
- File/Browser upload rootは未設定なら利用不可
- R2〜R4 Toolは承認要求、R5 Toolは拒否
- R4/R5はAdmin Tokenまたはlogin sessionだけの承認を拒否し、ActionごとのWebAuthn UVを要求
- finance profileはallowlist未設定なら全遷移拒否・Download禁止
- password/OTP/card fieldは通常の `browser.type` から入力不可
- Screenshotはpassword/OTP/payment fieldをmask
- Human Takeover中とtimeout後はAgent Mutationをlock
- transient Taskは再起動後に勝手に再実行せずPause
- LINEは登録済みPrimary Userのみ
- Admin Token未設定時はR5相当の管理操作を拒否
- Proactive、Preference学習、Workflow学習は自動実行しない
- Workflow候補は承認後も `accepted_disabled` のまま
- 実口座・実カード用Adapterなし

## 現在の限界

- WebAuthnはexact HTTPS Origin/RP IDが必要です。Tailscale ACL/Grantを狭くしない限り、同じ
  tailnet内の他端末から一般APIへ到達できるため、iPhone設定手順のアクセス制限が運用上必須です。
- Calendarはローカル正規化storeです。Google Calendar等とのprovider同期は未実装です。
- Gmailはaccess tokenの自動refreshを行いません。Slack/Gmail tokenの取得とrotationは手動です。
- Slack/Gmail attachment本文はconnectorから自動取得しません。必要な取得はBrowserの隔離Downloadを
  別Actionとして実行します。
- Shopping/Reservationは汎用Browser + Economic Intentで実行する基盤です。サイト固有Adapter、
  PDF/OCR、確認メールとの自動突合ルールはありません。
- MoneyはSandboxのみです。銀行Adapter、実カード、実送金を有効化するコードはありません。
- iPhoneはPWA/LINE/Tailscale、Face ID passkey、手動OTP入力を利用します。任意アプリの自動操作、
  遠隔画面操作、Web Pushによるバックグラウンド通知はしません。通知はLINEを併用してください。
- File Toolはテキスト読取と安全なファイル操作に限定し、形式変換・PDF OCR・自動taggingはしません。
- PC操作は状態取得・永続通知・Windows workstation lockに限定し、任意shellや任意app起動はしません。
- Wake Word/STT/TTS、Qwen、Chrome、Home Assistant、LINE、Slack、Gmailは対応する実機・model・
  credentialを用意して初めてend-to-endで動作します。

## CIとローカル検証

GitHub ActionsはPython 3.11/3.12で`pip install -e '.[dev]'`、`ruff check .`、`pytest`、
`python -m compileall -q src`を実行します。Windows/DPAPI/Windows Hello/実ブラウザはLinux CIで
実機E2Eせず、unit testではfakeまたはmockを使います。ローカル仮想環境`.venv/`、`.env`、SQLite DB、
GGUF modelはGit管理対象外です。

実口座、実カード、実購入先へ拡張する場合は、専用Adapter、strong-auth、Sandbox回帰試験、
Prompt Injection試験、provider固有の照合を追加してからSafety Lockを解除してください。
