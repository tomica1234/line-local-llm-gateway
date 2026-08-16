# 要件対応状況（v0.1）

この文書は要件定義のPhaseごとの実装範囲を示します。「実装済み」は自動テスト済みの
software境界を意味し、外部credential・実機・第三者serviceまで含む運用保証ではありません。

## Phase 0〜2: Core・Channel・Memory（実装済み）

- SQLite Durable Task State、checkpoint、再起動時の安全なPause、Pause/Resume/Cancel
- 型付きTool Broker、決定論的Policy、Risk、Reason Code、Policy version、4種Safety Lock
- Mutation Idempotency、Dry-run、single-use Approval、Secret redaction付きAudit
- loopback限定OpenAI互換Qwen client、Tier 0、最大12 stepのDeep Tool loop
- Responsive PWA（Chat処理中・経過秒・完了/失敗表示）、LINE署名/Primary User/再送排除、
  Voice HTTP/WebSocket contract
- openWakeWord、Energy VAD、whisper.cpp、Piperを接続するWindows Voice Gateway
- channelをまたぐTask継続、永続Timer/Alarm、claim/ack型通知、PWAとLINEへの独立fan-out
- 共通Raw Event、FTS5 trigram検索、Entity、Preference、Decision、Evidence付きMemory
- 90日Raw Event retention、日次要約、低重要度Memory decay
- Safari Private Activity Web Extension、AES-GCM offline queue、Sensitive URL最小化

## Phase 3〜4: Browser・Auth・Secret・Takeover（実装済み）

- Windows Playwright Worker、6用途別Persistent Chrome Profile、共有token認証
- Windows headed Chrome常駐Worker、WSL仮想NIC限定Firewall、動的WSL host解決
- 型付きBrowser Primitive、DOM ref、mask済みScreenshot、座標操作の順序強制
- tab/history/hover/key/scrollと、送信後条件を検証し不明時に再送しないBrowser submit
- navigation SSRF防止、finance allowlist、upload root、隔離Download、SHA-256
- Core/Worker二重Idempotency、送信不明時の `SUBMITTED_UNKNOWN` と再送停止
- CAPTCHA/Passkey/biometric/3DS検出、同じContextのHuman Takeover、timeout lock
- Windows user-scoped DPAPI Secret Store、PWA書込専用credential登録、username/password/TOTPの
  exact Origin/Action bindingとdirect-fill
- Password/OTPをCore・LLM・HTTP responseへ返さないWorker内復号
- Auth session優先、曖昧account停止、email/SMS OTPの手動入力、Task/期限/試行Binding
- PWAからApproval、OTP、Profile、Takeover、Secret metadata/利用履歴/失効を管理
- WebAuthn passkeyをiPhone Face ID / Windows Helloで登録・loginし、R4/R5はActionごとのUV署名で承認
- exact Origin/RP ID、approval内容hash、有効期限、試行回数、single-use、sign counterを検証
- Tailscale identityまたは送信元検証済みTLS proxy identityとpasskey sessionを重ね、一般の遠隔APIを二重認証

## Phase 5: Communication・Calendar・Scheduler（実装済み、一部provider待ち）

- LINE/Slack/Gmail/SMS共通message model、検索、thread、下書き、送信の分離
- 個人LINE Desktopは宛先allowlist、送信直前のOCR再照合、送信後OCR検証、不明時再送停止
- Slack `chat.postMessage` / `search.messages` とGmail messages read/send connector
- Slack/Gmail tokenをSecret Workerだけで復号し、送信idempotencyと不明状態を記録
- ローカルCalendarの検索、free/busy、作成、更新、取消、recurrence、reminder
- Proactive follow-upと朝/夜briefing

Google Calendar等の外部Calendar同期、Gmail OAuth refresh、attachment本文の自動取得、
native SMS Bridgeは未実装です。

## Phase 6〜7: Shopping・Reservation・Money（安全な基盤とSandboxを実装）

- Economic Intent、action type、条件、取消条件、payment ref、risk/evidence
- 確定見積のitem/数量/価格/送料/fee/合計/通貨/販売元/納期/取消可否の一致検査
- 共通Budgetの1回・日次・月次上限、30日内の重複購入検知
- Entityに結び付く登録Payee、信頼状態、1回・日次・月次上限、JPY限定
- 専用Sandbox残高、Sandbox購入/送金、Idempotency、取引記録、Reconciliation
- Finance Lock既定ON、実口座補充・Policy上限変更をAgent Toolに公開しない構成

汎用Browserで候補探索・フォーム操作はできますが、実店舗/予約サイト固有Adapter、確認メールの
自動照合、実カード、銀行Adapter、実送金はありません。MoneyはSandboxだけです。

## Phase 8: Proactive・学習・分析（基盤を実装）

- 既定OFF、カテゴリ別OFF、quiet hours、最低通知間隔を持つAttention Manager
- 返信、返金、配送、期限、subscriptionの根拠付き検出・重複排除・最大30日follow-up
- Preference候補はEvidenceとconfidenceを要求し、人が承認するまでMemoryへ反映しない
- 成功Tool sequenceのWorkflow候補化。承認後も `accepted_disabled` で自動実行しない
- DB integrity/quota/disk/process/GPU、Task/Action/Model latency、失敗分類
- 秘密を含まないJSON export、exact confirmation付き範囲削除、暗号化backup/restore
- 17カテゴリ、1〜3 trial、weighted score、skip/errorを区別するdry-run Benchmark

Liquid AI/Gemma等の第二model、選択的embedding、複数部屋Voice Satelliteは未実装です。

## Files・Computer・Home・PWA（実装済みの範囲）

- allowlist root、symlink escape防止、Secret/key除外、no-overwrite、回収可能Trash
- Text/JSON/Markdown/CSV/YAMLのbounded read。PDF/OCR/画像抽出・分類は未実装
- OS status、永続local notification、Windows workstation lock。任意shell/app起動は非公開
- private network限定Home Assistant、低リスクdomain、bounded temperature、safe-scene allowlist
- PWAのChat/Task/Memory/Safety/Ops、Connector/Budget/Payee/Audit/Metrics/Benchmark/Data control

## 運用前に必要なもの

- Windows 11のBitLocker/Device Encryptionと同梱preflightによるACL設定
- Wake Word/STT/TTS model、Chrome/Playwright
- 利用するLINE/Slack/Gmail/Home Assistant credentialとprovider側scope
  （LINEの署名付きWebhook専用Funnel経路と自動Push workerは構築済み、credential投入待ち）
- 本人の端末だけに絞ったTailscale Grant/ACL
- iPhone Face ID passkeyに加え、Windows HelloまたはFIDO2 security keyのbackup passkey
- 実機・実credentialを使ったend-to-end検証と、対象site/provider固有の回帰試験

このCyborgでは指定GGUFのSHA-256検証、CUDA llama.cpp起動、`ncmoe40`、32K context、API key、
Tailnet限定HTTPS、送信元/identity検証、未ログイン遠隔APIの401遮断、初回登録endpoint、通常応答、
実Tool loopまで確認済みです。実Tool loopの生成速度は約27〜28 token/秒でした。
iPhone Face ID passkeyの登録・sign-inも実機で完了しています。Grant/ACLの管理画面反映、backup passkey、
外部provider credentialの投入は利用者作業です。
