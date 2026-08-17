# Personal Agent 実装・検証状況

更新日: 2026-08-17

ここでは「コードがある」「自動テスト済み」「本人のcredential/実機で確認済み」を分けます。
Alexaと実銀行送金は今回のscope外です。

## 実装済み

### Safety / durability

- communication/calendar/browser/economic/transferを実体表示する`ApprovalMaterial`
- canonical material hash、実行直前再計算、変更時`APPROVAL_MATERIAL_CHANGED`、single-use
- Plan/Stepのstatus、入出力、evidence、attempt、model、prompt versionのSQLite永続化
- 完了step skip、read step resume、in-flight mutationの`SUBMITTED_UNKNOWN`停止
- Todo reminderのScheduler連携、update時差替え、complete/delete時cancel、snooze、recurrence
- recurrence解除時のDB NULL化、weekly→monthly差替え、旧job cancelと非recurring job再作成
- component別schema migration framework
- LLM Capability Proposalと、ユーザー原文/allowlist/riskに基づく決定論的validator

### Productivity / providers

- local/Google Calendar provider、free-busy、CRUD、recurrence、attendee、reminder、paging、同期mapping
- external version/etagを使う同期と、local変更競合時の自動上書き停止
- Google OAuth authorization code flow、Secret Worker refresh token保存、自動access-token refresh
- Gmail thread/label/draft/reply/send verification、添付metadata、50 MiB隔離download
- Manual/Google/Gmail/LINE/Memory sourceを統合するContactsと曖昧解決停止
- PDF/DOCX/XLSX/PPTX/HTML/Image/ZIPの非実行解析、PDF table/page、metadata、Vision fallback
- Today/Todo/Diary/Calendar/Inbox/Files/Tasks/Approvals/Memory/Safety/OpsのPWA画面
- Chatの処理中表示、経過秒、失敗時入力復元

### Model / agent capability

- Tier 0 deterministicと、文字数ではなくtyped purposeでfast/strong/visionを選ぶModel Registry/Router
- Capability planning/tool reasoning/coding/generalはstrong。低risk text/extractionだけfast
- 補助modelを含むlocal endpoint強制。remote許可はoperator設定だけ
- DOM/native extraction後だけのVision。Vision結果からpermission追加不可
- process/app/job/clipboard/desktop/fixed-commandの型付きComputer tool
- Clipboard metadata、JWT/Bearer/token/private-key/high-entropy検出とsecret-like raw返却禁止
- desktop.typeの一時clipboard利用とsuccess/exception時restore、restore失敗の値なしwarning
- cwd/app/command/env allowlist、timeout、output上限、child cleanup、no shell/no sudo/no secret env
- allowlisted repo内のCodex job start/send/status/cancel/test、永続job、完了通知
- Codexはworkspace/read-only sandbox、network off、commit/pushなしを既定にする

### Automation

- Browser locator retry、DOM安定化、stale ref/page change検出、popup/multi-tab
- login signal、upload count、download hash/completion、submit postcondition、confirmation ID抽出
- read-only `SiteAdapter` interfaceとlocal fixture用reservation example
- Shopping/Reservationのcandidate、selection、exact quote、submission、email/receipt reconciliation
- Browser evidenceと第二のdurable evidenceが一致しない場合の`SUBMITTED_UNKNOWN`維持
- Todo/Calendar/Communication/Refund/Reservationを直接読むevent-driven Proactive rule
- quiet hours、category opt-in、dedup、follow-up上限を持つAttention manager
- FTS + optional local Embedding + Recency + Importance + Confidence + EntityのHybrid Memory
- `supersedes` relation、source evidence、timestamp、expiry。矛盾情報を破壊的上書きしない

### Operations / supply chain

- schema version、暗号化backup/restore、復号+SQLite integrity verify、自動backup、件数/日数retention
- task/tool成功率、latency、model token/latency、browser failure、approval/auth wait、
  submitted_unknown、recovery、scheduler delay、通知成功率、provider sync error metrics
- `personal-agent doctor`によるCore/Model/DB/Browser/Secret/LINE/Google/Tailscale/Passkey/HA/Voice診断
- exact dependency lock、Dependabot、最小GitHub Actions permission
- CIのpip-audit、Bandit、detect-secrets、Python 3.11/3.12、Local E2E

## Unit test済み

- Approval material改変、single-use、R4/R5 strong-auth境界
- durable mutation crash/restart、idempotency、submitted_unknown replay抑止
- Todo scheduler/recurrence、Calendar conflict、Gmail OAuth/refresh/attachment quarantine
- Contacts ambiguity、各file parser、Vision順序、Computer/Coding allowlist
- Commerce quote/reconciliation/no-resend、Hybrid Memory/supersedes、Proactive event rule
- Browser SSRF、private subresource、finance allowlist、secret field、takeover
- external webpage/email/file/visionからのcapability昇格拒否
- 用途別Model routing、Vision未設定fail-closed、Plannerの明示的strong purpose
- Clipboard通常文/token/JWT/private key/high-entropy/OTP context、desktop restore/secret target拒否
- LINE署名/primary user、Tailscale header spoofing、WebAuthn binding、secret redaction
- backup round-trip/verify/prune、doctor DB check、observability

## Integration test済み

- TestClient経由のTodo作成→期限到来→PWA notification claim/ack→complete
- Diary create/search、Memory create/search、local Calendar create/list
- Browser Worker APIのauth/idempotency、Privileged Gmail/Slack/Google refresh mock
- Playwright Chromiumのsnapshot/type/secret guard/submit verification/masked screenshot
- local HTTP fixtureを実Chromium Controllerで操作するform/type/submit/postcondition test
- password direct type拒否、popup/tab、隔離download+SHA-256、allowlisted uploadとroot外拒否
- confirmation/booking ID抽出、DOM stale ref拒否、CAPTCHA検出後のHuman Takeoverと再submit停止
- fixtureのprompt injection文字列を実browserで取得。permission/tool exposure不変は上記Unitで検証
- Core restart相当のExecutionStore再生成とmutation不明状態復旧

## GitHub Actions確認済み

- code commit `29938d9`、Personal Agent CI run `31993845012`で確認
- Python 3.11: Ruff、Unit、Playwright Chromium install、Browser integration、Local E2E、compileall成功
- Python 3.12: Ruff、Unit、Playwright Chromium install、Browser integration、Local E2E、compileall成功
- Security: pip-audit、Bandit、detect-secrets成功

## 実機検証済み

- `unsloth/Qwen3.6-35B-A3B-GGUF` / `UD-Q4_K_XL`、llama.cpp、`--n-cpu-moe 40`
- Tailnet限定HTTPS、Tailscale identity検証、未login遠隔API遮断
- iPhone Safari/PWAからのFace ID passkey登録・sign-in
- local Qwen通常応答とtool-call loop（以前の環境で約25〜28 token/秒）

## Credential待ち

- 本人Gmail/Google CalendarでのOAuth・refresh・同期・送信E2E
- LINE Messaging API再構築時の本人channel credentialとpush/webhook再確認
- Slack/Home Assistantの本人credential E2E
- 実通販/ホテルサイトでの購入・予約。対象siteごとのAdapter/回帰fixture追加が必要

## 部分実装

- Google ContactsはOAuth scopeと統合store/sourceを持つが、People API取得・同期は未実装
- VisionはOpenAI互換local image endpointを設定した場合だけ有効。専用OCR modelは同梱しない
- SiteAdapterはframework + example。大量サイトAdapterは未実装
- Proactive ruleは決定論的な代表例。全provider/全subscription形式を網羅しない
- iOS background Web Pushは未実装。確実なbackground通知はLINE fan-outを使用

## 未実装（意図的scope外を含む）

- Alexa、複数部屋Alexa
- Google People APIからのContacts取得・同期
- 実銀行送金、実カード専用Adapter
- unrestricted root shell、任意sudo、credential dump
- Agent自身によるPolicy変更、Finance Lock解除、credential/trusted payee登録
- 任意のiPhone app操作やLINE暗号化DBの直接読取

## 実運用前の必須確認

1. `personal-agent doctor`で設定済みcomponentがすべて`OK`になること。
2. `ruff check .`、`pytest`、`pytest -m "integration and browser"`、`pytest -m e2e`、
   `python -m compileall -q src`を再実行すること。
3. Tailscale Grant/ACLを本人identityとPersonal Agent portだけに絞ること。
4. iPhone以外のbackup passkeyを登録すること。
5. Windows BitLocker/Device Encryption、Worker profile/Secret DB ACL、backup restore手順を確認すること。
6. 実provider/実siteは少額またはcancel可能なsandbox条件で個別E2Eを行うこと。

## DPAPI backupの注意

Secret Workerの暗号文は同じWindows user profileへbindingされます。DBファイルのbackupだけでは別PC・
別Windows userへ復元できません。Windows回復手段と、Google/LINE/Slack等のcredential再発行手順を
オフラインで保管してください。Core backupの自動verifyはSQLite破損を検出しますが、DPAPI portabilityを
保証するものではありません。

## Alexa readiness

将来Alexaを追加する場合はAlexa Skillから直接Toolを呼ばず、既存Voice GatewayのSTT済みtext contractへ
入力し、同じTask/Capability/Policy/Approval/Verification経路を通します。Alexa account linkingも新しい
trusted identity adapterとして追加し、既存passkeyやSafety Lockを迂回させません。
