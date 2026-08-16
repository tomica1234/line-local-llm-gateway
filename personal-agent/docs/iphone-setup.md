# iPhone連携とFace ID passkey

Coreは`127.0.0.1:8789`、Qwenは`127.0.0.1:8000`のまま公開しません。iPhoneの入口だけを
`https://your-machine.your-tailnet.ts.net:9443`として同じtailnet内へ公開します。WebAuthnはHTTPSのexact
OriginとRP IDを検証するため、IP addressではなく固定した`.ts.net` hostnameを使います。
Personal Agent用のTailscale Funnelは使用しません。

## 1. 現在のHTTPS構成

iOS SafariでTailscale ServeのTLS終端が失敗する環境を回避するため、9443はraw TCPとして
Windows loopbackのTLS proxyへ転送します。TailscaleのPROXY protocol v1で元のpeer IPを渡し、
proxyは明示的に許可したiPhone IPだけを受け入れます。Coreへ渡すidentity headerはproxyが生成し、
clientから届いた同名headerは破棄します。

```text
iPhone 100.64.0.10
  -> Tailscale raw TCP :9443 (tailnet only, PROXY protocol v1)
  -> Windows TLS proxy 127.0.0.1:9444
  -> Core 127.0.0.1:8789
  -> Qwen 127.0.0.1:8000
```

```text
PERSONAL_AGENT_PORT=8789
PERSONAL_AGENT_WEBAUTHN_RP_ID=your-machine.your-tailnet.ts.net
PERSONAL_AGENT_WEBAUTHN_ORIGIN=https://your-machine.your-tailnet.ts.net:9443
```

Tailscale側は次の形です。

```powershell
tailscale serve --bg --tcp=9443 --proxy-protocol=1 tcp://127.0.0.1:9444
tailscale serve status
```

Windows proxyは`scripts/windows-tls-proxy.py`を`pythonw.exe`で実行します。このCyborgでは
`PersonalAgentTLSProxy` scheduled taskを現在ユーザーのlogon triggerで登録済みです。taskは
loopbackだけにbindするため、Windowsの外向けPython firewall例外は不要です。

TLS certificate/keyは`%LOCALAPPDATA%\PersonalAgent`に置き、directory ACLを現在ユーザーと
SYSTEMだけに限定します。`PersonalAgentTLSCertificateRenewal` taskが毎日
`scripts/windows-renew-tls.ps1`を実行し、有効期限が14日未満なら更新してproxyを再起動します。

CoreとQwenはuser systemd serviceです。

```bash
systemctl --user status personal-agent.service
systemctl --user status personal-agent-qwen.service
```

CoreをTailscale IPへ直接bindする例外構成では、次も必要です。source IPとidentityが固定対応しない
設定ではCoreが起動を拒否します。通常のloopback TLS proxy構成では空のままにしてください。

```text
PERSONAL_AGENT_TAILSCALE_PEER_IDENTITIES=100.64.0.10=you@example.com
```

## 2. MagicDNS

iPhoneでraw Tailscale IPへ接続できるのに`.ts.net`名だけ失敗する場合、Tailscale DNS管理画面で
MagicDNSを有効にし、Cloudflareなどのglobal nameserverを追加して`Override DNS servers`を有効にします。
iPhone側の`Use Tailscale DNS settings`も有効にし、Tailscaleを一度off/onします。この設定は
tailnet全端末のDNSへ影響するため、組織のDNS policyに合わせてresolverを選んでください。

接続確認は次のURLで行います。

```text
https://your-machine.your-tailnet.ts.net:9443
```

IP直指定はcertificate hostnameとWebAuthn Originが一致しないため、本番利用には使いません。

## 3. tailnetのアクセスを本人だけに限定

管理画面のGrant/ACLで、Personal Agent hostのTCP 9443へ到達できるsourceを本人のTailscale identityだけに
限定します。次は概念例です。実際のidentity、tag ownership、host名へ置き換え、policy testも追加します。

```json
{
  "tagOwners": {
    "tag:personal-agent": ["you@example.com"]
  },
  "grants": [
    {
      "src": ["you@example.com"],
      "dst": ["tag:personal-agent"],
      "ip": ["tcp:9443"]
    }
  ]
}
```

proxyのpeer IP allowlistとCoreのidentity/passkey検証も併用します。Grant/ACLは到達前の第一境界、proxyの
送信元検証は第二境界、Coreのidentity/passkey検証は第三境界です。`PERSONAL_AGENT_HOST=0.0.0.0`への
変更、routerのport forwarding、Personal Agent用Funnelは行わないでください。

## 4. iPhoneへFace ID passkeyを登録

最初のcredentialが0件の間だけAdmin Tokenがbootstrap authorityになります。恒久Admin Tokenを端末へ
残さないため、初回登録時は一時的な32文字以上のrandom tokenへrotateし、登録確認後すぐ256-bitの
新しい値へ再rotateします。一時値をLINE、メール、通常のメモへ送らないでください。

1. iPhoneのTailscaleを接続し、Safariで9443のURLを開きます。
2. `Safety` tabのAdmin Token欄へ一時tokenを入力します。
3. labelを`iPhone Face ID`にして「この端末を登録」を押し、Face IDを完了します。
4. 「Face IDでサインイン」を押します。
5. server側でcredential数、registration/login verifyの成功を確認します。
6. Admin Tokenを新しい256-bit値へrotateし、Coreを再起動します。
7. 一時tokenが401、新tokenが200、未loginの`GET /api/tasks`が401になることを確認します。
8. Safariの共有メニューから「ホーム画面に追加」を選ぶとPWAとして起動できます。

passkeyのprivate keyやFace ID情報はCoreへ送信・保存されません。Coreが保存するのはcredential ID、
public key、sign counter、backup状態などの検証用metadataです。login済みでもR4/R5ごとに内容へbinding
した新しいFace ID署名が必要です。

## 5. backup認証器

iPhoneを紛失しても復旧できるよう、同じHTTPS URLからWindows HelloまたはFIDO2 security keyを
2本目として登録します。先に既存passkeyでsign inし、登録操作もそのsessionで承認します。Appleの
同期passkeyを利用する場合も別系統のFIDO2 keyを保管することを推奨します。事故防止のため最後の1本は
失効できません。

## 6. 動作確認

```bash
curl -fsS http://127.0.0.1:8789/api/health
tailscale serve status
```

iPhoneではcredential数が1以上、Face ID sign-in後に「Passkeyでサインイン済み」と表示されることを
確認します。未loginの`GET /api/tasks`は401、login後は200です。R4/R5ではlogin sessionやAdmin Token
だけの承認を拒否し、ActionごとのFace ID後だけTaskをresumeします。

PWAは開いている間に状態を取得しますが、iOS Web Pushのbackground deliveryは対象外です。承認待ちや
alarmを確実に受け取る用途には、Primary Userを固定したLINE channelを併用します。
