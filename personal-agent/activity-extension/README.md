# Safari Private Activity Extension

Safariの閲覧metadataを15〜30秒単位でPersonal Agentへ送るWebExtension sourceです。

収集する項目はURL、domain、page title、検索query、referrer domain、推定滞在時間、tab session、
時刻、device IDです。フォーム値、Password、OTP、Cookie、ページ本文、Screenshot、キー入力、
スクロール履歴は取得しません。

## iOS向けPackaging

このディレクトリをmacOSへコピーし、Xcode付属のconverterでiOS app containerを作成します。

```bash
xcrun safari-web-extension-converter . \
  --project-location ./build \
  --app-name PersonalAgentActivity
```

XcodeでiOS targetを署名してiPhoneへインストールします。初回インストール後、iPhoneの
SettingsからSafari > Extensionsを開き、本Extensionを有効化して、収集を許可するWeb siteを
明示的に選択してください。Private Browsingでの利用可否もSafari側の設定に従います。

全サイト権限は閲覧横断記録に必要ですが、Safariのsite permissionとCore側の禁止Domainを
併用し、不要なDomainは許可しないでください。

## 設定

Extension optionsで以下を設定します。

- Tailscale内またはlocalhost相当のCore URL
- `PERSONAL_AGENT_ACTIVITY_TOKEN` と同じランダムtoken
- 端末側の収集Pause

EventはWeb Crypto AES-GCMで暗号化してExtension local storageへqueueし、送信成功時のみ削除
します。Tokenと暗号鍵もExtension sandbox内にあるため、端末侵害に対するKeychain相当の保護を
意味するものではありません。iPhoneのdevice encryptionとscreen lockを必ず有効にしてください。

Core側は収集既定OFFです。Web PWAのSafety画面で有効化し、Sensitive DomainのOrigin-only化と
収集禁止Domainを管理します。
