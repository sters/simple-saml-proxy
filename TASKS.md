# GoによるSAMLプロキシアプリケーション実装タスク

このリポジトリでは、Go言語を使用してシンプルなSAMLプロキシアプリケーションを実装します。
以下に、実装に必要な主要なタスクをリストアップします。

## 1. 基本的なHTTPサーバーの実装
- [ ] HTTP/HTTPSリクエストを処理する基本的なサーバー構造を構築する。
- [ ] 設定ファイルからリッスンポートなどを読み込めるようにする。

## 2. 設定管理
- [ ] プロキシ自体の設定（エンドポイントURL、証明書/秘密鍵のパスなど）を管理する仕組みを実装する。
- [ ] SPおよび上流IdPのメタデータURLや設定情報を管理する仕組みを実装する。
- [ ] 設定ファイルのフォーマットを決定する（例: YAML, JSON, TOML）。

## 2.1. SAMLライブラリ
- [ ] Go言語で利用するSAMLライブラリを選定する (例: `crewjam/saml`, `russellhaering/gosaml2`)。
- [ ] 選定したライブラリをプロジェクトに導入し、基本的な動作確認を行う。

## 3. SAMLメッセージ処理 (SP -> Proxy)
- [ ] SPからのAuthnRequestを受信するエンドポイントを実装する (`/sso/request` など)。
- [ ] 受信したAuthnRequest (HTTP-Redirect Binding または HTTP-POST Binding) をデコードし、パースする。
- [ ] AuthnRequestのXML署名を検証する（SPの公開鍵を使用）。
- [ ] AuthnRequestの基本的な妥当性を確認する（Issuer, AssertionConsumerServiceURLなど）。

## 4. SAMLメッセージ処理 (Proxy -> IdP)
- [ ] 上流IdPへのAuthnRequestを生成する。
    - [ ] SPからのAuthnRequestの情報を元に、必要な情報を設定する。
    - [ ] Proxy自身のIssuer情報を設定する。
- [ ] 生成したAuthnRequestに署名する（Proxyの秘密鍵を使用）。
- [ ] 上流IdPのSSOServiceエンドポイントへAuthnRequestを送信する (HTTP-Redirect Binding または HTTP-POST Binding)。

## 5. SAMLメッセージ処理 (IdP -> Proxy)
- [ ] 上流IdPからのSAMLレスポンスを受信するエンドポイントを実装する (`/sso/acs` など)。
- [ ] 受信したSAMLレスポンス (HTTP-POST Binding) をデコードし、パースする。
- [ ] SAMLレスポンスのXML署名を検証する（IdPの公開鍵を使用）。
- [ ] Assertion内の署名を検証する（IdPの公開鍵を使用）。
- [ ] Assertionを復号する（必要な場合、Proxyの秘密鍵を使用）。
- [ ] Assertionの基本的な妥当性を確認する（Conditions, SubjectConfirmationDataなど）。
- [ ] RelayStateを適切に処理する。

## 6. SAMLメッセージ処理 (Proxy -> SP)
- [ ] SPへのSAMLレスポンスを生成する。
    - [ ] IdPからのAssertionの情報を元に、必要な情報を設定する。
    - [ ] Proxy自身のIssuer情報を設定する。
    - [ ] 必要に応じて属性情報をマッピングする。
- [ ] 生成したSAMLレスポンスに署名する（Proxyの秘密鍵を使用）。
- [ ] SPのAssertionConsumerServiceURLへSAMLレスポンスを送信する (HTTP-POST Binding)。
- [ ] RelayStateを適切に引き渡す。

## 7. メタデータ処理
- [ ] SPのメタデータを取得・パースし、検証に必要な情報（公開鍵、AssertionConsumerServiceURLなど）を抽出する機能。
- [ ] 上流IdPのメタデータを取得・パースし、リクエスト送信や検証に必要な情報（公開鍵、SSOService URLなど）を抽出する機能。
- [ ] Proxy自身のメタデータを生成・提供するエンドポイントを実装する (`/metadata`)。
    - [ ] Proxyの公開鍵、SSOエンドポイント、SLOエンドポイント（将来的に）などを含む。

## 8. 証明書・鍵管理
- [ ] SAMLメッセージの署名・検証、Assertionの暗号化・復号に使用する証明書と秘密鍵を安全に読み込み、管理する仕組みを実装する。

## 9. ロギングとエラーハンドリング
- [ ] 詳細な処理ログを出力する仕組みを実装する。
- [ ] エラー発生時に適切なSAMLエラーレスポンスまたはHTTPエラーを返す仕組みを実装する。

## 10. テスト
- [ ] 各SAMLメッセージ処理のユニットテストを実装する。
- [ ] 主要なユースケースの結合テストを実装する。
- [ ] 可能であれば、実際のIdP/SPとの連携テストを行う。

## 11. セキュリティ考慮事項
- [ ] リプレイ攻撃対策（IDやIssueInstantの管理）。
- [ ] XML External Entity (XXE) 攻撃対策。
- [ ] その他、SAML仕様に関連するセキュリティベストプラクティスを遵守する。

## 12. ドキュメント
- [ ] 設定方法、APIエンドポイント、ビルド・デプロイ方法などを記述したREADME.mdを作成・更新する。
- [ ] コード内のコメントを充実させる。

## 将来的な拡張機能 (オプション)
- [ ] Single Logout (SLO) のサポート。
- [ ] 複数の上流IdPのサポート。
- [ ] 属性変換ルールの詳細な設定機能。
- [ ] 管理用UIの実装。

---

このタスクリストは初期のものです。開発を進める中で、必要に応じてタスクの追加、削除、変更を行っていきます。
