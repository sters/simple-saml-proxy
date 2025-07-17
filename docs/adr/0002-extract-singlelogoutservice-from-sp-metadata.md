# ADR-0002: SPメタデータからSingleLogoutServiceを抽出する

## ステータス

提案済み

## 背景

現在、simple-saml-proxyはSPへのログアウト処理において、SingleLogoutServiceのURLをハードコードしています。これはGitHubのissue #28で追跡されています。現在の実装では以下の箇所でハードコードされています：

- `proxy/proxy_handler_logout_sp_selected.go:93` - `spEntityID + "/logout"`を使用
- `proxy/proxy_handler_sls.go:126` - `logoutCtx.OriginID + "/logout/response"`を使用

### 現在の状況

- プロキシはSPのログアウト要求に対して、固定のURLパターン（`entityID + "/logout"`）を仮定している
- SPのメタデータからSingleLogoutServiceエンドポイントを動的に読み込む機能がない
- IdP側のSingleLogoutServiceは既に適切にメタデータから抽出されている（`proxy/proxy_handler_logout_idp_selected.go:82-93`）
- 通常のSAML認証レスポンスはcrewjam/samlライブラリの`ParseResponse`メソッドを使用して検証されている

### 問題点

SingleLogoutServiceのURLをハードコードすることによる問題：

1. **柔軟性の欠如**: 異なるURLパターンを持つSPとの互換性がない
2. **設定の複雑さ**: 各SPに対してカスタムURLパターンを設定する必要がある
3. **SAML標準からの逸脱**: SAMLメタデータの仕様に従わない実装となっている
4. **メンテナンス負荷**: 各SPのログアウトエンドポイントを個別に管理する必要がある

## 決定

SPメタデータから動的にSingleLogoutServiceエンドポイントを抽出し、ハードコードされたURLパターンを置き換える。

## 実装計画

### フェーズ1: メタデータ解析機能の追加（優先度：高）

1. **SPメタデータ解析の拡張**
   - `proxy/saml/storage.go`の`GetEntityByID`機能を拡張
   - SPメタデータの`SPSSODescriptor`から`SingleLogoutService`要素を抽出
   - 複数のSingleLogoutServiceエンドポイントがある場合の優先度処理

2. **メタデータ構造の定義**
   ```go
   type SPMetadata struct {
       EntityID           string
       SingleLogoutServices []SingleLogoutService
       AssertionConsumerServices []AssertionConsumerService
   }
   
   type SingleLogoutService struct {
       Binding   string
       Location  string
       Index     int
   }
   ```

3. **バインディング対応**
   - HTTP-Redirect binding（`urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect`）を優先
   - HTTP-POST binding（`urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST`）も対応
   - 複数のバインディングがある場合の選択ロジック

### フェーズ2: 既存コードの更新（優先度：高）

1. **ログアウト処理の更新**
   - `proxy/proxy_handler_logout_sp_selected.go`の`handleLogoutSPSelected`関数を更新
   - `proxy/proxy_handler_sls.go`の`handleLogoutResponse`関数を更新
   - ハードコードされたURL構築ロジックを削除

2. **エラーハンドリングの実装**
   - SingleLogoutServiceが見つからない場合の処理
   - 無効なメタデータの処理
   - フォールバック機能の実装

3. **ログの改善**
   - SingleLogoutServiceの抽出状況をログに記録
   - 使用されるエンドポイントの詳細情報を記録

### フェーズ3: 下位互換性の確保（優先度：中）

1. **設定オプションの追加**
   - `PROXY_FALLBACK_LOGOUT_URL_PATTERN`設定
   - メタデータが利用できない場合のフォールバック機能
   - 段階的な移行をサポート

2. **デフォルト値の設定**
   - SingleLogoutServiceが見つからない場合のデフォルト動作
   - 既存のハードコードされたパターンを一時的なフォールバックとして維持

### フェーズ4: テストと検証（優先度：高）

1. **単体テスト**
   - メタデータ解析機能のテスト
   - 各種バインディングのテスト
   - エラーケースのテスト

2. **統合テスト**
   - 実際のSPメタデータを使用したE2Eテスト
   - 複数のSPとの互換性テスト
   - 既存の機能に対する回帰テスト

3. **ドキュメント更新**
   - SAML仕様サポートドキュメントの更新
   - 設定例の追加
   - 移行ガイドの作成

## 技術的詳細

### メタデータ解析のアルゴリズム

```go
func extractSingleLogoutService(metadata *serviceprovider.ServiceProvider) (*SingleLogoutService, error) {
    // SPメタデータからSPSSODescriptorを取得
    spDescriptor := metadata.GetSPSSODescriptor()
    if spDescriptor == nil {
        return nil, ErrNoSPSSODescriptor
    }
    
    // 優先度順でSingleLogoutServiceを検索
    bindings := []string{
        "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
        "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
    }
    
    for _, binding := range bindings {
        for _, sls := range spDescriptor.SingleLogoutServices {
            if sls.Binding == binding {
                return &SingleLogoutService{
                    Binding:  sls.Binding,
                    Location: sls.Location,
                    Index:    sls.Index,
                }, nil
            }
        }
    }
    
    return nil, ErrNoSingleLogoutService
}
```

### 更新されたログアウトURL構築

```go
func buildLogoutURLFromMetadata(sp *serviceprovider.ServiceProvider, logoutRequest *crewjamsaml.LogoutRequest, relayState string) (string, error) {
    sls, err := extractSingleLogoutService(sp)
    if err != nil {
        // フォールバック処理
        return buildFallbackLogoutURL(sp.EntityID, logoutRequest, relayState)
    }
    
    switch sls.Binding {
    case "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect":
        return buildRedirectLogoutURL(sls.Location, logoutRequest, relayState)
    case "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST":
        return buildPostLogoutURL(sls.Location, logoutRequest, relayState)
    default:
        return "", fmt.Errorf("unsupported binding: %s", sls.Binding)
    }
}
```

### 下位互換性の確保

```go
func buildFallbackLogoutURL(entityID string, logoutRequest *crewjamsaml.LogoutRequest, relayState string) (string, error) {
    // 既存のハードコードされたパターンを使用
    fallbackURL := entityID + "/logout"
    slog.Warn("Using fallback logout URL pattern", 
        slog.String("entityID", entityID),
        slog.String("fallbackURL", fallbackURL))
    
    return buildLogoutURLToSP(logoutRequest, fallbackURL, relayState)
}
```

## 結果

### 正の影響

- **動的なエンドポイント発見**: SPメタデータから自動的にSingleLogoutServiceエンドポイントを取得
- **SAML標準への準拠**: SAML 2.0仕様に従った適切な実装
- **運用性の向上**: 各SPのログアウトエンドポイントを個別に管理する必要がなくなる
- **柔軟性の向上**: 異なるURLパターンを持つSPとの互換性向上

### 負の影響

- **実装の複雑さ**: メタデータ解析とエラーハンドリングの追加
- **パフォーマンス**: メタデータ解析による軽微なCPUオーバーヘッド
- **デバッグの複雑さ**: 動的なエンドポイント選択によるトラブルシューティングの複雑化

## 検討された代替案

1. **設定ファイルによる明示的なマッピング**
   - 却下理由: SAMLメタデータの利点を活用できない
   - 各SPに対して個別設定が必要

2. **デフォルトパターンの継続使用**
   - 却下理由: SAML標準に準拠しない
   - 多様なSPとの互換性に問題

3. **カスタムメタデータ拡張**
   - 却下理由: 標準のSAMLメタデータから逸脱
   - 他のSAML実装との互換性に問題

## 参考資料

- [SAML 2.0 Metadata Specification](https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf)
- [SAML 2.0 Bindings Specification](https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf)
- [crewjam/saml library documentation](https://github.com/crewjam/saml)
- [zitadel/saml provider documentation](https://github.com/zitadel/saml)
- GitHub Issue #28: Extract SingleLogoutService from SP metadata

## 移行ガイド

### フェーズ1: 影響範囲の確認（1-2週間）
1. 現在のSP設定を確認
2. 各SPのメタデータでSingleLogoutServiceの利用可能性を確認
3. メタデータが利用できないSPの特定

### フェーズ2: 段階的な実装（2-3週間）
1. メタデータ解析機能の実装
2. フォールバック機能を含む新しいログアウト処理の実装
3. 統合テストの実施

### フェーズ3: 本番環境での段階的な導入（3-4週間）
1. フォールバック機能を有効にした状態でのデプロイ
2. 各SPでのログアウト機能の検証
3. 段階的なハードコードされたURLパターンの削除

### ロールバック計画
1. フォールバック機能により既存の動作を維持
2. 設定変更のみで以前の動作に戻すことが可能
3. コード変更は必要なし