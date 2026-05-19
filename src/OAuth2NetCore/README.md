# OAuth2NetCore

OAuth 2.0 / OpenID Connect 协议核心库，提供授权码（含 PKCE）、客户端凭证、资源所有者密码、隐式与刷新令牌等标准 grant type 的服务端实现。`netstandard2.0` 目标。

## 主要类型

- `IAuthServer` / `DefaultAuthServer` — Token / Authorize / EndSession / ClearToken 请求处理器。
- `AuthServerOptions` — 服务端配置（PKCE 必需、签名算法、各 store/factory 注册）。
- `ClientOptions` — 客户端配置（OAuth client 接入参数）。
- `IClientValidator` / `DefaultClientValidator` — Basic Auth 提取与客户端凭证、redirect URI、grant、scope、response type 校验。
- `IPkceValidator` / `DefaultPkceValidator` — PKCE `S256` / `plain` 校验。
- `ITokenGenerator` / `DefaultTokenGenerator` — 基于 `Microsoft.IdentityModel.JsonWebTokens` 的 JWT 签发，默认算法 PS256。
- `ISecretEncryptor` / `X509SecretEncryptor` — RSA OAEP-SHA256 加密器（v2.0+）。
- `IClientStore` / `IAuthCodeStore` / `IRefreshTokenInfoStore` / `IStateStore` — 各存储接口。内存版默认实现包含在主库中；Redis 实现在 [`OAuth2NetCore.Redis`](https://www.nuget.org/packages/OAuth2NetCore.Redis) 包。

## 快速接入

```csharp
services.AddOAuth2AuthServer(options => {
    options.SecurityKeyProviderFactory = _ => new X509SecurityKeyProvider(cert);
    options.ClientStoreFactory          = _ => myClientStore;
    options.RefreshTokenInfoStore       = _ => myRefreshTokenStore;
    options.StateStoreFactory           = _ => myStateStore;
    options.TokenClaimBuilderFactory    = _ => new MyTokenClaimBuilder();
    options.ResourceOwnerValidatorFactory = sp => new MyResourceOwnerValidator(...);
    // options.SigningAlgorithm   = SecurityAlgorithms.RsaSsaPssSha256;  // 默认 PS256
    // options.PKCERequired       = true;   // 默认开
    // options.AllowPlainPkce     = false;  // 默认拒绝 plain，仅过渡期可放行
});

// ...

app.UseEndpoints(endpoints => {
    endpoints.MapPost("/connect/token",        authServer.TokenRequestHandler);
    endpoints.MapGet ("/connect/authorize",    authServer.AuthorizeRequestHandler);
    endpoints.MapGet ("/connect/endsession",   authServer.EndSessionRequestHandler);
    endpoints.MapPost("/connect/endsession",   authServer.ClearTokenRequestHandler);
});
```

## v2.0 安全加固要点

v2.0 是 **major security release**。完整漏洞清单与下游升级指南见仓库内：

- [SECURITY-AUDIT-2026-05-19.md](https://github.com/Lukiya/oauth2net/blob/master/docs/SECURITY-AUDIT-2026-05-19.md)
- [UPGRADING-v2.md](https://github.com/Lukiya/oauth2net/blob/master/docs/UPGRADING-v2.md)
- [CHANGELOG.md](https://github.com/Lukiya/oauth2net/blob/master/CHANGELOG.md)

**从 v1.x 升级前必读**——RSA padding、PKCE 默认值、Cookie 名等均为 breaking change。

## 仓库

https://github.com/Lukiya/oauth2net

## 协议

GPL-3.0-or-later
