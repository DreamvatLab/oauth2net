# OAuth2NetCore.Host

[OAuth2NetCore](https://www.nuget.org/packages/OAuth2NetCore) 的 ASP.NET Core 集成包：提供 DI 扩展方法、OAuth 客户端 / 资源服务器 / 授权服务器三种角色的便捷接入。`net10.0` 目标。

## 提供的扩展方法

### Authorization Server

```csharp
services.AddOAuth2AuthServer(options => {
    // 配置 SecurityKeyProvider / ClientStore / TokenClaimBuilder 等
});
```

注册 `IAuthServer`，并通过 endpoint mapping 暴露 token / authorize / endsession 路由。

### Resource Server

```csharp
services.AddOAuth2Resource(o => {
    o.IssuerSigningKey = new RsaSecurityKey(cert.GetRSAPublicKey());
    o.ValidIssuer      = "https://your-auth.example";
    o.ValidAudience    = "https://your-api.example";
    // o.ValidAlgorithms = new[] { SecurityAlgorithms.RsaSsaPssSha256 };  // 默认 PS256
});
```

封装 `AddJwtBearer`，**默认锁定 `[PS256]` 算法白名单**，启用 `ValidateIssuer/Audience/Lifetime/IssuerSigningKey` 与 `RequireSignedTokens`，避免 alg=none / HS+RSA 公钥滥用。

### OAuth Client

```csharp
services.AddOAuth2Client(o => {
    o.StateStoreFactory  = _ => new RedisStateStore(redisConnStr);
    o.CookieSameSite     = SameSiteMode.None;
}, clientOptions);

app.UseEndpoints(endpoints => {
    endpoints.MapGet(clientOptions.SignOutPath,         clientServer.SignOutRequestHandler);
    endpoints.MapGet(clientOptions.SignOutCallbackPath, clientServer.SignOutCallbackRequestHandler);
});
```

注册 Cookie + OAuth 认证方案、自动 refresh token、token 加密存于 Cookie，并提供 `IClientServer` 处理 sign-in/sign-out 流程。

### 共享类型

- `OAuth2Handler` — 内置 OAuth handler，扩展 Microsoft 的 `OAuthHandler<OAuthOptions>` 接入自定义 token store。
- `HttpContextTokenStore` — `ITokenStore` 实现，将 token DTO 加密后写入浏览器 Cookie。
- `LocalRedirectGuard` — internal 工具，限制 sign-in/sign-out 的 `returnUrl` 为本地路径，防御开放重定向。

## v2.0 安全加固要点

- **`ResourceOptions.ValidAlgorithms` 默认 `[PS256]`**——签名算法不是 PS256 的资源服务器必须显式声明。
- **`LocalRedirectGuard` 默认拒绝跨站 `returnUrl`**——任何 `//`、`/\`、`http(s)://` 都会回退到 `/`。
- **Cookie 名修正为 `auth.token`**（v1.x 为 `atuh.cookie2`，拼写错误）；升级会导致一次性重登。
- **OAuth handler 内部不再在 `AddOAuth2Client` 配置阶段调 `BuildServiceProvider`**；服务从 `HttpContext.RequestServices` 即时解析。

完整漏洞清单与升级指南：

- [SECURITY-AUDIT-2026-05-19.md](https://github.com/Lukiya/oauth2net/blob/master/docs/SECURITY-AUDIT-2026-05-19.md)
- [UPGRADING-v2.md](https://github.com/Lukiya/oauth2net/blob/master/docs/UPGRADING-v2.md)
- [CHANGELOG.md](https://github.com/Lukiya/oauth2net/blob/master/CHANGELOG.md)

## 仓库

https://github.com/Lukiya/oauth2net

## 协议

GPL-3.0-or-later
