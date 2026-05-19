# OAuth2net 安全审计与修复记录（2026-05-19）

> 适用版本：v2.0.0
>
> 本文档列出 2026-05-19 安全审计中发现的全部漏洞、修复方式、影响面与迁移说明。所有修复已合入主分支，`dotnet build oauth2net.sln` 通过（0 warnings, 0 errors）。

## 总览

| ID  | 严重度 | 简述                                                 | 状态 |
| --- | ------ | ---------------------------------------------------- | ---- |
| C-1 | 严重   | Implicit 流 access_token 通过 URL query 返回         | ✅ 已修复 |
| C-2 | 严重   | client_secret 比对使用非常量时间                     | ✅ 已修复 |
| C-3 | 严重   | Redis refresh token/state 非原子取-删（replay）     | ✅ 已修复 |
| C-4 | 严重   | RSA 加密用 PKCS#1 v1.5 padding（Bleichenbacher）    | ✅ 已修复 |
| C-5 | 严重   | SignIn/SignOut returnUrl 开放重定向                  | ✅ 已修复 |
| H-1 | 高     | PKCE 默认 `plain` 且 code_challenge 回传到 redirect | ✅ 已修复 |
| H-2 | 高     | JWT 验证未限制 `ValidAlgorithms`                     | ✅ 已修复 |
| H-3 | 中-高  | HTTP Basic Auth 用 base64url 解码 + 未校验 scheme    | ✅ 已修复 |
| H-4 | 高     | 内存版授权码读取不校验过期（时间窗内可复用）         | ✅ 已修复 |
| H-5 | 高     | redirect URL 拼接对已有 query 不友好                 | ✅ 已修复 |
| M-1 | 中     | `/authorize` 缺 `state` 没告警                       | ✅ 已修复 |
| M-3 | 中     | clear_token 端点不写响应状态码                       | ✅ 已修复 |
| M-4 | 中     | EndSession 死代码                                    | ✅ 已修复 |
| M-5 | 中     | 库内仍用过时的 `X509Certificate2(path,...)`          | ⚠️ 部分（受 netstandard2.0 限制） |
| M-6 | 中     | `X509SecretEncryptor` 未实现 `IDisposable`           | ✅ 已修复 |
| M-7 | 中     | `Token.ToJsonString` 与错误响应手撕 JSON             | ✅ 已修复 |
| L-1 | 低     | Cookie 名称拼写错误 `atuh.cookie2`                   | ✅ 已修复 |
| L-2 | 低     | DefaultAuthServer 残余 Newtonsoft.Json 依赖          | ✅ 已修复 |
| L-3 | 低     | `services.BuildServiceProvider()` 反模式             | ✅ 已修复 |

未处理（属于新功能或部署侧，需另立计划）：
- OIDC 完整支持（id_token / nonce / `.well-known/openid-configuration`）
- Token revocation (RFC 7009) / introspection (RFC 7662)
- 客户端登录限流 / 锁定
- 单元测试补全
- SameSite=None 与 Secure 运行时一致性校验

---

## 严重（Critical）

### C-1. 隐式流 access_token 通过 URL query 返回（RFC 6749 违规）

**文件：** `src/OAuth2NetCore/DefaultAuthServer.cs` — `ImplicitTokenRequestHandler`

**问题：**
RFC 6749 §4.2.2 强制要求 implicit 流将令牌放入 URL **fragment**（`#`），fragment 不会被浏览器发送到服务器、不进 access log、不进 Referer 头。原实现用 `?` 拼接 query，access_token 会出现在：
- Web 服务器 access log
- 代理/CDN 日志
- 浏览器历史记录
- 后续请求的 Referer 头

任意一处泄漏都等于令牌泄露。

**修复：**
- 新增 `OAuth2Utils.AppendFragment(...)` 工具方法
- `ImplicitTokenRequestHandler` 改用 fragment：

```csharp
var redirect = OAuth2Utils.AppendFragment(redirectURI, new[] {
    new KeyValuePair<string, string>(OAuth2Consts.Form_AccessToken, token),
    new KeyValuePair<string, string>(OAuth2Consts.Form_TokenType, "Bearer"),
    ...
});
context.Response.Redirect(redirect);
```

**迁移说明：**
依赖隐式流的 SPA/JS 客户端需要从 `window.location.hash`（而非 `window.location.search`）读取 token。RFC 6749 自始至终都这样要求，此前的实现是 bug。

**长期建议：** OAuth 2.1 已弃用隐式流。建议彻底移除该分支，全部走授权码 + PKCE。

---

### C-2. client_secret 比对使用非常量时间（Timing Attack）

**文件：** `src/OAuth2NetCore/Security/DefaultClientValidator.cs:118`

**问题：**
原代码 `if (credential.Password != client.Secret)` 是逐字符短路比较，可被精心构造的请求时序差异逐字节探测出 secret。

**修复：**
引入常量时间比较 `FixedTimeEquals`（自实现，因 netstandard2.0 无 `CryptographicOperations.FixedTimeEquals`）：

```csharp
[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
private static bool FixedTimeEquals(string a, string b) {
    if (a == null || b == null) return a == b;
    var ab = Encoding.UTF8.GetBytes(a);
    var bb = Encoding.UTF8.GetBytes(b);
    var min = Math.Min(ab.Length, bb.Length);
    int diff = ab.Length ^ bb.Length;
    for (int i = 0; i < min; i++) diff |= ab[i] ^ bb[i];
    return diff == 0;
}
```

`NoInlining | NoOptimization` 防止 JIT 优化破坏常量时间特性。

**剩余风险：** `client.Secret` 仍以明文形式从存储中读出后比较。下个迭代建议改"存哈希、比哈希"（Argon2id / PBKDF2-SHA256）。

---

### C-3. Refresh Token / State Store 取-删非原子（Replay 风险）

**文件：**
- `src/OAuth2NetCore.Redis/Token/RedisRefreshTokenInfoStore.cs:29`
- `src/OAuth2NetCore.Redis/State/RedisStateStore.cs:22`

**问题：**
原实现是 `StringGetAsync` + `KeyDeleteAsync` 两步操作，期间存在窗口：

```
请求 A: GET key → 得到 token info
请求 B: GET key → 得到 token info  ← 同样成功！
请求 A: DEL key
请求 B: DEL key（已删，不影响）
```

两个并发 refresh 都拿到 token，绕过 refresh token rotation。同样问题影响 state（虽然 state 风险面更小）。

**修复：**
StackExchange.Redis 2.5+ 支持 `StringGetDeleteAsync`（对应 Redis 6.2 的 `GETDEL`），原子完成"读+删"：

```csharp
public async Task<RefreshTokenInfo> GetThenRemoveTokenInfoAsync(string refreshToken) {
    var json = await Database.StringGetDeleteAsync(_prefix + refreshToken);
    // ...
}
```

**依赖要求：** Redis 服务端 ≥ 6.2.0。

---

### C-4. RSA 加密使用 PKCS#1 v1.5 padding（Bleichenbacher）

**文件：** `src/OAuth2NetCore/Security/X509SecretEncryptor.cs`

**问题：**
`RSAEncryptionPadding.Pkcs1`（PKCS#1 v1.5）是经典的 padding oracle 漏洞面（Bleichenbacher 1998）。配合原 `TryDecrypt` 把异常吞掉返回原文的行为，更易被利用为 oracle。

**修复：**
全部改 `RSAEncryptionPadding.OaepSHA256`。同时让 `X509SecretEncryptor` 实现 `IDisposable`，释放底层 `RSA` 和 `X509Certificate2` 句柄（修 M-6）：

```csharp
var encryptedBytes = _publicRsaProvider.Encrypt(plainBytes, RSAEncryptionPadding.OaepSHA256);
```

**⚠️ Breaking 迁移：**
旧密文（PKCS#1）无法用新代码（OAEP-SHA256）解密。受影响数据：

1. **Redis 中加密的 client secret**（`RedisClientStore`）— 必须重新加密并写回。可使用 `tools/X509SecretEncryptor` 工具批量迁移：先用旧版本（v1.x 的库）解密，再用 v2.0 的库加密回 Redis。
2. **Redis 中加密的 refresh token info JSON**（`RedisRefreshTokenInfoStore`）— refresh token TTL 内的活动会话会失效。考虑到 refresh token 寿命短（默认 2 小时），建议在低峰发版后等待 TTL 自然过期。

**容量：** 2048-bit RSA + OAEP-SHA256 的最大明文长度约 190 字节（旧 PKCS#1 约 245 字节）。如有较长的 client secret/refresh token JSON，需要升级到 3072-bit 或 4096-bit 证书。

---

### C-5. SignIn/SignOut returnUrl 开放重定向

**文件：** `src/OAuth2NetCore.Host/DefaultClientServer.cs`

**问题：**
`HandleSignInRequestAsync` 与 `HandleSignOutCallbackRequestAsync` 直接将查询参数 `returnUrl` 用于最终跳转，没有同源/白名单校验。攻击者可构造钓鱼链接：

```
https://yoursite.com/signin?returnUrl=https://evil.com/phish
```

用户认证成功后被静默重定向到攻击者控制的页面，结合视觉模仿可窃取后续输入。

**修复：**
新增 `LocalRedirectGuard.SafeLocal(...)`，仅放行 `/` 开头且非协议相对（`//evil.com`、`/\evil.com`）的相对路径，否则强制回退到 `/`：

```csharp
internal static class LocalRedirectGuard {
    public static string SafeLocal(string returnUrl) {
        if (string.IsNullOrEmpty(returnUrl)) return "/";
        if (returnUrl[0] != '/') return "/";
        if (returnUrl.Length > 1 && (returnUrl[1] == '/' || returnUrl[1] == '\\')) return "/";
        return returnUrl;
    }
}
```

所有外部输入的 returnUrl 都经过此函数。

---

## 高（High）

### H-1. PKCE 默认 `plain` 且 code_challenge 回传到客户端

**文件：** `src/OAuth2NetCore/DefaultAuthServer.cs:AuthorizationCodeRequestHandler`

**问题：**
1. 当客户端未发送 `code_challenge_method` 时，默认设为 `plain`。`plain` 模式下 challenge == verifier，几乎等同没有 PKCE。
2. 原代码把 `code_challenge` 与 `code_challenge_method` 拼接到给客户端的 redirect URL 上——**非标准**，且把本应只在客户端侧持有的值暴露到 access log 与 Referer 头，毫无收益。

**修复：**
- 默认 method 改为 `S256`
- 新增 `AuthServerOptions.AllowPlainPkce`（默认 `false`），明确拒绝 `plain`，需要时可显式打开
- 授权响应严格按 RFC 6749 §4.1.2 仅返回 `code` 与 `state`

```csharp
if (string.IsNullOrWhiteSpace(codeChanllengeMethod)) {
    codeChanllengeMethod = OAuth2Consts.Pkce_S256;  // secure default
} else if (codeChanllengeMethod == OAuth2Consts.Pkce_Plain) {
    if (!AuthServerOptions.AllowPlainPkce) {
        await ErrorHandler(..., "code_challenge_method 'plain' is not allowed, use 'S256'.");
        return;
    }
}
```

**迁移：** 老客户端如发送 `code_challenge_method=plain`，将收到 `invalid_request`。修客户端用 S256，或临时打开 `AuthServerOptions.AllowPlainPkce = true` 过渡。

---

### H-2. JWT 验证未限制 `ValidAlgorithms`

**文件：** `src/OAuth2NetCore.Host/ResourceServerExtensions.cs`、`ResourceOptions.cs`

**问题：**
`TokenValidationParameters` 没声明 `ValidAlgorithms`，依赖默认行为防御"alg=none"与"HS256 abuse RSA public key"等经典 JWT 漏洞。Microsoft.IdentityModel 8.x 默认有按 key 类型筛选，但显式声明属于必备的深度防御。

**修复：**
- `ResourceOptions.ValidAlgorithms` 默认 `[ PS256 ]`（与 `AuthServerOptions.SigningAlgorithm` 默认值一致）
- `AddJwtBearer` 显式启用 `ValidateIssuer/Audience/Lifetime/IssuerSigningKey`、`RequireSignedTokens = true`、`ValidAlgorithms = options.ValidAlgorithms`

如签名算法不是 PS256，调用方需显式覆盖 `options.ValidAlgorithms`。

---

### H-3. HTTP Basic Auth 用 base64url 解码 + 未校验 scheme

**文件：** `src/OAuth2NetCore/Security/DefaultClientValidator.cs:ExractClientCredentialsFromHeader`

**问题：**
1. 原代码用 `Base64UrlEncoder.Decode` 解析 Basic auth。RFC 7617 强制要求 **标准** base64（含 `+`、`/`、`=`）。虽然 `Base64UrlEncoder.Decode` 在多数情况下能"碰巧"接受标准 base64，但语义错误且对边界字符不稳定。
2. 完全没校验 Authorization scheme 是否为 `Basic`，"Bearer xxx"、"Negotiate xxx" 都会被错误地走 Basic 解析流程。
3. 用户名/密码分隔时 `Split(..., RemoveEmptyEntries)` 错误处理：密码内含 `:` 时会被截断（RFC 7617 允许密码含 `:`，仅按**第一个** `:` 分隔）。

**修复：**
```csharp
const string basicPrefix = "Basic ";
if (!authorzation.StartsWith(basicPrefix, StringComparison.OrdinalIgnoreCase)) {
    // reject
}
var encoded = authorzation.Substring(basicPrefix.Length).Trim();
var authStr = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
var colonIdx = authStr.IndexOf(':');
var user = authStr.Substring(0, colonIdx);
var pass = authStr.Substring(colonIdx + 1);
```

---

### H-4. 内存版授权码 `TryRemove` 不验过期

**文件：** `src/OAuth2NetCore/Store/AutoCleanDictionary.cs`

**问题：**
`AutoCleanDictionary` 的 timer 每 60s 清扫一次，但 `TryRemove` 不查 `Expire`。一个授权码到期后、清扫前的窗口（最坏 60s）内仍可被兑换。

**修复：**
```csharp
public bool TryRemove(TKey key, out TValue value) {
    if (_dic.TryRemove(key, out var paylaod)) {
        if (DateTimeOffset.UtcNow >= paylaod.Expire) {
            value = default; return false;
        }
        value = paylaod.Payload; return true;
    }
    // ...
}
```

---

### H-5. URL 拼接对已有 query 不友好

**文件：** 多处（`DefaultAuthServer.cs`、`DefaultClientServer.cs`）

**问题：**
原代码用 `$"{redirectURI}?{key}={value}&..."` 字符串拼接。如果 `redirectURI` 已含 `?`（合法 redirect uri），结果出现两个 `?`，目标客户端解析失败。`clientID`、`endSessionID` 等也漏掉 URL 编码。

**修复：**
新增 `OAuth2Utils.AppendQuery` / `AppendFragment` 工具方法，自动判断 `?` 是否已存在、所有 key/value 都经 `Uri.EscapeDataString` 编码，null 值自动跳过。

---

## 中（Medium）

### M-1. `/authorize` 缺 `state` 没告警

**文件：** `src/OAuth2NetCore/DefaultAuthServer.cs:HandleAuthorizeRequestAsync`

**修复：** 检测 `state` 空时记 warning（不阻塞，因 RFC 6749 §10.12 推荐但不强制）：
```csharp
if (string.IsNullOrWhiteSpace(state)) {
    _logger.LogWarning("/authorize request missing 'state' parameter (client_id={ClientID})", clientID);
}
```

---

### M-3. clear_token 端点不写响应

**文件：** `src/OAuth2NetCore/DefaultAuthServer.cs:HandleClearTokenRequestAsync`

**修复：** 成功路径写 `200 OK`，让客户端能区分"删除成功"与"被中间件吞掉"。

---

### M-4. EndSession 死代码

**文件：** `src/OAuth2NetCore/DefaultAuthServer.cs:HandleEndSessionRequestAsync`

**修复：** 移除第二段 `if (!string.IsNullOrWhiteSpace(state))`（前文已保证非空）。

---

### M-5. 库内仍用过时的 `X509Certificate2(path, ...)` ⚠️ 部分修复

**文件：** `src/OAuth2NetCore/Security/X509SecretEncryptor.cs`、`X509SecurityKeyProvider.cs`

**情况：**
.NET 9+ 已弃用 `new X509Certificate2(string, string)`，新 API 是 `X509CertificateLoader.LoadPkcs12FromFile`（更严格的 `Pkcs12LoaderLimits`）。

**约束：**
两个文件所在的 `OAuth2NetCore` 是 **netstandard2.0** 目标，无法引用 .NET 9+ 才有的 `X509CertificateLoader`。

**目前做法：** 保留 `X509Certificate2` 便利构造，加注释提示 .NET 9+ 调用方应改用 `X509Certificate2` 重载并预先用 `X509CertificateLoader` 加载证书（测试项目 `test/api/Startup.cs`、`test/auth/Startup.cs` 已是该模式）。

**长期建议：** 把 `OAuth2NetCore` 多目标化（`netstandard2.0;net9.0`），在 net9.0 TFM 下提供使用新 API 的实现。

---

### M-6. `X509SecretEncryptor` 未实现 `IDisposable`

合并到 C-4 一起改：现已实现 `IDisposable`，`Dispose` 释放 `_publicRsaProvider`、`_privateRsaProvider`、`_x509Cert`。

DI 注册为 singleton 时影响有限，但在 worker/tools 短生命周期使用场景下会泄漏 CNG 句柄。如自行托管该类，请在 shutdown 时 `Dispose`。

---

### M-7. 手撕 JSON 易被注入

**文件：**
- `src/OAuth2NetCore/Model/Token.cs:ToJsonString`
- `src/OAuth2NetCore/DefaultAuthServer.cs:ErrorHandler`、`HandleOpenIDConfigRequestAsync`、`HandleOpenIDJwksRequestAsync`
- `src/OAuth2NetCore/OAuth2Consts.cs:Format_Error`（保留常量以备外部引用，但内部不再使用）

**问题：**
原代码用 `StringBuilder.AppendFormat`/`string.Format` 拼 JSON。一旦字段含 `"` 或控制字符（错误描述可能含用户传入的 `redirect_uri` 片段），JSON 结构会损坏。

**修复：**
全部改 `System.Text.Json.JsonSerializer.Serialize`：

```csharp
var json = JsonSerializer.Serialize(new { error, error_description = errorDescription });
```

同时移除 `using Newtonsoft.Json;`（L-2 修复）—— 主库 `OAuth2NetCore` 不再依赖 Newtonsoft.Json（之前仅在 wellknown 序列化处使用）。

---

## 低（Low）

### L-1. Cookie 名称拼写错误 `atuh.cookie2` → `auth.token`

**文件：** `src/OAuth2NetCore/OAuth2Consts.cs`

**Breaking 影响：**
所有现有的客户端 cookie（名为 `atuh.cookie2` 的浏览器 cookie）会被忽略，等同所有用户被注销。v2.0.0 是 major 版本，可以接受该 break。如不愿接受，可在升级时把旧 cookie 重命名到新名称。

---

### L-2. DefaultAuthServer 残余 Newtonsoft.Json 依赖

随 M-7 一并移除。`OAuth2NetCore` 主库不再 `using Newtonsoft.Json`，避免双 JSON 库带来的版本管理与不一致风险。

---

### L-3. `services.BuildServiceProvider()` 反模式

**文件：** `src/OAuth2NetCore.Host/ClientServerExtensions.cs:AddOAuth2Client`

**问题：**
原代码在 `AddOAuth2Client` 内部 `services.BuildServiceProvider()` 拿到 `IHttpClientFactory`、`ITokenStore`，把它们闭包到 event handler 里。这会创建第二个 DI 容器，singleton 的 `HttpClientFactory`、`DataProtector` 实例与主容器分离，长期可能造成内存/句柄异常。

**修复：**
event handler 改成从 `HttpContext.RequestServices` 即时解析：

```csharp
o.Events.OnValidatePrincipal = ctx => {
    var sp = ctx.HttpContext.RequestServices;
    return ValidatePrincipal(ctx,
        sp.GetRequiredService<IHttpClientFactory>(),
        sp.GetRequiredService<ITokenStore>(),
        options);
};
```

`OnCreatingTicket` 同理。

---

## 验证

- `dotnet build oauth2net.sln` — **0 Warning, 0 Error** ✅
- `dotnet test test/unittests` — **91 / 91 通过** ✅（在原 53 个基础上新增 38 个针对本次修复的回归测试）

### 单测新增明细（针对本次修复的回归保护）

| 测试文件 | 新增 | 锁定的修复 |
|---|---|---|
| `OAuth2UtilsTests.cs` | +9 | H-5（AppendQuery/AppendFragment 各路径）+ C-1（fragment 而非 query） |
| `AutoCleanDictionaryTests.cs`（新） | +4 | H-4 过期 payload 不再可取出 |
| `LocalRedirectGuardTests.cs`（新） | +10 | C-5 协议相对 / 绝对 URL / 反斜杠绕过全部回退 `/` |
| `DefaultClientValidatorTests.cs` | +6 | H-3 scheme 校验、首冒号分隔、`+/=` Base64 字符、Base64 异常；C-2 长度不同被拒 |
| `SecretEncryptorTests.cs` | +2 | C-4 PKCS#1 密文被 OAEP-SHA256 拒收；OAEP-SHA256 密文可解 |
| `DefaultAuthServerTests.cs`（新） | +7 | C-1 implicit fragment；H-1 默认 S256 + 拒 plain + AllowPlainPkce 重新放行 + redirect 不回传 challenge；M-1 state 缺失 warning；M-3 clear_token 写 200 |

配套结构改动：`OAuth2NetCore.csproj` 与 `OAuth2NetCore.Host.csproj` 各加 `<InternalsVisibleTo Include="unittests" />`，用于让 `AutoCleanDictionary` 和 `LocalRedirectGuard` 这两个 internal 类型可被测。

### 单测未覆盖的回归面（需要集成测试或后续 follow-up）

- **C-3 Redis GETDEL 原子性**：需要 Redis fixture（testcontainers / fake redis），属集成测试范围
- **C-2 时序属性**：C# 单元测试无法可靠验证时序常量；只能靠代码审查 + `[MethodImpl(NoInlining|NoOptimization)]` 保证
- **H-2 ValidAlgorithms 真实拒收行为**：需要 `WebApplicationFactory` 起一个 host，建议作为集成测试 follow-up

### 端到端建议下一步

- 未运行端到端 OAuth 流程测试。建议：
  1. 实施 OAEP-SHA256 后必须重新加密 Redis 中已存的 client secret，再做端到端授权码 + PKCE 流程冒烟测
  2. 用一个 implicit 客户端验证 fragment 取 token 正确
  3. 用错误的 client_secret 触发 401，确认日志时序差异不再可观察

## 升级清单（按操作顺序）

1. **数据迁移**（生产环境）：
   - [ ] 用 v1.x 解密 Redis 中的 client.Secret（PKCS#1 密文）
   - [ ] 部署 v2.0.0 二进制
   - [ ] 用 v2.0.0 重新加密 client.Secret 并写回 Redis（OAEP-SHA256）
   - [ ] 旧的 refresh token info 让其自然过期（默认 2 小时）

2. **客户端协调**：
   - [ ] PKCE 客户端确认使用 `code_challenge_method=S256`
   - [ ] 隐式流客户端确认从 URL fragment 读取 token
   - [ ] 资源服务器确认 `ResourceOptions.ValidAlgorithms` 与发行端签名算法一致

3. **预期影响**：
   - [ ] 所有已登录浏览器会话失效（cookie 名变化）
   - [ ] 老的 `code_challenge_method=plain` 请求将被拒（除非显式 `AllowPlainPkce = true`）
