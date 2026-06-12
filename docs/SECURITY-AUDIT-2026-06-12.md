# OAuth2net 安全审计与修复记录（2026-06-12）

> 适用版本：v3.0.0
>
> 本文档是 [`SECURITY-AUDIT-2026-05-19.md`](./SECURITY-AUDIT-2026-05-19.md)（v2.0.0）的后续。它记录两批改动：
> ① 目标框架从 `netstandard2.0` 升级到 `net10.0`（及其带来的依赖与 CVE 清理）；
> ② 在新框架基础上做的第二轮安全加固与若干功能 bug 修复。
> 所有修复已合入，`dotnet build oauth2net.sln` 通过（0 warnings, 0 errors），单测 94 / 94 通过。

## 总览

| ID  | 严重度 | 简述                                                          | 状态 |
| --- | ------ | ------------------------------------------------------------- | ---- |
| F-1 | 高     | netstandard2.0 → net10.0；移除遗留 OAuth 2.3.x 包消除传递 CVE | ✅ 已修复 |
| F-2 | 中     | 库内仍用过时的 `new X509Certificate2(path, ...)`（上次 M-5 遗留） | ✅ 已修复 |
| S-1 | 中     | 登录令牌 `t` 未编码拼入授权 URL，可注入授权请求参数           | ✅ 已修复 |
| S-2 | 中     | 公共客户端（PKCE）凭据路径不可达，变相逼迫内嵌 secret         | ✅ 已修复 |
| S-3 | 低     | 用户输入直接作为日志模板（格式注入 / 日志伪造）              | ✅ 已修复 |
| S-4 | 低     | PKCE challenge 与 state 比对使用非常量时间                    | ✅ 已修复 |
| B-1 | bug    | 同步 `RedisClientStore.GetClients()` 用错 key/value，方法不可用 | ✅ 已修复 |
| B-2 | bug    | 同步 `RedisClientStore.GetClient()` 缺 `IsNull` 判断，未知 client 抛异常 | ✅ 已修复 |

按设计保留（不视为缺陷）：
- **Redis client secret 解密失败时回退为明文**：明文存储是受支持的部署形态（使用 `DefaultSecretEncryptor` 或混存场景），故 `RedisClientStore` 解密失败继续按明文处理，未改为 fail-closed。能读取 Redis 内容者本就等同掌握凭据，此行为不扩大风险面。

未处理（属新功能或部署侧，需另立计划）：
- 登出 CSRF（`/endsession`、`/signout` 为无防伪造的 GET）——属 OIDC `id_token_hint` 范畴
- Refresh token 重用检测（被盗 token 先用时撤销整个 token 族，OAuth 2.1 BCP 推荐）
- 刷新时不重新校验 scopes（管理员收紧权限后，TTL 内旧 refresh token 仍按旧 scopes 续发）
- client secret 仍明文存储 + 比对（上次 C-2 的剩余风险，建议改存哈希）
- 内存版授权码存储为进程内静态字典，多实例部署需改用 Redis 实现（Redis 包当前未提供 `IAuthCodeStore`）

---

## 框架升级（Framework）

### F-1. netstandard2.0 → net10.0，并移除遗留 OAuth 2.3.x 包

**文件：** `src/common.props`、`src/OAuth2NetCore/OAuth2NetCore.csproj`、`src/OAuth2NetCore.Host/OAuth2NetCore.Host.csproj`、`src/OAuth2NetCore.Redis/OAuth2NetCore.Redis.csproj`

**背景：**
`netstandard2.0` 的唯一价值是兼容 .NET Framework / 老 Xamarin。本库的消费端（Host、资源服务器）均已在 net10 上运行，继续保留 netstandard 只剩成本：拿不到现代运行时 API、被迫依赖为 .NET Framework 维护的遗留包分支。

其中 `OAuth2NetCore` 核心库引用的 `Microsoft.AspNetCore.Authentication.OAuth` **2.3.x** 是给 .NET Framework 维护的遗留分支，会传递引入两个已知高危漏洞：

- `Newtonsoft.Json` 11.0.2 — GHSA-5crp-9r3c-p9vr
- `System.Security.Cryptography.Xml` 8.0.2 — GHSA-37gx-xxp4-5rgx / GHSA-w3x6-4m5h-cxqf

**修复：**
- 全部目标框架统一为 `net10.0`（`common.props`）。
- `OAuth2NetCore` 核心库删除 `Microsoft.AspNetCore.Authentication.OAuth` 包，改为 `<FrameworkReference Include="Microsoft.AspNetCore.App" />`。OAuth 认证类型自 ASP.NET Core 3.0 起已内置于共享框架，无需该包——两个传递 CVE 随之消失。
- 同时删除核心库中多余的 `System.Text.Json`、`Microsoft.Extensions.Configuration.Binder`、`Microsoft.Extensions.Logging` 显式引用（均已在共享框架内，触发 NU1510）。
- 从 Redis、Host 两个**发行库**移除误放的 `coverlet.collector`（测试覆盖率收集器不属于类库）。

**⚠ Breaking：**
- 仍在 .NET Framework / netstandard / net6-8 上的使用者**无法再引用**本库，必须升到 net10。
- 库现在绑定 ASP.NET Core 共享框架（原本是可跨框架的库）。

### F-2. 库内仍用过时的 `X509Certificate2` 构造（上次 M-5 遗留）

**文件：** `src/OAuth2NetCore/Security/X509SecurityKeyProvider.cs`、`X509SecretEncryptor.cs`

**情况：**
上次审计因受 netstandard2.0 限制，只能保留 `new X509Certificate2(path, pass)` 并加注释。升级到 net10 后该约束消失。

**修复：**
两处便利构造改用 `X509CertificateLoader.LoadPkcs12FromFile(...)`（更严格的 `Pkcs12LoaderLimits`，消除 SYSLIB0057）。公开构造签名不变，对调用方透明。

---

## 安全加固（Security）

### S-1. 登录令牌 `t` 未编码拼入授权 URL

**文件：** `src/OAuth2NetCore.Host/ClientServerExtensions.cs` — `OnRedirectToAuthorizationEndpoint`

**问题：**
登录令牌 `t` 来自 `/signin?t=...` 的原始查询参数，原代码直接字符串拼接到授权端点 URL：

```csharp
ctx.RedirectUri += "&t=" + ctx.Properties.Parameters["t"];
```

未经 URL 编码，攻击者可构造 `t=x%26code_challenge%3D...` 之类的值向 `/authorize` 注入额外参数。服务端取参用 `FirstOrDefault()`，已存在参数无法被覆盖，实际可利用面有限，但「用户输入未编码拼 URL」本身即注入面。

**修复：**
```csharp
if (ctx.Properties.Parameters.TryGetValue("t", out var t) && t != null) {
    ctx.RedirectUri += "&t=" + Uri.EscapeDataString(t.ToString());
}
```

授权端点按标准 query 解析会自动解码，正常往返一致。

### S-2. 公共客户端（PKCE）凭据路径不可达

**文件：** `src/OAuth2NetCore/Security/DefaultClientValidator.cs` — `ExractClientCredentialsFromBody`

**问题：**
`VerifyClientAsync` 有 `client.IsPublic` 免 secret 的分支，但 body 提取在 secret 为空时直接报 `invalid_request`（"client secret is missing"），该分支永远走不到。结果 SPA / 原生应用必须内嵌 client secret——内嵌即泄露。

**修复：**
body 提取放开空 secret，把公共 / 机密判定交给 `VerifyClientAsync`：

```csharp
var secret = context.Request.Form[OAuth2Consts.Form_ClientSecret].FirstOrDefault();
mr.Result = new NetworkCredential(id, secret ?? string.Empty);
return mr;
```

公共客户端（`IsPublic = true`）凭 PKCE 放行；机密客户端漏传 secret 时空密码过不了常量时间比对，仍被拒。

**⚠ 行为变化：**
token 端点对「机密客户端漏传 secret」的错误码从 `invalid_request`（"client secret is missing"）变为 `invalid_client`（语义上 `invalid_client` 更符合 RFC，也不泄露「secret 缺失」细节）。对错误字符串硬断言的自动化客户端会注意到。直接调用公开方法 `ExractClientCredentials` 并依赖其失败的代码也受影响。

### S-3. 用户输入直接作为日志模板

**文件：** `src/OAuth2NetCore/Security/DefaultClientValidator.cs`（多处）、`src/OAuth2NetCore/DefaultAuthServer.cs` — `ErrorHandler`

**问题：**
`_logger.LogWarning(mr.MsgCodeDescription)` 把含用户输入（`redirect_uri`、`client_id` 等）的字符串当作消息模板。输入含 `{` 时部分 logger 会抛 `FormatException`（请求 500），也存在日志伪造空间。

**修复：**
全部改结构化模板：`_logger.LogWarning("{Message}", mr.MsgCodeDescription)`（24 处 + `ErrorHandler`）。

### S-4. PKCE challenge 与 state 比对非常量时间

**文件：** `src/OAuth2NetCore/OAuth2Utils.cs`（新增）、`Security/DefaultPkceValidator.cs`、`DefaultAuthServer.cs`、`Security/DefaultClientValidator.cs`

**问题：**
- `DefaultPkceValidator` 用 `==` 比对 code_challenge。
- `DefaultAuthServer` clear-token 用 `storedState != state` 比对 state。
S256 模式下可利用性极低，但升 net10 后改常量时间成本为零。

**修复：**
新增 `OAuth2Utils.FixedTimeEquals`（net10 直接复用 BCL `CryptographicOperations.FixedTimeEquals`）：

```csharp
public static bool FixedTimeEquals(string a, string b) {
    if (a == null || b == null) return ReferenceEquals(a, b);
    return CryptographicOperations.FixedTimeEquals(
        Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b));
}
```

PKCE、state 三处统一调用；`DefaultClientValidator` 里上次手写的 `FixedTimeEquals`（含 netstandard2.0 兼容注释）也删除并改为复用此方法。相等性结果完全不变，仅改时序，非破坏性。

---

## 功能 Bug

### B-1. 同步 `RedisClientStore.GetClients()` 不可用

**文件：** `src/OAuth2NetCore.Redis/Client/RedisClientStore.cs`

原代码 `hashEntries.ToDictionary(x => x.ToString(), x => Deserialize(x.ToString()))` 把整个 `HashEntry` 转成 `"name: value"` 字符串当 key 和 JSON，方法实际不可用。改为 `x.Name` / `x.Value`，与异步版一致。

### B-2. 同步 `RedisClientStore.GetClient()` 缺 `IsNull` 判断

未知 client 时 `json.IsNull` 未判，直接反序列化抛异常而非返回 null（异步版一直返回 null）。补 `if (json.IsNull) return null;`。

**⚠ 行为变化：** 同步 `GetClient` 对未知 client 从抛异常变为返回 null（修正为与异步版及接口契约一致）。

---

## 验证

- `dotnet build oauth2net.sln` — **0 Warning, 0 Error** ✅
- `dotnet test test/unittests` — **94 / 94 通过** ✅（含锁定 S-2 新契约的更新测试 `ExractCreds_BodyHasIdButNoSecret_ExtractsEmptySecret`）

### 单测未覆盖的回归面

- **S-4 时序属性**：单元测试无法可靠验证时序常量，靠代码审查 + BCL `CryptographicOperations.FixedTimeEquals` 保证。
- **F-1 传递 CVE 消除**：靠 `dotnet build` 无 NU1903 与依赖图确认（`dotnet nuget why`）。

---

## 升级清单（按操作顺序）

1. **目标框架：**
   - [ ] 下游升级到 **net10**（无法继续在 .NET Framework / netstandard / net6-8 引用本库）。

2. **客户端协调：**
   - [ ] 公共客户端确认 `IsPublic = true` 并使用 PKCE（不再需要内嵌 secret）。
   - [ ] 对 token 端点错误码硬断言的自动化客户端，注意「机密客户端漏传 secret」从 `invalid_request` 变为 `invalid_client`。

3. **预期影响：**
   - [ ] 绝大多数使用者（机密客户端 + 正常传 secret）无感。
   - [ ] 直接调用 `ExractClientCredentials` 且依赖其对「无 secret」返回失败的代码需调整。
