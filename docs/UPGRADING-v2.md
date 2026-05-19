# 从 v1.x 升级到 v2.0

v2.0 是安全加固的 major 版本。本文档面向 **接入 oauth2net 的下游开发者**，列出从 v1.x 升级时**必须**、**建议**与**可忽略**的改动。

> 完整漏洞修复清单见 [`SECURITY-AUDIT-2026-05-19.md`](./SECURITY-AUDIT-2026-05-19.md)。
> 本文档是给"已经在用 v1.x、要升 v2.0"的同学的速查表。

---

## 🔴 必须做（不做会立刻挂）

### 1. 重新加密 Redis 中现存的 client secret

`X509SecretEncryptor` 从 PKCS#1 v1.5 改为 OAEP-SHA256，**密文格式不兼容**。线上已有的 client secret 必须迁移，否则 v2.0 启动后所有 client 登录返回 `invalid_client`。

**操作步骤：**

```powershell
# 1. 部署前 — 在 v1.x 环境下导出明文 secret
#    （读取 Redis -> 用旧版 X509SecretEncryptor.Decrypt 解密 -> 临时保存）

# 2. 部署 v2.0.0

# 3. 用 v2.0 的 tools/X509SecretEncryptor 重新加密
dotnet run --project tools/X509SecretEncryptor -- `
    --CertPath=path/to/cert.pfx `
    --CertPass=your-pass `
    --Mode=e `
    --Value=<plaintext-secret>

# 4. 把输出写回 Redis 的 client hash
redis-cli -h <host> HSET <client-key> <client-id> '<json-with-new-encrypted-secret>'
```

**容量提示：** OAEP-SHA256 的明文上限比 PKCS#1 v1.5 略小：

| 证书强度 | PKCS#1 v1.5 明文上限 | OAEP-SHA256 明文上限 |
|---|---|---|
| RSA-2048 | 245 bytes | **190 bytes** |
| RSA-3072 | 373 bytes | 318 bytes |
| RSA-4096 | 501 bytes | 446 bytes |

绝大多数 client secret 远小于 190 字节，不受影响。如果你的 refresh token info JSON 较大（scope 列表很长），考虑升级证书强度。

### 2. Redis 服务端版本 ≥ 6.2.0

`RedisRefreshTokenInfoStore` 和 `RedisStateStore` 改用原子的 `GETDEL` 命令（Redis 6.2 引入）。低于 6.2 会在第一次 refresh token 或 sign-out 时抛 `RedisServerException`。

```powershell
redis-cli -h <host> INFO server | findstr redis_version
```

### 3. 客户端使用 PKCE S256

`AuthServerOptions.AllowPlainPkce` 默认 `false`，发送 `code_challenge_method=plain` 会被服务端返回 `invalid_request`。

**两种处理：**

- **推荐**：客户端改用 S256。如果你用 Microsoft 的 `AddOAuth(...)` 内置 handler 且 `UsePkce = true`，**它自 .NET 6 起永远发 S256，无需任何改动**。
- **过渡**：在 auth 服务器侧设 `AllowPlainPkce = true`：

```csharp
services.AddOAuth2AuthServer(options => {
    options.AllowPlainPkce = true;  // 临时过渡，长期建议关掉
    // ...
});
```

### 4. 资源服务器签名算法要匹配

`ResourceOptions.ValidAlgorithms` 默认 `[ SecurityAlgorithms.RsaSsaPssSha256 ]`（即 `PS256`，与 `AuthServerOptions.SigningAlgorithm` 默认值匹配）。

**如果你的 auth server 用的不是 PS256**，资源服务器必须显式声明：

```csharp
services.AddOAuth2Resource(o => {
    o.ValidAlgorithms = new[] { SecurityAlgorithms.RsaSha256 };  // 例：RS256
    // ...
});
```

不显式声明 + 不匹配，所有 JWT 验证返回 401。

---

## 🟡 建议检查（不改大概率没事）

### 5. Implicit 流客户端读 URL fragment

如果你仍在用 implicit grant（OAuth 2.1 已弃用，建议迁移到 authorization code + PKCE）：

- 旧版（错误）：`?access_token=...`
- 新版（RFC 6749 正确）：`#access_token=...`

正经 OAuth client 库都读 fragment，无影响。**只有自己写 JS 解析 `window.location.search` 的代码需要改成读 `window.location.hash`。**

### 6. SignIn / SignOut 的 returnUrl 必须本地路径

`LocalRedirectGuard` 现在强制 `returnUrl` 是 `/` 开头的相对路径（不能 `//`、`/\`、`javascript:`、`http(s)://`），否则静默改为 `/`。

如果你的应用确实需要跨站 returnUrl（极少见，通常是错误设计），需要继承 `DefaultClientServer` 并覆盖 `HandleSignInRequestAsync` / `HandleSignOutCallbackRequestAsync`。

### 7. Newtonsoft.Json 不再传递引用

`OAuth2NetCore` 主库不再依赖 `Newtonsoft.Json`（已切到 `System.Text.Json`）。

**如果你的项目代码里有 `using Newtonsoft.Json;` 但 csproj 里没显式 `PackageReference`，编译会报错。**

修复：在自己的 csproj 加上：

```xml
<PackageReference Include="Newtonsoft.Json" Version="13.0.4" />
```

### 8. Cookie 名变化

`OAuth2Consts.Cookie_TokenDTO` 从 `atuh.cookie2`（拼写错误）改为 `auth.token`。

**影响：**所有现有浏览器登录会话失效（cookie 名不匹配 → 视为未登录）。**用户会被强制重新登录一次。**不需要代码改动，但建议发个公告。

---

## 🟢 完全无感（无需任何动作）

这些是内部行为加固，对接入方零影响：

- C-2 客户端 secret 常量时间比对
- C-3 Redis GETDEL（升级 Redis 即可，无 API 改动）
- H-4 内存版授权码到期校验
- H-5 URL 构造工具
- M-1 `/authorize` 缺 state 仅记 warning
- M-3 clear_token 端点写 200
- M-4 EndSession 死代码清理
- M-7 错误响应用 STJ 序列化
- L-3 移除了 `services.BuildServiceProvider()` 反模式

---

## 新增 API（你**可选**用上）

### `AuthServerOptions.AllowPlainPkce : bool = false`

放行 PKCE plain 模式（仅过渡期使用）。

### `ResourceOptions.ValidAlgorithms : IList<string> = [PS256]`

显式声明 JWT 接受的签名算法白名单。

### `OAuth2Utils.AppendQuery(...)` / `OAuth2Utils.AppendFragment(...)`

URL 构造工具（自动处理 `?`/`#`/`&`，自动 URL 编码，跳过 null 值）。

### `X509SecretEncryptor : IDisposable`

加密器现在实现 `IDisposable`。如果你把它作为短生命周期对象使用（非 singleton），记得用 `using` 或显式 Dispose 释放底层 RSA 与证书句柄。

---

## 升级核对清单

复制下面这段到你的 release ticket：

```
[Auth 服务端]
□ Redis 已升到 6.2.0+
□ 现存 client secret 已用 v2.0 的 X509SecretEncryptor 重新加密
□ 如签名算法不是 PS256，已在 AuthServerOptions.SigningAlgorithm 显式设置

[资源服务器]
□ 如签名算法不是 PS256，已在 ResourceOptions.ValidAlgorithms 显式设置

[OAuth 客户端]
□ PKCE 使用 S256（Microsoft 内置 handler 自动满足；自实现需检查）
□ 如果用 implicit 流，自定义 JS 已从 query 改读 fragment
□ 如果代码用了 Newtonsoft.Json 且依赖传递引用,已添加显式 PackageReference

[运维]
□ 通知用户：升级后需要重新登录一次（cookie 名变化）
□ 监控 invalid_client 错误率，第一时间发现迁移漏网的 client
□ 监控 invalid_request（method=plain）错误率，识别需要协调 S256 升级的客户端
```

---

## 还原 v1.x 行为（不推荐，但保留逃生通道）

如果某些 break 真的需要短期回退：

| 想还原什么 | 怎么做 | 注意 |
|---|---|---|
| 接受 PKCE plain | `AuthServerOptions.AllowPlainPkce = true` | 长期建议改 S256 |
| 接受多算法 JWT | `ResourceOptions.ValidAlgorithms = new[] { PS256, RS256, ... }` | 永远显式列举，**别留空让默认接受所有** |
| 旧 cookie 名 | 暂无开关；如必需，自行继承 `HttpContextTokenStore` 并覆盖读写位置 | 建议接受一次性重登 |

**无法还原**（设计上就不该退回）：

- PKCS#1 v1.5 RSA padding — 已知有 Bleichenbacher 攻击面，无 opt-in
- Implicit query 而非 fragment — RFC 强制
- 开放重定向 — 安全底线
- 时序攻击 secret 比对 — 安全底线

---

如有疑问，先查 [`SECURITY-AUDIT-2026-05-19.md`](./SECURITY-AUDIT-2026-05-19.md) 中对应漏洞条目；那里的"修复"和"迁移说明"小节会给到代码片段与原理解释。
