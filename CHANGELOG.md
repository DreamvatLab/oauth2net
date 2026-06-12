# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 风格，版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [3.0.0] — 2026-06-12

整体定位：**框架升级（net10）+ 第二轮安全加固 major 版本**。完整清单见 [`docs/SECURITY-AUDIT-2026-06-12.md`](docs/SECURITY-AUDIT-2026-06-12.md)。

### ⚠ Breaking Changes

- **目标框架 `netstandard2.0` → `net10.0`**（F-1）。仍在 .NET Framework / netstandard / net6-8 的使用者无法再引用本库，必须升到 net10。
- **核心库 `OAuth2NetCore` 改用 ASP.NET Core 共享框架**（F-1）。移除遗留的 `Microsoft.AspNetCore.Authentication.OAuth` 2.3.x 包、改为 `<FrameworkReference Include="Microsoft.AspNetCore.App" />`；库由「可跨框架」变为绑定 ASP.NET Core 共享框架。
- **token 端点对「机密客户端漏传 secret」的错误码改变**（S-2）：从 `invalid_request`（"client secret is missing"）变为 `invalid_client`。对错误字符串硬断言的自动化客户端会受影响。
- **同步 `RedisClientStore.GetClient()` 对未知 client 从抛异常改为返回 `null`**（B-2），与异步版及接口契约一致。

### Added

- `OAuth2Utils.FixedTimeEquals(...)`：常量时间字符串比较（基于 BCL `CryptographicOperations.FixedTimeEquals`），用于 PKCE / state / secret 比对（S-4）。
- `docs/SECURITY-AUDIT-2026-06-12.md`：本轮审计与修复记录。

### Changed

- 所有项目目标框架统一为 `net10.0`（F-1）。
- `X509SecurityKeyProvider`、`X509SecretEncryptor` 改用 `X509CertificateLoader.LoadPkcs12FromFile`（F-2，了结上次 M-5 遗留；公开构造签名不变）。
- 公共客户端（PKCE）凭据可经 body 提取：`ExractClientCredentialsFromBody` 放开空 secret，由 `VerifyClientAsync` 依 `IsPublic` 判定（S-2）。
- `DefaultPkceValidator`（PKCE challenge）、`DefaultAuthServer`（clear-token state）、`DefaultClientValidator`（client secret）三处比对统一改为常量时间（S-4）。
- `DefaultClientValidator`、`DefaultAuthServer.ErrorHandler` 日志改用结构化模板，杜绝用户输入被当作日志格式串（S-3）。
- 登录令牌 `t` 拼入授权 URL 前做 `Uri.EscapeDataString` 编码（S-1）。

### Fixed

- F-1 移除遗留 OAuth 2.3.x 包后消除两个传递高危 CVE：`Newtonsoft.Json` 11.0.2（GHSA-5crp-9r3c-p9vr）、`System.Security.Cryptography.Xml` 8.0.2（GHSA-37gx-xxp4-5rgx / GHSA-w3x6-4m5h-cxqf）。
- S-1 登录令牌 `t` 未编码拼入授权 URL，可注入授权请求参数。
- S-2 公共客户端凭据路径不可达，`IsPublic` 形同虚设，变相逼迫内嵌 secret。
- S-3 用户输入直接作为日志模板，含 `{` 时可致 `FormatException`（500）/ 日志伪造。
- S-4 PKCE challenge 与 state 比对非常量时间。
- B-1 同步 `RedisClientStore.GetClients()` 用错 key/value，方法不可用。
- B-2 同步 `RedisClientStore.GetClient()` 缺 `IsNull` 判断，未知 client 抛异常。

### Removed

- 核心库 `Microsoft.AspNetCore.Authentication.OAuth` 2.3.x 包及其传递 CVE（F-1）。
- 核心库多余的 `System.Text.Json` / `Microsoft.Extensions.Configuration.Binder` / `Microsoft.Extensions.Logging` 显式引用（已在共享框架内，NU1510）。
- Redis、Host 发行库中误放的 `coverlet.collector`。
- `DefaultClientValidator` 中上次手写的 `FixedTimeEquals`（netstandard2.0 兼容产物，改为复用 `OAuth2Utils.FixedTimeEquals`）。

### Known Limitations (未在本次发版处理)

- 登出 CSRF（`/endsession`、`/signout` 为无防伪造的 GET）——属 OIDC `id_token_hint` 范畴。
- Refresh token 重用检测（被盗 token 先用时撤销整个 token 族）。
- 刷新时不重新校验 scopes（TTL 内旧 refresh token 仍按旧 scopes 续发）。
- client secret 仍明文存储 + 比对（上次 C-2 剩余风险，建议改存哈希）。
- 内存版授权码存储为进程内静态字典，多实例部署需 Redis 实现（当前未提供）。
- 沿用上一版未处理项：OIDC 完整支持、token revocation/introspection、登录限流。

### Note（按设计保留）

- **Redis client secret 解密失败回退明文**：明文存储是受支持形态，`RedisClientStore` 维持回退行为，未改为 fail-closed。

---

## [2.0.0] — 2026-05-19

整体定位：**安全加固 major 版本**。完整漏洞清单与修复细节见 [`docs/SECURITY-AUDIT-2026-05-19.md`](docs/SECURITY-AUDIT-2026-05-19.md)，下游升级指南见 [`docs/UPGRADING-v2.md`](docs/UPGRADING-v2.md)。

### ⚠ Breaking Changes

- **RSA 加密 padding 从 PKCS#1 v1.5 改为 OAEP-SHA256**（C-4）。Redis 中已加密的 client secret 必须重新加密，否则 v2.0 启动后所有 client 登录返回 `invalid_client`。
- **PKCE `plain` 方法默认拒绝**（H-1）。`AuthServerOptions.AllowPlainPkce` 默认 `false`；老客户端发送 `code_challenge_method=plain` 会被拒。
- **PKCE method 缺失默认为 S256**（H-1），不再是 RFC 7636 默认的 `plain`。
- **Cookie 名 `atuh.cookie2` 改为 `auth.token`**（L-1）。所有现有浏览器会话失效，用户被强制重新登录一次。
- **资源服务器 JWT 验证默认仅接受 PS256**（H-2）。如签名算法非 PS256，必须显式设 `ResourceOptions.ValidAlgorithms`。
- **Implicit 流 access_token 改在 URL fragment 返回**（C-1，RFC 6749 §4.2.2）。自定义 JS 解析 query 的代码需改读 fragment。
- **`OAuth2NetCore` 不再传递 Newtonsoft.Json 依赖**（L-2），全部切到 `System.Text.Json`。
- **Redis 服务端需要 ≥ 6.2.0**（C-3），因使用了原子 `GETDEL` 命令。
- **SignIn / SignOut 的 `returnUrl` 只接受本地路径**（C-5）。绝对 URL、协议相对（`//`、`/\`）一律静默回退到 `/`。

### Added

- `AuthServerOptions.AllowPlainPkce`：默认 `false`，允许过渡期重新放行 PKCE plain。
- `ResourceOptions.ValidAlgorithms`：JWT 签名算法白名单，默认 `[PS256]`。
- `OAuth2Utils.AppendQuery(...)` / `OAuth2Utils.AppendFragment(...)`：URL 构造工具，自动处理 `?`/`#`/`&` 与 URL 编码。
- `X509SecretEncryptor` 实现 `IDisposable`，释放底层 RSA 与证书句柄（M-6）。
- **38 个针对本次修复的回归测试**，单测从 53 个增至 91 个，全部通过。
- `docs/SECURITY-AUDIT-2026-05-19.md`、`docs/UPGRADING-v2.md`、各包 README。

### Changed

- `DefaultClientValidator` 客户端 secret 比对改为常量时间（C-2）。
- `DefaultClientValidator` HTTP Basic Auth 解析改用标准 Base64、显式校验 `Basic` scheme、按第一个 `:` 切分（H-3）。
- `AutoCleanDictionary.TryRemove` 读取时校验过期时间，不再仅靠定时清扫（H-4）。
- `RedisRefreshTokenInfoStore`、`RedisStateStore` 改用原子 `StringGetDeleteAsync`（C-3）。
- `DefaultAuthServer` 错误响应、wellknown 配置改用 `System.Text.Json` 序列化（M-7）。
- 授权码 redirect 不再回传 `code_challenge` / `code_challenge_method`（H-1）。
- `HandleClearTokenRequestAsync` 成功路径显式返回 200 OK（M-3）。
- `HandleEndSessionRequestAsync` 移除冗余的 state 判空（M-4）。
- `/authorize` 缺少 `state` 时记录 warning（M-1）。
- `ClientServerExtensions.AddOAuth2Client` 不再调用 `services.BuildServiceProvider()`，event handler 改为从 `HttpContext.RequestServices` 即时解析依赖（L-3）。

### Fixed

- C-1 隐式流 access_token 通过 URL query 返回（RFC 6749 违规，可经 Referer/access log 泄漏）。
- C-2 client_secret 非常量时间比对，可被时序攻击。
- C-3 Redis refresh token 与 state 取-删非原子，可被重放。
- C-4 RSA 加密用 PKCS#1 v1.5 padding（Bleichenbacher）。
- C-5 SignIn/SignOut returnUrl 开放重定向。
- H-1 PKCE 默认 `plain` + 把 code_challenge 回传到客户端。
- H-2 JWT 验证未限制 `ValidAlgorithms`，可能放行 `alg=none` 或 HS+RSA 公钥滥用。
- H-3 HTTP Basic Auth 用 base64url 解码 + 未校验 scheme + 密码含冒号被切断。
- H-4 内存版授权码到期前可被取出（TTL 与清扫间存在窗口）。
- H-5 URL 拼接对已含 `?` 的 redirect uri 不友好；多处缺 URL 编码。

### Removed

- `OAuth2NetCore` 主库的 `Newtonsoft.Json` 依赖（L-2）。
- `DefaultAuthServer` 中残留的 `IDisposable` 句柄泄漏路径（M-6）。

### Internal

- `OAuth2NetCore.csproj`、`OAuth2NetCore.Host.csproj` 各加 `<InternalsVisibleTo Include="unittests" />`，让 internal 类型可被单测。
- 测试工程依据上次依赖升级保持 net10.0，使用 `X509CertificateLoader.LoadPkcs12FromFile` 加载证书。

### Known Limitations (未在本次发版处理)

- 暂未实现 OIDC 完整支持（id_token、nonce、暴露 `.well-known/openid-configuration` 与 `jwks.json` 路由）。
- 暂未实现 token revocation (RFC 7009) 与 introspection (RFC 7662)。
- 暂未实现客户端登录限流 / 锁定。
- 暂未提供集成测试覆盖 C-3 (Redis GETDEL) 与 H-2 (JWT ValidAlgorithms 实际拒收行为)；这两项目前仅靠代码审查与单元测试间接保证。

---

## [1.4.0] 及更早

详细历史见 `git log`，主要变化：

- 1.4.0 — 增加 public client 支持
- 1.3.x — 修复 IPv6 host signout 路径问题、cookie SameSite 配置
- 1.2.x — OpenID Connect wellknown 支持、login token、各类 Redis 相关 bug fix
- 1.0.0 — 首版发布

---

## 链接

- [Repository](https://github.com/Lukiya/oauth2net)
- [Security Audit (2026-05-19)](docs/SECURITY-AUDIT-2026-05-19.md)
- [Upgrade Guide v1 → v2](docs/UPGRADING-v2.md)
