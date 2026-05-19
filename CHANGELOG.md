# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 风格，版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

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
