# OAuth2NetCore.Redis

[OAuth2NetCore](https://www.nuget.org/packages/OAuth2NetCore) 的 Redis 后端实现，基于 `StackExchange.Redis`。`netstandard2.0` 目标。

## 提供的实现

- `RedisClientStore` — 实现 `IClientStore`，将客户端定义存于 Redis hash；可配合 `ISecretEncryptor` 对 client secret 字段加密。
- `RedisRefreshTokenInfoStore` — 实现 `IRefreshTokenInfoStore`，refresh token 与 token info JSON 加密存储；**取-删原子（v2.0 起使用 Redis `GETDEL`）**。
- `RedisStateStore` — 实现 `IStateStore`，state / endSessionID 短期存储；**取-删原子（v2.0 起使用 Redis `GETDEL`）**。

## 服务端要求

- **Redis ≥ 6.2.0**（v2.0 起使用 `GETDEL` 命令）。

## 用法

```csharp
services.AddOAuth2AuthServer(options => {
    var encryptor = new X509SecretEncryptor(cert);   // OAEP-SHA256
    options.ClientStoreFactory   = _ => new RedisClientStore(redisConnStr, "ec:CLIENTS", secretEncryptor: encryptor);
    options.RefreshTokenInfoStore = _ => new RedisRefreshTokenInfoStore(redisConnStr, secretEncryptor: encryptor);
    options.StateStoreFactory     = _ => new RedisStateStore(redisConnStr, prefix: "st:");
    // ...
});
```

## v2.0 注意

- v2.0 起 RSA padding 切换到 **OAEP-SHA256**（v1.x 是 PKCS#1 v1.5）。已存的加密 client secret 需要先用 v1.x 解密、再用 v2.0 加密回去。详见 [UPGRADING-v2.md](https://github.com/Lukiya/oauth2net/blob/master/docs/UPGRADING-v2.md)。
- v2.0 起 `GetThenRemove*` 方法改用原子 `GETDEL`，消除 refresh token 重放窗口；要求 Redis 服务端 ≥ 6.2.0。

## 仓库

https://github.com/Lukiya/oauth2net

## 协议

GPL-3.0-or-later
