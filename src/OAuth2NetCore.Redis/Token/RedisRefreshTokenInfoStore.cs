using OAuth2NetCore.Model;
using OAuth2NetCore.Security;
using OAuth2NetCore.Store;
using System;
using System.Text.Json;
using System.Threading.Tasks;

namespace OAuth2NetCore.Redis.Token {
    public class RedisRefreshTokenInfoStore : RedisStore, IRefreshTokenInfoStore
    {
        private readonly string _prefix;
        private readonly ISecretEncryptor _secertEncryptor;

        public RedisRefreshTokenInfoStore(string connStr, int db = -1, string prefix = "rt:", ISecretEncryptor secretEncryptor = null)
            : base(connStr, db)
        {
            _prefix = prefix;
            _secertEncryptor = secretEncryptor ?? new DefaultSecretEncryptor();
        }

        public async Task SaveRefreshTokenAsync(string refreshToken, RefreshTokenInfo refreshTokenInfo, int expireSeconds)
        {
            var json = JsonSerializer.Serialize(refreshTokenInfo);
            json = _secertEncryptor.Encrypt(json);
            await Database.StringSetAsync(_prefix + refreshToken, json, expiry: TimeSpan.FromSeconds(expireSeconds));

        }

        public async Task<RefreshTokenInfo> GetThenRemoveTokenInfoAsync(string refreshToken)
        {
            // Atomic GETDEL (Redis 6.2+) — eliminates the race that would otherwise let two
            // concurrent requests both consume the same refresh token.
            var json = await Database.StringGetDeleteAsync(_prefix + refreshToken);
            if (!string.IsNullOrWhiteSpace(json))
            {
                if (_secertEncryptor.TryDecrypt(json, out var decryptedJson))
                {
                    return JsonSerializer.Deserialize<RefreshTokenInfo>(decryptedJson);
                }
            }

            return null;
        }

        public async Task RemoveRefreshTokenAsync(string refreshToken)
        {
            await Database.KeyDeleteAsync(_prefix + refreshToken);
        }
    }
}
