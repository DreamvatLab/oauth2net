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

        /// <summary>
        /// Derives the Redis key from a refresh token. Only the SHA-256 digest is stored, never the
        /// token itself, so anyone able to list Redis keys cannot replay the refresh tokens they see.
        /// Refresh tokens are 64 random bytes, so an unsalted fast hash is sufficient.
        /// Must stay identical to RedisTokenStore.key in oauth2go.
        /// </summary>
        protected virtual string GetKey(string refreshToken) => _prefix + OAuth2Utils.ToSHA256Base64URL(refreshToken);

        public async Task SaveRefreshTokenAsync(string refreshToken, RefreshTokenInfo refreshTokenInfo, int expireSeconds)
        {
            var json = JsonSerializer.Serialize(refreshTokenInfo);
            json = _secertEncryptor.Encrypt(json);
            await Database.StringSetAsync(GetKey(refreshToken), json, expiry: TimeSpan.FromSeconds(expireSeconds));

        }

        public async Task<RefreshTokenInfo> GetThenRemoveTokenInfoAsync(string refreshToken)
        {
            // Atomic GETDEL (Redis 6.2+) — eliminates the race that would otherwise let two
            // concurrent requests both consume the same refresh token.
            var json = await Database.StringGetDeleteAsync(GetKey(refreshToken));
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
            await Database.KeyDeleteAsync(GetKey(refreshToken));
        }
    }
}
