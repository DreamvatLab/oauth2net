using OAuth2NetCore.Store;
using System;
using System.Threading.Tasks;

namespace OAuth2NetCore.Redis.State {
    public class RedisStateStore : RedisStore, IStateStore {
        private readonly string _prefix;

        public RedisStateStore(string connStr, int db = -1, string prefix = "st:")
            : base(connStr, db) {
            _prefix = prefix;
        }

        public async Task SaveAsync(string key, string value, int expireSeconds) {
            if (expireSeconds > 0) {
                await Database.StringSetAsync(_prefix + key, value, expiry: TimeSpan.FromSeconds(expireSeconds));
            } else {
                await Database.StringSetAsync(_prefix + key, value);
            }
        }

        public async Task<string> GetThenRemoveAsync(string key) {
            // Atomic GETDEL (Redis 6.2+) — prevents concurrent reuse of the same state value.
            var value = await Database.StringGetDeleteAsync(_prefix + key);
            return value;
        }
    }
}
