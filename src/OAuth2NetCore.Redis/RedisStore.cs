using StackExchange.Redis;
using System;

namespace OAuth2NetCore.Redis {
    public abstract class RedisStore
    {
        private readonly Lazy<IDatabase> _lazyDatabase;
        protected virtual IDatabase Database => _lazyDatabase.Value;

        public RedisStore(string connStr, int db)
        {
            _lazyDatabase = new Lazy<IDatabase>(() =>
            {
                var a = ConnectionMultiplexer.Connect(connStr);
                return a.GetDatabase(db);
            });
        }
    }
}
