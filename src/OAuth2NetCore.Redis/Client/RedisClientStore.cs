using OAuth2NetCore.Model;
using OAuth2NetCore.Security;
using OAuth2NetCore.Store;
using StackExchange.Redis;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

namespace OAuth2NetCore.Redis.Client {
    public class RedisClientStore : RedisStore, IClientStore
    {
        private readonly string _key;
        private readonly ISecretEncryptor _secertEncryptor;

        public RedisClientStore(string connStr, string key, int db = -1, ISecretEncryptor secretEncryptor = null)
            : base(connStr, db)
        {
            _key = key;
            _secertEncryptor = secretEncryptor ?? new DefaultSecretEncryptor();
        }

        public IClient GetClient(string clientID)
        {
            var json = Database.HashGet(_key, clientID);
            var client = JsonSerializer.Deserialize<Model.Client>(json);

            _secertEncryptor.TryDecrypt(client.Secret, out var secret);
            client.Secret = secret;
            return client;
        }

        public async Task<IClient> GetClientAsync(string clientID)
        {
            var json = await Database.HashGetAsync(_key, clientID);
            if (json.IsNull)
            {
                return null;
            }
            var client = JsonSerializer.Deserialize<Model.Client>(json.ToString());

            _secertEncryptor.TryDecrypt(client.Secret, out var secret);
            client.Secret = secret;
            return client;
        }

        public IDictionary<string, IClient> GetClients()
        {
            var hashEntries = Database.HashGetAll(_key);
            var dic = hashEntries.ToDictionary(x => x.ToString(), x => (IClient)JsonSerializer.Deserialize<Model.Client>(x.ToString()));

            //foreach (var client in dic.Values)
            //{
            //    client.Secret = _secertEncryptor.Decrypt(client.Secret);
            //}

            return dic;
        }

        public async Task<IDictionary<string, IClient>> GetClientsAsync()
        {
            var hashEntries = await Database.HashGetAllAsync(_key);

            var dic = hashEntries.ToDictionary(x => x.Name.ToString(), x => (IClient)JsonSerializer.Deserialize<Model.Client>(x.Value.ToString()));

            //foreach (var client in dic.Values)
            //{
            //    client.Secret = _secertEncryptor.Decrypt(client.Secret);
            //}

            return dic;
        }

        //public IClient Verify(string clientID, string clientSecret)
        //{
        //    var client = GetClient(clientID);
        //    if (client != null && client.Secret == clientSecret)
        //    {
        //        return client;
        //    }

        //    return null;
        //}
        //public async Task<IClient> VerifyAsync(string clientID, string clientSecret)
        //{
        //    var client = await GetClientAsync(clientID);
        //    if (client != null && client.Secret == clientSecret)
        //    {
        //        return client;
        //    }

        //    return null;
        //}
    }
}
