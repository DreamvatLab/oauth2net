using OAuth2NetCore.Model;
using System.Threading.Tasks;

namespace OAuth2NetCore.Store {
    public interface IClientStore
    {
        //IClient GetClient(string clientID);
        //IDictionary<string, IClient> GetClients();
        //IClient Verify(string clientID, string clientSecret);

        Task<IClient> GetClientAsync(string clientID);
        //Task<IDictionary<string, IClient>> GetClientsAsync();
        //Task<IClient> VerifyAsync(string clientID, string clientSecret);
    }
}
