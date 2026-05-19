using Microsoft.IdentityModel.JsonWebTokens;
using System.Threading.Tasks;

namespace OAuth2NetCore.Store {
    public interface ITokenStore
    {
        Task<JsonWebToken> SaveTokenDTOAsync(Model.Token tokenDTO);
        Task<JsonWebToken> SaveTokenDTOAsync(string json);
        Task<Model.Token> GetTokenDTOAsync();
    }
}
