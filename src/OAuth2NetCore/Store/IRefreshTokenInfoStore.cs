using OAuth2NetCore.Model;
using System.Threading.Tasks;

namespace OAuth2NetCore.Store {
    public interface IRefreshTokenInfoStore
    {
        Task SaveRefreshTokenAsync(string refreshToken, RefreshTokenInfo requestInfo, int expireSeconds);
        Task<RefreshTokenInfo> GetThenRemoveTokenInfoAsync(string refreshToken);
        Task RemoveRefreshTokenAsync(string refreshToken);
    }
}
