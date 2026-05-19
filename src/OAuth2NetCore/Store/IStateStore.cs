using System.Threading.Tasks;

namespace OAuth2NetCore.Store {
    public interface IStateStore
    {
        Task SaveAsync(string key, string value, int expireSeconds = 60);
        Task<string> GetThenRemoveAsync(string key);
    }
}
