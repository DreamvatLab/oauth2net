using OAuth2NetCore.Model;
using System.Threading.Tasks;

namespace OAuth2NetCore.Store {
    public class DefaultAuthCodeStore : IAuthCodeStore
    {
        static AutoCleanDictionary<string, RefreshTokenInfo> _dic = new AutoCleanDictionary<string, RefreshTokenInfo>(60, 60);

        public Task SaveAsync(string code, RefreshTokenInfo requestInfo)
        {
            _dic.TryAdd(code, requestInfo);
            return Task.CompletedTask;
        }

        public Task<RefreshTokenInfo> GetThenRemoveAsync(string code)
        {
            _dic.TryRemove(code, out var o);
            return Task.FromResult(o);
        }
    }
}
