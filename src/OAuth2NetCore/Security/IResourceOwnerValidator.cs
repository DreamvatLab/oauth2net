using System.Threading.Tasks;

namespace OAuth2NetCore.Security {
    public interface IResourceOwnerValidator
    {
        Task<bool> VerifyAsync(string username, string password);
    }
}
