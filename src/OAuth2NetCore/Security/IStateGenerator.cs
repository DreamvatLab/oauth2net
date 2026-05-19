using System.Threading.Tasks;

namespace OAuth2NetCore.Security {
    public interface IStateGenerator
    {
        Task<string> GenerateAsync();
    }
}
