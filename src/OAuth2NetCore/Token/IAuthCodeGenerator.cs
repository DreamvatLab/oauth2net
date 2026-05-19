using System.Threading.Tasks;

namespace OAuth2NetCore.Token {
    public interface IAuthCodeGenerator
    {
        Task<string> GenerateAsync();
    }
}
