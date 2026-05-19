using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace OAuth2NetCore.Token {
    public class DefaultAuthCodeGenerator : IAuthCodeGenerator
    {
        public Task<string> GenerateAsync()
        {
            var randomNumber = new byte[64];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                var r = Base64UrlEncoder.Encode(randomNumber);
                return Task.FromResult(r);
            }
        }
    }
}
