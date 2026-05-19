using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OAuth2NetCore.Model;
using OAuth2NetCore.Security;
using System;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace OAuth2NetCore.Token {
    public class DefaultTokenGenerator : ITokenGenerator
    {
        public AuthServerOptions AuthServerOptions { get; }

        private readonly ISecurityKeyProvider _securityKeyProvider;
        private readonly ITokenClaimBuilder _claimGenerator;

        public DefaultTokenGenerator(ISecurityKeyProvider certProvider, ITokenClaimBuilder claimGenerator, AuthServerOptions options)
        {
            AuthServerOptions = options;
            _securityKeyProvider = certProvider;
            _claimGenerator = claimGenerator;
        }

        public async Task<string> GenerateAccessTokenAsync(HttpContext context, GrantType grantType, IClient client, string[] scopes, string username)
        {
            var securityKey = _securityKeyProvider.GetSecurityKey();

            var handler = new JsonWebTokenHandler();
            var now = DateTime.UtcNow;

            var claims = await _claimGenerator.GenerateAsync(context, grantType, client, scopes, username);

            var descriptor = new SecurityTokenDescriptor
            {
                IssuedAt = now,
                NotBefore = now,
                Expires = now.AddSeconds(client.AccessTokenExpireSeconds),
                Subject = new ClaimsIdentity(claims),
                SigningCredentials = new SigningCredentials(securityKey, AuthServerOptions.SigningAlgorithm)
            };

            string token = handler.CreateToken(descriptor);
            return token;
        }

        public Task<string> GenerateRefreshTokenAsync()
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
