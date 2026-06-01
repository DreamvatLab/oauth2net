using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NUnit.Framework;

namespace UnitTests
{
    /// <summary>
    /// Regression for the post-upgrade 403: under net10 / JwtBearer 10.x the active
    /// JsonWebTokenHandler ignores JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear(),
    /// so inbound "role"/"name" claims get remapped to legacy WS-* URIs unless we explicitly
    /// set JwtBearerOptions.MapInboundClaims = false. Downstream code matches claim types by
    /// the short literal "role", so the remapping made roles unreadable and authorization failed.
    /// </summary>
    [TestFixture]
    public class InboundClaimMappingTests
    {
        private const string Issuer = "https://issuer.test";
        private const string Audience = "test-aud";
        private const string RoleClaimType = "role"; // OAuth2Consts.Claim_Role / CONSTANTS.CLAIMTYPES.ROLE
        private const string LegacyRoleClaimType = ClaimTypes.Role; // the WS-* URI we must NOT see

        private static ServiceProvider BuildProvider(RsaSecurityKey signingKey)
        {
            var services = new ServiceCollection();
            services.AddOAuth2Resource(options =>
            {
                options.ValidIssuer = Issuer;
                options.ValidAudience = Audience;
                options.IssuerSigningKey = signingKey;
                // RoleClaimType / NameClaimType / ValidAlgorithms keep their defaults (role / name / PS256)
            });
            return services.BuildServiceProvider();
        }

        private static JwtBearerOptions ResolveBearerOptions(ServiceProvider provider) =>
            provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
                    .Get(JwtBearerDefaults.AuthenticationScheme);

        private static string CreateRoleToken(RsaSecurityKey signingKey, DateTime utcNow)
        {
            var descriptor = new SecurityTokenDescriptor
            {
                Issuer = Issuer,
                Audience = Audience,
                NotBefore = utcNow.AddMinutes(-5),
                Expires = utcNow.AddMinutes(5),
                IssuedAt = utcNow,
                SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSsaPssSha256),
                Claims = new Dictionary<string, object>
                {
                    [RoleClaimType] = "1",
                    ["name"] = "ec",
                },
            };

            // CreateToken does not remap claim names — the wire token carries the short "role".
            return new JsonWebTokenHandler().CreateToken(descriptor);
        }

        // ---------------------------------------------------------------------------------------
        // 1. Config layer: our one-line fix is actually applied to the Bearer options.

        [Test]
        public void AddJwtBearerAuth_DisablesInboundClaimMapping()
        {
            using var rsa = RSA.Create(2048);
            using var provider = BuildProvider(new RsaSecurityKey(rsa));

            var jwtOptions = ResolveBearerOptions(provider);

            Assert.That(jwtOptions.MapInboundClaims, Is.False,
                "MapInboundClaims must be false so short claim names ('role'/'name') survive verbatim.");
            Assert.That(jwtOptions.TokenValidationParameters.RoleClaimType, Is.EqualTo(RoleClaimType));
        }

        // ---------------------------------------------------------------------------------------
        // 2. Behavioral layer (the real regression): a signed token's "role" claim is readable
        //    by its short literal type after validation — i.e. UserRoles() would find it.

        [Test]
        public async Task ValidatedToken_KeepsShortRoleClaimType()
        {
            using var rsa = RSA.Create(2048);
            var signingKey = new RsaSecurityKey(rsa);
            using var provider = BuildProvider(signingKey);

            var jwtOptions = ResolveBearerOptions(provider);
            var token = CreateRoleToken(signingKey, DateTime.UtcNow);

            // Mirror how JwtBearerHandler builds its handler: MapInboundClaims comes from the options.
            var handler = new JsonWebTokenHandler { MapInboundClaims = jwtOptions.MapInboundClaims };
            var result = await handler.ValidateTokenAsync(token, jwtOptions.TokenValidationParameters);

            Assert.That(result.IsValid, Is.True, result.Exception?.Message);

            var identity = result.ClaimsIdentity;
            var roleClaim = identity.FindFirst(c => c.Type == RoleClaimType);

            Assert.That(roleClaim, Is.Not.Null, "role claim must keep its short type 'role'.");
            Assert.That(roleClaim!.Value, Is.EqualTo("1"));
            Assert.That(identity.FindFirst(c => c.Type == LegacyRoleClaimType), Is.Null,
                "role must NOT be remapped to the legacy WS-* URI.");
        }

        // ---------------------------------------------------------------------------------------
        // 3. Contrast / root-cause guard: with mapping ON, the very same token's role becomes the
        //    legacy URI and the short-name lookup fails — exactly the 403 we hit after the upgrade.

        [Test]
        public async Task WithInboundMappingEnabled_RoleIsRemappedAndShortLookupFails()
        {
            using var rsa = RSA.Create(2048);
            var signingKey = new RsaSecurityKey(rsa);
            using var provider = BuildProvider(signingKey);

            var jwtOptions = ResolveBearerOptions(provider);
            var token = CreateRoleToken(signingKey, DateTime.UtcNow);

            var handler = new JsonWebTokenHandler { MapInboundClaims = true }; // the broken behavior
            var result = await handler.ValidateTokenAsync(token, jwtOptions.TokenValidationParameters);

            Assert.That(result.IsValid, Is.True, result.Exception?.Message);

            var identity = result.ClaimsIdentity;
            Assert.That(identity.FindFirst(c => c.Type == RoleClaimType), Is.Null,
                "demonstrates the bug: short 'role' lookup finds nothing when mapping is enabled.");
            Assert.That(identity.FindFirst(c => c.Type == LegacyRoleClaimType), Is.Not.Null,
                "role got remapped to the legacy WS-* URI.");
        }
    }
}
