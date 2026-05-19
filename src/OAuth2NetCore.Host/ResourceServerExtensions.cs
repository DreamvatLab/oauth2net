using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;

namespace Microsoft.Extensions.DependencyInjection {
    public static class ResourceServerExtensions {
        public static IServiceCollection AddOAuth2Resource(this IServiceCollection services, Action<ResourceOptions> configOptions, ResourceOptions options = null) {
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearerAuth(configOptions, options);

            return services;
        }

        public static AuthenticationBuilder AddJwtBearerAuth(this AuthenticationBuilder authBuilder, Action<ResourceOptions> configOptions, ResourceOptions options = null) {
            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();

            options = options ?? new ResourceOptions();

            configOptions(options);

            CheckOptions(options);

            authBuilder
                .AddJwtBearer(jwtOptions => {
                    jwtOptions.TokenValidationParameters = new TokenValidationParameters {
                        NameClaimType = options.NameClaimType,
                        RoleClaimType = options.RoleClaimType,
                        IssuerSigningKey = options.IssuerSigningKey,
                        ValidIssuer = options.ValidIssuer,
                        ValidAudience = options.ValidAudience,
                        // Explicit defense against alg=none / HS-with-RSA-public-key confusion.
                        ValidAlgorithms = options.ValidAlgorithms,
                        RequireSignedTokens = true,
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidateLifetime = true,
                        ValidateIssuerSigningKey = true,
                    };
                }
            );

            return authBuilder;
        }

        private static void CheckOptions(ResourceOptions options) {
            if (options.IssuerSigningKey == null)
                throw new ArgumentNullException($"{nameof(options)}.{nameof(options.IssuerSigningKey)}");

            if (string.IsNullOrWhiteSpace(options.ValidAudience))
                throw new ArgumentNullException($"{nameof(options)}.{nameof(options.ValidAudience)}");

            if (string.IsNullOrWhiteSpace(options.ValidIssuer))
                throw new ArgumentNullException($"{nameof(options)}.{nameof(options.ValidIssuer)}");
        }
    }
}
