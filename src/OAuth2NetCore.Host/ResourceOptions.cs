using Microsoft.IdentityModel.Tokens;
using OAuth2NetCore;
using System.Collections.Generic;

namespace Microsoft.Extensions.DependencyInjection {
    public class ResourceOptions
    {
        public string NameClaimType { get; set; } = OAuth2Consts.Claim_Name;
        public string RoleClaimType { get; set; } = OAuth2Consts.Claim_Role;
        public string ValidIssuer { get; set; }
        public string ValidAudience { get; set; }
        public SecurityKey IssuerSigningKey { get; set; }
        /// <summary>
        /// Whitelist of accepted JWT signing algorithms. Restricting this prevents
        /// "alg: none" / algorithm-confusion attacks (e.g. HS256 abusing an RSA public key).
        /// Defaults to PS256 (matches DefaultAuthServer's default signing algorithm).
        /// </summary>
        public IList<string> ValidAlgorithms { get; set; } = new List<string> { SecurityAlgorithms.RsaSsaPssSha256 };
    }
}