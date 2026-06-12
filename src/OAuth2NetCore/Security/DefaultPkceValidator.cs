namespace OAuth2NetCore.Security {
    public class DefaultPkceValidator : IPkceValidator
    {
        public bool Verify(string codeVerifier, string codeChanllenge, string codeChanllengeMethod)
        {
            bool r = false;

            if (codeChanllengeMethod == OAuth2Consts.Pkce_Plain)
            {
                r = OAuth2Utils.FixedTimeEquals(codeVerifier, codeChanllenge);
            }
            else if (codeChanllengeMethod == OAuth2Consts.Pkce_S256)
            {
                r = OAuth2Utils.FixedTimeEquals(codeChanllenge, OAuth2Utils.ToSHA256Base64URL(codeVerifier));
            }

            // not suppor other methods
            return r;
        }
    }
}
