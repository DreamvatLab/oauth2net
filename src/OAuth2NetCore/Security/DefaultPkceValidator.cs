namespace OAuth2NetCore.Security {
    public class DefaultPkceValidator : IPkceValidator
    {
        public bool Verify(string codeVerifier, string codeChanllenge, string codeChanllengeMethod)
        {
            bool r = false;

            if (codeChanllengeMethod == OAuth2Consts.Pkce_Plain)
            {
                r = codeVerifier == codeChanllenge;
            }
            else if (codeChanllengeMethod == OAuth2Consts.Pkce_S256)
            {
                r = codeChanllenge == OAuth2Utils.ToSHA256Base64URL(codeVerifier);
            }

            // not suppor other methods
            return r;
        }
    }
}
