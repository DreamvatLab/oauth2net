namespace OAuth2NetCore.Security {
    public interface IPkceValidator
    {
        bool Verify(string codeVerifier, string codeChanllenge, string codeChanllengeMethod);
    }
}
