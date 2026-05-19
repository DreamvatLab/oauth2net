namespace OAuth2NetCore.Security {
    /// <summary>
    /// no ecryption, it is not recommanded to use this implementation
    /// </summary>
    public class DefaultSecretEncryptor : ISecretEncryptor
    {
        public string Encrypt(string input) => input;
        public string Decrypt(string input) => input;
        public bool TryDecrypt(string input, out string output)
        {
            output = input;
            return true;
        }
    }
}
