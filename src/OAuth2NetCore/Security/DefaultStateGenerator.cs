using System;
using System.Threading.Tasks;

namespace OAuth2NetCore.Security {
    public class DefaultStateGenerator : IStateGenerator
    {
        public Task<string> GenerateAsync()
        {
            return Task.FromResult(Guid.NewGuid().ToString("n"));
        }
    }
}
