using auth.Services;
using OAuth2NetCore.Security;
using System.Threading.Tasks;

namespace auth {
    public class MyResourceOwnerValidator : IResourceOwnerValidator
    {
        private readonly IUserService _userService;

        public MyResourceOwnerValidator(IUserService userService)
        {
            _userService = userService;
        }

        public Task<bool> VerifyAsync(string username, string password)
        {
            return _userService.VerifyAsync(username, password);
        }
    }
}
