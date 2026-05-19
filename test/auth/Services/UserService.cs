using System.Threading.Tasks;

namespace auth.Services {
    public class UserService : IUserService
    {
        public Task<bool> VerifyAsync(string username, string password)
        {
            //return Task.FromResult(username == password);
            return Task.FromResult(true);
        }
    }
}
