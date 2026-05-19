using System.Threading.Tasks;

namespace auth.Services {
    public interface IUserService
    {
        Task<bool> VerifyAsync(string username, string password);
    }
}
