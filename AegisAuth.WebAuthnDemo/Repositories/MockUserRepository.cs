using AegisAuthBase.Entities;
using AegisAuthBase.Repositories;
namespace AegisAuth.WebAuthnDemo.Repositories;
// Mock repositories
public class MockUserRepository : IUserRepository
{
    private readonly List<User> _users = new();

    public Task<User?> GetByIdAsync(string id, bool includeRelated = false)
    {
        return Task.FromResult(_users.FirstOrDefault(u => u.Id == id));
    }

    public Task<User?> GetUserByUserNameAsync(string userName)
    {
        return Task.FromResult(_users.FirstOrDefault(u => u.UserName == userName));
    }

    public Task CreateAsync(User user)
    {
        _users.Add(user);
        return Task.CompletedTask;
    }

    public Task UpdateAsync(User user) => Task.CompletedTask;
    public Task DeleteAsync(string id) => Task.CompletedTask;
    public Task CommitAsync() => Task.CompletedTask;
}
