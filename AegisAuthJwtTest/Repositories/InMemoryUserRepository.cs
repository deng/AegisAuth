using AegisAuth.Core.Entities;
using AegisAuth.Core.Repositories;

namespace AegisAuthJwtTest.Repositories;

public class InMemoryUserRepository : IUserRepository
{
    private readonly List<User> _users = new();

    public InMemoryUserRepository()
    {
        // Add a test user
        var testUser = new User
        {
            Id = "1",
            Username = "testuser",
            PasswordHash = "hashedpassword", // In real implementation, this would be properly hashed
            PasswordSalt = "salt",
            Role = "Admin",
            IsActive = true,
            FailedLoginAttempts = 0
        };
        _users.Add(testUser);
    }

    public Task<User?> GetUserByUserNameAsync(string userName)
    {
        var user = _users.FirstOrDefault(u => u.Username == userName);
        return Task.FromResult(user);
    }

    public Task<User?> GetByIdAsync(string id, bool getForUpdate)
    {
        var user = _users.FirstOrDefault(u => u.Id == id);
        return Task.FromResult(user);
    }

    public Task UpdateAsync(User user)
    {
        var existingUser = _users.FirstOrDefault(u => u.Id == user.Id);
        if (existingUser != null)
        {
            var index = _users.IndexOf(existingUser);
            _users[index] = user;
        }
        return Task.CompletedTask;
    }

    public Task CommitAsync()
    {
        // In-memory implementation doesn't need to commit
        return Task.CompletedTask;
    }
}
