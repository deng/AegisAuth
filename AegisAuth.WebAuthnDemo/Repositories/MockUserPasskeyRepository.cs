using AegisAuthBase.Entities;
using AegisAuthBase.Repositories;

namespace AegisAuth.WebAuthnDemo.Repositories;

public class MockUserPasskeyRepository : IUserPasskeyRepository
{
    private readonly List<UserPasskey> _passkeys = new();

    public Task AddAsync(UserPasskey passkey)
    {
        passkey.Id = Guid.NewGuid().ToString();
        _passkeys.Add(passkey);
        return Task.CompletedTask;
    }

    public Task<UserPasskey?> GetByCredentialIdAsync(string credentialId)
    {
        return Task.FromResult(_passkeys.FirstOrDefault(p => p.CredentialId == credentialId));
    }

    public Task<IEnumerable<UserPasskey>> GetByUserIdAsync(string userId)
    {
        return Task.FromResult<IEnumerable<UserPasskey>>(_passkeys.Where(p => p.UserId == userId).ToList());
    }

    public Task UpdateCounterAsync(string id, uint counter, DateTime lastUsed) => Task.CompletedTask;
}
