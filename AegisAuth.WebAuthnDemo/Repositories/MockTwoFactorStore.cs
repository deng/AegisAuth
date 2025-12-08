using AegisAuthBase.Services;

namespace AegisAuth.WebAuthnDemo.Repositories;

public class MockTwoFactorStore : ITwoFactorStore
{
    private readonly Dictionary<string, (string Code, string UserId)> _store = new();

    public Task SaveCodeAsync(string id, string code, string userId, TimeSpan expiration)
    {
        _store[id] = (code, userId);
        return Task.CompletedTask;
    }

    public Task<(string? Code, string? UserId)> GetCodeAsync(string id)
    {
        return Task.FromResult(_store.TryGetValue(id, out var val) ? (val.Code, val.UserId) : (null, null));
    }

    public Task RemoveCodeAsync(string id)
    {
        _store.Remove(id);
        return Task.CompletedTask;
    }
}
