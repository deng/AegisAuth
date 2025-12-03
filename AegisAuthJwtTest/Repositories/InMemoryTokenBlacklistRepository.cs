using AegisAuthBase.Entities;
using AegisAuthBase.Repositories;

namespace AegisAuthJwtTest.Repositories;

public class InMemoryTokenBlacklistRepository : ITokenBlacklistRepository
{
    private readonly List<TokenBlacklist> _blacklist = new();

    public Task AddAsync(TokenBlacklist tokenBlacklist)
    {
        tokenBlacklist.Id = (_blacklist.Count + 1).ToString();
        _blacklist.Add(tokenBlacklist);
        return Task.CompletedTask;
    }

    public Task<int> CleanupExpiredTokensAsync()
    {
        var expiredCount = _blacklist.RemoveAll(t => t.IsExpired);
        return Task.FromResult(expiredCount);
    }

    public Task<List<string>> GetValidTokenHashesAsync()
    {
        var validHashes = _blacklist.Where(t => !t.IsExpired).Select(t => t.TokenHash).ToList();
        return Task.FromResult(validHashes);
    }

    public Task CommitAsync()
    {
        // In-memory implementation doesn't need to commit
        return Task.CompletedTask;
    }
}
