using AegisAuthBase.Entities;
using AegisAuthBase.Repositories;
using Microsoft.EntityFrameworkCore;

namespace AegisAuthJwtDemo.Repositories;

public class DbTokenBlacklistRepository : ITokenBlacklistRepository
{
    private readonly ApplicationDbContext _context;

    public DbTokenBlacklistRepository(ApplicationDbContext context)
    {
        _context = context;
    }

    public async Task AddAsync(TokenBlacklist tokenBlacklist)
    {
        _context.TokenBlacklists.Add(tokenBlacklist);
        await _context.SaveChangesAsync();
    }

    public async Task<int> CleanupExpiredTokensAsync()
    {
        var now = DateTimeOffset.UtcNow;
        var expiredTokens = _context.TokenBlacklists
            .AsEnumerable()
            .Where(t => t.ExpiresAt < now)
            .ToList();

        _context.TokenBlacklists.RemoveRange(expiredTokens);
        await _context.SaveChangesAsync();

        return expiredTokens.Count;
    }

    public async Task<List<string>> GetValidTokenHashesAsync()
    {
        var now = DateTimeOffset.UtcNow;
        return _context.TokenBlacklists
            .AsEnumerable()
            .Where(t => t.ExpiresAt > now)
            .Select(t => t.TokenHash)
            .ToList();
    }

    public async Task CommitAsync()
    {
        await _context.SaveChangesAsync();
    }
}