using AegisAuthBase.Entities;
using AegisAuthBase.Repositories;
using Microsoft.EntityFrameworkCore;

namespace AegisAuthJwtDemo.Repositories;

public class DbUserPasskeyRepository : IUserPasskeyRepository
{
    private readonly ApplicationDbContext _context;

    public DbUserPasskeyRepository(ApplicationDbContext context)
    {
        _context = context;
    }

    public async Task<UserPasskey?> GetByCredentialIdAsync(string credentialId)
    {
        return await _context.UserPasskeys.FirstOrDefaultAsync(p => p.CredentialId == credentialId);
    }

    public async Task<IEnumerable<UserPasskey>> GetByUserIdAsync(string userId)
    {
        return await _context.UserPasskeys.Where(p => p.UserId == userId).ToListAsync();
    }

    public async Task AddAsync(UserPasskey passkey)
    {
        _context.UserPasskeys.Add(passkey);
        await _context.SaveChangesAsync();
    }

    public async Task UpdateCounterAsync(string id, uint newCounter, DateTime lastUsedAt)
    {
        var passkey = await _context.UserPasskeys.FindAsync(id);
        if (passkey != null)
        {
            passkey.SignatureCounter = newCounter;
            passkey.LastUsedAt = lastUsedAt;
            await _context.SaveChangesAsync();
        }
    }
}