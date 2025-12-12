using AegisAuthBase.Entities;
using AegisAuthBase.Repositories;
using Microsoft.EntityFrameworkCore;

namespace AegisAuthJwtDemo.Repositories;

public class DbUserRepository : IUserRepository
{
    private readonly ApplicationDbContext _context;

    public DbUserRepository(ApplicationDbContext context)
    {
        _context = context;
    }

    public async Task<User?> GetUserByUserNameAsync(string userName)
    {
        return await _context.Users.FirstOrDefaultAsync(u => u.UserName == userName);
    }

    public async Task CreateAsync(User user)
    {
        _context.Users.Add(user);
        await _context.SaveChangesAsync();
    }

    public async Task<User?> GetByIdAsync(string id, bool getForUpdate)
    {
        return await _context.Users.FirstOrDefaultAsync(u => u.Id == id);
    }

    public async Task UpdateAsync(User user)
    {
        _context.Users.Update(user);
        await _context.SaveChangesAsync();
    }

    public async Task CommitAsync()
    {
        await _context.SaveChangesAsync();
    }
}