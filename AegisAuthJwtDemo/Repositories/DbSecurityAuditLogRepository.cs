using AegisAuthBase.Entities;
using AegisAuthBase.Repositories;

namespace AegisAuthJwtDemo.Repositories;

public class DbSecurityAuditLogRepository : ISecurityAuditLogRepository
{
    private readonly ApplicationDbContext _context;

    public DbSecurityAuditLogRepository(ApplicationDbContext context)
    {
        _context = context;
    }

    public async Task AddAsync(SecurityAuditLog log)
    {
        _context.SecurityAuditLogs.Add(log);
        await _context.SaveChangesAsync();
    }

    public async Task CommitAsync()
    {
        await _context.SaveChangesAsync();
    }
}