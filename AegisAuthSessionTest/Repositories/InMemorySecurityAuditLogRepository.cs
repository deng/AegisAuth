using AegisAuthBase.Entities;
using AegisAuthBase.Repositories;

namespace AegisAuthSessionTest.Repositories;

public class InMemorySecurityAuditLogRepository : ISecurityAuditLogRepository
{
    private readonly List<SecurityAuditLog> _logs = new();

    public Task AddAsync(SecurityAuditLog log)
    {
        log.Id = (_logs.Count + 1).ToString();
        log.CreatedAt = DateTimeOffset.UtcNow;
        _logs.Add(log);
        return Task.CompletedTask;
    }

    public Task CommitAsync()
    {
        return Task.CompletedTask;
    }
}
