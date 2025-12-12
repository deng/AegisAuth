using AegisAuthBase.Services;

namespace AegisAuthJwtDemo.Services;

/// <summary>
/// 内存双因素认证存储实现（生产环境应该使用数据库）
/// </summary>
public class InMemoryTwoFactorStore : ITwoFactorStore
{
    private readonly Dictionary<string, (string Code, string UserId, DateTime Expiration)> _store = new();

    public Task SaveCodeAsync(string twoFactorId, string code, string userId, TimeSpan expiration)
    {
        _store[twoFactorId] = (code, userId, DateTime.UtcNow.Add(expiration));
        return Task.CompletedTask;
    }

    public Task<(string? Code, string? UserId)> GetCodeAsync(string twoFactorId)
    {
        if (_store.TryGetValue(twoFactorId, out var data))
        {
            if (data.Expiration > DateTime.UtcNow)
            {
                return Task.FromResult<(string?, string?)>((data.Code, data.UserId));
            }
            else
            {
                // 过期了，移除
                _store.Remove(twoFactorId);
            }
        }
        return Task.FromResult<(string?, string?)>((null, null));
    }

    public Task RemoveCodeAsync(string twoFactorId)
    {
        _store.Remove(twoFactorId);
        return Task.CompletedTask;
    }
}