using AegisAuthBase.Entities;
using AegisAuthBase.Services;

namespace AegisAuthJwtDemo.Services;

/// <summary>
/// 内存凭据存储实现（生产环境应该使用数据库）
/// </summary>
public class InMemoryCredentialStore : ICredentialStore
{
    private readonly List<UserCredential> _credentials = new();

    public void AddCredential(UserCredential credential)
    {
        _credentials.Add(credential);
    }

    public UserCredential? FindCredential(string credentialId, string userId)
    {
        return _credentials.FirstOrDefault(c => c.CredentialId == credentialId && c.UserId == userId);
    }

    public IEnumerable<UserCredential> GetUserCredentials(string userId)
    {
        return _credentials.Where(c => c.UserId == userId);
    }

    public void UpdateCredential(UserCredential credential)
    {
        var existing = _credentials.FirstOrDefault(c => c.CredentialId == credential.CredentialId && c.UserId == credential.UserId);
        if (existing != null)
        {
            existing.PublicKey = credential.PublicKey;
        }
    }
}