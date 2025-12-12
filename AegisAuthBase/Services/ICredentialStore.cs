using AegisAuthBase.Entities;

namespace AegisAuthBase.Services;

/// <summary>
/// 凭据存储服务接口
/// </summary>
public interface ICredentialStore
{
    /// <summary>
    /// 添加凭据
    /// </summary>
    void AddCredential(UserCredential credential);

    /// <summary>
    /// 查找凭据
    /// </summary>
    UserCredential? FindCredential(string credentialId, string userId);

    /// <summary>
    /// 获取用户的所有凭据
    /// </summary>
    IEnumerable<UserCredential> GetUserCredentials(string userId);

    /// <summary>
    /// 更新凭据
    /// </summary>
    void UpdateCredential(UserCredential credential);
}