using AegisAuthBase.Entities;
using AegisAuthBase.Repositories;

namespace AegisAuth.WebAuthnDemo.Services;

/// <summary>
/// 演示用户服务
/// </summary>
public class DemoUserService
{
    private readonly IUserRepository _userRepo;

    public DemoUserService(IUserRepository userRepo)
    {
        _userRepo = userRepo;
    }

    /// <summary>
    /// 获取或创建演示用户
    /// </summary>
    public async Task<User> GetOrCreateDemoUserAsync()
    {
        const string demoUserName = "demo";
        const string demoUserId = "demo-user-1";

        // 首先尝试通过用户名查找用户
        var user = await _userRepo.GetUserByUserNameAsync(demoUserName);
        if (user != null)
        {
            return user;
        }

        // 如果找不到，通过ID查找
        user = await _userRepo.GetByIdAsync(demoUserId, false);
        if (user != null)
        {
            return user;
        }

        // 如果都找不到，创建新用户
        user = new User
        {
            Id = demoUserId,
            UserName = demoUserName,
            PasswordHash = "demo", // Not used in demo
            PasswordSalt = "demo", // Not used in demo
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        };
        await _userRepo.CreateAsync(user);
        return user;
    }
}