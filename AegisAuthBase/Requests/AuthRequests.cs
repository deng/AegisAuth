using System.ComponentModel.DataAnnotations;

namespace AegisAuthBase.Requests;

/// <summary>
/// 登录请求
/// </summary>
public class LoginRequest
{
    /// <summary>
    /// 用户名
    /// </summary>
    [Required]
    public required string UserName { get; set; }

    /// <summary>
    /// 密码
    /// </summary>
    [Required]
    public required string Password { get; set; }

    /// <summary>
    /// 是否记住登录状态
    /// </summary>
    public bool RememberMe { get; set; }
}

/// <summary>
/// 刷新令牌请求
/// </summary>
public class RefreshTokenRequest
{
    /// <summary>
    /// 刷新令牌
    /// </summary>
    [Required]
    public required string RefreshToken { get; set; }
}

/// <summary>
/// 注册请求
/// </summary>
public class RegisterRequest
{
    /// <summary>
    /// 用户名
    /// </summary>
    [Required]
    public required string UserName { get; set; }

    /// <summary>
    /// 密码
    /// </summary>
    [Required]
    public required string Password { get; set; }

    /// <summary>
    /// 确认密码
    /// </summary>
    [Required]
    [Compare("Password")]
    public required string ConfirmPassword { get; set; }
}