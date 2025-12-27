using AegisAuthBase.Repositories;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;

namespace AegisAuthBase.Middleware;

/// <summary>
/// 双因素认证验证中间件
/// </summary>
public class TwoFactorAuthMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IUserRepository _userRepository;

    public TwoFactorAuthMiddleware(RequestDelegate next, IUserRepository userRepository)
    {
        _next = next;
        _userRepository = userRepository;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // 检查用户是否已认证
        if (context.User.Identity?.IsAuthenticated == true)
        {
            // 获取用户ID
            var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (!string.IsNullOrEmpty(userId))
            {
                // 获取用户信息
                var user = await _userRepository.GetByIdAsync(userId, false);
                if (user != null && user.TwoFactorEnabled)
                {
                    // 检查是否已通过双因素认证
                    var twoFactorVerified = context.User.FindFirst("TwoFactorVerified")?.Value;
                    if (string.IsNullOrEmpty(twoFactorVerified) || twoFactorVerified != "true")
                    {
                        // 未通过双因素认证，重定向到双因素认证页面或返回错误
                        // 这里假设有一个双因素认证端点
                        context.Response.StatusCode = StatusCodes.Status403Forbidden;
                        await context.Response.WriteAsync("双因素认证未完成");
                        return;
                    }
                }
            }
        }

        // 继续处理请求
        await _next(context);
    }
}

/// <summary>
/// 双因素认证验证中间件扩展方法
/// </summary>
public static class TwoFactorAuthMiddlewareExtensions
{
    public static IApplicationBuilder UseTwoFactorAuth(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<TwoFactorAuthMiddleware>();
    }
}