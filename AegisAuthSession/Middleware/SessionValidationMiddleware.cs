using AegisAuthSession.Managers;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;

namespace AegisAuthSession.Middleware;

/// <summary>
/// Session 验证中间件
/// </summary>
public class SessionValidationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly SessionAuthManager _sessionAuthManager;

    public SessionValidationMiddleware(RequestDelegate next, SessionAuthManager sessionAuthManager)
    {
        _next = next;
        _sessionAuthManager = sessionAuthManager;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // 从多种来源尝试获取 Session ID
        var sessionId = GetSessionIdFromRequest(context);

        if (!string.IsNullOrEmpty(sessionId))
        {
            var (isValid, session, error) = await _sessionAuthManager.ValidateSessionAsync(sessionId);

            if (isValid && session != null)
            {
                // 创建用户身份
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, session.UserName),
                    new Claim(ClaimTypes.NameIdentifier, session.UserId),
                    new Claim("SessionId", session.Id)
                };

                // 添加角色声明
                claims.Add(new Claim(ClaimTypes.Role, session.Role.ToString()));

                var identity = new ClaimsIdentity(claims, "Session");
                context.User = new ClaimsPrincipal(identity);

                // 将 Session 信息添加到请求上下文
                context.Items["Session"] = session;
            }
        }

        await _next(context);
    }

    private string? GetSessionIdFromRequest(HttpContext context)
    {
        // 1. 从 Authorization header 获取 (Authorization: Session {sessionId})
        var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
        if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith("Session "))
        {
            return authHeader.Substring("Session ".Length);
        }

        // 2. 从 Cookie 获取
        var sessionCookie = context.Request.Cookies["AegisAuthSession"];
        if (!string.IsNullOrEmpty(sessionCookie))
        {
            return sessionCookie;
        }

        // 3. 从查询参数获取
        var sessionId = context.Request.Query["sessionId"].FirstOrDefault();
        if (!string.IsNullOrEmpty(sessionId))
        {
            return sessionId;
        }

        return null;
    }
}

/// <summary>
/// Session 验证中间件扩展方法
/// </summary>
public static class SessionValidationMiddlewareExtensions
{
    public static IApplicationBuilder UseSessionValidation(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<SessionValidationMiddleware>();
    }
}
