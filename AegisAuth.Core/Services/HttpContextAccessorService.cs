using Microsoft.AspNetCore.Http;

namespace AegisAuth.Core.Services;

/// <summary>
/// HTTP上下文访问器接口
/// </summary>
public interface IHttpContextAccessorService
{
    /// <summary>
    /// 获取客户端IP地址
    /// </summary>
    string? GetClientIpAddress();

    /// <summary>
    /// 获取用户代理
    /// </summary>
    string? GetUserAgent();

    /// <summary>
    /// 获取Authorization头
    /// </summary>
    string? GetAuthorizationHeader();

    /// <summary>
    /// 获取当前用户ID
    /// </summary>
    string GetCurrentUserId();
}

/// <summary>
/// HTTP上下文访问器实现
/// </summary>
public class HttpContextAccessorService : IHttpContextAccessorService
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    public HttpContextAccessorService(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }

    public string? GetClientIpAddress()
    {
        var httpContext = _httpContextAccessor.HttpContext;
        if (httpContext == null) return null;

        // 尝试从X-Forwarded-For头获取（代理场景）
        var forwardedFor = httpContext.Request.Headers["X-Forwarded-For"].FirstOrDefault();
        if (!string.IsNullOrEmpty(forwardedFor))
        {
            return forwardedFor.Split(',').First().Trim();
        }

        // 尝试从X-Real-IP头获取
        var realIp = httpContext.Request.Headers["X-Real-IP"].FirstOrDefault();
        if (!string.IsNullOrEmpty(realIp))
        {
            return realIp;
        }

        // 使用远程IP地址
        return httpContext.Connection.RemoteIpAddress?.ToString();
    }

    public string? GetUserAgent()
    {
        return _httpContextAccessor.HttpContext?.Request.Headers["User-Agent"].ToString();
    }

    public string? GetAuthorizationHeader()
    {
        return _httpContextAccessor.HttpContext?.Request.Headers["Authorization"].ToString();
    }

    public string GetCurrentUserId()
    {
        var httpContext = _httpContextAccessor.HttpContext;
        if (httpContext == null)
        {
            throw new InvalidOperationException("HTTP上下文不可用");
        }

        var userId = httpContext.User?.Claims?.FirstOrDefault(c => c.Type == "nameid" || c.Type == System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userId))
        {
            throw new InvalidOperationException("用户未认证或用户ID不存在");
        }

        return userId;
    }
}