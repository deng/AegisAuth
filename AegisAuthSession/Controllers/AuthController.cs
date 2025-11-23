using AegisAuthSession.Managers;
using AegisAuth.Core.Requests;
using AegisAuth.Core.Responses;
using AegisAuthSession.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AegisAuthSession.Controllers;

/// <summary>
/// Session 认证控制器
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly SessionAuthManager _sessionAuthManager;

    public AuthController(
        SessionAuthManager sessionAuthManager)
    {
        _sessionAuthManager = sessionAuthManager;
    }

    /// <summary>
    /// 用户登录 - 创建 Session
    /// </summary>
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        // 调用 SessionAuthManager 的完整验证逻辑
        var result = await _sessionAuthManager.SignIn(request);

        if (!result.Success)
        {
            return BadRequest(result);
        }

        return Ok(result);
    }

    /// <summary>
    /// 刷新 Session（续期）
    /// </summary>
    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh([FromBody] RefreshTokenRequest request)
    {
        try
        {
            // request.RefreshToken 实际上是 Session ID
            var success = await _sessionAuthManager.RenewSessionAsync(request.RefreshToken);

            if (!success)
            {
                return BadRequest(new ApiResponse<SignedInUser>
                {
                    Success = false,
                    Error = "Failed to refresh session"
                });
            }

            // 获取更新后的 Session 信息
            var sessionInfo = await _sessionAuthManager.GetSessionInfoAsync(request.RefreshToken);
            if (sessionInfo == null)
            {
                return BadRequest(new ApiResponse<SignedInUser>
                {
                    Success = false,
                    Error = "Session not found after refresh"
                });
            }

            var signedInUser = new SignedInUser
            {
                UserId = sessionInfo.UserId,
                UserName = sessionInfo.UserName,
                Token = sessionInfo.SessionId,
                RefreshToken = sessionInfo.SessionId, // Session ID 作为 RefreshToken
                Role = sessionInfo.Role,
                ExpiresAt = sessionInfo.ExpiresAt,
                RememberMe = false // 刷新时不改变记住状态
            };

            return Ok(new ApiResponse<SignedInUser>
            {
                Success = true,
                Data = signedInUser
            });
        }
        catch (Exception ex)
        {
            return BadRequest(new ApiResponse<SignedInUser>
            {
                Success = false,
                Error = $"Refresh failed: {ex.Message}"
            });
        }
    }

    /// <summary>
    /// 用户登出
    /// </summary>
    [HttpPost("logout")]
    [Authorize]
    public async Task<IActionResult> Logout()
    {
        var sessionId = GetSessionIdFromRequest();
        if (string.IsNullOrEmpty(sessionId))
        {
            return Unauthorized(new ApiResponse<bool>
            {
                Success = false,
                Error = "Session ID not found"
            });
        }

        var success = await _sessionAuthManager.DestroySessionAsync(sessionId);
        if (!success)
        {
            return BadRequest(new ApiResponse<bool>
            {
                Success = false,
                Error = "Failed to logout"
            });
        }

        return Ok(new ApiResponse<bool>
        {
            Success = true,
            Data = true
        });
    }

    /// <summary>
    /// 销毁用户的所有 Session
    /// </summary>
    [HttpPost("logout-all")]
    [Authorize]
    public async Task<IActionResult> LogoutAll()
    {
        var sessionId = GetSessionIdFromRequest();
        if (string.IsNullOrEmpty(sessionId))
        {
            return Unauthorized(new ApiResponse<int>
            {
                Success = false,
                Error = "Session ID not found"
            });
        }

        // 获取当前用户信息
        var sessionInfo = await _sessionAuthManager.GetSessionInfoAsync(sessionId);
        if (sessionInfo == null)
        {
            return Unauthorized(new ApiResponse<int>
            {
                Success = false,
                Error = "Session not found"
            });
        }

        var remainingSessions = await _sessionAuthManager.DestroyUserSessionsAsync(sessionInfo.UserId);

        return Ok(new ApiResponse<int>
        {
            Success = true,
            Data = remainingSessions
        });
    }

    /// <summary>
    /// 获取当前 Session 信息
    /// </summary>
    [HttpGet("info")]
    [Authorize]
    public async Task<IActionResult> GetSessionInfo()
    {
        // 从请求头或Cookie中获取Session ID
        var sessionId = GetSessionIdFromRequest();
        if (string.IsNullOrEmpty(sessionId))
        {
            return Unauthorized(new ApiResponse<SessionInfo>
            {
                Success = false,
                Error = "Session ID not found"
            });
        }

        var sessionInfo = await _sessionAuthManager.GetSessionInfoAsync(sessionId);
        if (sessionInfo == null)
        {
            return Unauthorized(new ApiResponse<SessionInfo>
            {
                Success = false,
                Error = "Session not found or expired"
            });
        }

        return Ok(new ApiResponse<SessionInfo>
        {
            Success = true,
            Data = sessionInfo
        });
    }

    /// <summary>
    /// 验证 Session 状态
    /// </summary>
    [HttpGet("validate")]
    public async Task<IActionResult> ValidateSession([FromQuery] string sessionId)
    {
        if (string.IsNullOrEmpty(sessionId))
        {
            return BadRequest(new ApiResponse<bool>
            {
                Success = false,
                Error = "Session ID is required"
            });
        }

        var (isValid, session, error) = await _sessionAuthManager.ValidateSessionAsync(sessionId);

        return Ok(new ApiResponse<bool>
        {
            Success = isValid,
            Data = isValid,
            Error = error
        });
    }

    /// <summary>
    /// 从请求中获取 Session ID
    /// 支持从 Authorization header 或 Cookie 中获取
    /// </summary>
    private string? GetSessionIdFromRequest()
    {
        // 首先尝试从 Authorization header 获取
        var authHeader = Request.Headers["Authorization"].FirstOrDefault();
        if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith("Session "))
        {
            return authHeader.Substring("Session ".Length);
        }

        // 然后尝试从 Cookie 获取
        var sessionCookie = Request.Cookies["AegisAuthSession"];
        if (!string.IsNullOrEmpty(sessionCookie))
        {
            return sessionCookie;
        }

        // 最后尝试从查询参数获取
        var sessionId = Request.Query["sessionId"].FirstOrDefault();
        return sessionId;
    }
}

/// <summary>
/// API响应模型
/// </summary>
public class ApiResponse
{
    /// <summary>
    /// 是否成功
    /// </summary>
    public bool Success { get; set; }

    /// <summary>
    /// 错误信息
    /// </summary>
    public string? Error { get; set; }
}

/// <summary>
/// API响应模型
/// </summary>
/// <typeparam name="T">数据类型</typeparam>
public class ApiResponse<T> : ApiResponse
{
    /// <summary>
    /// 响应数据
    /// </summary>
    public T? Data { get; set; }
}