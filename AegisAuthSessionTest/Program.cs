using AegisAuth.Core.Repositories;
using AegisAuthSession.Extensions;
using AegisAuthSessionTest.Repositories;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();

// Register repositories
builder.Services.AddScoped<IUserRepository, InMemoryUserRepository>();
builder.Services.AddScoped<ISecurityAuditLogRepository, InMemorySecurityAuditLogRepository>();

// Configure AegisAuthSession with memory store (for testing)
builder.Services.AddAegisAuthSessionWithMemory(settings =>
{
    settings.SessionExpirationMinutes = 30;
    settings.SessionRenewalMinutes = 10;
    settings.MaxSessionsPerUser = 3;
    settings.SessionIdLength = 64;
    settings.SessionCookieName = "AegisAuthSession";
    settings.EnableSessionFixationProtection = true;
    settings.EnableSlidingExpiration = true;
    settings.CleanupIntervalMinutes = 60;
});

// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

// Use AegisAuthSession middleware
app.UseAegisAuthSession();

app.UseAuthorization();

app.MapControllers();

app.Run();