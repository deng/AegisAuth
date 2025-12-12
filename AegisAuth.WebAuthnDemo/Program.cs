using AegisAuth.WebAuthnDemo.Repositories;
using AegisAuth.WebAuthnDemo.Services;
using AegisAuthBase.Repositories;
using AegisAuthBase.Services;
using AegisAuthBase.Extensions;
using Microsoft.AspNetCore.Builder;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Add CORS for frontend
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader();
    });
});

// Add AegisAuth services (mock implementations for demo)
builder.Services.AddSingleton<IUserRepository, MockUserRepository>();
builder.Services.AddSingleton<IUserPasskeyRepository, MockUserPasskeyRepository>();
builder.Services.AddSingleton<ITwoFactorStore, MockTwoFactorStore>();
builder.Services.AddSingleton<ICredentialStore, InMemoryCredentialStore>();
builder.Services.AddSingleton<DemoUserService>();

// Add WebAuthn services
builder.Services.AddWebAuthnServices(options =>
{
    options.ServerDomain = "localhost";
    options.ServerName = "WebAuthn Demo";
    options.Origins = new HashSet<string> { "https://localhost:7122", "http://localhost:5202" };
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseCors("AllowAll");
app.UseStaticFiles(); // Add static files middleware

app.UseAuthorization();

app.MapControllers();

app.Run();
