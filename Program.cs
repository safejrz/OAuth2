using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDataProtection();
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<AuthService>();

var app = builder.Build();

app.Use((ctx, next) =>
{
    var idp = ctx.RequestServices.GetRequiredService<IDataProtectionProvider>();
    var protector = idp.CreateProtector("auth-cookie");

    var authcookie = ctx.Request.Headers.Cookie.FirstOrDefault(c => c.StartsWith("auth="));
    var protectedPayload = authcookie?.Split('=').Last();
    var payload = protectedPayload is null ? null : protector.Unprotect(protectedPayload);
    var parts = payload?.Split(':');
    var key = parts?.FirstOrDefault();
    var value = parts?.LastOrDefault();

    return next();
});

//Recognizing the authenticated user from the auth cookie
app.MapGet("username", (HttpContext ctx) =>
    {
        return ctx.User;
    });

//Creating the auth cookie
app.MapGet("/login", (AuthService auth) =>
    {
        auth.SignIn();
        return "ok";
    });

app.Run();


public class AuthService
{
    private readonly IDataProtectionProvider _idp;
    private readonly IHttpContextAccessor _accessor;

    public AuthService(IDataProtectionProvider idp, IHttpContextAccessor accessor)
    {
        _idp = idp;
        _accessor = accessor;
    }

    public void SignIn()
    {
        var protector = _idp.CreateProtector("auth-cookie");
        _accessor.HttpContext.Response.Headers["set-cookie"] = $"auth={protector.Protect("usr:javier")}";
    }
}