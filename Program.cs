using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDataProtection();

var app = builder.Build();

app.MapGet("username", (HttpContext http, IDataProtectionProvider idp) => 
    {        
        var protector = idp.CreateProtector("auth-cookie");

        var authcookie = http.Request.Headers.Cookie.FirstOrDefault(c => c.StartsWith("auth="));
        var protectedPayload = authcookie?.Split('=').Last();
        var payload = protectedPayload is null ? null : protector.Unprotect(protectedPayload);
        var parts = payload?.Split(':');
        var key = parts?.FirstOrDefault();
        var value = parts?.LastOrDefault();
        return value;
    });

app.MapGet("/login", (HttpContext http, IDataProtectionProvider idp) =>
    {
        var protector = idp.CreateProtector("auth-cookie");
        http.Response.Headers["set-cookie"] = $"auth={protector.Protect("usr:javier")}";
        return "ok";
    });

    app.Run();