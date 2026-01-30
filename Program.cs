using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDataProtection();

var app = builder.Build();

app.MapGet("username", (HttpContext http, [FromServices] IDataProtectionProvider idp) =>
    {
        if (!http.Request.Cookies.TryGetValue("auth", out var protectedPayload))
        {
            return Results.Unauthorized();
        }

        var protector = idp.CreateProtector("auth-cookie");

        string payload;
        try
        {
            payload = protector.Unprotect(protectedPayload);
        }
        catch (CryptographicException)
        {
            return Results.Unauthorized();
        }

        var value = payload.Split(':').LastOrDefault();
        return value is null ? Results.Unauthorized() : Results.Ok(value);
    });

app.MapGet("/login", (HttpContext http, [FromServices] IDataProtectionProvider idp) =>
    {
        var protector = idp.CreateProtector("auth-cookie");
        http.Response.Cookies.Append("auth", protector.Protect("usr:javier"));
        return Results.Ok("ok");
    });

app.Run();