using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDataProtection();

var app = builder.Build();

app.MapGet("username", (HttpContext http) => 
    {        

        var authcookie = http.Request.Headers.Cookie.FirstOrDefault(x => x.StartsWith("auth="));        
        var payload = authcookie?.Split('=').Last();
        var parts = payload?.Split(':');
        var key = parts?.FirstOrDefault();
        var value = parts?.LastOrDefault();
        return value;
    });

app.MapGet("/login", (HttpContext http) =>
    {
        http.Response.Headers["set-cookie"] = "auth=usr:javier";
        return "ok";
    });

    app.Run();