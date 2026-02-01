using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

const string AuthScheme = "cookie";

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(AuthScheme)
    .AddCookie(AuthScheme);

var app = builder.Build();

app.UseAuthentication();

//Recognizing the authenticated user from the auth cookie
app.MapGet("/unsecure", (HttpContext ctx) =>
    {
        var userClaim = ctx.User?.FindFirst("usr");
        return userClaim?.Value ?? "empty";
    });

app.MapGet("/sweden", (HttpContext ctx) =>
    {
        if(!ctx.User.Identities.Any(x => x.AuthenticationType == AuthScheme))
        {
            ctx.Response.StatusCode = 401;
            return "";
        }
        
        if (!ctx.User.HasClaim("passport_type", "eur"))
        {
            ctx.Response.StatusCode = 403;
            return "";
        }
        
        return "allowed";
    });

//Creating the auth cookie
app.MapGet("/login", async (HttpContext ctx) =>
    {
        var claims = new List<Claim>
        {
            new Claim("usr", "javi"),
            new Claim("passport_type", "eur")
        };
        var identity = new ClaimsIdentity(claims, AuthScheme);
        var user = new ClaimsPrincipal(identity);
        await ctx.SignInAsync(AuthScheme, user);
    });

app.Run();