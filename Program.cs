using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;


var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication("cookie")
    .AddCookie("cookie");

var app = builder.Build();

app.UseAuthentication();

//Recognizing the authenticated user from the auth cookie
app.MapGet("/username", (HttpContext ctx) =>
    {
        return ctx.User.FindFirst("usr").Value;
    });

//Creating the auth cookie
app.MapGet("/login", async (HttpContext ctx) =>
    {
        //ctx.SignIn();
        var claims = new List<Claim>();
        claims.Add(new Claim("usr", "javi"));
        var identity = new ClaimsIdentity(claims, "cookie");
        var user = new ClaimsPrincipal(identity);
        
        await ctx.SignInAsync("cookie", user);
        return "ok";
    });

app.Run();