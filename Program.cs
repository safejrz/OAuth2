using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

const string AuthScheme = "cookie";
const string AuthScheme2 = "cookie2";

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(AuthScheme)
    .AddCookie(AuthScheme, ConfigureCookieRedirects)
    .AddCookie(AuthScheme2, ConfigureCookieRedirects);

builder.Services.AddAuthorization(builder =>
{
    builder.AddPolicy("eu passport", pb =>
    {
        pb.RequireAuthenticatedUser();
        pb.RequireClaim("passport_type", "eur");
    });

    builder.AddPolicy("NOR passport", pb =>
    {
        pb.RequireAuthenticatedUser();
        pb.RequireClaim("passport_type", "NOR");
    });
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

//Recognizing the authenticated user from the auth cookie
app.MapGet("/unsecure", (HttpContext ctx) =>
    {
        var userClaim = ctx.User?.FindFirst("usr");
        return userClaim?.Value ?? "empty";
    }).AllowAnonymous();

app.MapGet("/sweden", (HttpContext ctx) =>
    {
        return "allowed";
    }).RequireAuthorization("eu passport");

app.MapGet("/norway", (HttpContext ctx) =>
{
    if (!ctx.User.HasClaim("passport_type", "NOR"))
    {
        ctx.Response.StatusCode = 403;
        return "";
    }

    return "allowed";
}).RequireAuthorization("NOR passport");

app.MapGet("/denmark", (HttpContext ctx) =>
{
    return "allowed";
}).RequireAuthorization("eu passport");

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
    }).AllowAnonymous();

app.Run();

static void ConfigureCookieRedirects(CookieAuthenticationOptions options)
{
    options.LoginPath = "/login";

    options.Events = new CookieAuthenticationEvents
    {
        OnRedirectToLogin = ctx =>
        {
            ctx.Response.Redirect("/login");
            return Task.CompletedTask;
        },

        OnRedirectToAccessDenied = ctx =>
        {
            ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
            return Task.CompletedTask;
        }
    };
}