using AuthApi.Data;
using AuthApi.DTOs;
using AuthApi.Models;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);


var keyVaultUrl = "https://auth-kv-full.vault.azure.net/";

var secretClient = new SecretClient(
    new Uri(keyVaultUrl),
    new DefaultAzureCredential());

var jwtKey =
    (await secretClient.GetSecretAsync("JwtSecretKey"))
    .Value
    .Value;

var jwtIssuer =
    (await secretClient.GetSecretAsync("JwtIssuer"))
    .Value
    .Value;

var jwtAudience =
    (await secretClient.GetSecretAsync("JwtAudience"))
    .Value
    .Value;
var sqlConnectionString =
    (await secretClient.GetSecretAsync("SqlConnectionString"))
    .Value
    .Value;

builder.Services.AddOpenApi();

builder.Services.AddDbContext<AppDbContext>(options =>
{
    options.UseSqlServer(sqlConnectionString);
});

builder.Services.AddCors(options =>
{
    options.AddPolicy("Open", policy =>
    {
        policy
            .AllowAnyOrigin()
            .AllowAnyHeader()
            .AllowAnyMethod();
    });
});

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters =
            new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateIssuerSigningKey = true,
                ValidateLifetime = true,

                ValidIssuer = builder.Configuration["Jwt:Issuer"],
                ValidAudience = builder.Configuration["Jwt:Audience"],

                IssuerSigningKey =
                    new SymmetricSecurityKey(
                        Encoding.UTF8.GetBytes(
                            builder.Configuration["Jwt:Key"]!))
            };
    });

builder.Services.AddAuthorization();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

if (app.Environment.IsDevelopment()|| app.Environment.IsProduction())
{
    app.MapOpenApi();
    app.UseSwagger();
    app.UseSwaggerUI();
}
app.UseCors("Open");
app.UseAuthentication();
app.UseAuthorization();

var passwordHasher = new PasswordHasher<User>();

app.MapPost("/api/auth/register",
async (UserRegisterRequest request,
       AppDbContext db) =>
{
    var existingUser =
        await db.Users.FirstOrDefaultAsync(
            x => x.Email == request.Email);

    if (existingUser != null)
    {
        return Results.BadRequest("User already exists");
    }

    var user = new User
    {
        UserName = request.UserName,
        Email = request.Email
    };

    user.PasswordHash =
        passwordHasher.HashPassword(user, request.Password);

    db.Users.Add(user);

    await db.SaveChangesAsync();

    return Results.Ok("User Registered");
});

app.MapPost("/api/auth/login",
async (UserLoginRequest request,
       AppDbContext db) =>
{
    var user =
        await db.Users.FirstOrDefaultAsync(
            x => x.Email == request.Email);

    if (user == null)
    {
        return Results.Unauthorized();
    }

    var result =
        passwordHasher.VerifyHashedPassword(
            user,
            user.PasswordHash,
            request.Password);

    if (result == PasswordVerificationResult.Failed)
    {
        return Results.Unauthorized();
    }

    var claims = new List<Claim>
    {
        new(ClaimTypes.Name, user.UserName),
        new(ClaimTypes.Email, user.Email)
    };

    var key = new SymmetricSecurityKey(
        Encoding.UTF8.GetBytes(
            builder.Configuration["Jwt:Key"]!));

    var credentials =
        new SigningCredentials(
            key,
            SecurityAlgorithms.HmacSha256);

    var token =
        new JwtSecurityToken(
            issuer: builder.Configuration["Jwt:Issuer"],
            audience: builder.Configuration["Jwt:Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddHours(2),
            signingCredentials: credentials);

    return Results.Ok(new
    {
        token = new JwtSecurityTokenHandler()
            .WriteToken(token)
    });
});

app.MapGet("/api/auth/profile",
() => "Authorized User")
.RequireAuthorization();


app.MapGet("/", () =>
{
    return Results.Ok("Auth API Running");
});

app.Run();