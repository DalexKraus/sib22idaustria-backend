using IDAustriaDemo.Util;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

var oidcAuthority = EnvUtil.GetValueOrThrow("OIDC_AUTHORITY");
var jwtAudience = EnvUtil.GetValueOrThrow("JWT_AUDIENCE");
var jwtIssuer = EnvUtil.GetValueOrThrow("JWT_ISSUER");

var builder = WebApplication.CreateBuilder(args);

// @@@ BSC
builder.Services.AddHttpContextAccessor();
builder.Services.AddControllers();
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = oidcAuthority;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = true,
            ValidAudience = jwtAudience,
            ValidateIssuer = true,
            ValidIssuer = jwtIssuer,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true
        };
        options.RequireHttpsMetadata = true;
    });

var app = builder.Build();

// Allow CORS during development
if (builder.Environment.IsDevelopment())
{
    app.UseCors(builder => builder
        .AllowAnyOrigin()
        .AllowAnyMethod()
        .AllowAnyHeader()
    );
}
else
{
    // Allow CORS only from the API host specified in the environment variable
    var apiHost = EnvUtil.GetValueOrThrow("API_HOST");
    if (string.IsNullOrEmpty(apiHost))
    {
        throw new Exception("API_HOST environment variable is not set");
    }

    app.UseCors(builder => builder
        .WithOrigins(apiHost)
        .AllowAnyMethod()
        .AllowAnyHeader()
    );
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.Run();
