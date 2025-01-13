using IDAustriaDemo.Util;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();

// @@@ BSC
builder.Services.AddHttpContextAccessor();

builder.Services.AddControllers();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = "https://eid2.oesterreich.gv.at";
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = true,
            ValidAudience = "https://sib22idaustria.cc/auth/c79c8897-e563-4d4e-bc3a-7386e1b208c3",
            ValidateIssuer = true,
            ValidIssuer = "https://eid2.oesterreich.gv.at",
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
