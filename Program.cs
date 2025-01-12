var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();

// @@@ BSC
builder.Services.AddHttpContextAccessor();

builder.Services.AddControllers();

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
    var apiHost = Environment.GetEnvironmentVariable("API_HOST");
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
app.UseAuthorization();
app.MapControllers();
app.Run();
