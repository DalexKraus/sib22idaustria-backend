namespace IDAustriaDemo.Util;

public static class EnvUtil
{
    public static string GetValueOrThrow(string variableName)
    {
        return Environment.GetEnvironmentVariable(variableName)
            ?? throw new InvalidOperationException(
                $"Environment variable '{variableName}' is not set!"
            );
    }
}