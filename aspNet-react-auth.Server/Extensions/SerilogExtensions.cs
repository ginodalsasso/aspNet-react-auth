using Serilog;

namespace aspNet_react_auth.Server.Extensions
{
    public static class SerilogExtensions
    {
        public static void SerilogConfiguration(this IHostBuilder host)
        {
            host.UseSerilog((context, loggerConfig) =>
            {
                loggerConfig.WriteTo.Console();
            });
        }
    }
}