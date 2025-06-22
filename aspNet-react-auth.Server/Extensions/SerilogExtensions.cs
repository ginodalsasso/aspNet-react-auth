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
                loggerConfig.WriteTo.File("Logs/logs-.txt", Serilog.Events.LogEventLevel.Information, rollingInterval: RollingInterval.Day);
            });
        }
    }
}