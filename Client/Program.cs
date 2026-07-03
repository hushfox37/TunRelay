using System.Collections.Concurrent;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace TunRelayClient
{
    class Program
    {
        private const string ConfigPath = "config.json";

        public static string TunnelIP = "";
        public static string ServerIP = "";
        public static int ServerPort;
        public static TUN tunnelTUN = null!;
        public static TunnelNet tunnelNet = null!;
        public static ConcurrentBag<int> PortConfig = new ConcurrentBag<int>();
        public static ILogger logger = null!;
        public static TunRelayConfig CurrentConfig = null!;
        public static LogLevel CurrentLogLevel;

        static async Task Main(string[] args)
        {
            HandleCommandLine(args, ConfigPath);

            // 先加载配置并同步到旧静态字段，供现有 TUN/DataChannel 代码读取。
            var config = ConfigManager.LoadOrCreate(ConfigPath);
            CurrentConfig = config;
            ServerIP = config.ServerIp;
            ServerPort = config.EffectiveServerPort;

            // 日志需要先初始化，后续配置校验和运行时都通过它输出。
            using var provider = BuildServiceProvider(config);
            logger = provider
                .GetRequiredService<ILoggerFactory>()
                .CreateLogger("");

            // 交互式 stats shell 独立运行，进程退出时统一取消。
            using var shellCts = new CancellationTokenSource();
            _ = Task.Run(() => ConsoleShell.RunAsync(shellCts.Token));

            ValidateConfig(config);
            EnsureClientId(ConfigPath, config);
            if (string.IsNullOrWhiteSpace(config.Secret))
            {
                logger.LogWarning("Secret 未填写，将尝试向服务端申请一次性自动配置");
            }

            // Ctrl+C 只触发取消，让各层按自己的 finally 做收尾。
            using var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (_, e) =>
            {
                e.Cancel = true;
                cts.Cancel();
            };

            try
            {
                // 运行期负责 TUN 生命周期、数据会话和重连循环。
                var runtime = new ClientRuntime(config, ConfigPath, logger);
                await runtime.RunAsync(cts.Token);
            }
            catch (OperationCanceledException) when (cts.IsCancellationRequested)
            {
            }
            finally
            {
                cts.Cancel();
                shellCts.Cancel();
                tunnelNet?.Close();
            }
        }

        private static void HandleCommandLine(string[] args, string configPath)
        {
            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "--Secret":
                        if (i + 1 < args.Length)
                        {
                            ConfigManager.Update(configPath, config =>
                            {
                                config.Secret = args[++i];
                            });
                            Console.WriteLine("已更新 Secret 到 config.json");
                        }
                        break;
                }
            }
        }

        private static ServiceProvider BuildServiceProvider(TunRelayConfig config)
        {
            var services = new ServiceCollection();

            Enum.TryParse<LogLevel>(
                config.LogLevel,
                true,
                out var logLevel);
            CurrentLogLevel = logLevel;

            services.AddLogging(builder =>
            {
                builder.SetMinimumLevel(LogLevel.Trace);
                builder.AddFilter((_, level) => level >= CurrentLogLevel);
                builder.AddSimpleConsole(options =>
                {
                    options.SingleLine = true;
                    options.TimestampFormat = "yyyy/MM/dd HH:mm:ss ";
                });
            });

            return services.BuildServiceProvider();
        }

        private static void ValidateConfig(TunRelayConfig config)
        {
            if (string.IsNullOrWhiteSpace(ServerIP))
            {
                logger.LogError("config.json: ServerIp 不能为空");
                throw new InvalidOperationException("config.json: ServerIp 不能为空");
            }

            if (ServerPort <= 0 || ServerPort > 65535)
            {
                logger.LogError("config.json: ServerPort 必须是 1-65535");
                throw new InvalidOperationException("config.json: ServerPort 必须是 1-65535");
            }
        }

        private static void EnsureClientId(string configPath, TunRelayConfig config)
        {
            if (!string.IsNullOrWhiteSpace(config.ClientID))
            {
                return;
            }

            config.ClientID = $"{Guid.NewGuid():N}";
            ConfigManager.Save(configPath, config);
            logger.LogInformation($"已生成 ClientID: {config.ClientID}");
        }
    }
}
