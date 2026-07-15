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
        public static BatchOptions? CurrentBatchOptions;
        public static LogLevel CurrentLogLevel;

        static async Task Main(string[] args)
        {
            // 先加载配置并同步到旧静态字段，供现有 TUN/DataChannel 代码读取。
            var config = ConfigManager.LoadOrCreate(ConfigPath);
            ApplyCommandLine(args, config);
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

        private static void ApplyCommandLine(string[] args, TunRelayConfig config)
        {
            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "--Secret":
                    case "--secret":
                        config.Secret = ReadValue(args, ref i);
                        break;
                    case "--ClientID":
                    case "--client-id":
                        config.ClientID = ReadValue(args, ref i);
                        break;
                    case "--ServerIP":
                    case "--server-ip":
                        config.ServerIp = ReadValue(args, ref i);
                        break;
                    case "--ServerPort":
                    case "--server-port":
                        config.ServerPorts = ParsePort(ReadValue(args, ref i), "ServerPort");
                        break;
                    case "--LogLevel":
                    case "--log-level":
                        config.LogLevel = ReadValue(args, ref i);
                        break;
                    case "--ReconnectDelayMs":
                    case "--reconnect-delay-ms":
                        config.ReconnectDelayMs = ParseInt(ReadValue(args, ref i), "ReconnectDelayMs");
                        break;
                    case "--MaxReconnectAttempts":
                    case "--max-reconnect-attempts":
                        config.MaxReconnectAttempts = ParseInt(ReadValue(args, ref i), "MaxReconnectAttempts");
                        break;
                    case "--BatchDelayMs":
                    case "--batch-delay-ms":
                        config.BatchDelayMs = ParseInt(ReadValue(args, ref i), "BatchDelayMs");
                        break;
                    case "--MaxBatchBytes":
                    case "--max-batch-bytes":
                        config.MaxBatchBytes = ParseInt(ReadValue(args, ref i), "MaxBatchBytes");
                        break;
                    case "--MaxBatchPackets":
                    case "--max-batch-packets":
                        config.MaxBatchPackets = ParseInt(ReadValue(args, ref i), "MaxBatchPackets");
                        break;
                    case "--AdaptiveBatching":
                    case "--adaptive-batching":
                        config.AdaptiveBatching = ParseBool(ReadValue(args, ref i), "AdaptiveBatching");
                        break;
                }
            }
        }

        private static string ReadValue(string[] args, ref int index)
        {
            if (index + 1 >= args.Length)
                throw new ArgumentException($"Missing value for {args[index]}");
            return args[++index];
        }

        private static int ParseInt(string value, string name)
        {
            if (!int.TryParse(value, out var result))
                throw new ArgumentException($"{name} must be an integer");
            return result;
        }

        private static bool ParseBool(string value, string name)
        {
            if (!bool.TryParse(value, out bool result))
                throw new ArgumentException($"{name} must be true or false");
            return result;
        }

        public static void SetAdaptiveBatching(bool enabled)
        {
            CurrentBatchOptions?.SetAdaptiveBatching(enabled);
            logger?.LogInformation("AdaptiveBatching runtime mode changed to {Enabled}", enabled);
        }

        public static bool GetAdaptiveBatching()
            => CurrentBatchOptions?.AdaptiveBatching ?? CurrentConfig?.AdaptiveBatching ?? false;

        private static int ParsePort(string value, string name)
        {
            int port = ParseInt(value, name);
            if (port <= 0 || port > 65535)
                throw new ArgumentException($"{name} must be 1-65535");
            return port;
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
