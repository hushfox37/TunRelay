using System.Collections.Concurrent;
using System.Threading.Channels;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace TunRelayClient
{
    class Program
    {
        public static readonly Channel<PacketBuffer> RX_channel =
            Channel.CreateBounded<PacketBuffer>(new BoundedChannelOptions(4096)
            {
                FullMode = BoundedChannelFullMode.Wait,
                SingleReader = true,
                SingleWriter = true
            });

        public static readonly Channel<PacketBuffer> TX_channel =
            Channel.CreateBounded<PacketBuffer>(new BoundedChannelOptions(4096)
            {
                FullMode = BoundedChannelFullMode.Wait,
                SingleReader = true,
                SingleWriter = true
            });

        public static string TunnelIP;
        public static string ServerIP;
        public static int ServerPort;
        public static TUN tunnelTUN;
        public static TunnelNet tunnelNet;
        public static ConcurrentBag<int> PortConfig = new ConcurrentBag<int>();
        public static ILogger logger;
        static async Task Main(string[] args)
        {
            // 命令行参数
            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "--Secret":
                        if (i + 1 < args.Length)
                        {
                            ConfigManager.Update<TunRelayConfig>("config.json", config =>
                            {
                                config.Secret = args[++i];
                            });
                            Console.WriteLine("已更新 Secret 到 config.json");
                        }
                        break;
                }
            }

            // 加载配置文件
            const string configPath = "config.json";
            var config = ConfigManager.LoadOrCreate<TunRelayConfig>(configPath);

            ServerIP = config.ServerIp;
            ServerPort = config.EffectiveServerPort;

            //配置日志
            var services = new ServiceCollection();

            Enum.TryParse<LogLevel>(
                config.LogLevel,
                true,
                out var logLevel);

            services.AddLogging(builder =>
            {
                builder.SetMinimumLevel(logLevel);

                builder.AddSimpleConsole(options =>
                {
                    options.SingleLine = true;
                    options.TimestampFormat = "yyyy/MM/dd HH:mm:ss ";
                });
            });

            using var provider = services.BuildServiceProvider();

            logger = provider
                .GetRequiredService<ILoggerFactory>()
                .CreateLogger("");

            // 合格性检查
            if (string.IsNullOrWhiteSpace(ServerIP))
            {
                logger?.LogError("config.json: ServerIp 不能为空");
                throw new InvalidOperationException("config.json: ServerIp 不能为空");
            }

            if (ServerPort <= 0 || ServerPort > 65535)
            {
                logger?.LogError("config.json: ServerPort 必须是 1-65535");
                throw new InvalidOperationException("config.json: ServerPort 必须是 1-65535");
            }

            if (string.IsNullOrWhiteSpace(config.ClientID))
            {
                config.ClientID = $"{Guid.NewGuid():N}";
                ConfigManager.Save(configPath, config);
                logger?.LogInformation($"已生成 ClientID: {config.ClientID}");
            }

            if (string.IsNullOrWhiteSpace(config.Secret))
            {
                logger?.LogError("密钥未填写");
                return;
            }

            logger?.LogInformation($"配置: Server={ServerIP}:{ServerPort}, ClientID={config.ClientID}");

            using var cts = new CancellationTokenSource();
            tunnelNet = new TunnelNet(ServerIP, ServerPort);

            logger?.LogInformation("正在连接服务器...");
            await tunnelNet.ConnectAsync();
            logger?.LogInformation("服务器连接已建立");

            // 服务器身份验证
            if (!await Authentication(tunnelNet, config.Secret, config.ClientID, cts.Token))
            {
                logger?.LogError("认证失败");
                throw new InvalidOperationException("认证失败");
            }
            else logger?.LogInformation("认证成功");

            // 接收服务器分配的虚拟IP地址,端口配置
            var Data = await tunnelNet.ReceiveControlAsync(cts.Token);
            var json = JObject.Parse(Data);
            TunnelIP = json["TunnelIP"]?.ToString() ?? TunnelIP;
            var ports = (JArray)json["Ports"]!;
            foreach (var port in ports)
            {
                PortConfig.Add(port.ToObject<int>());
            }

            logger?.LogInformation($"服务端下发: TunnelIP={TunnelIP}, Ports={string.Join(",", PortConfig)}");

            // 启动 TUN 
            ITunDriver driver = TunDriverFactory.Create();
            tunnelTUN = new TUN(driver, RX_channel, TX_channel);
            await tunnelTUN.StartAsync(TunnelIP, cts.Token);
            _ = Task.Run(() => SendPacketAsync(cts.Token));
            await ReceivePacketAsync(cts.Token);
        }

        static async Task<bool> Authentication(TunnelNet tunnelNet, string secret, string data, CancellationToken ct = default)
        {
            byte[] key = Encoding.UTF8.GetBytes(secret);
            long timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            string signData = $"{data}:{timestamp}";
            byte[] msg = Encoding.UTF8.GetBytes(signData);

            using var hmac = new HMACSHA256(key);

            string sign = Convert.ToHexString(hmac.ComputeHash(msg));

            var json = JsonConvert.SerializeObject(new { ClientID = data, Timestamp = timestamp, Sign = sign });
            logger?.LogInformation($"[AUTH] 发送认证 ClientID={data}, Timestamp={timestamp}");
            await tunnelNet.SendControlAsync(json, ct);
            var IfSuccess = await tunnelNet.ReceiveControlAsync(ct);
            logger?.LogInformation($"[AUTH] 服务端响应: {IfSuccess}");
            if (IfSuccess == "Success")
            {
                return true;
            }
            if (IfSuccess == "Failed")
            {
                return false;
            }
            return false;
        }

        static async Task SendPacketAsync(CancellationToken ct = default)
        {
            while (!ct.IsCancellationRequested)
            {
                var packet = await RX_channel.Reader.ReadAsync(ct);
                using (packet)
                {
                    await tunnelNet.SendDataAsync(packet.ReadOnlyMemory, ct);
                    if (logger.IsEnabled(LogLevel.Trace))
                    {
                        var dump = Convert.ToHexString(packet.Buffer);
                        logger?.LogTrace("[Send]Packet={Dump}", dump);
                    }
                }
            }
        }
        static async Task ReceivePacketAsync(CancellationToken ct = default)
        {
            while (!ct.IsCancellationRequested)
            {
                var packet = await tunnelNet.ReceiveDataAsync(ct);
                try
                {
                    await TX_channel.Writer.WriteAsync(packet, ct);
                    if (logger.IsEnabled(LogLevel.Trace))
                    {
                        var dump = Convert.ToHexString(packet.Buffer);
                        logger?.LogTrace("[Receive]Packet={Dump}", dump);
                    }
                }
                catch
                {
                    packet.Dispose();
                    throw;
                }
            }
        }
    }
}
