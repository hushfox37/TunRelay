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

            // 交互式 stats shell
            using var shellCts = new CancellationTokenSource();
            _ = Task.Run(() => ConsoleShell.RunAsync(shellCts.Token));

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
            await tunnelNet.ConnectControlAsync(cts.Token);
            logger?.LogInformation("服务器控制连接已建立");

            // 服务器身份验证
            if (!await Authentication(tunnelNet, config.Secret, config.ClientID, cts.Token))
            {
                logger?.LogError("认证失败");
                throw new InvalidOperationException("认证失败");
            }
            else logger?.LogInformation("认证成功");

            // 接收服务器分配的虚拟IP地址、端口配置、并行连接数与 sessionId
            var Data = await tunnelNet.ReceiveControlAsync(cts.Token);
            var json = JObject.Parse(Data);
            TunnelIP = json["TunnelIP"]?.ToString() ?? TunnelIP;
            var ports = (JArray)json["Ports"]!;
            foreach (var port in ports)
            {
                PortConfig.Add(port.ToObject<int>());
            }

            int uplink = Math.Clamp(json["UplinkConnections"]?.ToObject<int>() ?? 1, 1, 16);
            int downlink = Math.Clamp(json["DownlinkConnections"]?.ToObject<int>() ?? 1, 1, 16);
            string sessionId = json["SessionId"]?.ToString() ?? "";
            if (string.IsNullOrEmpty(sessionId))
            {
                logger?.LogError("服务端未下发 sessionId");
                throw new InvalidOperationException("服务端未下发 sessionId");
            }

            logger?.LogInformation($"服务端下发: TunnelIP={TunnelIP}, Ports={string.Join(",", PortConfig)}, Uplink={uplink}, Downlink={downlink}");

            // 建立 N 条上行 + N 条下行数据连接
            await tunnelNet.ConnectDataChannelsAsync(uplink, downlink, sessionId, cts.Token);
            logger?.LogInformation($"数据连接已建立: 上行 {uplink} 条, 下行 {downlink} 条");

            // 每条上行连接一个入口队列(TUN 读 -> 按流哈希分流到其中之一)
            var uplinkChannels = new Channel<PacketBuffer>[uplink];
            for (int i = 0; i < uplink; i++)
                uplinkChannels[i] = Channel.CreateBounded<PacketBuffer>(new BoundedChannelOptions(4096)
                {
                    FullMode = BoundedChannelFullMode.Wait,
                    SingleReader = true,
                    SingleWriter = true
                });

            // 启动 TUN
            ITunDriver driver = TunDriverFactory.Create();
            tunnelTUN = new TUN(driver, uplinkChannels);
            await tunnelTUN.StartAsync(TunnelIP, cts.Token);

            var batchOptions = new BatchOptions(config.BatchDelayMs, config.MaxBatchBytes, config.MaxBatchPackets);
            logger?.LogInformation($"数据通道批处理参数: DelayMs={batchOptions.DelayMs}, MaxBytes={batchOptions.MaxBytes}, MaxPackets={batchOptions.MaxPackets}");

            var loops = new List<Task>(uplink + downlink);

            // 上行: 每条连接 uplinkChannels[i] 聚合成 batch -> TLS Tx[i]
            var txStreams = tunnelNet.TxStreams;
            for (int i = 0; i < uplink; i++)
            {
                int idx = i;
                loops.Add(Task.Run(() => DataChannel.SendLoopAsync(uplinkChannels[idx].Reader, txStreams[idx], batchOptions, cts.Token)));
            }

            // 下行: 每条连接 TLS Rx[i] 解析 batch -> 并发逐包写入 TUN
            var rxStreams = tunnelNet.RxStreams;
            for (int i = 0; i < downlink; i++)
            {
                int idx = i;
                loops.Add(Task.Run(() => DataChannel.ReceiveLoopAsync(
                    rxStreams[idx],
                    (packet, c) => new ValueTask(tunnelTUN.WriteAsync(packet, c)),
                    cts.Token)));
            }

            // 原子会话: 任一连接断开则整体收尾
            await Task.WhenAny(loops);
            cts.Cancel();
            try { await Task.WhenAll(loops); } catch { }
            logger?.LogWarning("数据连接已断开");
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
    }
}
