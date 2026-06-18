using System.Collections.Concurrent;
using System.Threading.Channels;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Security.Cryptography;
using System.Text;

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

            // 合格性检查
            if (string.IsNullOrWhiteSpace(ServerIP))
                throw new InvalidOperationException("config.json: ServerIp 不能为空");

            if (ServerPort <= 0 || ServerPort > 65535)
                throw new InvalidOperationException("config.json: ServerPort 必须是 1-65535");

            if (string.IsNullOrWhiteSpace(config.ClientID))
            {
                config.ClientID = $"{Guid.NewGuid():N}";
                ConfigManager.Save(configPath, config);
                Console.WriteLine($"已生成 ClientID: {config.ClientID}");
            }

            if (string.IsNullOrWhiteSpace(config.Secret))
            {
                Console.WriteLine("密钥未填写");
                return;
            }

            Console.WriteLine($"配置: Server={ServerIP}:{ServerPort}, ClientID={config.ClientID}");

            using var cts = new CancellationTokenSource();
            tunnelNet = new TunnelNet(ServerIP, ServerPort);
            Console.WriteLine("正在连接服务器...");
            await tunnelNet.ConnectAsync();
            Console.WriteLine("服务器连接已建立");

            // 服务器身份验证
            if (!await Authentication(tunnelNet, config.Secret, config.ClientID, cts.Token))
                throw new InvalidOperationException("认证失败");

            Console.WriteLine("认证成功");

            // 接收服务器分配的虚拟IP地址,端口配置
            var Data = await tunnelNet.ReceiveControlAsync(cts.Token);
            var json = JObject.Parse(Data);
            TunnelIP = json["TunnelIP"]?.ToString() ?? TunnelIP;
            var ports = (JArray)json["Ports"]!;
            foreach (var port in ports)
            {
                PortConfig.Add(port.ToObject<int>());
            }
            Console.WriteLine($"服务端下发: TunnelIP={TunnelIP}, Ports={string.Join(",", PortConfig)}");

            // 启动 TUN 
            tunnelTUN = new TUN(TunnelIP, PortConfig, RX_channel, TX_channel);
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
            Console.WriteLine($"[AUTH] 发送认证 ClientID={data}, Timestamp={timestamp}");
            await tunnelNet.SendControlAsync(json, ct);
            var IfSuccess = await tunnelNet.ReceiveControlAsync(ct);
            Console.WriteLine($"[AUTH] 服务端响应: {IfSuccess}");
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
