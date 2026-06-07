using System.Collections.Concurrent;
using System.Threading.Channels;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace VirtualIPClient
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
        public static string TunnelIP = "10.0.0.1";
        public static string ServerIP = "192.168.192.1";
        public static int ServerPort = 12345;
        public static TUN tunnelTUN;
        public static TunnelNet tunnelNet;
        public static ConcurrentBag<int> PortConfig = new ConcurrentBag<int>();

        static async Task Main(string[] args)
        {
            var config = ConfigManager.LoadOrCreate<VirtualIPConfig>("config.json");
            ServerIP = config.ServerIp;
            ServerPort = config.EffectiveServerPort;
            if (string.IsNullOrWhiteSpace(ServerIP))
                throw new InvalidOperationException("config.json: ServerIp 不能为空");
            if (ServerPort <= 0 || ServerPort > 65535)
                throw new InvalidOperationException("config.json: ServerPort 必须是 1-65535");
            Console.WriteLine($"配置: Server={ServerIP}:{ServerPort}");

            using var cts = new CancellationTokenSource();
            tunnelNet = new TunnelNet(ServerIP, ServerPort);
            await tunnelNet.ConnectAsync();

            // 认证
            await Authentication(tunnelNet, cts.Token);

            // 接收服务器分配的虚拟IP地址,端口配置
            var Data = await tunnelNet.ReceiveControlAsync(cts.Token);
            var json = JObject.Parse(Data);
            TunnelIP = json["TunnelIP"]?.ToString() ?? TunnelIP;
            var ports = (JArray)json["Ports"]!;
            foreach (var port in ports)
            {
                PortConfig.Add(port.ToObject<int>());
            }

            // 启动 TUN 
            tunnelTUN = new TUN(TunnelIP, PortConfig, RX_channel, TX_channel);
            await tunnelTUN.StartAsync(TunnelIP, cts.Token);
            _ = Task.Run(() => SendPacketAsync(cts.Token));
            await ReceivePacketAsync(cts.Token);
        }
        static async Task Authentication(TunnelNet tunnelNet, CancellationToken ct = default)
        {

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
