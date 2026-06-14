using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Threading.Channels;
using Newtonsoft.Json;

namespace VirtualIPServer
{
    class Program
    {
        public static readonly Channel<PacketBuffer> RX_channel =
            Channel.CreateBounded<PacketBuffer>(new BoundedChannelOptions(8192)
            {
                SingleReader = true,
                SingleWriter = true,
                FullMode = BoundedChannelFullMode.Wait
            });

        public static readonly Channel<PacketBuffer> TX_channel =
            Channel.CreateBounded<PacketBuffer>(new BoundedChannelOptions(8192)
            {
                SingleReader = true,
                SingleWriter = true,
                FullMode = BoundedChannelFullMode.Wait
            });

        static string TunnelIP;
        public static int ListenPort;
        static int[] tcpPorts;
        static int[] udpPorts;
        static int[] ports;

        static async Task Main(string[] args)
        {
            const string configPath = "config.json";
            var config = ConfigManager.LoadOrCreate<VirtualIPConfig>(configPath);
            LoadConfig(config);

            if (string.IsNullOrWhiteSpace(config.Secret))
            {
                config.Secret = ServerNet.GenerateSecret();
                ConfigManager.Save(configPath, config);
                Console.WriteLine("已生成 Secret");
                return;
            }

            Console.WriteLine($"配置: TunnelIP={TunnelIP}, ListenPort={ListenPort}, Ports={string.Join(",", ports)}, TcpPorts={string.Join(",", tcpPorts)}, UdpPorts={string.Join(",", udpPorts)}, ClientID={config.ClientID}");

            var cert = ServerNet.GenerateSelfSignedCertificate(config.ServerIP);
            var listener = new TcpListener(IPAddress.Any, ListenPort);
            listener.Start();

            Console.WriteLine($"服务端监听端口 {ListenPort}");

            using var cts = new CancellationTokenSource();

            Console.CancelKeyPress += (_, e) =>
            {
                e.Cancel = true;
                IptablesManager.Remove(tcpPorts, udpPorts);
                cts.Cancel();
            };
            AppDomain.CurrentDomain.ProcessExit += (_, _) =>
            {
                IptablesManager.Remove(tcpPorts, udpPorts);
            };

            using var client = await ServerNet.AcceptAuthenticatedClientAsync(listener, cert, config, cts.Token);

            var json = JsonConvert.SerializeObject(new { TunnelIP, Ports = ports, TcpPorts = tcpPorts, UdpPorts = udpPorts });
            await ServerNet.SendAsync(client.ControlSsl, Encoding.UTF8.GetBytes(json), cts.Token);
            Console.WriteLine($"已下发 TunnelIP: {TunnelIP}, Ports: {string.Join(",", ports)}, TcpPorts: {string.Join(",", tcpPorts)}, UdpPorts: {string.Join(",", udpPorts)}");

            RawSender.Init();
            IptablesManager.Add(tcpPorts, udpPorts);
            NFQueue.Start(100, TunnelIP, TX_channel, cts.Token);

            _ = Task.Run(() => RawInjectLoop(cts.Token), cts.Token);

            Console.WriteLine("开始转发...");

            await Task.WhenAll(
                ReceiveLoopAsync(client.TxSsl, cts.Token),
                SendLoopAsync(client.RxSsl, cts.Token)
            );

            listener.Stop();
        }

        static void LoadConfig(VirtualIPConfig config)
        {
            TunnelIP = config.VirtualIp;
            ListenPort = config.ListenPort;
            tcpPorts = NormalizePorts(config.TcpPorts);
            udpPorts = NormalizePorts(config.UdpPorts);
            ports = tcpPorts.Concat(udpPorts).Distinct().OrderBy(port => port).ToArray();

            if (string.IsNullOrWhiteSpace(TunnelIP))
                throw new InvalidOperationException("config.json: VirtualIp 不能为空");
            if (ListenPort <= 0 || ListenPort > 65535)
                throw new InvalidOperationException("config.json: ListenPort 必须是 1-65535");
            if (ports.Length == 0)
                throw new InvalidOperationException("config.json: TcpPorts/UdpPorts 至少需要配置一个端口");

            ValidatePorts("TcpPorts", tcpPorts);
            ValidatePorts("UdpPorts", udpPorts);

            if (string.IsNullOrWhiteSpace(config.ClientID))
                throw new InvalidOperationException("config.json: ClientID 不能为空");
        }

        static int[] NormalizePorts(IEnumerable<int> values)
        {
            return values.Distinct().OrderBy(port => port).ToArray();
        }

        static void ValidatePorts(string name, int[] values)
        {
            if (values.Any(port => port <= 0 || port > 65535))
                throw new InvalidOperationException($"config.json: {name} 必须是 1-65535 的端口列表");
        }

        static async Task RawInjectLoop(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                var packet = await RX_channel.Reader.ReadAsync(ct);
                using (packet)
                {
                    RawSender.Send(packet);
                }
            }
        }

        static async Task ReceiveLoopAsync(SslStream dataSsl, CancellationToken ct)
        {
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    var data = await ServerNet.ReceiveAsync(dataSsl, ct);
                    try
                    {
                        await RX_channel.Writer.WriteAsync(data, ct);
                    }
                    catch
                    {
                        data.Dispose();
                        throw;
                    }
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex) { Console.WriteLine($"数据连接断开(收): {ex.Message}"); }
        }

        static async Task SendLoopAsync(SslStream dataSsl, CancellationToken ct)
        {
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    var data = await TX_channel.Reader.ReadAsync(ct);
                    using (data)
                    {
                        await ServerNet.SendAsync(dataSsl, data.ReadOnlyMemory, ct);
                    }
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex) { Console.WriteLine($"数据连接断开(发): {ex.Message}"); }
        }
    }
}
