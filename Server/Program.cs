using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Threading.Channels;
using Newtonsoft.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;


namespace TunRelayServer
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

        private static string TunnelIP;
        private static int ListenPort;
        private static int[] tcpPorts;
        private static int[] udpPorts;
        private static int[] ports;
        private static ILogger logger;

        static async Task Main(string[] args)
        {
            const string configPath = "config.json";
            var config = ConfigManager.LoadOrCreate<TunRelayConfig>(configPath);
            LoadConfig(config);

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

            IptablesManager.Init(logger);
            ServerNet.Init(logger);

            if (string.IsNullOrWhiteSpace(config.Secret))
            {
                config.Secret = ServerNet.GenerateSecret();
                ConfigManager.Save(configPath, config);
                logger?.LogInformation("已生成 Secret");
                return;
            }

            logger?.LogInformation($"配置: TunnelIP={TunnelIP}, ListenPort={ListenPort}, Ports={string.Join(",", ports)}, TcpPorts={string.Join(",", tcpPorts)}, UdpPorts={string.Join(",", udpPorts)}, ClientID={config.ClientID}");

            var cert = ServerNet.GenerateSelfSignedCertificate(config.ServerIP);
            var listener = new TcpListener(IPAddress.Any, ListenPort);
            listener.Start();

            logger?.LogInformation($"服务端监听端口 {ListenPort}");

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

            RawSender.Init(logger);
            IptablesManager.Add(tcpPorts, udpPorts);
            NFQueue.Init(logger);

            NFQueue.Start(100, TunnelIP, TX_channel, cts.Token);

            _ = Task.Run(() => RawInjectLoop(cts.Token), cts.Token);

            while (!cts.IsCancellationRequested)
            {
                try
                {
                    DrainChannel(TX_channel);
                    DrainChannel(RX_channel);

                    using var client = await ServerNet.AcceptAuthenticatedClientAsync(listener, cert, config, cts.Token);
                    using var clientCts = CancellationTokenSource.CreateLinkedTokenSource(cts.Token);

                    var json = JsonConvert.SerializeObject(new { TunnelIP, Ports = ports, TcpPorts = tcpPorts, UdpPorts = udpPorts });
                    await ServerNet.SendAsync(client.ControlSsl, Encoding.UTF8.GetBytes(json), clientCts.Token);
                    logger?.LogInformation($"已下发 TunnelIP: {TunnelIP}, Ports: {string.Join(",", ports)}, TcpPorts: {string.Join(",", tcpPorts)}, UdpPorts: {string.Join(",", udpPorts)}");

                    logger?.LogInformation("开始转发...");

                    var receiveTask = ReceiveLoopAsync(client.TxSsl, clientCts.Token);
                    var sendTask = SendLoopAsync(client.RxSsl, clientCts.Token);

                    await Task.WhenAny(receiveTask, sendTask);
                    clientCts.Cancel();
                    await Task.WhenAll(receiveTask, sendTask);

                    logger?.LogWarning("客户端已断开，等待重连...");
                }
                catch (OperationCanceledException) when (cts.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception ex)
                {
                    logger?.LogWarning($"客户端会话异常: {ex.Message}");
                }
            }

            IptablesManager.Remove(tcpPorts, udpPorts);
            listener.Stop();
        }

        static void LoadConfig(TunRelayConfig config)
        {
            TunnelIP = config.TunIp;
            ListenPort = config.ListenPort;
            tcpPorts = NormalizePorts(config.TcpPorts);
            udpPorts = NormalizePorts(config.UdpPorts);
            ports = tcpPorts.Concat(udpPorts).Distinct().OrderBy(port => port).ToArray();

            if (string.IsNullOrWhiteSpace(TunnelIP))
                throw new InvalidOperationException("config.json: TunIp 不能为空");
            if (ListenPort <= 0 || ListenPort > 65535)
                throw new InvalidOperationException("config.json: ListenPort 必须是 1-65535");
            if (ports.Length == 0)
                throw new InvalidOperationException("config.json: TcpPorts/UdpPorts 至少需要配置一个端口");

            ValidatePorts("TcpPorts", tcpPorts);
            ValidatePorts("UdpPorts", udpPorts);

            if (string.IsNullOrWhiteSpace(config.ClientID))
            {
                logger?.LogError("config.json: ClientID 不能为空");
                throw new InvalidOperationException("config.json: ClientID 不能为空");
            }
        }

        static int[] NormalizePorts(IEnumerable<int> values)
        {
            return values.Distinct().OrderBy(port => port).ToArray();
        }

        static void DrainChannel(Channel<PacketBuffer> channel)
        {
            while (channel.Reader.TryRead(out var packet))
                packet.Dispose();
        }

        static void ValidatePorts(string name, int[] values)
        {
            if (values.Any(port => port <= 0 || port > 65535))
            {
                logger?.LogError($"config.json: {name} 必须是 1-65535 的端口列表");
                throw new InvalidOperationException($"config.json: {name} 必须是 1-65535 的端口列表");
            }          
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
                        if (logger?.IsEnabled(LogLevel.Trace) ?? false)
                        {
                            var dump = Convert.ToHexString(data.Buffer);
                            logger?.LogTrace("[Receive]Packet={Dump}", dump);
                        }
                    }
                    catch
                    {
                        data.Dispose();
                        throw;
                    }
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex) { logger?.LogWarning($"数据连接断开(收): {ex.Message}"); }
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
                        if (logger.IsEnabled(LogLevel.Trace))
                        {
                            var dump = Convert.ToHexString(data.Buffer);
                            logger?.LogTrace("[Send]Packet={Dump}", dump);
                        }
                    }
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex) { logger?.LogWarning($"数据连接断开(发): {ex.Message}"); }
        }
    }
}
