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
        // 下行单包入口队列(每条下行连接一个): NFQueue 按流哈希分流写入。满则丢包计数。
        private static Channel<PacketBuffer>[] _downlinkChannels = Array.Empty<Channel<PacketBuffer>>();

        private static string TunnelIP;
        private static int ListenPort;
        private static int[] tcpPorts;
        private static int[] udpPorts;
        private static int[] ports;
        private static int uplinkConnections;
        private static int downlinkConnections;
        public static ILogger logger;
        private static BatchOptions batchOptions;

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

            batchOptions = new BatchOptions(config.BatchDelayMs, config.MaxBatchBytes, config.MaxBatchPackets);
            logger?.LogInformation($"数据通道批处理参数: DelayMs={batchOptions.DelayMs}, MaxBytes={batchOptions.MaxBytes}, MaxPackets={batchOptions.MaxPackets}");

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

            // 交互式 stats shell
            _ = Task.Run(() => ConsoleShell.RunAsync(cts.Token));

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

            _downlinkChannels = new Channel<PacketBuffer>[downlinkConnections];
            for (int i = 0; i < downlinkConnections; i++)
                _downlinkChannels[i] = Channel.CreateBounded<PacketBuffer>(new BoundedChannelOptions(8192)
                {
                    SingleReader = true,
                    SingleWriter = false,
                    FullMode = BoundedChannelFullMode.Wait
                });

            NFQueue.Start(100, TunnelIP, _downlinkChannels, cts.Token);

            while (!cts.IsCancellationRequested)
            {
                ControlChannel? control = null;
                Session? session = null;
                try
                {
                    DrainChannels(_downlinkChannels);

                    control = await ServerNet.AcceptControlAsync(listener, cert, config, cts.Token);

                    var json = JsonConvert.SerializeObject(new
                    {
                        TunnelIP,
                        Ports = ports,
                        TcpPorts = tcpPorts,
                        UdpPorts = udpPorts,
                        UplinkConnections = uplinkConnections,
                        DownlinkConnections = downlinkConnections,
                        SessionId = control.SessionId
                    });
                    await ServerNet.SendAsync(control.Ssl, Encoding.UTF8.GetBytes(json), cts.Token);
                    logger?.LogInformation($"已下发配置: TunnelIP={TunnelIP}, Uplink={uplinkConnections}, Downlink={downlinkConnections}");

                    session = await ServerNet.AssembleDataConnectionsAsync(listener, cert, control, uplinkConnections, downlinkConnections, cts.Token);
                    control = null; // 所有权移交给 session

                    using var clientCts = CancellationTokenSource.CreateLinkedTokenSource(cts.Token);

                    logger?.LogInformation("开始转发...");

                    var loops = new List<Task>(uplinkConnections + downlinkConnections);
                    // 上行: server 读 TxSsl[i] -> RawSender
                    foreach (var tx in session.TxSsl)
                        loops.Add(ReceiveLoopAsync(tx, clientCts.Token));
                    // 下行: server 把 downlinkChannels[i] 聚合 -> RxSsl[i]
                    for (int i = 0; i < session.RxSsl.Length; i++)
                        loops.Add(SendLoopAsync(session.RxSsl[i], _downlinkChannels[i].Reader, clientCts.Token));

                    await Task.WhenAny(loops);
                    clientCts.Cancel();
                    await Task.WhenAll(loops);

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
                finally
                {
                    session?.Dispose();
                    control?.Dispose();
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

            uplinkConnections = Math.Clamp(config.UplinkConnections, 1, 16);
            downlinkConnections = Math.Clamp(config.DownlinkConnections, 1, 16);

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

        static void DrainChannels(Channel<PacketBuffer>[] channels)
        {
            foreach (var channel in channels)
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

        // 下行: TLS Rx 解析 batch -> 直接逐包注入 Raw socket(不再经过 channel)
        static async Task ReceiveLoopAsync(SslStream dataSsl, CancellationToken ct)
        {
            try
            {
                await DataChannel.ReceiveLoopAsync(
                    dataSsl,
                    (packet, _) => { RawSender.Send(packet); return ValueTask.CompletedTask; },
                    ct);
            }
            catch (OperationCanceledException) { }
            catch (Exception ex) { logger?.LogWarning($"数据连接断开(收): {ex.Message}"); }
        }

        // 下行: 指定 channel 聚合成 batch -> TLS 写
        static async Task SendLoopAsync(SslStream dataSsl, ChannelReader<PacketBuffer> reader, CancellationToken ct)
        {
            try
            {
                await DataChannel.SendLoopAsync(reader, dataSsl, batchOptions, ct);
            }
            catch (OperationCanceledException) { }
            catch (Exception ex) { logger?.LogWarning($"数据连接断开(发): {ex.Message}"); }
        }
    }
}
