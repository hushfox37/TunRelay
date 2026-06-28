using System.Collections.Concurrent;
using System.Threading.Channels;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace TunRelayClient
{
    class Program
    {
        public static string TunnelIP = "";
        public static string ServerIP = "";
        public static int ServerPort;
        public static TUN tunnelTUN = null!;
        public static TunnelNet tunnelNet = null!;
        public static ConcurrentBag<int> PortConfig = new ConcurrentBag<int>();
        public static ILogger logger = null!;

        private sealed class ServerAssignment
        {
            public string TunnelIp { get; init; } = "";
            public int[] Ports { get; init; } = Array.Empty<int>();
            public int Uplink { get; init; }
            public int Downlink { get; init; }
            public string SessionId { get; init; } = "";
        }

        private sealed class ControlSession
        {
            public TunnelNet Net { get; init; } = null!;
            public ServerAssignment Assignment { get; init; } = null!;
        }

        private sealed class ReconnectPolicy
        {
            public ReconnectPolicy(TimeSpan delay, int maxAttempts)
            {
                Delay = delay;
                MaxAttempts = maxAttempts;
            }

            public TimeSpan Delay { get; }
            public int MaxAttempts { get; }
            public int Attempts { get; private set; }
            public string LimitText => MaxAttempts == 0 ? "无限" : MaxAttempts.ToString();
            public bool HasReachedLimit => MaxAttempts > 0 && Attempts >= MaxAttempts;

            public int RecordFailure()
            {
                Attempts++;
                return Attempts;
            }

            public void Reset()
            {
                Attempts = 0;
            }
        }

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
                            ConfigManager.Update("config.json", config =>
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
            var config = ConfigManager.LoadOrCreate(configPath);

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
            var reconnectPolicy = new ReconnectPolicy(
                NormalizeReconnectDelay(config.ReconnectDelayMs),
                Math.Max(0, config.MaxReconnectAttempts));
            logger?.LogInformation($"重连参数: DelayMs={(int)reconnectPolicy.Delay.TotalMilliseconds}, MaxAttempts={reconnectPolicy.LimitText}");

            using var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (_, e) =>
            {
                e.Cancel = true;
                cts.Cancel();
            };

            try
            {
                var control = await ConnectControlWithRetryAsync(config, reconnectPolicy, cts.Token);
                TunnelIP = control.Assignment.TunnelIp;
                int uplink = control.Assignment.Uplink;
                int downlink = control.Assignment.Downlink;
                ApplyPortConfig(control.Assignment.Ports);

                logger?.LogInformation($"服务端下发: TunnelIP={TunnelIP}, Ports={string.Join(",", control.Assignment.Ports)}, Uplink={uplink}, Downlink={downlink}");

                // 每条上行连接一个入口队列(TUN 读 -> 按流哈希分流到其中之一)
                var uplinkChannels = new Channel<PacketBuffer>[uplink];
                for (int i = 0; i < uplink; i++)
                {
                    uplinkChannels[i] = Channel.CreateBounded<PacketBuffer>(new BoundedChannelOptions(4096)
                    {
                        FullMode = BoundedChannelFullMode.DropOldest,
                        SingleReader = true,
                        SingleWriter = true
                    });
                }

                // 启动 TUN。TUN 生命周期跟随进程，不跟随单次数据会话。
                ITunDriver driver = TunDriverFactory.Create();
                tunnelTUN = new TUN(driver, uplinkChannels);
                await tunnelTUN.StartAsync(TunnelIP, cts.Token);

                var batchOptions = new BatchOptions(config.BatchDelayMs, config.MaxBatchBytes, config.MaxBatchPackets);
                logger?.LogInformation($"数据通道批处理参数: DelayMs={batchOptions.DelayMs}, MaxBytes={batchOptions.MaxBytes}, MaxPackets={batchOptions.MaxPackets}");

                while (!cts.IsCancellationRequested)
                {
                    try
                    {
                        ApplyPortConfig(control.Assignment.Ports);
                        await RunSessionAsync(control.Net, control.Assignment.SessionId, uplinkChannels, uplink, downlink, batchOptions, cts.Token);
                        reconnectPolicy.Reset();
                    }
                    catch (OperationCanceledException) when (cts.IsCancellationRequested)
                    {
                        break;
                    }
                    catch (Exception ex)
                    {
                        logger?.LogError(ex, "数据会话异常断开");
                        control.Net.Close();
                    }

                    if (cts.IsCancellationRequested)
                    {
                        break;
                    }

                    logger?.LogWarning($"数据连接已断开，{(int)reconnectPolicy.Delay.TotalMilliseconds} 毫秒后重连...");
                    await Task.Delay(reconnectPolicy.Delay, cts.Token);

                    control = await ConnectControlWithRetryAsync(config, reconnectPolicy, cts.Token, TunnelIP, uplink, downlink);
                    logger?.LogInformation($"服务端下发: TunnelIP={control.Assignment.TunnelIp}, Ports={string.Join(",", control.Assignment.Ports)}, Uplink={control.Assignment.Uplink}, Downlink={control.Assignment.Downlink}");
                }
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

        private static async Task<ControlSession> ConnectControlWithRetryAsync(
            TunRelayConfig config,
            ReconnectPolicy reconnectPolicy,
            CancellationToken ct,
            string? expectedTunnelIp = null,
            int? expectedUplink = null,
            int? expectedDownlink = null)
        {
            while (true)
            {
                TunnelNet? net = null;
                try
                {
                    net = new TunnelNet(ServerIP, ServerPort);
                    tunnelNet = net;

                    logger?.LogInformation("正在连接服务器...");
                    await net.ConnectControlAsync(ct);
                    logger?.LogInformation("服务器控制连接已建立");

                    if (!await Authentication(net, config.Secret, config.ClientID, ct))
                    {
                        throw new InvalidOperationException("认证失败");
                    }

                    logger?.LogInformation("认证成功");
                    var assignment = await ReceiveServerAssignmentAsync(net, ct);

                    if (expectedTunnelIp != null &&
                        (!string.Equals(assignment.TunnelIp, expectedTunnelIp, StringComparison.Ordinal) ||
                         assignment.Uplink != expectedUplink ||
                         assignment.Downlink != expectedDownlink))
                    {
                        throw new InvalidOperationException(
                            $"重连下发参数变化: TunnelIP={assignment.TunnelIp}, Uplink={assignment.Uplink}, Downlink={assignment.Downlink}");
                    }

                    return new ControlSession { Net = net, Assignment = assignment };
                }
                catch (OperationCanceledException)
                {
                    net?.Close();
                    throw;
                }
                catch (Exception ex)
                {
                    net?.Close();
                    int attempts = reconnectPolicy.RecordFailure();
                    if (reconnectPolicy.HasReachedLimit)
                    {
                        logger?.LogError(ex, $"连接服务器失败，已达到重连上限 {reconnectPolicy.MaxAttempts}");
                        throw;
                    }

                    logger?.LogError(ex, $"连接服务器失败，第 {attempts} 次/上限 {reconnectPolicy.LimitText}，{(int)reconnectPolicy.Delay.TotalMilliseconds} 毫秒后重试");
                    await Task.Delay(reconnectPolicy.Delay, ct);
                }
            }
        }

        private static TimeSpan NormalizeReconnectDelay(int reconnectDelayMs)
        {
            int delayMs = reconnectDelayMs <= 0 ? 5000 : reconnectDelayMs;
            delayMs = Math.Clamp(delayMs, 100, 600000);
            return TimeSpan.FromMilliseconds(delayMs);
        }

        private static async Task<ServerAssignment> ReceiveServerAssignmentAsync(TunnelNet net, CancellationToken ct)
        {
            var data = await net.ReceiveControlAsync(ct);
            using var json = JsonDocument.Parse(data);
            var root = json.RootElement;

            string tunnelIp = root.TryGetProperty("TunnelIP", out var tunnelIpJson)
                ? tunnelIpJson.GetString() ?? ""
                : "";

            if (string.IsNullOrWhiteSpace(tunnelIp))
            {
                logger?.LogError("服务端未下发 TunnelIP");
                throw new InvalidOperationException("服务端未下发 TunnelIP");
            }

            if (!root.TryGetProperty("Ports", out var portsJson) || portsJson.ValueKind != JsonValueKind.Array)
            {
                logger?.LogError("服务端未下发端口配置");
                throw new InvalidOperationException("服务端未下发端口配置");
            }

            var ports = portsJson.EnumerateArray().Select(port => port.GetInt32()).ToArray();
            int uplink = Math.Clamp(root.TryGetProperty("UplinkConnections", out var uplinkJson) ? uplinkJson.GetInt32() : 1, 1, 16);
            int downlink = Math.Clamp(root.TryGetProperty("DownlinkConnections", out var downlinkJson) ? downlinkJson.GetInt32() : 1, 1, 16);
            string sessionId = root.TryGetProperty("SessionId", out var sessionIdJson) ? sessionIdJson.GetString() ?? "" : "";
            if (string.IsNullOrEmpty(sessionId))
            {
                logger?.LogError("服务端未下发 sessionId");
                throw new InvalidOperationException("服务端未下发 sessionId");
            }

            return new ServerAssignment
            {
                TunnelIp = tunnelIp,
                Ports = ports,
                Uplink = uplink,
                Downlink = downlink,
                SessionId = sessionId
            };
        }

        private static async Task RunSessionAsync(
            TunnelNet net,
            string sessionId,
            Channel<PacketBuffer>[] uplinkChannels,
            int uplink,
            int downlink,
            BatchOptions batchOptions,
            CancellationToken ct)
        {
            using var sessionCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var sessionToken = sessionCts.Token;
            var loops = new List<Task>(uplink + downlink);

            try
            {
                DrainUplinkChannels(uplinkChannels);

                // 建立 N 条上行 + N 条下行数据连接
                await net.ConnectDataChannelsAsync(uplink, downlink, sessionId, sessionToken);
                logger?.LogInformation($"数据连接已建立: 上行 {uplink} 条, 下行 {downlink} 条");

                // 上行: 每条连接 uplinkChannels[i] 聚合成 batch -> TLS Tx[i]
                var txStreams = net.TxStreams;
                for (int i = 0; i < uplink; i++)
                {
                    int idx = i;
                    loops.Add(Task.Run(() => DataChannel.SendLoopAsync(uplinkChannels[idx].Reader, txStreams[idx], batchOptions, sessionToken)));
                }

                // 下行: 每条连接 TLS Rx[i] 解析 batch -> 并发逐包写入 TUN
                var rxStreams = net.RxStreams;
                for (int i = 0; i < downlink; i++)
                {
                    int idx = i;
                    loops.Add(Task.Run(() => DataChannel.ReceiveLoopAsync(
                        rxStreams[idx],
                        (packet, c) => new ValueTask(tunnelTUN.WriteAsync(packet, c)),
                        sessionToken)));
                }

                // 原子会话: 任一连接断开则整体收尾
                await Task.WhenAny(loops);
            }
            finally
            {
                sessionCts.Cancel();
                try { await Task.WhenAll(loops); } catch { }
                net.Close();
            }
        }

        private static void ApplyPortConfig(IEnumerable<int> ports)
        {
            PortConfig = new ConcurrentBag<int>(ports);
        }

        private static void DrainUplinkChannels(Channel<PacketBuffer>[] uplinkChannels)
        {
            foreach (var channel in uplinkChannels)
            {
                while (channel.Reader.TryRead(out var packet))
                {
                    packet.Dispose();
                }
            }
        }

        static async Task<bool> Authentication(TunnelNet tunnelNet, string secret, string data, CancellationToken ct = default)
        {
            byte[] key = Encoding.UTF8.GetBytes(secret);
            long timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            string signData = $"{data}:{timestamp}";
            byte[] msg = Encoding.UTF8.GetBytes(signData);

            using var hmac = new HMACSHA256(key);

            string sign = Convert.ToHexString(hmac.ComputeHash(msg));

            var json = JsonSerializer.Serialize(
                new AuthenticationRequest { ClientID = data, Timestamp = timestamp, Sign = sign },
                TunRelayJsonContext.Default.AuthenticationRequest);
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
