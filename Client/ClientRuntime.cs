using System.Collections.Concurrent;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;

namespace TunRelayClient
{
    internal sealed class ClientRuntime
    {
        private readonly TunRelayConfig _config;
        private readonly ILogger _logger;
        private readonly ReconnectPolicy _reconnectPolicy;
        private readonly ControlHandshake _controlHandshake;

        public ClientRuntime(TunRelayConfig config, string configPath, ILogger logger)
        {
            _config = config;
            _logger = logger;
            _reconnectPolicy = ReconnectPolicy.FromConfig(config);
            _controlHandshake = new ControlHandshake(config, configPath, logger);
        }

        public async Task RunAsync(CancellationToken ct)
        {
            _logger.LogInformation($"配置: Server={Program.ServerIP}:{Program.ServerPort}, ClientID={_config.ClientID}");
            _logger.LogInformation($"重连参数: DelayMs={(int)_reconnectPolicy.Delay.TotalMilliseconds}, MaxAttempts={_reconnectPolicy.LimitText}");

            var control = await _controlHandshake.ConnectWithRetryAsync(_reconnectPolicy, ct);
            Program.TunnelIP = control.Assignment.TunnelIp;
            int uplink = control.Assignment.Uplink;
            int downlink = control.Assignment.Downlink;
            ApplyPortConfig(control.Assignment.Ports);
            RuntimeStatus.SetAssigned(uplink, downlink, control.Assignment.SessionId);

            _logger.LogInformation($"服务端下发: TunnelIP={Program.TunnelIP}, Ports={string.Join(",", control.Assignment.Ports)}, Uplink={uplink}, Downlink={downlink}");

            var uplinkChannels = CreateUplinkChannels(uplink);

            // TUN 跟随进程生命周期；重连只重建网络会话。
            ITunDriver driver = TunDriverFactory.Create();
            Program.tunnelTUN = new TUN(driver, uplinkChannels);
            await Program.tunnelTUN.StartAsync(Program.TunnelIP, ct);

            var batchOptions = new BatchOptions(_config.BatchDelayMs, _config.MaxBatchBytes, _config.MaxBatchPackets);
            _logger.LogInformation($"数据通道批处理参数: DelayMs={batchOptions.DelayMs}, MaxBytes={batchOptions.MaxBytes}, MaxPackets={batchOptions.MaxPackets}");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    ApplyPortConfig(control.Assignment.Ports);
                    RuntimeStatus.SetSessionRunning(control.Assignment.SessionId);
                    await RunSessionAsync(control.Net, control.Assignment.SessionId, uplinkChannels, uplink, downlink, batchOptions, ct);
                    _reconnectPolicy.Reset();
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "数据会话异常断开");
                    control.Net.Close();
                }

                if (ct.IsCancellationRequested)
                {
                    break;
                }

                _logger.LogWarning($"数据连接已断开，{(int)_reconnectPolicy.Delay.TotalMilliseconds} 毫秒后重连...");
                await Task.Delay(_reconnectPolicy.Delay, ct);

                control = await _controlHandshake.ConnectWithRetryAsync(_reconnectPolicy, ct, Program.TunnelIP, uplink, downlink);
                RuntimeStatus.SetAssigned(uplink, downlink, control.Assignment.SessionId);
                _logger.LogInformation($"服务端下发: TunnelIP={control.Assignment.TunnelIp}, Ports={string.Join(",", control.Assignment.Ports)}, Uplink={control.Assignment.Uplink}, Downlink={control.Assignment.Downlink}");
            }
        }

        private static Channel<PacketBuffer>[] CreateUplinkChannels(int uplink)
        {
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

            return uplinkChannels;
        }

        private async Task RunSessionAsync(
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
            var loops = new List<(string Name, Task Task)>(uplink + downlink);

            try
            {
                // 丢弃断线期间积压的包，让新会话从干净队列开始。
                DrainUplinkChannels(uplinkChannels);

                await net.ConnectDataChannelsAsync(uplink, downlink, sessionId, sessionToken);
                _logger.LogInformation($"数据连接已建立: 上行 {uplink} 条, 下行 {downlink} 条");

                var txStreams = net.TxStreams;
                for (int i = 0; i < uplink; i++)
                {
                    int idx = i;
                    loops.Add(($"tx#{idx}", Task.Run(() => DataChannel.SendLoopAsync(uplinkChannels[idx].Reader, txStreams[idx], batchOptions, sessionToken))));
                }

                var rxStreams = net.RxStreams;
                for (int i = 0; i < downlink; i++)
                {
                    int idx = i;
                    loops.Add(($"rx#{idx}", Task.Run(() => DataChannel.ReceiveLoopAsync(
                        rxStreams[idx],
                        (packet, c) => new ValueTask(Program.tunnelTUN.WriteAsync(packet, c)),
                        sessionToken))));
                }

                var completed = await Task.WhenAny(loops.Select(loop => loop.Task));
                LogCompletedLoop(loops, completed);
            }
            finally
            {
                sessionCts.Cancel();
                try { await Task.WhenAll(loops.Select(loop => loop.Task)); } catch { }
                net.Close();
            }
        }

        private void LogCompletedLoop(List<(string Name, Task Task)> loops, Task completed)
        {
            var loopName = loops.FirstOrDefault(loop => ReferenceEquals(loop.Task, completed)).Name ?? "unknown";
            if (completed.IsFaulted)
            {
                _logger.LogError(completed.Exception?.GetBaseException(), $"[SESSION] 首个退出: {loopName} faulted");
            }
            else if (completed.IsCanceled)
            {
                _logger.LogWarning($"[SESSION] 首个退出: {loopName} canceled");
            }
            else
            {
                _logger.LogWarning($"[SESSION] 首个退出: {loopName} completed");
            }
        }

        private static void ApplyPortConfig(IEnumerable<int> ports)
        {
            Program.PortConfig = new ConcurrentBag<int>(ports);
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
    }
}
