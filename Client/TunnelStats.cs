using System.Text;
using System.Threading;
using Microsoft.Extensions.Logging;

namespace TunRelayClient
{
    /// <summary>
    /// 轻量级运行时统计,使用无锁 Interlocked 计数,供交互式 stats 命令观察吞吐/批量/丢包情况。
    /// </summary>
    public static class TunnelStats
    {
        private sealed class ChannelCounter
        {
            private long _packets;
            private long _bytes;
            private long _batches;
            private long _flushes;
            private long _queuePeak;

            public void AddBatch(int packets, long bytes, int queueDepth, bool flushed)
            {
                Interlocked.Add(ref _packets, packets);
                Interlocked.Add(ref _bytes, bytes);
                Interlocked.Increment(ref _batches);
                if (flushed)
                    Interlocked.Increment(ref _flushes);
                UpdatePeak(ref _queuePeak, queueDepth);
            }

            public void Reset()
            {
                Interlocked.Exchange(ref _packets, 0);
                Interlocked.Exchange(ref _bytes, 0);
                Interlocked.Exchange(ref _batches, 0);
                Interlocked.Exchange(ref _flushes, 0);
                Interlocked.Exchange(ref _queuePeak, 0);
            }

            public void AppendTo(StringBuilder sb, string direction, int index)
            {
                long packets = Interlocked.Read(ref _packets);
                long bytes = Interlocked.Read(ref _bytes);
                long batches = Interlocked.Read(ref _batches);
                long flushes = Interlocked.Read(ref _flushes);
                long queuePeak = Interlocked.Read(ref _queuePeak);
                double average = batches > 0 ? packets / (double)batches : 0;
                sb.AppendLine($"{direction}#{index,-2}             : {packets} pkts, {bytes} bytes, {batches} batches, avg={average:F2}, flush={flushes}, queuePeak={queuePeak}");
            }
        }

        private static ChannelCounter[] _sendChannels = Array.Empty<ChannelCounter>();
        private static ChannelCounter[] _receiveChannels = Array.Empty<ChannelCounter>();

        private static long _packetsSent;
        private static long _bytesSent;
        private static long _batchesSent;

        private static long _packetsReceived;
        private static long _bytesReceived;
        private static long _batchesReceived;

        private static long _channelDrops;
        private static long _protocolErrors;
        private static long _sinkWriteFailures;

        private static long _routeUpdatesQueued;
        private static long _routeUpdateFailures;

        private static long _startTicks = DateTime.UtcNow.Ticks;

        public static void ConfigureChannels(int sendCount, int receiveCount)
        {
            Volatile.Write(ref _sendChannels, CreateCounters(sendCount));
            Volatile.Write(ref _receiveChannels, CreateCounters(receiveCount));
        }

        public static void AddBatchSent(int channelIndex, int packetCount, long bytes, int queueDepth)
        {
            Interlocked.Add(ref _packetsSent, packetCount);
            Interlocked.Add(ref _bytesSent, bytes);
            Interlocked.Increment(ref _batchesSent);
            GetCounter(Volatile.Read(ref _sendChannels), channelIndex)?.AddBatch(packetCount, bytes, queueDepth, flushed: true);
        }

        public static void AddBatchReceived(int channelIndex, int packetCount, long bytes)
        {
            Interlocked.Add(ref _packetsReceived, packetCount);
            Interlocked.Add(ref _bytesReceived, bytes);
            Interlocked.Increment(ref _batchesReceived);
            GetCounter(Volatile.Read(ref _receiveChannels), channelIndex)?.AddBatch(packetCount, bytes, 0, flushed: false);
        }

        public static void IncrementChannelDrops() => Interlocked.Increment(ref _channelDrops);
        public static void IncrementProtocolErrors() => Interlocked.Increment(ref _protocolErrors);
        public static void IncrementSinkWriteFailures() => Interlocked.Increment(ref _sinkWriteFailures);
        public static void IncrementRouteUpdatesQueued() => Interlocked.Increment(ref _routeUpdatesQueued);
        public static void IncrementRouteUpdateFailures() => Interlocked.Increment(ref _routeUpdateFailures);

        public static void Reset()
        {
            Interlocked.Exchange(ref _packetsSent, 0);
            Interlocked.Exchange(ref _bytesSent, 0);
            Interlocked.Exchange(ref _batchesSent, 0);
            Interlocked.Exchange(ref _packetsReceived, 0);
            Interlocked.Exchange(ref _bytesReceived, 0);
            Interlocked.Exchange(ref _batchesReceived, 0);
            Interlocked.Exchange(ref _channelDrops, 0);
            Interlocked.Exchange(ref _protocolErrors, 0);
            Interlocked.Exchange(ref _sinkWriteFailures, 0);
            Interlocked.Exchange(ref _routeUpdatesQueued, 0);
            Interlocked.Exchange(ref _routeUpdateFailures, 0);
            foreach (var counter in Volatile.Read(ref _sendChannels))
                counter.Reset();
            foreach (var counter in Volatile.Read(ref _receiveChannels))
                counter.Reset();
            Interlocked.Exchange(ref _startTicks, DateTime.UtcNow.Ticks);
        }

        public static string Snapshot()
        {
            long packetsSent = Interlocked.Read(ref _packetsSent);
            long bytesSent = Interlocked.Read(ref _bytesSent);
            long batchesSent = Interlocked.Read(ref _batchesSent);
            long packetsReceived = Interlocked.Read(ref _packetsReceived);
            long bytesReceived = Interlocked.Read(ref _bytesReceived);
            long batchesReceived = Interlocked.Read(ref _batchesReceived);
            long channelDrops = Interlocked.Read(ref _channelDrops);
            long protocolErrors = Interlocked.Read(ref _protocolErrors);
            long sinkFailures = Interlocked.Read(ref _sinkWriteFailures);
            long routeQueued = Interlocked.Read(ref _routeUpdatesQueued);
            long routeFailures = Interlocked.Read(ref _routeUpdateFailures);

            double seconds = Math.Max(1e-3, (DateTime.UtcNow.Ticks - Interlocked.Read(ref _startTicks)) / (double)TimeSpan.TicksPerSecond);
            double avgPktPerBatchSent = batchesSent > 0 ? packetsSent / (double)batchesSent : 0;
            double avgPktPerBatchRecv = batchesReceived > 0 ? packetsReceived / (double)batchesReceived : 0;

            var sb = new StringBuilder();
            sb.AppendLine("===== TunnelStats =====");
            sb.AppendLine($"uptime            : {seconds:F1}s");
            sb.AppendLine($"sent              : {packetsSent} pkts, {bytesSent} bytes, {batchesSent} batches");
            sb.AppendLine($"received          : {packetsReceived} pkts, {bytesReceived} bytes, {batchesReceived} batches");
            sb.AppendLine($"avgPktsPerBatch   : sent={avgPktPerBatchSent:F2}, recv={avgPktPerBatchRecv:F2}");
            sb.AppendLine($"throughput        : out={bytesSent / seconds / 1024.0:F1} KB/s, in={bytesReceived / seconds / 1024.0:F1} KB/s");
            sb.AppendLine($"channelDrops      : {channelDrops}");
            sb.AppendLine($"protocolErrors    : {protocolErrors}");
            sb.AppendLine($"sinkWriteFailures : {sinkFailures}");
            sb.AppendLine($"routeUpdates      : queued={routeQueued}, failures={routeFailures}");
            AppendChannels(sb, "send", Volatile.Read(ref _sendChannels));
            AppendChannels(sb, "recv", Volatile.Read(ref _receiveChannels));
            sb.Append("=======================");
            return sb.ToString();
        }

        private static ChannelCounter[] CreateCounters(int count)
            => Enumerable.Range(0, Math.Max(0, count)).Select(_ => new ChannelCounter()).ToArray();

        private static ChannelCounter? GetCounter(ChannelCounter[] counters, int index)
            => (uint)index < (uint)counters.Length ? counters[index] : null;

        private static void AppendChannels(StringBuilder sb, string direction, ChannelCounter[] counters)
        {
            for (int i = 0; i < counters.Length; i++)
                counters[i].AppendTo(sb, direction, i);
        }

        private static void UpdatePeak(ref long target, long value)
        {
            long current = Volatile.Read(ref target);
            while (value > current)
            {
                long observed = Interlocked.CompareExchange(ref target, value, current);
                if (observed == current)
                    return;
                current = observed;
            }
        }
    }

    /// <summary>
    /// 程序运行中的交互式命令循环: stats / stats reset / help。不影响数据热路径。
    /// </summary>
    public static class ConsoleShell
    {
        private const string HelpText =
            "命令:\n" +
            "  status       打印当前运行状态\n" +
            "  config       打印当前生效配置(隐藏 Secret)\n" +
            "  loglevel <level>  动态调整日志级别\n" +
            "  stats        打印当前统计快照\n" +
            "  stats reset  清零统计\n" +
            "  batch adaptive on|off|status  切换运行时自适应批处理\n" +
            "  help         显示帮助";

        public static async Task RunAsync(CancellationToken ct)
        {
            if (Console.IsInputRedirected)
                return;

            Console.WriteLine("[shell] 已就绪,输入 help 查看命令");
            while (!ct.IsCancellationRequested)
            {
                string? line;
                try
                {
                    line = await Console.In.ReadLineAsync(ct);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch
                {
                    break;
                }

                if (line == null)
                    break;

                var command = line.Trim();
                if (command.StartsWith("loglevel ", StringComparison.OrdinalIgnoreCase))
                {
                    SetLogLevel(command["loglevel ".Length..].Trim());
                    continue;
                }
                if (command.StartsWith("batch adaptive", StringComparison.OrdinalIgnoreCase))
                {
                    HandleAdaptiveBatching(command["batch adaptive".Length..].Trim());
                    continue;
                }

                switch (command)
                {
                    case "":
                        break;
                    case "status":
                        Console.WriteLine(RuntimeStatus.Snapshot());
                        break;
                    case "config":
                        Console.WriteLine(ConfigSnapshot());
                        break;
                    case "stats":
                        Console.WriteLine(TunnelStats.Snapshot());
                        break;
                    case "stats reset":
                        TunnelStats.Reset();
                        Console.WriteLine("[shell] 统计已清零");
                        break;
                    case "help":
                    case "?":
                        Console.WriteLine(HelpText);
                        break;
                    default:
                        Console.WriteLine($"[shell] 未知命令: {command} (输入 help)");
                        break;
                }
            }
        }

        private static void SetLogLevel(string value)
        {
            if (!Enum.TryParse<LogLevel>(value, true, out var level))
            {
                Console.WriteLine($"[shell] 无效日志级别: {value}");
                return;
            }

            Program.CurrentLogLevel = level;
            Console.WriteLine($"[shell] 日志级别已切换为 {level}");
        }

        private static string ConfigSnapshot()
        {
            var config = Program.CurrentConfig;
            if (config == null)
                return "[shell] 配置尚未加载";

            var sb = new StringBuilder();
            sb.AppendLine("===== ClientConfig =====");
            sb.AppendLine($"ServerIp              : {config.ServerIp}");
            sb.AppendLine($"ServerPort            : {config.EffectiveServerPort}");
            sb.AppendLine($"ClientID              : {config.ClientID}");
            sb.AppendLine($"Secret                : {(string.IsNullOrEmpty(config.Secret) ? "" : "****")}");
            sb.AppendLine($"LogLevel              : {Program.CurrentLogLevel}");
            sb.AppendLine($"BatchDelayMs          : {config.BatchDelayMs}");
            sb.AppendLine($"MaxBatchBytes         : {config.MaxBatchBytes}");
            sb.AppendLine($"MaxBatchPackets       : {config.MaxBatchPackets}");
            sb.AppendLine($"AdaptiveBatching      : configured={config.AdaptiveBatching}, runtime={Program.GetAdaptiveBatching()}");
            sb.AppendLine($"ReconnectDelayMs      : {config.ReconnectDelayMs}");
            sb.AppendLine($"MaxReconnectAttempts  : {config.MaxReconnectAttempts}");
            sb.Append("========================");
            return sb.ToString();
        }

        private static void HandleAdaptiveBatching(string value)
        {
            switch (value.ToLowerInvariant())
            {
                case "on":
                case "true":
                    Program.SetAdaptiveBatching(true);
                    break;
                case "off":
                case "false":
                    Program.SetAdaptiveBatching(false);
                    break;
                case "":
                case "status":
                    break;
                default:
                    Console.WriteLine("[shell] 用法: batch adaptive on | off | status");
                    return;
            }

            Console.WriteLine($"[shell] AdaptiveBatching={(Program.GetAdaptiveBatching() ? "on" : "off")} (runtime only)");
        }
    }
}
