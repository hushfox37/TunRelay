using System.Text;
using System.Threading;

namespace TunRelayServer
{
    /// <summary>
    /// 轻量级运行时统计,使用无锁 Interlocked 计数,供交互式 stats 命令观察吞吐/批量/丢包情况。
    /// </summary>
    public static class TunnelStats
    {
        private static long _packetsSent;
        private static long _bytesSent;
        private static long _batchesSent;

        private static long _packetsReceived;
        private static long _bytesReceived;
        private static long _batchesReceived;

        private static long _channelDrops;
        private static long _protocolErrors;
        private static long _sinkWriteFailures;

        private static long _startTicks = DateTime.UtcNow.Ticks;

        public static void AddSent(int bytes)
        {
            Interlocked.Increment(ref _packetsSent);
            Interlocked.Add(ref _bytesSent, bytes);
        }

        public static void AddBatchSent(int packetCount) => Interlocked.Increment(ref _batchesSent);

        public static void AddReceived(int bytes)
        {
            Interlocked.Increment(ref _packetsReceived);
            Interlocked.Add(ref _bytesReceived, bytes);
        }

        public static void AddBatchReceived() => Interlocked.Increment(ref _batchesReceived);

        public static void IncrementChannelDrops() => Interlocked.Increment(ref _channelDrops);
        public static void IncrementProtocolErrors() => Interlocked.Increment(ref _protocolErrors);
        public static void IncrementSinkWriteFailures() => Interlocked.Increment(ref _sinkWriteFailures);

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
            sb.Append("=======================");
            return sb.ToString();
        }
    }

    /// <summary>
    /// 程序运行中的交互式命令循环: stats / stats reset / help。不影响数据热路径。
    /// </summary>
    public static class ConsoleShell
    {
        private const string HelpText =
            "命令:\n" +
            "  stats        打印当前统计快照\n" +
            "  stats reset  清零统计\n" +
            "  autocred on      开启一次性客户端自动配置\n" +
            "  autocred off     关闭一次性客户端自动配置\n" +
            "  autocred status  查看一次性客户端自动配置状态\n" +
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
                if (command.StartsWith("autocred ", StringComparison.OrdinalIgnoreCase))
                {
                    HandleAutoCredentials(command["autocred ".Length..].Trim());
                    continue;
                }

                switch (command)
                {
                    case "":
                        break;
                    case "stats":
                        Console.WriteLine(TunnelStats.Snapshot());
                        break;
                    case "stats reset":
                        TunnelStats.Reset();
                        Console.WriteLine("[shell] 统计已清零");
                        break;
                    case "autocred":
                    case "autocred status":
                        PrintAutoCredentialsStatus();
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

        private static void HandleAutoCredentials(string value)
        {
            switch (value.ToLowerInvariant())
            {
                case "on":
                case "true":
                case "enable":
                case "enabled":
                    Program.SetAutoCredentials(true);
                    break;
                case "off":
                case "false":
                case "disable":
                case "disabled":
                    Program.SetAutoCredentials(false);
                    break;
                case "":
                case "status":
                    PrintAutoCredentialsStatus();
                    break;
                default:
                    Console.WriteLine("[shell] 用法: autocred on | off | status");
                    break;
            }
        }

        private static void PrintAutoCredentialsStatus()
        {
            Console.WriteLine($"[shell] AutoCredentials={(Program.GetAutoCredentials() ? "on" : "off")}");
        }
    }
}
