using System.Text;
using System.Threading;

namespace TunRelayClient
{
    internal static class RuntimeStatus
    {
        private static long _startedTicks = DateTime.UtcNow.Ticks;
        private static int _uplink;
        private static int _downlink;
        private static int _reconnectAttempts;
        private static string _state = "starting";
        private static string _sessionId = "";

        public static void SetAssigned(int uplink, int downlink, string sessionId)
        {
            Interlocked.Exchange(ref _uplink, uplink);
            Interlocked.Exchange(ref _downlink, downlink);
            Interlocked.Exchange(ref _startedTicks, DateTime.UtcNow.Ticks);
            Volatile.Write(ref _sessionId, sessionId);
            Volatile.Write(ref _state, "assigned");
        }

        public static void SetSessionRunning(string sessionId)
        {
            Volatile.Write(ref _sessionId, sessionId);
            Volatile.Write(ref _state, "running");
        }

        public static void SetReconnecting(int attempts)
        {
            Interlocked.Exchange(ref _reconnectAttempts, attempts);
            Volatile.Write(ref _state, "reconnecting");
        }

        public static string Snapshot()
        {
            double seconds = Math.Max(1e-3, (DateTime.UtcNow.Ticks - Interlocked.Read(ref _startedTicks)) / (double)TimeSpan.TicksPerSecond);
            var sb = new StringBuilder();
            sb.AppendLine("===== RuntimeStatus =====");
            sb.AppendLine($"state             : {Volatile.Read(ref _state)}");
            sb.AppendLine($"uptime            : {seconds:F1}s");
            sb.AppendLine($"server            : {Program.ServerIP}:{Program.ServerPort}");
            sb.AppendLine($"tunnelIP          : {Program.TunnelIP}");
            sb.AppendLine($"ports             : {string.Join(",", Program.PortConfig.OrderBy(port => port))}");
            sb.AppendLine($"dataChannels      : uplink={Interlocked.CompareExchange(ref _uplink, 0, 0)}, downlink={Interlocked.CompareExchange(ref _downlink, 0, 0)}");
            sb.AppendLine($"sessionId         : {Volatile.Read(ref _sessionId)}");
            sb.AppendLine($"reconnectAttempts : {Interlocked.CompareExchange(ref _reconnectAttempts, 0, 0)}");
            sb.Append("=========================");
            return sb.ToString();
        }
    }
}
