using System.Text.Json;

namespace TunRelayClient
{
    internal sealed class ServerAssignment
    {
        public string TunnelIp { get; init; } = "";
        public int[] Ports { get; init; } = Array.Empty<int>();
        public int Uplink { get; init; }
        public int Downlink { get; init; }
        public string SessionId { get; init; } = "";

        // 解析数据通道建立前服务端下发的控制面参数。
        public static ServerAssignment Parse(string data)
        {
            using var json = JsonDocument.Parse(data);
            var root = json.RootElement;

            string tunnelIp = root.TryGetProperty("TunnelIP", out var tunnelIpJson)
                ? tunnelIpJson.GetString() ?? ""
                : "";

            if (string.IsNullOrWhiteSpace(tunnelIp))
            {
                throw new InvalidOperationException("服务端未下发 TunnelIP");
            }

            if (!root.TryGetProperty("Ports", out var portsJson) || portsJson.ValueKind != JsonValueKind.Array)
            {
                throw new InvalidOperationException("服务端未下发端口配置");
            }

            var ports = portsJson.EnumerateArray().Select(port => port.GetInt32()).ToArray();
            int uplink = Math.Clamp(root.TryGetProperty("UplinkConnections", out var uplinkJson) ? uplinkJson.GetInt32() : 1, 1, 16);
            int downlink = Math.Clamp(root.TryGetProperty("DownlinkConnections", out var downlinkJson) ? downlinkJson.GetInt32() : 1, 1, 16);
            string sessionId = root.TryGetProperty("SessionId", out var sessionIdJson) ? sessionIdJson.GetString() ?? "" : "";
            if (string.IsNullOrEmpty(sessionId))
            {
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
    }
}
